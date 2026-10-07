import os
import re
import ast
import copy
import time
import json
import hmac
import hashlib
import datetime
from typing import Any, Dict, List, Optional, Tuple, Union

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import NameOID
from cryptography.exceptions import InvalidSignature

from mcp_shield.src.schemas import (
    JSONRPCRequest,
    CapabilityCert,
    MCPSecHeader,
    PolicyResult
)
from mcp_shield.src.exceptions import (
    MCPShieldException,
    PolicyViolationException,
    ASTValidationException,
    NamespaceViolationException,
    CapabilityViolationException,
)
from mcp_shield.src.session import SessionState



class NonceWindow:
    """Implements a sliding window replay protection filter for nonces with a 30s TTL."""
    def __init__(self):
        # Maps server_id -> Dict[nonce, timestamp]
        self._nonces: Dict[str, Dict[str, float]] = {}

    def check_and_add(self, server_id: str, nonce: str, timestamp: float) -> bool:
        now = time.time()
        # 1. Check if the timestamp is within the ±30s window of the proxy's clock
        if abs(now - timestamp) > 30.0:
            return False

        if server_id not in self._nonces:
            self._nonces[server_id] = {}

        # 2. Prune expired nonces from the map
        self._nonces[server_id] = {
            n: t for n, t in self._nonces[server_id].items() if abs(now - t) <= 30.0
        }

        # 3. Check for replay
        if nonce in self._nonces[server_id]:
            return False

        # 4. Record new nonce
        self._nonces[server_id][nonce] = timestamp
        return True


def resolve_env_vars(val: Any) -> Any:
    """Recursively walks configuration structures and resolves environment variable patterns."""
    if isinstance(val, str):
        if val.startswith("${") and val.endswith("}"):
            env_var = val[2:-1]
            return os.environ.get(env_var, "")
        return val
    elif isinstance(val, dict):
        return {k: resolve_env_vars(v) for k, v in val.items()}
    elif isinstance(val, list):
        return [resolve_env_vars(x) for x in val]
    return val


def find_blocked_regex(value: Any, compiled_patterns: List[Tuple[re.Pattern, str]]) -> Optional[str]:
    """Recursively walks a nested data structure searching for regex pattern matches."""
    if isinstance(value, str):
        for pattern, raw_pat in compiled_patterns:
            if pattern.search(value):
                return raw_pat
    elif isinstance(value, dict):
        for v in value.values():
            res = find_blocked_regex(v, compiled_patterns)
            if res:
                return res
    elif isinstance(value, list):
        for item in value:
            res = find_blocked_regex(item, compiled_patterns)
            if res:
                return res
    return None


class PolicyEngine:
    """Unified security evaluator mapping input parameters and payloads against security rules."""
    def __init__(self, config_path: str = "config/shield_config.json"):
        self.config_path = config_path
        self.config: Dict[str, Any] = {}
        # NOTE: nonce_window is intentionally preserved across load_config() calls.
        self.nonce_window = NonceWindow()
        self.load_config()

    def load_config(self) -> None:
        """Loads and parses the shield configuration file, resolving env vars and compiling regexes."""
        if os.path.exists(self.config_path):
            with open(self.config_path, "r", encoding="utf-8") as f:
                raw_config = json.load(f)
                self.config = resolve_env_vars(raw_config)
        else:
            self.config = {}

        # Precompile Regex Blacklists
        self.compiled_default_regex: List[Tuple[re.Pattern, str]] = []
        default_blacklist = self.config.get("default", {}).get("regex_blacklist", [])
        for pat in default_blacklist:
            try:
                self.compiled_default_regex.append((re.compile(pat, re.IGNORECASE), pat))
            except re.error:
                pass

        self.compiled_server_regex: Dict[str, List[Tuple[re.Pattern, str]]] = {}
        servers = self.config.get("servers", {})
        for srv_id, srv_cfg in servers.items():
            self.compiled_server_regex[srv_id] = []
            server_blacklist = srv_cfg.get("regex_blacklist", [])
            for pat in server_blacklist:
                try:
                    self.compiled_server_regex[srv_id].append((re.compile(pat, re.IGNORECASE), pat))
                except re.error:
                    pass

    def evaluate(
        self,
        request: JSONRPCRequest,
        session_state: SessionState,
        body_bytes: Optional[bytes] = None,
        sec_header: Optional[MCPSecHeader] = None
    ) -> PolicyResult:
        """Evaluates a JSON-RPC request through the sequential 6-stage policy chain."""
        policy_res = self._evaluate_impl(request, session_state, body_bytes, sec_header)
        
        # Record call outcome in session history
        tool_name = request.params.get("name") if isinstance(request.params, dict) else None
        outcome = policy_res.stage if not policy_res.allowed else "allowed"
        session_state.record_call(request.method, tool_name, outcome)
        
        return policy_res

    def _evaluate_impl(
        self,
        request: JSONRPCRequest,
        session_state: SessionState,
        body_bytes: Optional[bytes] = None,
        sec_header: Optional[MCPSecHeader] = None
    ) -> PolicyResult:
        """Internal evaluation logic, wrapped to ensure call history is always recorded."""
        server_id = session_state.server_id or (sec_header.server_id if sec_header else "unknown")

        # 1. HMAC validation (only in HTTP/SSE transport modes where sec_header is provided)
        if sec_header is not None and body_bytes is not None:
            server_keys = self.config.get("server_keys", {})
            psk = server_keys.get(server_id)
            if not psk:
                return PolicyResult(
                    allowed=False,
                    reason=f"HMAC validation failed: missing key for server '{server_id}'",
                    stage="hmac"
                )

            # Recompute and compare HMAC
            msg = f"{sec_header.timestamp}:{sec_header.nonce}:".encode("utf-8") + body_bytes
            computed_hmac = hmac.new(psk.encode("utf-8"), msg, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(computed_hmac, sec_header.hmac):
                return PolicyResult(
                    allowed=False,
                    reason="HMAC validation failed: signature mismatch",
                    stage="hmac"
                )

            # Verify nonce sliding window replay protection
            if not self.nonce_window.check_and_add(server_id, sec_header.nonce, sec_header.timestamp):
                return PolicyResult(
                    allowed=False,
                    reason="HMAC validation failed: nonce replay or timestamp expired",
                    stage="hmac"
                )

        # 1.5 Sequence Check
        seq_res = self._check_sequence(request, session_state)
        if seq_res:
            return seq_res

        # 2. Capability Attestation check
        # Map requested JSON-RPC methods to required capabilities.
        req_capability = None
        if request.method == "tools/call":
            req_capability = "tools"
        elif request.method == "tools/list":
            req_capability = "tools"
        elif request.method == "sampling/createMessage":
            req_capability = "sampling"
        elif request.method.startswith("resources/"):
            req_capability = "resources"
        elif request.method.startswith("prompts/"):
            req_capability = "prompts"

        if req_capability is not None:
            # If server_id is configured with allowed_tools, it might not need certificates
            # in fallback mode, but if trust_mode is strict or we require certs, check them.
            # For the attestation check, verify if capability is attested.
            # If server has sampling_allowed in config, that behaves as an attestation override.
            server_cfg = self.config.get("servers", {}).get(server_id, {})
            trust_mode = self.config.get("trust_mode", "prompt")

            if req_capability == "sampling":
                is_allowed = (
                    "sampling" in session_state.verified_capabilities
                    or server_cfg.get("sampling_allowed", False)
                )
            else:
                if trust_mode == "strict":
                    is_allowed = req_capability in session_state.verified_capabilities
                else:
                    is_allowed = (
                        req_capability in session_state.verified_capabilities
                        or server_id in self.config.get("servers", {})
                    )

            if not is_allowed:
                return PolicyResult(
                    allowed=False,
                    reason=f"Capability violation: capability '{req_capability}' not attested for server '{server_id}'",
                    stage="attestation"
                )

        # 3. Regex scan recursively checking request parameters
        server_patterns = self.compiled_server_regex.get(server_id, [])
        patterns = server_patterns + self.compiled_default_regex
        if request.params:
            matched_pattern = find_blocked_regex(self._regex_scan_target(request), patterns)
            if matched_pattern:
                return PolicyResult(
                    allowed=False,
                    reason=f"Security policy violation: blocked pattern '{matched_pattern}' detected in parameters",
                    stage="regex"
                )

        # 4. AST scan (only if a code param is present)
        code_param_names = self.config.get("code_param_names", ["code", "script", "py_code", "python_code", "command"])
        code_to_scan = None
        if isinstance(request.params, dict):
            # Check top-level params first (e.g. {"method": "execute_code", "params": {"code": ...}})
            for key in code_param_names:
                if key in request.params and isinstance(request.params[key], str):
                    code_to_scan = request.params[key]
                    break
            # Fall through to params.arguments if not found at top level
            if not code_to_scan:
                arguments = request.params.get("arguments", {}) or {}
                if isinstance(arguments, dict):
                    for key in code_param_names:
                        if key in arguments and isinstance(arguments[key], str):
                            code_to_scan = arguments[key]
                            break

        if code_to_scan is not None:
            try:
                tree = ast.parse(code_to_scan)
                
                ast_policy = self.config.get("ast_policy", {})
                if ast_policy.get("fine_grained", True):
                    ast_result = _check_ast_fine_grained(tree, ast_policy)
                else:
                    ast_result = _check_ast_original(tree, ast_policy)
                if ast_result:
                    return ast_result
            except SyntaxError as se:
                return PolicyResult(
                    allowed=False,
                    reason=f"SyntaxError: unparseable code payload: {se}",
                    stage="ast"
                )

        # 5. Namespace Lock (evaluates request namespacing)
        if request.method == "tools/call":
            tool_name = request.params.get("name") if isinstance(request.params, dict) else None
            server_cfg = self.config.get("servers", {}).get(server_id, {})
            allowed_tools = server_cfg.get("allowed_tools", self.config.get("default", {}).get("allowed_tools", []))
            if allowed_tools and tool_name not in allowed_tools:
                return PolicyResult(
                    allowed=False,
                    reason=f"Namespace lock violation: tool '{tool_name}' not in allowed namespace for server '{server_id}'",
                    stage="namespace"
                )

        return PolicyResult(allowed=True, reason="Passed all security policies", stage="passed")

    _WRITE_TOOL_RE = re.compile(r"(write|save|create|append|put)", re.IGNORECASE)

    def _regex_scan_target(self, request: JSONRPCRequest) -> Any:
        """Params to run the regex blacklist over.

        The blacklist exists to stop dangerous commands and paths from being passed
        as arguments. When a write tool stores prose into a documentation file
        (README, SECURITY.md, ...), that prose is data, and a warning such as
        "never run curl ... | bash" is not a command. With regex_doc_exemption
        enabled (default), the body of such a write is skipped; the path and every
        other argument are still scanned, and executable or unknown file types are
        scanned in full.
        """
        cfg = self.config.get("regex_doc_exemption", {})
        if not cfg.get("enabled", True) or request.method != "tools/call" or not isinstance(request.params, dict):
            return request.params
        tool = request.params.get("name") or ""
        args = request.params.get("arguments")
        if not isinstance(args, dict) or not self._WRITE_TOOL_RE.search(tool):
            return request.params
        exts = tuple(cfg.get("extensions", [".md", ".txt", ".rst", ".adoc"]))
        content_keys = set(cfg.get("content_keys", ["content", "text", "body"]))
        dest = next((args[k] for k in ("path", "file", "filepath", "destination", "dest")
                     if isinstance(args.get(k), str)), "")
        if not dest.lower().endswith(exts):
            return request.params
        scanned = dict(request.params)
        scanned["arguments"] = {k: v for k, v in args.items() if k not in content_keys}
        return scanned

    def _check_sequence(self, request: JSONRPCRequest, session_state: SessionState) -> Optional[PolicyResult]:
        """Evaluates the current request against configured sequence patterns and rate limits."""
        seq_policy = self.config.get("sequence_policy", {})
        if not seq_policy:
            return None
            
        now = time.time()
        rules = seq_policy.get("default", [])
        server_rules = seq_policy.get("servers", {}).get(session_state.server_id, [])
        all_rules = server_rules + rules
        
        history = session_state.call_history
        current_method = request.method
        current_tool = request.params.get("name") if isinstance(request.params, dict) else None
        current_sig = f"tools/call:{current_tool}" if current_method == "tools/call" and current_tool else current_method
        
        for rule in all_rules:
            action = rule.get("action", "block")
            if action != "block":
                continue
                
            # Rate limit rule
            if "max_calls" in rule and "window_seconds" in rule:
                max_calls = rule["max_calls"]
                window_seconds = rule["window_seconds"]
                recent_calls = [c for c in history if now - c["timestamp"] <= window_seconds]
                if len(recent_calls) >= max_calls:
                    return PolicyResult(allowed=False, reason=rule.get("name", "rate_limit_exceeded"), stage="sequence")
                    
            # Pattern rule
            if "pattern" in rule:
                pattern = rule["pattern"]
                window_size = rule.get("window", len(pattern))
                
                recent_history = history[-(window_size - 1):] if window_size > 1 else []
                recent_sigs = []
                for call in recent_history:
                    method = call["method"]
                    tool = call.get("tool_name")
                    sig = f"tools/call:{tool}" if method == "tools/call" and tool else method
                    recent_sigs.append(sig)
                recent_sigs.append(current_sig)
                
                # Check for contiguous sublist matching the pattern
                n = len(pattern)
                if any(pattern == recent_sigs[i:i+n] for i in range(len(recent_sigs)-n+1)):
                    return PolicyResult(allowed=False, reason=rule.get("name", "suspicious_sequence"), stage="sequence")
                    
        return None

    def verify_capability_cert(self, cert_json: dict) -> Tuple[bool, str]:
        """Loads and verifies a cryptographic capability certificate using the Root CA certificate."""
        ca_cert_path = os.environ.get("MCP_CA_CERT", "config/ca_cert.pem")
        if not os.path.exists(ca_cert_path):
            return False, f"Missing CA certificate at path '{ca_cert_path}'"

        try:
            with open(ca_cert_path, "rb") as f:
                ca_cert_bytes = f.read()
            ca_cert = x509.load_pem_x509_certificate(ca_cert_bytes)
        except Exception as e:
            return False, f"Failed to load CA certificate: {e}"

        try:
            cert_model = CapabilityCert(**cert_json)
        except Exception as e:
            return False, f"Invalid CapabilityCert schema structure: {e}"

        try:
            cert = x509.load_pem_x509_certificate(cert_model.cert_pem.encode("utf-8"))
            
            # 1. Verify cryptographic signature
            ca_pubkey = ca_cert.public_key()
            ca_pubkey.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm
            )
        except InvalidSignature:
            return False, "Signature verification failed"
        except Exception as e:
            return False, f"Failed to parse or verify certificate signature payload: {e}"

        # 2. Verify certificate timeframe
        now = datetime.datetime.now(datetime.timezone.utc)
        try:
            valid_time = cert.not_valid_before_utc <= now <= cert.not_valid_after_utc
        except AttributeError:
            # Support older python-cryptography library formats
            naive_now = datetime.datetime.utcnow()
            valid_time = cert.not_valid_before <= naive_now <= cert.not_valid_after

        if not valid_time:
            return False, "Signature certificate validity timeframe check failed"

        # Compare CapabilityCert timestamp fields
        if cert_model.expires_at <= time.time():
            return False, "Capability Certificate has expired"

        # 3. Verify Server ID Identity
        name_matched = False
        for attr in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
            if attr.value == cert_model.server_id:
                name_matched = True
        if not name_matched:
            try:
                san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                for dns_name in san.value:
                     if isinstance(dns_name, x509.DNSName) and dns_name.value == cert_model.server_id:
                         name_matched = True
            except x509.ExtensionNotFound:
                pass

        if not name_matched:
            return False, f"Certificate CN/SAN does not match server_id '{cert_model.server_id}'"

        return True, "Passed capability certificate attestation"

    def filter_tools_list_response(self, server_id: str, response_dict: dict) -> dict:
        """Filters tool declarations from list responses based on allowed namespaces."""
        response_dict = copy.deepcopy(response_dict)
        server_cfg = self.config.get("servers", {}).get(server_id, {})
        allowed_tools = server_cfg.get("allowed_tools", self.config.get("default", {}).get("allowed_tools", []))

        # If server is declared in config, it MUST only return tools in allowed_tools.
        if server_id in self.config.get("servers", {}):
            result = response_dict.get("result", {})
            if isinstance(result, dict) and "tools" in result:
                tools = result.get("tools", [])
                filtered = [t for t in tools if isinstance(t, dict) and t.get("name") in allowed_tools]
                response_dict["result"]["tools"] = filtered
        return response_dict

    def sanitize_output(self, text: str) -> Tuple[str, bool]:
        """Sanitizes text outputs for prompt injections using line-start and full-text substring rules.

        With output_sanitizer.context_rules (default true), two classes of match are
        treated as data rather than injection:
          * a line-start role label whose line parses as a Python annotated
            assignment / key-value field (``user: postgres``,
            ``assistant: Assistant = Assistant(...)``) -- prose after the label,
            which is what a spoofed role header needs to carry instructions,
            never parses this way;
          * substring hits that fall under a context rule in _CONTEXT_RULES
            (status reports, CLI examples, file-metadata lines, purpose clauses).
        Set context_rules to false to restore the original behaviour.
        """
        san_config = self.config.get("output_sanitizer", {})
        case_insensitive = san_config.get("case_insensitive", True)
        use_context = san_config.get("context_rules", True)
        flags = re.IGNORECASE if case_insensitive else 0

        lines = text.split("\n")
        flagged = False
        cleaned_lines = []

        line_patterns = [
            re.compile(r"^\s*" + re.escape(p), flags)
            for p in san_config.get("line_start_patterns", [])
        ]
        sub_patterns = [
            (p, re.compile(re.escape(p), flags))
            for p in san_config.get("substring_patterns", [])
        ]

        # 1. Line-start surgical pattern replacement
        for line in lines:
            if any(p.match(line) for p in line_patterns) and not (use_context and _is_field_line(line)):
                cleaned_lines.append("[SANITIZED: potential prompt injection removed]")
                flagged = True
            else:
                cleaned_lines.append(line)

        result_text = "\n".join(cleaned_lines)

        # 2. Whole text substring detection and override
        hit = False
        for raw, pat in sub_patterns:
            for m in pat.finditer(result_text):
                if use_context and _context_exempt(raw, result_text, m):
                    continue
                hit = True
                break
            if hit:
                break
        if hit:
            result_text = "[CONTENT SANITIZED: prompt injection pattern detected in tool output]"
            flagged = True

        return result_text, flagged


# ---------------------------------------------------------------------------
# Fine-grained AST policy
# ---------------------------------------------------------------------------

# Members of otherwise-blocked modules that cannot execute commands, open network
# connections, or load native code. Extend or override via ast_policy.safe_members.
DEFAULT_SAFE_MEMBERS = {
    "os": ["path"],
    "socket": ["gethostname", "getfqdn"],
    "signal": ["signal", "getsignal", "SIGTERM", "SIGINT", "SIGHUP", "SIG_IGN", "SIG_DFL"],
    "shutil": ["copy", "copy2", "copyfile", "copyfileobj"],
    "threading": ["Thread", "Lock", "RLock", "Event", "Semaphore", "BoundedSemaphore",
                  "Condition", "Timer", "current_thread", "get_ident"],
    "urllib": ["parse"],
}
_ATTR_BUILTINS = {"setattr", "delattr"}


def _ast_block(reason: str) -> PolicyResult:
    return PolicyResult(allowed=False, reason=f"AST violation: {reason}", stage="ast")


def _check_ast_fine_grained(tree: ast.AST, ast_policy: dict) -> Optional[PolicyResult]:
    """Member-level AST policy.

    Differences from the original whole-module policy:
      * A blocked module may be imported only for members listed in safe_members
        (e.g. os.path, socket.gethostname), and every use of it must stay inside
        that list; os.system, socket.socket, a module with no safe members, or
        passing the module object around are still blocked.
      * Names in blocked_calls used as methods (re.compile, app.run) are only
        blocked on a blocked module or on builtins, not on arbitrary objects.
      * setattr/delattr with a literal, non-dunder attribute name are equivalent
        to plain attribute assignment and are allowed; dunder or computed names
        are blocked. getattr stays blocked outright (dynamic resolution).
      * Non-dunder blocked_attributes are checked on blocked modules only;
        dunder blocked_attributes (__globals__, __subclasses__, ...) are blocked
        everywhere.
    """
    blocked_modules = ast_policy.get("blocked_modules", [])
    blocked_calls = set(ast_policy.get("blocked_calls", []))
    blocked_attributes = set(ast_policy.get("blocked_attributes", []))
    safe = {k: set(v) for k, v in DEFAULT_SAFE_MEMBERS.items()}
    for k, v in ast_policy.get("safe_members", {}).items():
        safe[k] = set(v)

    def root_blocked(name: str) -> Optional[str]:
        for bm in blocked_modules:
            if name == bm or name.startswith(bm + "."):
                return bm
        return None

    # local name -> (blocked module, allowed members)
    restricted: dict = {}

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                bm = root_blocked(alias.name)
                if not bm:
                    continue
                allowed = safe.get(bm, set())
                parts = alias.name.split(".")
                if len(parts) > 1:
                    if parts[1] not in allowed:
                        return _ast_block(f"import of restricted module '{alias.name}'")
                    if alias.asname:
                        continue  # binds the safe submodule itself
                    restricted[parts[0]] = (bm, {parts[1]})
                else:
                    if not allowed:
                        return _ast_block(f"import of restricted module '{alias.name}'")
                    restricted[alias.asname or alias.name] = (bm, allowed)
        elif isinstance(node, ast.ImportFrom):
            for name_node in node.names:
                if name_node.name in blocked_calls:
                    return _ast_block(f"import of restricted call '{name_node.name}'")
            if not node.module:
                continue
            bm = root_blocked(node.module)
            if not bm:
                for name_node in node.names:
                    if root_blocked(name_node.name):
                        return _ast_block(f"import of restricted module '{name_node.name}'")
                continue
            allowed = safe.get(bm, set())
            parts = node.module.split(".")
            if len(parts) > 1:
                if parts[1] not in allowed:
                    return _ast_block(f"import from restricted module '{node.module}'")
            else:
                for name_node in node.names:
                    if name_node.name not in allowed:
                        return _ast_block(f"import of restricted member '{node.module}.{name_node.name}'")

    attr_values = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            attr_values.add(id(node.value))
            if node.attr.startswith("__") and node.attr in blocked_attributes:
                return _ast_block(f"access to restricted attribute '{node.attr}'")
            if isinstance(node.value, ast.Name) and node.value.id in restricted:
                bm, allowed = restricted[node.value.id]
                if node.attr not in allowed:
                    return _ast_block(f"use of restricted member '{bm}.{node.attr}'")

    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in restricted and id(node) not in attr_values \
                and isinstance(node.ctx, ast.Load):
            return _ast_block(f"restricted module '{restricted[node.id][0]}' used as a value")
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name):
            if func.id == "getattr":
                return _ast_block("call to getattr() is restricted to prevent dynamic resolution obfuscation")
            if func.id in _ATTR_BUILTINS and func.id in blocked_calls:
                name_arg = node.args[1] if len(node.args) > 1 else None
                names = _static_string_values(tree, name_arg)
                if names is None or any(n.startswith("__") for n in names):
                    return _ast_block(f"call to {func.id}() with a dynamic or dunder attribute name")
                continue
            if func.id in blocked_calls:
                return _ast_block(f"call to restricted function '{func.id}'")
        elif isinstance(func, ast.Attribute):
            recv = func.value.id if isinstance(func.value, ast.Name) else None
            on_restricted = recv in restricted or recv in ("builtins", "__builtins__")
            if func.attr in blocked_calls and on_restricted:
                return _ast_block(f"call to restricted function attribute '{func.attr}'")
    return None


def _literal_strings(node: ast.AST) -> Optional[set]:
    """String constants of a dict/list/tuple/set literal, or None."""
    if isinstance(node, ast.Dict):
        elts = node.keys
    elif isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        elts = node.elts
    else:
        return None
    vals = set()
    for e in elts:
        if not (isinstance(e, ast.Constant) and isinstance(e.value, str)):
            return None
        vals.add(e.value)
    return vals


def _static_string_values(tree: ast.AST, node: Optional[ast.AST]) -> Optional[set]:
    """All strings an attribute-name argument can take, if statically known.

    Handles a string literal, or a variable whose every binding is a for-loop
    over a literal collection (``for k in ['a', 'b']``, ``for k, v in {...}.items()``).
    Anything else returns None (unknown).
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return {node.value}
    if not isinstance(node, ast.Name):
        return None
    name, values, bound = node.id, set(), False
    for n in ast.walk(tree):
        targets = []
        if isinstance(n, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
            targets = n.targets if isinstance(n, ast.Assign) else [n.target]
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            if any(a.arg == name for a in n.args.args + n.args.kwonlyargs):
                return None
        elif isinstance(n, (ast.With, ast.AsyncWith)):
            targets = [i.optional_vars for i in n.items if i.optional_vars is not None]
        elif isinstance(n, ast.comprehension):
            targets = [n.target]
        if any(isinstance(t, ast.Name) and t.id == name for t in targets for t in ast.walk(t)):
            return None
        if isinstance(n, (ast.For, ast.AsyncFor)):
            it, tgt = n.iter, n.target
            if isinstance(tgt, ast.Name) and tgt.id == name:
                if isinstance(it, ast.Call) and isinstance(it.func, ast.Attribute) and it.func.attr == "keys":
                    it = it.func.value
                vals = _literal_strings(it)
            elif isinstance(tgt, ast.Tuple) and tgt.elts and isinstance(tgt.elts[0], ast.Name) \
                    and tgt.elts[0].id == name:
                if not (isinstance(it, ast.Call) and isinstance(it.func, ast.Attribute) and it.func.attr == "items"):
                    return None
                vals = _literal_strings(it.func.value) if isinstance(it.func.value, ast.Dict) else None
            elif any(isinstance(t, ast.Name) and t.id == name for t in ast.walk(tgt)):
                return None
            else:
                continue
            if vals is None:
                return None
            values |= vals
            bound = True
    return values if bound else None


def _check_ast_original(tree: ast.AST, ast_policy: dict) -> Optional[PolicyResult]:
    """Original whole-module AST policy (used when ast_policy.fine_grained is false)."""
    # Check AST tree nodes
    blocked_modules = ast_policy.get("blocked_modules", [])
    blocked_calls = ast_policy.get("blocked_calls", [])
    blocked_attributes = ast_policy.get("blocked_attributes", [])

    for node in ast.walk(tree):
        # Check Import nodes
        if isinstance(node, ast.Import):
            for name_node in node.names:
                for bm in blocked_modules:
                    if name_node.name == bm or name_node.name.startswith(bm + "."):
                        return PolicyResult(
                            allowed=False,
                            reason=f"AST violation: import of restricted module '{name_node.name}'",
                            stage="ast"
                        )
        # Check ImportFrom nodes
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                for bm in blocked_modules:
                    if node.module == bm or node.module.startswith(bm + "."):
                        return PolicyResult(
                            allowed=False,
                            reason=f"AST violation: import from restricted module '{node.module}'",
                            stage="ast"
                        )
            for name_node in node.names:
                for bm in blocked_modules:
                    if name_node.name == bm or name_node.name.startswith(bm + "."):
                        return PolicyResult(
                            allowed=False,
                            reason=f"AST violation: import of restricted module '{name_node.name}'",
                            stage="ast"
                        )
                if name_node.name in blocked_calls:
                    return PolicyResult(
                            allowed=False,
                            reason=f"AST violation: import of restricted call '{name_node.name}'",
                            stage="ast"
                        )
        # Check Call nodes
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name):
                if func.id == "getattr":
                    return PolicyResult(
                        allowed=False,
                        reason="AST violation: call to getattr() is restricted to prevent dynamic resolution obfuscation",
                        stage="ast"
                    )
                if func.id in blocked_calls:
                    return PolicyResult(
                        allowed=False,
                        reason=f"AST violation: call to restricted function '{func.id}'",
                        stage="ast"
                    )
            elif isinstance(func, ast.Attribute):
                if func.attr in blocked_calls:
                    return PolicyResult(
                        allowed=False,
                        reason=f"AST violation: call to restricted function attribute '{func.attr}'",
                        stage="ast"
                    )
                if func.attr in blocked_attributes:
                    return PolicyResult(
                        allowed=False,
                        reason=f"AST violation: call using restricted attribute '{func.attr}'",
                        stage="ast"
                    )
        # Check general Attribute accesses
        elif isinstance(node, ast.Attribute):
            if node.attr in blocked_attributes:
                return PolicyResult(
                    allowed=False,
                    reason=f"AST violation: access to restricted attribute '{node.attr}'",
                    stage="ast"
                )
    return None

# ---------------------------------------------------------------------------
# Context rules for the output sanitizer
# ---------------------------------------------------------------------------

def _is_field_line(line: str) -> bool:
    """True if the line is a key/value field or annotated assignment, not prose."""
    stripped = line.strip()
    if not stripped:
        return False
    try:
        tree = ast.parse(stripped)
    except SyntaxError:
        return False
    return len(tree.body) == 1 and isinstance(tree.body[0], ast.AnnAssign)


def _line_of(text: str, pos: int) -> str:
    start = text.rfind("\n", 0, pos) + 1
    end = text.find("\n", pos)
    return text[start: end if end != -1 else len(text)]


def _sentence_prefix(text: str, pos: int) -> str:
    """Text between the start of the current sentence and pos."""
    cut = max(text.rfind(ch, 0, pos) for ch in ".!?\n")
    return text[cut + 1: pos]


_SENSITIVE_OBJECT = re.compile(
    r"secret|credential|password|passwd|token|key|system\s*prompt|config|instruction|guardrail",
    re.IGNORECASE)

# "you are now" is an injection when it assigns a mode, role or persona;
# a status report ("you are now on version 2.4.1") is not.
_YOU_ARE_NOW_DIRECTIVE = re.compile(
    r"you are now\s+(?:in\b|operating|acting|running\s+(?:in|as)\b|an?\b|the\b|my\b|your\b|"
    r"no longer|dan\b|jailbroken|unrestricted|unfiltered|free\b|root\b|admin)",
    re.IGNORECASE)

# "disregard your ..." is an injection when the object is the model's instructions.
_DISREGARD_YOUR_DIRECTIVE = re.compile(
    r"disregard\s+your\s+(?:(?:previous|prior|earlier|original|current|above|existing)\s+)?"
    r"(?:instructions|rules|guidelines|directives|system\s*prompt|programming|guardrails|"
    r"restrictions|safety|training|constraints|policies)",
    re.IGNORECASE)

_CLI_TARGET_THEN_FLAG = re.compile(r"[\w.-]*\s+--?[A-Za-z][\w-]*")
_FILE_ACCESS = re.compile(
    r"\$(?:\d|y|2[aby])\$|\b(?:dump|cat|contents?|send|upload|exfiltrat\w*|copy|print|show)\b",
    re.IGNORECASE)
_FILE_METADATA = re.compile(
    r"\s*(?:(?:permissions?|perms|mode|owner(?:ship)?|group)\b"
    r"|is\s+(?:not\s+)?(?:world-|group-|other-)?(?:readable|writable|writeable|executable)\b)",
    re.IGNORECASE)


def _context_exempt(raw_pattern: str, text: str, m: "re.Match") -> bool:
    key = raw_pattern.strip().lower()
    if key == "you are now":
        return not _YOU_ARE_NOW_DIRECTIVE.match(text, m.start())
    if key == "disregard your":
        return not _DISREGARD_YOUR_DIRECTIVE.match(text, m.start())
    if key.startswith("output all"):
        # Purpose clause at sentence start ("To output all tools, call list_tools()")
        # describes how to do something; exempt unless the object is sensitive.
        prefix = _sentence_prefix(text, m.start()).strip().lower()
        rest = text[m.end(): m.end() + 60]
        return prefix == "to" and not _SENSITIVE_OBJECT.search(key + rest)
    if key.startswith("invoke server"):
        # A CLI example: "invoke" is a subcommand of an earlier command, the target
        # is followed directly by a flag, and the line asks for nothing sensitive.
        line = _line_of(text, m.start())
        after = text[m.end():]
        return (not line.lstrip().lower().startswith("invoke")
                and bool(_CLI_TARGET_THEN_FLAG.match(after))
                and not _SENSITIVE_OBJECT.search(line))
    if key.startswith("/etc/shadow") or key.startswith("/etc/passwd"):
        # A permissions/ownership line describes the file; it does not expose it.
        # Not exempt if the text also asks to access the file or contains hash entries.
        return bool(_FILE_METADATA.match(text, m.end())) and not _FILE_ACCESS.search(text)
    return False