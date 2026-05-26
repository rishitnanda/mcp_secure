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
# NOTE: JSONRPCResponse and MethodNotFoundException are intentionally excluded —
# they are not used in the policy engine and were dead imports (Problems 10, 11).
from mcp_shield.src.exceptions import (
    MCPShieldException,
    PolicyViolationException,
    ASTValidationException,
    NamespaceViolationException,
    CapabilityViolationException,
)

class ConnectionState:
    """Tracks connection-specific capability attestation state."""
    def __init__(self, server_id: Optional[str] = None):
        self.server_id = server_id
        # We start with empty capabilities, which will be populated
        # upon successful validation of the CapabilityCert.
        self.verified_capabilities: List[str] = []
        self.cert_expiry: Optional[float] = None


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
        # If the engine were ever re-instantiated (e.g. in tests), each instance gets
        # a fresh window — which is correct for test isolation but means production
        # restarts lose the nonce history. This is acceptable since the 30s TTL
        # makes replays from before a restart irrelevant (Problem 13).
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
        conn_state: ConnectionState,
        body_bytes: Optional[bytes] = None,
        sec_header: Optional[MCPSecHeader] = None
    ) -> PolicyResult:
        """Evaluates a JSON-RPC request through the sequential 5-stage policy chain.
        
        Order of evaluation:
          1. HMAC check (SSE mode only — skipped in stdio mode)
          2. Capability attestation check
          3. Regex scan
          4. AST scan (only if a code parameter is present)
          5. Namespace lock (verifies that tool name in tools/call matches allowed tools)
        """
        server_id = conn_state.server_id or (sec_header.server_id if sec_header else "unknown")

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
                    "sampling" in conn_state.verified_capabilities
                    or server_cfg.get("sampling_allowed", False)
                )
            else:
                if trust_mode == "strict":
                    is_allowed = req_capability in conn_state.verified_capabilities
                else:
                    is_allowed = (
                        req_capability in conn_state.verified_capabilities
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
            matched_pattern = find_blocked_regex(request.params, patterns)
            if matched_pattern:
                return PolicyResult(
                    allowed=False,
                    reason=f"Security policy violation: blocked pattern '{matched_pattern}' detected in parameters",
                    stage="regex"
                )

        # 4. AST scan (only if a code param is present)
        # Mirrors the two-level extraction in gateway.py: check top-level params first,
        # then params.arguments. Without this, a payload using top-level 'code' would
        # pass the AST scan but still reach the executor (Problem 12).
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
                
                # Check AST tree nodes
                ast_policy = self.config.get("ast_policy", {})
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

        # If allowed_tools is empty or not configured, allow all by default or block?
        # Typically if allowed_tools is configured we restrict, if it is not configured, we might allow all
        # unless configured to strict.
        # Let's check config schema: "filesystem-server" has allowed_tools listed.
        # If server_id matches but has no allowed tools, or if allowed_tools is an empty list, no tools are allowed.
        # Let's do a strict filter:
        # If server is declared in config, it MUST only return tools in allowed_tools.
        if server_id in self.config.get("servers", {}):
            result = response_dict.get("result", {})
            if isinstance(result, dict) and "tools" in result:
                tools = result.get("tools", [])
                filtered = [t for t in tools if isinstance(t, dict) and t.get("name") in allowed_tools]
                response_dict["result"]["tools"] = filtered
        return response_dict

    def sanitize_output(self, text: str) -> Tuple[str, bool]:
        """Sanitizes text outputs for prompt injections using line-start and full-text substring rules."""
        san_config = self.config.get("output_sanitizer", {})
        case_insensitive = san_config.get("case_insensitive", True)
        flags = re.IGNORECASE if case_insensitive else 0

        lines = text.split("\n")
        flagged = False
        cleaned_lines = []

        line_patterns = [
            re.compile(r"^\s*" + re.escape(p), flags)
            for p in san_config.get("line_start_patterns", [])
        ]
        sub_patterns = [
            re.compile(re.escape(p), flags)
            for p in san_config.get("substring_patterns", [])
        ]

        # 1. Line-start surgical pattern replacement
        for line in lines:
            if any(p.match(line) for p in line_patterns):
                cleaned_lines.append("[SANITIZED: potential prompt injection removed]")
                flagged = True
            else:
                cleaned_lines.append(line)

        result_text = "\n".join(cleaned_lines)

        # 2. Whole text substring detection and override
        if any(p.search(result_text) for p in sub_patterns):
            result_text = "[CONTENT SANITIZED: prompt injection pattern detected in tool output]"
            flagged = True

        return result_text, flagged
