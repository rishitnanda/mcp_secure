"""
Real (label-free) implementations of the multi-turn defense options.

Every decision here is a function of (a) the requests the proxy actually sees,
(b) proxy configuration, and (c) for Option 2 only, a signed attestation the
host app attaches to the session. Nothing reads test names, session-name
substrings like "FP", or benchmark labels.

Shared changes applied to Options 1-fixed, 2, 3 and 4:

  * Suffix matching. The baseline matches a pattern anywhere inside the window,
    so once R,R,S has happened, every later call re-triggers the block (the
    "trailing" false positives MPS-119..122). A multi-turn rule should fire on
    the call that *completes* the pattern, so here the pattern must end at the
    current call. This is a bug fix, independent of semantics.

  * Argument history. SessionState.call_history stores only method/tool/outcome,
    so the proxy forgets which files were read. evaluate() is wrapped to keep a
    parallel list of request params on the session object. If the session was
    rebuilt from the DB (e.g. MPS-046), older entries have no params; those are
    treated as UNKNOWN and the options fail closed on them.
"""
from __future__ import annotations

import base64
import fnmatch
import hashlib
import hmac
import json
import math
import os
import posixpath
import re
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote, urlparse

from mcp_shield.src.policy import PolicyEngine
from mcp_shield.src.schemas import JSONRPCRequest, PolicyResult

_UNKNOWN = object()  # marker: params not available (history rebuilt from DB)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _sig(method: str, tool: Optional[str]) -> str:
    return f"tools/call:{tool}" if method == "tools/call" and tool else method


_READ_TOOL = re.compile(r"(read|get|fetch|load|open|cat|download|search|query)", re.I)
_WRITE_TOOL = re.compile(r"(write|save|upload|send|post|put|append|move|copy|export|create)", re.I)
_LIST_TOOL = re.compile(r"(list|stat|ls|exists)", re.I)
_PATH_KEYS = ("path", "file", "filepath", "filename", "uri", "url", "source", "src")
_DEST_KEYS = ("destination", "dest", "dst", "target", "output", "out", "url", "path", "uri")


def classify_call(method: str, tool: Optional[str]) -> str:
    """Coarse action class: read | write | list | sampling | tool | other."""
    if method == "sampling/createMessage":
        return "sampling"
    if method.startswith("resources/"):
        return "list" if method.endswith("/list") else "read"
    if method == "tools/call" and tool:
        if _LIST_TOOL.search(tool) and not _READ_TOOL.search(tool.replace("list", "")):
            return "list"
        if _WRITE_TOOL.search(tool):
            return "write"
        if _READ_TOOL.search(tool):
            return "read"
        return "tool"
    return "other"


def extract_target(method: str, params: Any, action: str) -> Optional[str]:
    """Returns the file/URI a call touches, or None if the call names no target."""
    if not isinstance(params, dict):
        return None
    if method.startswith("resources/"):
        return params.get("uri") or params.get("name")
    args = params.get("arguments") or {}
    if not isinstance(args, dict):
        return None
    keys = _DEST_KEYS if action == "write" else _PATH_KEYS
    for k in keys:
        v = args.get(k)
        if isinstance(v, str) and v:
            return v
    return None


def canonicalize(target: str) -> str:
    """Normalizes a path/URI so encodings and traversal can't hide a sensitive path."""
    t = target.strip()
    for _ in range(3):  # defeat double/triple percent-encoding
        nt = unquote(t)
        if nt == t:
            break
        t = nt
    if t.lower().startswith("file://"):
        t = t[7:]
    elif t.lower().startswith("file:"):
        t = t[5:]
    t = t.replace("\\", "/")
    home = t.startswith("~")
    if home:
        t = "/HOME" + t[1:]
    t = posixpath.normpath(t) if t else t
    return t.lower()


def is_external(target: str) -> bool:
    p = urlparse(target.strip())
    return p.scheme.lower() in ("http", "https", "ftp", "ftps", "ws", "wss", "smtp", "s3", "gs")


SENSITIVE_PATTERNS = [
    r"(^|/)\.ssh(/|$)", r"id_(rsa|dsa|ecdsa|ed25519)", r"\.pem$", r"\.key$", r"\.p12$", r"\.pfx$",
    r"(^|/)\.env(\.|$)", r"(^|/)\.aws(/|$)", r"(^|/)\.kube/config", r"(^|/)\.netrc$",
    r"(^|/)\.git-credentials$", r"(^|/)\.docker/config\.json$", r"(^|/)\.gnupg(/|$)",
    r"^/etc/(passwd|shadow|sudoers|gshadow)", r"(^|/)keychains?(/|$)",
    r"secret", r"credential", r"passw(or)?d", r"(^|[/_.-])tokens?([/_.-]|$)", r"private[_-]?key",
]
_SENSITIVE_RE = [re.compile(p) for p in SENSITIVE_PATTERNS]
SCRATCH_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/")


def is_sensitive(canon: str) -> bool:
    return any(r.search(canon) for r in _SENSITIVE_RE)


class _BaseSequenceEngine(PolicyEngine):
    """Adds argument history + suffix-anchored pattern matching. Subclasses add a gate."""

    ARGS_ATTR = "_shield_arg_history"

    def evaluate(self, request, session_state, body_bytes=None, sec_header=None):
        res = super().evaluate(request, session_state, body_bytes, sec_header)
        hist = getattr(session_state, self.ARGS_ATTR, None)
        if hist is None:
            hist = []
            setattr(session_state, self.ARGS_ATTR, hist)
        hist.append(request.params if request.params is not None else {})
        return res

    # -- history with params aligned to call_history -------------------------
    def _calls_with_params(self, session_state) -> List[Tuple[str, Optional[str], Any]]:
        history = session_state.call_history
        args = getattr(session_state, self.ARGS_ATTR, [])
        n_known = min(len(args), len(history))
        tail_args = args[-n_known:] if n_known else []
        out = []
        for i, call in enumerate(history):
            j = i - (len(history) - n_known)
            params = tail_args[j] if j >= 0 else _UNKNOWN
            out.append((call["method"], call.get("tool_name"), params))
        return out

    # -- rule evaluation -----------------------------------------------------
    def _rules(self, session_state):
        seq_policy = self.config.get("sequence_policy", {})
        if not seq_policy:
            return []
        return seq_policy.get("servers", {}).get(session_state.server_id, []) + seq_policy.get("default", [])

    def _check_rate_limits(self, rules, session_state) -> Optional[PolicyResult]:
        now = time.time()
        for rule in rules:
            if rule.get("action", "block") != "block":
                continue
            if "max_calls" in rule and "window_seconds" in rule:
                recent = [c for c in session_state.call_history if now - c["timestamp"] <= rule["window_seconds"]]
                if len(recent) >= rule["max_calls"]:
                    return PolicyResult(allowed=False, reason=rule.get("name", "rate_limit_exceeded"), stage="sequence")
        return None

    def _matched_pattern_rules(self, rules, request, session_state) -> List[dict]:
        """Pattern rules whose pattern ends exactly at the current call."""
        tool = request.params.get("name") if isinstance(request.params, dict) else None
        current = _sig(request.method, tool)
        sigs = [_sig(c["method"], c.get("tool_name")) for c in session_state.call_history] + [current]
        hits = []
        for rule in rules:
            if rule.get("action", "block") != "block" or "pattern" not in rule:
                continue
            pat = rule["pattern"]
            if len(sigs) >= len(pat) and sigs[-len(pat):] == pat:
                hits.append(rule)
        return hits

    def gate(self, rule, request, session_state) -> Optional[PolicyResult]:
        """Return a block result, or None to let the matched sequence through."""
        return PolicyResult(allowed=False, reason=rule.get("name", "suspicious_sequence"), stage="sequence")

    def _check_sequence(self, request: JSONRPCRequest, session_state) -> Optional[PolicyResult]:
        rules = self._rules(session_state)
        if not rules:
            return None
        rl = self._check_rate_limits(rules, session_state)
        if rl:
            return rl
        for rule in self._matched_pattern_rules(rules, request, session_state):
            res = self.gate(rule, request, session_state)
            if res:
                return res
        return None


# ---------------------------------------------------------------------------
# Option 1-fixed: baseline + suffix matching only (no semantic change)
# ---------------------------------------------------------------------------

class PolicyEngineOption1Fixed(_BaseSequenceEngine):
    pass


# ---------------------------------------------------------------------------
# Option 3: Target-boundary / path-scoped sequence rules
# ---------------------------------------------------------------------------

class PolicyEngineOption3(_BaseSequenceEngine):
    """
    A matched pattern is released only when the proxy can positively show it is
    safe: every read in the session named a known, non-sensitive target, and the
    egress (sampling, or a write) does not go to an external or sensitive sink.
    Fails closed when targets are missing or unknown, or when the pattern has
    no reads to scope (e.g. S,S,S), since path rules have nothing to say there.
    """

    def gate(self, rule, request, session_state):
        block = lambda why: PolicyResult(allowed=False, reason=f"{rule.get('name', 'suspicious_sequence')}: {why}", stage="sequence")
        tool = request.params.get("name") if isinstance(request.params, dict) else None
        calls = self._calls_with_params(session_state) + [(request.method, tool, request.params or {})]

        sources = 0
        for method, tname, params in calls:
            action = classify_call(method, tname)
            if action != "read":
                continue
            sources += 1
            if params is _UNKNOWN:
                return block("read target unknown (history rebuilt without params)")
            target = extract_target(method, params, action)
            if not target:
                return block(f"read via '{tname or method}' names no target")
            if is_external(target):
                continue  # public fetch; not a local secret source
            if is_sensitive(canonicalize(target)):
                return block(f"sensitive source {canonicalize(target)}")

        if sources == 0:
            return block("no scoped reads in sequence")

        cur_action = classify_call(request.method, tool)
        if cur_action == "write":
            dest = extract_target(request.method, request.params, "write")
            if not dest:
                return block("write names no destination")
            if is_external(dest):
                return block(f"external sink {dest}")
            c = canonicalize(dest)
            if is_sensitive(c):
                return block(f"sensitive sink {c}")
            is_scratch = c.startswith(SCRATCH_PREFIXES)
            is_workspace_relative = not c.startswith("/")
            if not (is_scratch or is_workspace_relative):
                return block(f"sink outside scratch/workspace {c}")
        return None


# ---------------------------------------------------------------------------
# Option 4: Kill-chain HMM stage classification (forward filtering)
# ---------------------------------------------------------------------------

# Hidden stages
BENIGN, COLLECT, STAGE, EXFIL = range(4)
STAGE_NAMES = ["benign", "collection", "staging", "exfiltration"]
# Observation symbols
SYMBOLS = ["read_sensitive", "read_benign", "read_unknown", "tool_generic", "write_scratch",
           "write_external_or_sensitive", "sampling", "list", "other"]
_SYM = {s: i for i, s in enumerate(SYMBOLS)}

# Parameters are priors written from the threat model (kill-chain semantics),
# NOT fitted to the benchmark. Replace with parameters estimated on real,
# held-out traces before quoting results as a trained HMM.
HMM_INITIAL = [0.85, 0.10, 0.04, 0.01]
HMM_TRANSITION = [
    #  B     C     S     E
    [0.85, 0.12, 0.02, 0.01],  # benign
    [0.20, 0.50, 0.25, 0.05],  # collection
    [0.10, 0.10, 0.40, 0.40],  # staging
    [0.30, 0.10, 0.10, 0.50],  # exfiltration
]
HMM_EMISSION = [
    # rs    rb    ru    tool  wscr  wext  samp  list  other
    [0.01, 0.35, 0.10, 0.20, 0.10, 0.01, 0.13, 0.09, 0.01],  # benign
    [0.35, 0.15, 0.15, 0.10, 0.02, 0.01, 0.02, 0.19, 0.01],  # collection
    [0.10, 0.10, 0.10, 0.15, 0.30, 0.05, 0.15, 0.04, 0.01],  # staging
    [0.02, 0.02, 0.02, 0.05, 0.09, 0.40, 0.38, 0.01, 0.01],  # exfiltration
]
EGRESS_SYMBOLS = {_SYM["sampling"], _SYM["write_scratch"], _SYM["write_external_or_sensitive"]}
HMM_ALERT_THRESHOLD = 0.5  # P(staging or exfiltration | observations so far) at an egress call


def symbolize(method: str, tool: Optional[str], params: Any) -> int:
    action = classify_call(method, tool)
    if action == "sampling":
        return _SYM["sampling"]
    if action == "list":
        return _SYM["list"]
    if action == "read":
        if params is _UNKNOWN:
            return _SYM["read_unknown"]
        t = extract_target(method, params, action)
        if not t:
            return _SYM["read_unknown"]
        return _SYM["read_sensitive"] if (not is_external(t) and is_sensitive(canonicalize(t))) else _SYM["read_benign"]
    if action == "write":
        if params is _UNKNOWN:
            return _SYM["write_external_or_sensitive"]
        d = extract_target(method, params, action)
        if not d or is_external(d) or is_sensitive(canonicalize(d)):
            return _SYM["write_external_or_sensitive"]
        return _SYM["write_scratch"]
    if action == "tool":
        return _SYM["tool_generic"]
    return _SYM["other"]


def hmm_filter(symbols: List[int]) -> List[float]:
    """Forward algorithm; returns P(state_t | o_1..o_t) for the last step."""
    alpha = [HMM_INITIAL[s] * HMM_EMISSION[s][symbols[0]] for s in range(4)]
    z = sum(alpha) or 1.0
    alpha = [a / z for a in alpha]
    for o in symbols[1:]:
        alpha = [sum(alpha[p] * HMM_TRANSITION[p][s] for p in range(4)) * HMM_EMISSION[s][o] for s in range(4)]
        z = sum(alpha) or 1.0
        alpha = [a / z for a in alpha]
    return alpha


class PolicyEngineOption4(_BaseSequenceEngine):
    """
    Replaces pattern rules with a kill-chain HMM. Rate-limit rules from config
    are kept. Alerts only on egress calls (sampling / writes) when the filtered
    probability of being in staging or exfiltration crosses the threshold.
    """

    def _check_sequence(self, request, session_state):
        rules = self._rules(session_state)
        rl = self._check_rate_limits(rules, session_state) if rules else None
        if rl:
            return rl
        tool = request.params.get("name") if isinstance(request.params, dict) else None
        calls = self._calls_with_params(session_state) + [(request.method, tool, request.params or {})]
        syms = [symbolize(m, t, p) for m, t, p in calls]
        if syms[-1] not in EGRESS_SYMBOLS:
            return None
        post = hmm_filter(syms)
        risk = post[STAGE] + post[EXFIL]
        if risk >= HMM_ALERT_THRESHOLD:
            top = STAGE_NAMES[max(range(4), key=lambda s: post[s])]
            return PolicyResult(allowed=False, reason=f"kill_chain_progression: P(staging|exfil)={risk:.2f}, likely stage={top}", stage="sequence")
        return None


# ---------------------------------------------------------------------------
# Option 2: Intent-attested capability scoping
# ---------------------------------------------------------------------------

def mint_intent_token(key: str, server_id: str, resources: List[str], tools: List[str],
                      sampling: bool, ttl: float = 300.0) -> str:
    """Host-side helper: sign the scope of what the user actually asked for."""
    payload = {"sid": server_id, "resources": resources, "tools": tools,
               "sampling": sampling, "exp": time.time() + ttl}
    body = base64.urlsafe_b64encode(json.dumps(payload, sort_keys=True).encode()).decode()
    sig = hmac.new(key.encode(), body.encode(), hashlib.sha256).hexdigest()
    return f"{body}.{sig}"


class PolicyEngineOption2(_BaseSequenceEngine):
    """
    A matched pattern is released only if the host attached a valid, unexpired
    HMAC-signed intent token to the session, and everything the sequence touched
    is inside that token's scope. The token lives on session_state.intent_attestation
    (in production: delivered by the host, e.g. in request _meta or a header).
    Without a token, behaves exactly like Option 1-fixed.
    """

    TOKEN_ATTR = "intent_attestation"

    def _host_key(self) -> Optional[str]:
        return os.environ.get("MCP_HOST_INTENT_KEY") or self.config.get("host_intent_key")

    def _verify(self, token: str, server_id: str) -> Tuple[Optional[dict], str]:
        key = self._host_key()
        if not key:
            return None, "no host intent key configured"
        try:
            body, sig = token.rsplit(".", 1)
        except ValueError:
            return None, "malformed token"
        expected = hmac.new(key.encode(), body.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, sig):
            return None, "bad signature"
        try:
            payload = json.loads(base64.urlsafe_b64decode(body.encode()))
        except Exception:
            return None, "undecodable payload"
        if payload.get("exp", 0) < time.time():
            return None, "token expired"
        if payload.get("sid") != server_id:
            return None, "token bound to a different session"
        return payload, "ok"

    def gate(self, rule, request, session_state):
        block = lambda why: PolicyResult(allowed=False, reason=f"{rule.get('name', 'suspicious_sequence')}: {why}", stage="sequence")
        token = getattr(session_state, self.TOKEN_ATTR, None)
        if not token:
            return block("no intent attestation")
        scope, why = self._verify(token, session_state.server_id)
        if scope is None:
            return block(f"attestation rejected ({why})")

        globs = [canonicalize(g) for g in scope.get("resources", [])]
        allowed_tools = set(scope.get("tools", []))
        tool = request.params.get("name") if isinstance(request.params, dict) else None
        calls = self._calls_with_params(session_state) + [(request.method, tool, request.params or {})]
        for method, tname, params in calls:
            action = classify_call(method, tname)
            if method == "sampling/createMessage":
                if not scope.get("sampling", False):
                    return block("sampling not attested")
                continue
            if method == "tools/call" and tname not in allowed_tools:
                return block(f"tool '{tname}' not attested")
            if action in ("read", "write"):
                if params is _UNKNOWN:
                    return block("target unknown (history rebuilt without params)")
                t = extract_target(method, params, action)
                if not t:
                    if method.startswith("resources/"):
                        return block("resource read names no target")
                    continue  # tool-level attestation already checked
                c = canonicalize(t)
                if not any(fnmatch.fnmatchcase(c, g) for g in globs):
                    return block(f"target {c} outside attested scope")
        return None