import hashlib
import hmac as hmac_mod
import json
import os
import re
import statistics
import time
import pytest

from mcp_shield.src.policy import PolicyEngine
from mcp_shield.src.session import SessionState, SessionStore
from mcp_shield.src.schemas import JSONRPCRequest, MCPSecHeader


N = 1000  # iterations per stage

def percentile(data: list, p: float) -> float:
    """Returns the p-th percentile of a sorted list."""
    s = sorted(data)
    k = (len(s) - 1) * p / 100
    lo, hi = int(k), min(int(k) + 1, len(s) - 1)
    return round(s[lo] + (s[hi] - s[lo]) * (k - lo), 3)


def make_req(method="tools/call", tool_name="read_file", code=None):
    if code:
        return JSONRPCRequest(
            jsonrpc="2.0", id=1, method=method,
            params={"name": "execute_code", "arguments": {"code": code}}
        )
    return JSONRPCRequest(
        jsonrpc="2.0", id=1, method=method,
        params={"name": tool_name, "arguments": {"path": "/workspace/file.txt"}}
    )


def fresh_session(server_id="filesystem-server", caps=None):
    s = SessionState(server_id=server_id)
    s.verified_capabilities = caps or ["resources", "tools", "sampling"]
    return s

@pytest.fixture(scope="module")
def engine():
    return PolicyEngine()


@pytest.fixture(scope="module")
def results_collector():
    rows = []
    yield rows
    # Print table after all tests
    print("\n\n" + "=" * 60)
    print("TABLE V — MCP-SHIELD PER-REQUEST LATENCY OVERHEAD (ms)")
    print("=" * 60)
    print(f"{'Stage':<35} {'P50':>8} {'P95':>8}")
    print("-" * 60)
    total_p50, total_p95 = 0.0, 0.0
    for r in rows:
        if r.get("is_total"):
            continue
        print(f"{r['stage']:<35} {r['p50']:>8.3f} {r['p95']:>8.3f}")
        total_p50 += r["p50"]
        total_p95 += r["p95"]
    print("-" * 60)
    print(f"{'Total (no code exec)':<35} {total_p50:>8.3f} {total_p95:>8.3f}")
    # MCP-Box row if measured
    for r in rows:
        if r.get("is_total"):
            print(f"{'MCP-Box container exec':<35} {r['p50']:>8.3f} {r['p95']:>8.3f}")
    print("=" * 60 + "\n")
    print(f"  N = {N} iterations per stage, warm connections\n")

def test_stage_hmac_verification(engine, results_collector, monkeypatch):
    """Isolates HMAC compute + nonce window check time."""
    monkeypatch.setenv("MCP_KEY_FILESYSTEM", "benchmarkkey123")
    engine.load_config()

    req = make_req()
    body_bytes = req.model_dump_json().encode("utf-8")
    deltas = []

    for i in range(N):
        ts = time.time()
        nonce = f"nonce_{i}_{ts}"
        msg = f"{ts}:{nonce}:".encode("utf-8") + body_bytes
        sig = hmac_mod.new(b"benchmarkkey123", msg, hashlib.sha256).hexdigest()
        sec_header = MCPSecHeader(
            server_id="filesystem-server",
            timestamp=ts,
            nonce=nonce,
            hmac=sig
        )
        session = fresh_session()

        t0 = time.perf_counter()
        # Replicate exact HMAC stage from _evaluate_impl
        psk = "benchmarkkey123"
        msg2 = f"{sec_header.timestamp}:{sec_header.nonce}:".encode("utf-8") + body_bytes
        computed = hmac_mod.new(psk.encode(), msg2, hashlib.sha256).hexdigest()
        hmac_mod.compare_digest(computed, sec_header.hmac)
        engine.nonce_window.check_and_add(
            sec_header.server_id, sec_header.nonce, sec_header.timestamp
        )
        deltas.append((time.perf_counter() - t0) * 1000.0)

    results_collector.append({
        "stage": "HMAC verification",
        "p50": percentile(deltas, 50),
        "p95": percentile(deltas, 95),
    })

def test_stage_sequence_check(engine, results_collector):
    """Isolates _check_sequence() on a session with realistic call history."""
    req = make_req()
    deltas = []

    for _ in range(N):
        session = fresh_session()
        # Pre-populate history to simulate mid-session state (worst-case window scan)
        for j in range(5):
            session.record_call("resources/read", None, "allowed")

        t0 = time.perf_counter()
        engine._check_sequence(req, session)
        deltas.append((time.perf_counter() - t0) * 1000.0)

    results_collector.append({
        "stage": "Sequence check",
        "p50": percentile(deltas, 50),
        "p95": percentile(deltas, 95),
    })

def test_stage_attestation_cached(engine, results_collector):
    """
    Measures the fast path: session already has verified_capabilities set
    (cert was validated at handshake time and cached). This is the per-request
    cost — just a list membership check.
    """
    req = make_req(method="tools/call")
    deltas = []

    for _ in range(N):
        session = fresh_session(caps=["tools", "resources"])

        t0 = time.perf_counter()
        # Replicate attestation fast-path from _evaluate_impl
        method_prefix = req.method.split("/")[0]
        _ = method_prefix in session.verified_capabilities or \
            any(req.method.startswith(c) for c in session.verified_capabilities)
        deltas.append((time.perf_counter() - t0) * 1000.0)

    results_collector.append({
        "stage": "Attestation (cert cached)",
        "p50": percentile(deltas, 50),
        "p95": percentile(deltas, 95),
    })

def test_stage_regex_scan(engine, results_collector):
    """Isolates find_blocked_regex() against the compiled default blacklist."""
    req = make_req()
    deltas = []

    # Use a clean payload — measures cost of full scan with no match (worst case)
    params_to_scan = {"name": "read_file", "arguments": {"path": "/workspace/safe_file.txt"}}

    patterns = engine.compiled_default_regex or engine.compiled_server_regex.get("filesystem-server", [])

    for _ in range(N):
        t0 = time.perf_counter()
        from mcp_shield.src.policy import find_blocked_regex
        find_blocked_regex(params_to_scan, patterns)
        deltas.append((time.perf_counter() - t0) * 1000.0)

    results_collector.append({
        "stage": "Regex scan",
        "p50": percentile(deltas, 50),
        "p95": percentile(deltas, 95),
    })

def test_stage_ast_parse_walk(engine, results_collector):
    """Isolates ast.parse() + node walk on a representative safe code payload."""
    import ast as ast_mod

    # Realistic code snippet — not trivially short, not pathological
    code = (
        "def compute(x, y):\n"
        "    result = x * y + 42\n"
        "    values = [i**2 for i in range(result)]\n"
        "    return sum(values)\n"
        "\n"
        "print(compute(3, 7))\n"
    )

    blocked_modules = set(engine.config.get("ast_policy", {}).get("blocked_modules", []))
    blocked_calls   = set(engine.config.get("ast_policy", {}).get("blocked_calls", []))
    blocked_attrs   = set(engine.config.get("ast_policy", {}).get("blocked_attributes", []))

    deltas = []
    for _ in range(N):
        t0 = time.perf_counter()
        try:
            tree = ast_mod.parse(code)
            for node in ast_mod.walk(tree):
                if isinstance(node, (ast_mod.Import, ast_mod.ImportFrom)):
                    for alias in node.names:
                        _ = alias.name.split(".")[0] in blocked_modules
                elif isinstance(node, ast_mod.Call):
                    if isinstance(node.func, ast_mod.Name):
                        _ = node.func.id in blocked_calls
                    elif isinstance(node.func, ast_mod.Attribute):
                        _ = node.func.attr in blocked_attrs
                elif isinstance(node, ast_mod.Attribute):
                    _ = node.attr in blocked_attrs
        except SyntaxError:
            pass
        deltas.append((time.perf_counter() - t0) * 1000.0)

    results_collector.append({
        "stage": "AST parse + walk",
        "p50": percentile(deltas, 50),
        "p95": percentile(deltas, 95),
    })

def test_stage_namespace_lock(engine, results_collector):
    """Isolates namespace/allowed_tools membership check."""
    req = make_req(tool_name="read_file")
    deltas = []

    server_cfg = engine.config.get("servers", {}).get("filesystem-server", {})
    allowed_tools = server_cfg.get(
        "allowed_tools",
        engine.config.get("default", {}).get("allowed_tools", [])
    )

    for _ in range(N):
        tool_name = "read_file"
        t0 = time.perf_counter()
        _ = allowed_tools and tool_name not in allowed_tools
        deltas.append((time.perf_counter() - t0) * 1000.0)

    results_collector.append({
        "stage": "Namespace lock",
        "p50": percentile(deltas, 50),
        "p95": percentile(deltas, 95),
    })


def test_stage_output_sanitizer(engine, results_collector):
    """Isolates sanitize_output() on a clean multi-line tool response."""
    text = (
        "File contents of /workspace/report.txt:\n"
        "Line 1: analysis complete\n"
        "Line 2: total records processed: 1042\n"
        "Line 3: no anomalies detected\n"
        "Line 4: execution time 0.34s\n"
    )
    deltas = []

    for _ in range(N):
        t0 = time.perf_counter()
        engine.sanitize_output(text)
        deltas.append((time.perf_counter() - t0) * 1000.0)

    results_collector.append({
        "stage": "Output sanitizer",
        "p50": percentile(deltas, 50),
        "p95": percentile(deltas, 95),
    })

def test_full_pipeline_end_to_end(engine, results_collector):
    """
    Full evaluate() call — used as a sanity check that stage sum ≈ pipeline total.
    Runs against filesystem-server with a clean tools/call payload.
    """
    req = make_req()
    deltas = []

    for _ in range(N):
        session = fresh_session()
        t0 = time.perf_counter()
        engine.evaluate(req, session)
        deltas.append((time.perf_counter() - t0) * 1000.0)

    p50 = percentile(deltas, 50)
    p95 = percentile(deltas, 95)

    print(f"\n[Sanity] Full pipeline P50={p50:.3f}ms  P95={p95:.3f}ms")