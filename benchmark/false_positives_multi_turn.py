"""
This file isolates the multi-turn false positive cases.
"""

import copy
import json
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from mcp_shield.src.policy import PolicyEngine
from mcp_shield.src.session import SessionState, SessionStore
from mcp_shield.src.schemas import JSONRPCRequest

WINDOW_SIZES = [2, 3, 4, 5, 7, 10]
CONFIG_PATH  = "config/shield_config.json"

def _req(method: str, params: dict | None = None) -> JSONRPCRequest:
    return JSONRPCRequest(jsonrpc="2.0", id=1, method=method, params=params or {})

def _tool_req(tool_name: str) -> JSONRPCRequest:
    return _req("tools/call", {"name": tool_name, "arguments": {}})

def _session(server_id: str = "test-server", caps: list | None = None) -> SessionState:
    s = SessionState(server_id=server_id)
    s.verified_capabilities = caps if caps is not None else ["resources", "sampling", "tools"]
    return s

def _make_engine(base_config: dict, window: int) -> PolicyEngine:
    cfg = copy.deepcopy(base_config)
    seq = cfg.get("sequence_policy", {})
    for rule in seq.get("default", []):
        if "pattern" in rule:
            rule["window"] = window
    for rules in seq.get("servers", {}).values():
        for rule in rules:
            if "pattern" in rule:
                rule["window"] = window
    
    engine = PolicyEngine.__new__(PolicyEngine)
    engine.config_path = CONFIG_PATH
    engine.nonce_window = PolicyEngine("config/shield_config.json").nonce_window
    engine.config = cfg
    engine.load_config = lambda: None
    
    import re
    engine.compiled_default_regex = []
    for pat in cfg.get("default", {}).get("regex_blacklist", []):
        try:
            engine.compiled_default_regex.append((re.compile(pat, re.IGNORECASE), pat))
        except re.error:
            pass
    engine.compiled_server_regex = {}
    for srv_id, srv_cfg in cfg.get("servers", {}).items():
        engine.compiled_server_regex[srv_id] = []
        for pat in srv_cfg.get("regex_blacklist", []):
            try:
                engine.compiled_server_regex[srv_id].append((re.compile(pat, re.IGNORECASE), pat))
            except re.error:
                pass
    return engine

@pytest.fixture(scope="module")
def base_config():
    with open(CONFIG_PATH) as f:
        return json.load(f)

# ── The individual test functions ─────────────────────────────────────────────

@pytest.mark.parametrize("window", WINDOW_SIZES)
def test_FPMT001_legitimate_summary(base_config, window):
    """FPMT001: Legitimate Two-File Summary (R, R, S)"""
    engine = _make_engine(base_config, window)
    session = _session("FPMT001-w")
    engine.evaluate(_req("resources/read", {"name": "f1.txt"}), session)
    engine.evaluate(_req("resources/read", {"name": "f2.txt"}), session)
    r3 = engine.evaluate(_req("sampling/createMessage"), session)
    if not r3.allowed:
        pytest.xfail(f"FPMT001 blocked incorrectly at window size {window}")

@pytest.mark.parametrize("window", WINDOW_SIZES)
def test_FPMT002_legitimate_pipeline(base_config, window):
    """FPMT002: Legitimate Data Pipeline (Get, Format, Analyze, Sample)"""
    engine = _make_engine(base_config, window)
    session = _session("FPMT002-w")
    engine.evaluate(_tool_req("get_data"), session)
    engine.evaluate(_tool_req("format_data"), session)
    engine.evaluate(_tool_req("analyze"), session)
    r4 = engine.evaluate(_req("sampling/createMessage"), session)
    if not r4.allowed:
        pytest.xfail(f"FPMT002 blocked incorrectly at window size {window}")

@pytest.mark.parametrize("window", WINDOW_SIZES)
def test_FPMT003_legitimate_copy(base_config, window):
    """FPMT003: Legitimate Direct File Copy (Read, Write)"""
    engine = _make_engine(base_config, window)
    session = _session("filesystem-server", caps=["tools"])
    engine.evaluate(_tool_req("read_file"), session)
    r2 = engine.evaluate(_tool_req("write_file"), session)
    if not r2.allowed:
        pytest.xfail(f"FPMT003 blocked incorrectly at window size {window}")

@pytest.mark.parametrize("window", WINDOW_SIZES)
def test_FPMT004_legitimate_conversation(base_config, window):
    """FPMT004: Legitimate Conversational Sampling (S, S, S)"""
    engine = _make_engine(base_config, window)
    session = _session("FPMT004-w")
    engine.evaluate(_req("sampling/createMessage"), session)
    engine.evaluate(_req("sampling/createMessage"), session)
    r3 = engine.evaluate(_req("sampling/createMessage"), session)
    if not r3.allowed:
        pytest.xfail(f"FPMT004 blocked incorrectly at window size {window}")

@pytest.mark.parametrize("window", WINDOW_SIZES)
def test_FPMT005_trailing_summary(base_config, window):
    """FPMT005: Trailing FP (Summary -> Tool)"""
    engine = _make_engine(base_config, window)
    session = _session("FPMT005-w")
    engine.evaluate(_req("resources/read", {"name": "f1.txt"}), session)
    engine.evaluate(_req("resources/read", {"name": "f2.txt"}), session)
    engine.evaluate(_req("sampling/createMessage"), session)
    trail = engine.evaluate(_tool_req("list_directory"), session)
    if not trail.allowed:
        pytest.xfail(f"FPMT005 blocked incorrectly at window size {window}")

@pytest.mark.parametrize("window", WINDOW_SIZES)
def test_FPMT006_trailing_copy(base_config, window):
    """FPMT006: Trailing FP (Copy -> List)"""
    engine = _make_engine(base_config, window)
    session = _session("filesystem-server", caps=["tools"])
    engine.evaluate(_tool_req("read_file"), session)
    engine.evaluate(_tool_req("write_file"), session)
    trail = engine.evaluate(_tool_req("list_directory"), session)
    if not trail.allowed:
        pytest.xfail(f"FPMT006 blocked incorrectly at window size {window}")

@pytest.mark.parametrize("window", WINDOW_SIZES)
def test_FPMT007_trailing_pipeline(base_config, window):
    """FPMT007: Trailing FP (Pipeline -> Resource)"""
    engine = _make_engine(base_config, window)
    session = _session("FPMT007-w")
    engine.evaluate(_tool_req("get_data"), session)
    engine.evaluate(_tool_req("format_data"), session)
    engine.evaluate(_tool_req("analyze"), session)
    engine.evaluate(_req("sampling/createMessage"), session)
    trail = engine.evaluate(_req("resources/read", {"name": "f1.txt"}), session)
    if not trail.allowed:
        pytest.xfail(f"FPMT007 blocked incorrectly at window size {window}")

@pytest.mark.parametrize("window", WINDOW_SIZES)
def test_FPMT008_trailing_conversation(base_config, window):
    """FPMT008: Trailing FP (Conversation -> Tool)"""
    engine = _make_engine(base_config, window)
    session = _session("FPMT008-w")
    engine.evaluate(_req("sampling/createMessage"), session)
    engine.evaluate(_req("sampling/createMessage"), session)
    engine.evaluate(_req("sampling/createMessage"), session)
    trail = engine.evaluate(_tool_req("list_directory"), session)
    if not trail.allowed:
        pytest.xfail(f"FPMT008 blocked incorrectly at window size {window}")

@pytest.mark.parametrize("window", WINDOW_SIZES)
def test_FPMT009_rapid_benign(base_config, window):
    """FPMT009: Rapid Benign Tool Execution"""
    engine = _make_engine(base_config, window)
    session = _session("filesystem-server", caps=["tools"])
    res = []
    for i in range(6):
        res.append(engine.evaluate(_tool_req("read_file"), session))
    if any(not r.allowed for r in res):
        pytest.xfail(f"FPMT009 blocked incorrectly at window size {window}")

@pytest.mark.parametrize("window", WINDOW_SIZES)
def test_FPMT010_embedded_pattern(base_config, window):
    """FPMT010: Embedded Pattern in Large Task (e.g. Read, Write deep in pipeline)"""
    engine = _make_engine(base_config, window)
    session = _session("filesystem-server", caps=["tools"])
    engine.evaluate(_tool_req("list_directory"), session)
    engine.evaluate(_tool_req("read_file"), session)
    r = engine.evaluate(_tool_req("write_file"), session)
    if not r.allowed:
        pytest.xfail(f"FPMT010 blocked incorrectly at window size {window}")

@pytest.mark.parametrize("window", WINDOW_SIZES)
def test_FPMT011_deferred_subsequence(base_config, window):
    """FPMT011: Deferred Subsequence Match (Harmless suffix flagged by large window)"""
    engine = _make_engine(base_config, window)
    session = _session("FPMT011-w")
    # Some older context
    engine.evaluate(_tool_req("get_data"), session)
    engine.evaluate(_tool_req("format_data"), session)
    # A harmless 3-turn chat happens later
    engine.evaluate(_req("sampling/createMessage"), session)
    engine.evaluate(_req("sampling/createMessage"), session)
    r = engine.evaluate(_req("sampling/createMessage"), session)
    if not r.allowed:
        pytest.xfail(f"FPMT011 blocked incorrectly at window size {window}")

@pytest.mark.parametrize("window", WINDOW_SIZES)
def test_FPMT012_stuttering_read(base_config, window):
    """FPMT012: Stuttering Read (Agent re-reads same file due to error, then samples)"""
    engine = _make_engine(base_config, window)
    session = _session("FPMT012-w")
    engine.evaluate(_req("resources/read", {"name": "f1.txt"}), session)
    engine.evaluate(_req("resources/read", {"name": "f1.txt"}), session)
    r = engine.evaluate(_req("sampling/createMessage"), session)
    if not r.allowed:
        pytest.xfail(f"FPMT012 blocked incorrectly at window size {window}")

@pytest.mark.parametrize("window", WINDOW_SIZES)
def test_FPMT013_partial_abandonment(base_config, window):
    """FPMT013: Partial Abandonment (Pipeline finishes, user asks joke -> sample)"""
    engine = _make_engine(base_config, window)
    session = _session("FPMT013-w")
    engine.evaluate(_tool_req("get_data"), session)
    engine.evaluate(_tool_req("format_data"), session)
    engine.evaluate(_tool_req("analyze"), session)
    r = engine.evaluate(_req("sampling/createMessage"), session)
    if not r.allowed:
        pytest.xfail(f"FPMT013 blocked incorrectly at window size {window}")

@pytest.mark.parametrize("window", WINDOW_SIZES)
def test_FPMT014_read_modify_write(base_config, window):
    """FPMT014: Read-Modify-Write (Agent updates its own file)"""
    engine = _make_engine(base_config, window)
    session = _session("filesystem-server", caps=["tools"])
    engine.evaluate(_tool_req("read_file"), session)
    r = engine.evaluate(_tool_req("write_file"), session)
    if not r.allowed:
        pytest.xfail(f"FPMT014 blocked incorrectly at window size {window}")

@pytest.mark.parametrize("window", WINDOW_SIZES)
def test_FPMT015_read_write_formatter(base_config, window):
    """FPMT015: JSON formatter reads then immediately writes the same file (moved
    from the single-turn file — this is a genuine two-call sequence)."""
    engine = _make_engine(base_config, window)
    session = _session("filesystem-server", caps=["tools"])
    engine.evaluate(_tool_req("read_file"), session)
    r = engine.evaluate(_tool_req("write_file"), session)
    if not r.allowed:
        pytest.xfail(f"FPMT015 blocked incorrectly at window size {window}")

@pytest.mark.parametrize("window", WINDOW_SIZES)
def test_FPMT016_batch_indexer_101_calls(base_config, window):
    """FPMT016: batch file indexer makes 101 separate read_file calls in one
    session — must not be blocked by max_calls_per_session on a purely benign,
    single-tool-type burst."""
    engine = _make_engine(base_config, window)
    session = _session("filesystem-server", caps=["tools"])
    results = [engine.evaluate(_tool_req("read_file"), session) for _ in range(101)]
    if not results[-1].allowed:
        pytest.xfail(f"FPMT016 blocked incorrectly at window size {window}")

@pytest.mark.parametrize("window", WINDOW_SIZES)
def test_FPMT017_six_step_etl_pipeline(base_config, window):
    """FPMT017: six-step ETL pipeline (read, parse, validate, transform, write,
    report) — must not trip rapid_tool_escalation on a legitimate, non-sampling
    tool chain."""
    engine = _make_engine(base_config, window)
    session = _session("filesystem-server", caps=["tools"])
    for tool in ["read_file", "parse_csv", "validate_schema", "transform_rows", "write_file"]:
        engine.evaluate(_tool_req(tool), session)
    r = engine.evaluate(_tool_req("send_report"), session)
    if not r.allowed:
        pytest.xfail(f"FPMT017 blocked incorrectly at window size {window}")

@pytest.mark.parametrize("window", WINDOW_SIZES)
def test_FPMT018_trusted_server_resource_then_sampling(base_config, window):
    """FPMT018: trusted-server with a verified 'sampling' capability reads two
    resources then samples — the default sampling_after_resource_read sequence
    rule should be exempted by capability, not just by rule tuning."""
    engine = _make_engine(base_config, window)
    session = _session("trusted-server", caps=["resources", "sampling", "tools"])
    engine.evaluate(_req("resources/read", {"name": "config_a.json"}), session)
    engine.evaluate(_req("resources/read", {"name": "config_b.json"}), session)
    r = engine.evaluate(_req("sampling/createMessage"), session)
    if not r.allowed:
        pytest.xfail(f"FPMT018 blocked incorrectly at window size {window}")

@pytest.mark.parametrize("window", WINDOW_SIZES)
def test_FPMT019_analytics_pipeline_name_collision(base_config, window):
    """FPMT019: get_data -> format_data -> analyze -> sampling, a legitimate
    analytics summary flow that shares tool names with a blocked pattern —
    intent (regression summary request), not name alone, should decide this."""
    engine = _make_engine(base_config, window)
    session = _session("FPMT019-w")
    engine.evaluate(_tool_req("get_data"), session)
    engine.evaluate(_tool_req("format_data"), session)
    engine.evaluate(_tool_req("analyze"), session)
    r = engine.evaluate(_req("sampling/createMessage"), session)
    if not r.allowed:
        pytest.xfail(f"FPMT019 blocked incorrectly at window size {window}")

# ── sweep ─────────────────────────────────────────────────────────────────────

FPMT0_META = [
    ("FPMT001", "Legitimate Two-File Summary"),
    ("FPMT002", "Legitimate Data Pipeline"),
    ("FPMT003", "Legitimate Direct File Copy"),
    ("FPMT004", "Legitimate Conversational Sampling"),
    ("FPMT005", "Trailing FP: Summary -> Tool"),
    ("FPMT006", "Trailing FP: Copy -> List"),
    ("FPMT007", "Trailing FP: Pipeline -> Resource"),
    ("FPMT008", "Trailing FP: Conversation -> Tool"),
    ("FPMT009", "Rapid Benign Tool Execution (Rate Limit)"),
    ("FPMT010", "Embedded Pattern in Large Task"),
    ("FPMT011", "Deferred Subsequence Match"),
    ("FPMT012", "Stuttering Read (Same file)"),
    ("FPMT013", "Partial Abandonment (Joke)"),
    ("FPMT014", "Read-Modify-Write (Self-Update)"),
    ("FPMT015", "Read-Write Formatter (moved from single-turn)"),
    ("FPMT016", "Batch Indexer, 101 Calls (moved from single-turn)"),
    ("FPMT017", "Six-Step ETL Pipeline (moved from single-turn)"),
    ("FPMT018", "Trusted-Server Resource-then-Sampling (moved from single-turn)"),
    ("FPMT019", "Analytics Pipeline Name Collision (moved from single-turn)"),
]

def run_FPMT0_sweep(base_config: dict) -> dict:
    results = {meta[0]: {} for meta in FPMT0_META}
    
    for window in WINDOW_SIZES:
        for case_id, _ in FPMT0_META:
            engine = _make_engine(base_config, window)
            session = _session(f"{case_id}-w", caps=["resources", "sampling", "tools"])
            if "FPMT003" in case_id or "FPMT006" in case_id or "FPMT009" in case_id or \
               "FPMT010" in case_id or "FPMT012" in case_id or "FPMT013" in case_id or \
               "FPMT014" in case_id or "FPMT015" in case_id or "FPMT016" in case_id or \
               "FPMT017" in case_id:
                session = _session("filesystem-server", caps=["tools", "sampling", "resources"])
            if case_id == "FPMT018":
                session = _session("trusted-server", caps=["resources", "sampling", "tools"])
            
            if case_id == "FPMT001":
                engine.evaluate(_req("resources/read", {"name": "f1.txt"}), session)
                engine.evaluate(_req("resources/read", {"name": "f2.txt"}), session)
                r = engine.evaluate(_req("sampling/createMessage"), session)
                results[case_id][window] = not r.allowed
                
            elif case_id == "FPMT002":
                engine.evaluate(_tool_req("get_data"), session)
                engine.evaluate(_tool_req("format_data"), session)
                engine.evaluate(_tool_req("analyze"), session)
                r = engine.evaluate(_req("sampling/createMessage"), session)
                results[case_id][window] = not r.allowed
                
            elif case_id == "FPMT003":
                engine.evaluate(_tool_req("read_file"), session)
                r = engine.evaluate(_tool_req("write_file"), session)
                results[case_id][window] = not r.allowed
                
            elif case_id == "FPMT004":
                engine.evaluate(_req("sampling/createMessage"), session)
                engine.evaluate(_req("sampling/createMessage"), session)
                r = engine.evaluate(_req("sampling/createMessage"), session)
                results[case_id][window] = not r.allowed
                
            elif case_id == "FPMT005":
                engine.evaluate(_req("resources/read", {"name": "f1.txt"}), session)
                engine.evaluate(_req("resources/read", {"name": "f2.txt"}), session)
                engine.evaluate(_req("sampling/createMessage"), session)
                r = engine.evaluate(_tool_req("list_directory"), session)
                results[case_id][window] = not r.allowed
                
            elif case_id == "FPMT006":
                engine.evaluate(_tool_req("read_file"), session)
                engine.evaluate(_tool_req("write_file"), session)
                r = engine.evaluate(_tool_req("list_directory"), session)
                results[case_id][window] = not r.allowed
                
            elif case_id == "FPMT007":
                engine.evaluate(_tool_req("get_data"), session)
                engine.evaluate(_tool_req("format_data"), session)
                engine.evaluate(_tool_req("analyze"), session)
                engine.evaluate(_req("sampling/createMessage"), session)
                r = engine.evaluate(_req("resources/read", {"name": "f1.txt"}), session)
                results[case_id][window] = not r.allowed
                
            elif case_id == "FPMT008":
                engine.evaluate(_req("sampling/createMessage"), session)
                engine.evaluate(_req("sampling/createMessage"), session)
                engine.evaluate(_req("sampling/createMessage"), session)
                r = engine.evaluate(_tool_req("list_directory"), session)
                results[case_id][window] = not r.allowed
                
            elif case_id == "FPMT009":
                res = []
                for i in range(6):
                    res.append(engine.evaluate(_tool_req("read_file"), session))
                results[case_id][window] = any(not r.allowed for r in res)
                
            elif case_id == "FPMT010":
                engine.evaluate(_tool_req("list_directory"), session)
                engine.evaluate(_tool_req("read_file"), session)
                r = engine.evaluate(_tool_req("write_file"), session)
                results[case_id][window] = not r.allowed
                
            elif case_id == "FPMT011":
                engine.evaluate(_tool_req("get_data"), session)
                engine.evaluate(_tool_req("format_data"), session)
                engine.evaluate(_req("sampling/createMessage"), session)
                engine.evaluate(_req("sampling/createMessage"), session)
                r = engine.evaluate(_req("sampling/createMessage"), session)
                results[case_id][window] = not r.allowed
                
            elif case_id == "FPMT012":
                engine.evaluate(_req("resources/read", {"name": "f1.txt"}), session)
                engine.evaluate(_req("resources/read", {"name": "f1.txt"}), session)
                r = engine.evaluate(_req("sampling/createMessage"), session)
                results[case_id][window] = not r.allowed
                
            elif case_id == "FPMT013":
                engine.evaluate(_tool_req("get_data"), session)
                engine.evaluate(_tool_req("format_data"), session)
                engine.evaluate(_tool_req("analyze"), session)
                r = engine.evaluate(_req("sampling/createMessage"), session)
                results[case_id][window] = not r.allowed
                
            elif case_id == "FPMT014":
                engine.evaluate(_tool_req("read_file"), session)
                r = engine.evaluate(_tool_req("write_file"), session)
                results[case_id][window] = not r.allowed

            elif case_id == "FPMT015":
                engine.evaluate(_tool_req("read_file"), session)
                r = engine.evaluate(_tool_req("write_file"), session)
                results[case_id][window] = not r.allowed

            elif case_id == "FPMT016":
                res = [engine.evaluate(_tool_req("read_file"), session) for _ in range(101)]
                results[case_id][window] = not res[-1].allowed

            elif case_id == "FPMT017":
                for tool in ["read_file", "parse_csv", "validate_schema", "transform_rows", "write_file"]:
                    engine.evaluate(_tool_req(tool), session)
                r = engine.evaluate(_tool_req("send_report"), session)
                results[case_id][window] = not r.allowed

            elif case_id == "FPMT018":
                engine.evaluate(_req("resources/read", {"name": "config_a.json"}), session)
                engine.evaluate(_req("resources/read", {"name": "config_b.json"}), session)
                r = engine.evaluate(_req("sampling/createMessage"), session)
                results[case_id][window] = not r.allowed

            elif case_id == "FPMT019":
                engine.evaluate(_tool_req("get_data"), session)
                engine.evaluate(_tool_req("format_data"), session)
                engine.evaluate(_tool_req("analyze"), session)
                r = engine.evaluate(_req("sampling/createMessage"), session)
                results[case_id][window] = not r.allowed

    return results

def print_table(results: dict) -> None:
    col_w  = 9
    id_w   = 10
    desc_w = 44

    header_wins = "".join(f"  w={w:<{col_w-3}}" for w in WINDOW_SIZES)
    total_w = id_w + desc_w + len(header_wins)

    print()
    print("=" * total_w)
    print("  MULTI-TURN FALSE POSITIVES (BENIGN WORKFLOWS)")
    print("=" * total_w)
    print(f"{'Case':<{id_w}} {'Description':<{desc_w}}" + header_wins)
    print("-" * total_w)

    case_ids = [m[0] for m in FPMT0_META]
    case_descs = {m[0]: m[1] for m in FPMT0_META}

    for case_id in case_ids:
        row = f"{case_id:<{id_w}} {case_descs[case_id]:<{desc_w}}"
        for w in WINDOW_SIZES:
            cell = "FALSE POS" if results[case_id][w] else "allowed"
            row += f"  {cell:<{col_w-2}}"
        print(row)

    print("-" * total_w)
    
    rate_row = f"{'FP rate':<{id_w}} {'':<{desc_w}}"
    n = len(case_ids)
    for w in WINDOW_SIZES:
        flagged = sum(1 for cid in case_ids if results[cid][w])
        pct = f"{flagged/n*100:.0f}%"
        rate_row += f"  {pct:<{col_w-2}}"
    print(rate_row)
    print("=" * total_w)
    print(f"  Window sizes tested: {WINDOW_SIZES}")
    print()

if __name__ == "__main__":
    with open(CONFIG_PATH) as f:
        cfg = json.load(f)
    results = run_FPMT0_sweep(cfg)
    print_table(results)