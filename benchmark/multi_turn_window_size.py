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

CASE_META = [
    ("MPS-020", "Gradual escalation"),
    ("MPS-026", "Data staging via sampling"),
    ("MPS-027", "Cascade attack"),
    ("MPS-029", "Cross-session restart"),
    ("MPS-030", "Below window size (14-read)"),
    ("MPS-033", "Rate-limit probe maxTokens"),
    ("MPS-034", "Sequential sampling context buildup"),
    ("MPS-035", "Resource-to-sampling exfiltration"),
    ("MPS-037", "Sampling after tool sequence"),
    ("MPS-039", "Slow-burn sampling"),
]

def _req(method: str, params: dict | None = None) -> JSONRPCRequest:
    return JSONRPCRequest(jsonrpc="2.0", id=1, method=method, params=params or {})


def _tool_req(tool_name: str) -> JSONRPCRequest:
    return _req("tools/call", {"name": tool_name, "arguments": {}})


def _session(server_id: str = "test-server",
             caps: list | None = None) -> SessionState:
    s = SessionState(server_id=server_id)
    s.verified_capabilities = caps if caps is not None else ["resources", "sampling", "tools"]
    return s


def _make_engine(base_config: dict, window: int) -> PolicyEngine:
    """
    Return a PolicyEngine whose sequence-policy rules all have their 'window'
    field overridden to `window`.  Rate-limit rules (max_calls/window_seconds)
    are left untouched because they are not pattern-window based.
    """
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
    engine.nonce_window = PolicyEngine("config/shield_config.json").nonce_window  # fresh nonce window
    engine.config = cfg
    engine.load_config = lambda: None  # prevent re-reading from disk
    # Re-run the regex compilation part of load_config manually
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


def _run_case(engine: PolicyEngine, store: SessionStore, case_id: str) -> bool:

    if case_id == "MPS-020":
        session = _session("mps020-w")
        engine.evaluate(_req("resources/read", {"name": "file.txt"}), session)
        engine.evaluate(_req("resources/read", {"name": "file.txt"}), session)
        result = engine.evaluate(_req("sampling/createMessage"), session)
        return not result.allowed

    if case_id == "MPS-026":
        session = _session("mps026-w")
        for _ in range(3):
            engine.evaluate(_req("resources/read", {"name": "secrets.txt"}), session)
        result = engine.evaluate(_req("sampling/createMessage"), session)
        return not result.allowed

    if case_id == "MPS-027":
        session = _session("mps027-w")
        engine.evaluate(_req("resources/read", {"name": "trigger.txt"}), session)
        engine.evaluate(_req("resources/read", {"name": "trigger.txt"}), session)
        result = engine.evaluate(_req("sampling/createMessage"), session)
        return not result.allowed

    if case_id == "MPS-029":
        # Split across two independent sessions — cross-session gap by design
        s1 = _session("mps029-w-s1")
        engine.evaluate(_req("resources/read", {"name": "s1.txt"}), s1)
        s2 = _session("mps029-w-s2")          # fresh session, no history
        result = engine.evaluate(_req("sampling/createMessage"), s2)
        return not result.allowed

    if case_id == "MPS-030":
        session = _session("mps030-w")
        for i in range(14):
            engine.evaluate(_req("resources/read", {"name": f"f{i}.txt"}), session)
        result = engine.evaluate(_req("sampling/createMessage"), session)
        return not result.allowed

    if case_id == "MPS-033":
        session = _session("mps033-w")
        engine.evaluate(_req("resources/read"), session)
        engine.evaluate(_req("resources/read"), session)
        result = engine.evaluate(_req("sampling/createMessage", {"maxTokens": 32000}), session)
        return not result.allowed

    if case_id == "MPS-034":
        session = _session("mps034-w")
        engine.evaluate(_req("sampling/createMessage"), session)
        engine.evaluate(_req("sampling/createMessage"), session)
        result = engine.evaluate(_req("sampling/createMessage"), session)
        return not result.allowed

    if case_id == "MPS-035":
        session = _session("mps035-w")
        engine.evaluate(_req("resources/read", {"name": "credentials.txt"}), session)
        engine.evaluate(_req("resources/read", {"name": "credentials.txt"}), session)
        result = engine.evaluate(_req("sampling/createMessage"), session)
        return not result.allowed

    if case_id == "MPS-037":
        session = _session("mps037-w")
        for tool in ["get_data", "format_data", "analyze"]:
            engine.evaluate(_tool_req(tool), session)
        result = engine.evaluate(_req("sampling/createMessage"), session)
        return not result.allowed

    if case_id == "MPS-039":
        session = _session("mps039-w")
        for i in range(10):
            engine.evaluate(_req("resources/read", {"name": f"f{i}.txt"}), session)
        result = engine.evaluate(_req("sampling/createMessage"), session)
        return not result.allowed

    raise ValueError(f"Unknown case_id: {case_id}")

def run_sweep(base_config: dict) -> dict:
    """
    Returns results[case_id][window] = True (BLOCKED) / False (MISSED).
    """
    store = SessionStore()
    results = {meta[0]: {} for meta in CASE_META}

    for window in WINDOW_SIZES:
        engine = _make_engine(base_config, window)
        for case_id, _ in CASE_META:
            results[case_id][window] = _run_case(engine, store, case_id)

    return results


def print_table(results: dict) -> None:
    case_ids = [m[0] for m in CASE_META]
    case_descs = {m[0]: m[1] for m in CASE_META}

    col_w  = 9          # width of each window column
    id_w   = 9
    desc_w = 44

    header_wins = "".join(f"  w={w:<{col_w-3}}" for w in WINDOW_SIZES)
    total_w = id_w + desc_w + len(header_wins)

    print()
    print("=" * total_w)
    print("  MULTI-TURN DETECTION RATE vs. SEQUENCE-RULE WINDOW SIZE")
    print("=" * total_w)
    print(f"{'Case':<{id_w}} {'Description':<{desc_w}}" + header_wins)
    print("-" * total_w)

    for case_id in case_ids:
        row = f"{case_id:<{id_w}} {case_descs[case_id]:<{desc_w}}"
        for w in WINDOW_SIZES:
            cell = "BLOCKED" if results[case_id][w] else "missed "
            row += f"  {cell:<{col_w-2}}"
        print(row)

    print("-" * total_w)

    # Detection rate per window
    rate_row = f"{'Detection rate':<{id_w}} {'':<{desc_w-5}}"
    n = len(case_ids)
    for w in WINDOW_SIZES:
        blocked = sum(1 for cid in case_ids if results[cid][w])
        pct = f"{blocked/n*100:.2f}%"
        rate_row += f"  {pct:<{col_w-2}}"
    print(rate_row)

    print("=" * total_w)

@pytest.fixture(scope="module")
def base_config():
    with open(CONFIG_PATH) as f:
        return json.load(f)


@pytest.fixture(scope="module")
def sweep_results(base_config):
    return run_sweep(base_config)

def test_print_sweep_table(sweep_results):
    """Prints the full BLOCKED/MISSED matrix. Run with -s to see output."""
    print_table(sweep_results)

if __name__ == "__main__":
    with open(CONFIG_PATH) as f:
        cfg = json.load(f)
    results = run_sweep(cfg)
    print_table(results)
