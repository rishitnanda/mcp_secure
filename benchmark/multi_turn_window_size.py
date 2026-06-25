import asyncio
import copy
import json
import os
import re
import sys
import uuid
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from mcp_shield.src.policy import PolicyEngine
from mcp_shield.src.session import SessionState, SessionStore
from mcp_shield.src.schemas import JSONRPCRequest
from mcp_shield.src.database import DatabaseManager


# ---------------------------------------------------------------------------
# Shared async helpers
# ---------------------------------------------------------------------------

async def _make_db_store_async(db_path: str) -> tuple[SessionStore, DatabaseManager]:
    """Create a DB-backed SessionStore. Returns (store, db) for teardown."""
    if os.path.exists(db_path):
        os.remove(db_path)
    db = DatabaseManager(db_path=db_path)
    await db.init_db()
    store = SessionStore(db_manager=db)
    return store, db


async def _drain_tasks() -> None:
    """Give the event loop enough cycles to flush all pending aiosqlite write tasks.

    A short real sleep guarantees every fire-and-forget record_call coroutine
    has completed before we close the DB connection or return from asyncio.run().
    This must be awaited before any store.clear() call and before returning from
    every case runner — not only MPS-029.
    """
    await asyncio.sleep(0.05)


async def _get_session(store: SessionStore, session_id: str) -> SessionState:
    """Tiny await gap so record_call write tasks can flush, then fetch/create."""
    await asyncio.sleep(0.02)
    return await store.get_or_create(session_id)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Request / session helpers
# ---------------------------------------------------------------------------

def _req(method: str, params: dict | None = None) -> JSONRPCRequest:
    return JSONRPCRequest(jsonrpc="2.0", id=1, method=method, params=params or {})


def _tool_req(tool_name: str) -> JSONRPCRequest:
    return _req("tools/call", {"name": tool_name, "arguments": {}})


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
    engine.config_path  = CONFIG_PATH
    engine.nonce_window = cfg.get("nonce_window", 300)
    engine.config       = cfg
    engine.load_config  = lambda: None  # prevent re-reading from disk

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


def _sid(base: str) -> str:
    """Unique session ID per asyncio.run() scope — prevents history bleeding."""
    return f"{base}-{uuid.uuid4().hex[:8]}"


# ---------------------------------------------------------------------------
# Per-case async runner
#
# Every case follows the same three-step contract:
#   1. All engine.evaluate() calls happen inside this coroutine on the single
#      event loop that owns the DB connection (no threads, no nested loops).
#   2. _drain_tasks() is awaited BEFORE any store.clear() so SQLite has the
#      rows before in-memory state is wiped.
#   3. _drain_tasks() is awaited again before returning so the outer _run()
#      finally block can safely close the DB.
#
# MPS-029 is not special — it follows the same pattern as every other case.
# ---------------------------------------------------------------------------

async def _run_case_async(engine: PolicyEngine, store: SessionStore, case_id: str) -> bool:
    """Runs a single attack case against the given engine+store. Returns True=BLOCKED."""

    if case_id == "MPS-020":
        s = await _get_session(store, _sid("mps020"))
        s.verified_capabilities = ["resources", "sampling", "tools"]
        engine.evaluate(_req("resources/read", {"name": "file.txt"}), s)
        engine.evaluate(_req("resources/read", {"name": "file.txt"}), s)
        result = engine.evaluate(_req("sampling/createMessage"), s)
        await _drain_tasks()
        return not result.allowed

    if case_id == "MPS-026":
        s = await _get_session(store, _sid("mps026"))
        s.verified_capabilities = ["resources", "sampling", "tools"]
        for _ in range(3):
            engine.evaluate(_req("resources/read", {"name": "secrets.txt"}), s)
        result = engine.evaluate(_req("sampling/createMessage"), s)
        await _drain_tasks()
        return not result.allowed

    if case_id == "MPS-027":
        s = await _get_session(store, _sid("mps027"))
        s.verified_capabilities = ["resources", "sampling", "tools"]
        engine.evaluate(_req("resources/read", {"name": "trigger.txt"}), s)
        engine.evaluate(_req("resources/read", {"name": "trigger.txt"}), s)
        result = engine.evaluate(_req("sampling/createMessage"), s)
        await _drain_tasks()
        return not result.allowed

    if case_id == "MPS-029":
        # Phase 1: seed history pre-restart.
        # Phase 2: drain → clear → reconstruct from DB → evaluate.
        # All on the same event loop that owns the DB — no thread needed.
        sid = _sid("mps029")
        s1 = await _get_session(store, sid)
        s1.verified_capabilities = ["resources", "sampling", "tools"]
        engine.evaluate(_req("resources/read", {"name": "s1.txt"}), s1)
        engine.evaluate(_req("resources/read", {"name": "s1.txt"}), s1)
        # Drain BEFORE clear so SQLite has the rows before wiping in-memory state.
        await _drain_tasks()
        store.clear()
        s2 = await _get_session(store, sid)
        s2.verified_capabilities = ["resources", "sampling", "tools"]
        assert len(s2.call_history) >= 2, (
            f"MPS-029: DB reconstruction failed — expected >=2 history rows, "
            f"got {len(s2.call_history)}"
        )
        result = engine.evaluate(_req("sampling/createMessage"), s2)
        await _drain_tasks()
        return not result.allowed

    if case_id == "MPS-030":
        s = await _get_session(store, _sid("mps030"))
        s.verified_capabilities = ["resources", "sampling", "tools"]
        for i in range(14):
            engine.evaluate(_req("resources/read", {"name": f"f{i}.txt"}), s)
        result = engine.evaluate(_req("sampling/createMessage"), s)
        await _drain_tasks()
        return not result.allowed

    if case_id == "MPS-033":
        s = await _get_session(store, _sid("mps033"))
        s.verified_capabilities = ["resources", "sampling", "tools"]
        engine.evaluate(_req("resources/read"), s)
        engine.evaluate(_req("resources/read"), s)
        result = engine.evaluate(_req("sampling/createMessage", {"maxTokens": 32000}), s)
        await _drain_tasks()
        return not result.allowed

    if case_id == "MPS-034":
        s = await _get_session(store, _sid("mps034"))
        s.verified_capabilities = ["resources", "sampling", "tools"]
        engine.evaluate(_req("sampling/createMessage"), s)
        engine.evaluate(_req("sampling/createMessage"), s)
        result = engine.evaluate(_req("sampling/createMessage"), s)
        await _drain_tasks()
        return not result.allowed

    if case_id == "MPS-035":
        s = await _get_session(store, _sid("mps035"))
        s.verified_capabilities = ["resources", "sampling", "tools"]
        engine.evaluate(_req("resources/read", {"name": "credentials.txt"}), s)
        engine.evaluate(_req("resources/read", {"name": "credentials.txt"}), s)
        result = engine.evaluate(_req("sampling/createMessage"), s)
        await _drain_tasks()
        return not result.allowed

    if case_id == "MPS-037":
        s = await _get_session(store, _sid("mps037"))
        s.verified_capabilities = ["resources", "sampling", "tools"]
        for tool in ["get_data", "format_data", "analyze"]:
            engine.evaluate(_tool_req(tool), s)
        result = engine.evaluate(_req("sampling/createMessage"), s)
        await _drain_tasks()
        return not result.allowed

    if case_id == "MPS-039":
        s = await _get_session(store, _sid("mps039"))
        s.verified_capabilities = ["resources", "sampling", "tools"]
        for i in range(10):
            engine.evaluate(_req("resources/read", {"name": f"f{i}.txt"}), s)
        result = engine.evaluate(_req("sampling/createMessage"), s)
        await _drain_tasks()
        return not result.allowed

    raise ValueError(f"Unknown case_id: {case_id}")


# ---------------------------------------------------------------------------
# Sweep runner
# ---------------------------------------------------------------------------

def run_sweep(base_config: dict) -> dict:
    """
    Returns results[case_id][window] = True (BLOCKED) / False (MISSED).

    Each (window, case) pair gets its own UUID-suffixed DB file via asyncio.run(),
    ensuring full isolation and consistent event-loop ownership.  UUID suffix
    prevents stale DB rows from a prior run poisoning the store.

    engine is captured explicitly as a default argument in _run to prevent the
    late-binding closure bug: without it, every asyncio.run(_run()) call would
    see the engine from the final loop iteration rather than the current window.
    """
    results = {meta[0]: {} for meta in CASE_META}

    for window in WINDOW_SIZES:
        engine = _make_engine(base_config, window)

        for case_id, _ in CASE_META:
            run_id  = uuid.uuid4().hex[:8]
            db_path = f"sweep_w{window}_{case_id.replace('-', '')}_{run_id}.db"

            async def _run(
                db_path=db_path,
                case_id=case_id,
                engine=engine,      # capture by value — prevents late-binding
            ):
                store, db = await _make_db_store_async(db_path)
                try:
                    return await _run_case_async(engine, store, case_id)
                finally:
                    await _drain_tasks()
                    await db.close()
                    if os.path.exists(db_path):
                        os.remove(db_path)

            results[case_id][window] = asyncio.run(_run())

    return results


# ---------------------------------------------------------------------------
# Table printer
# ---------------------------------------------------------------------------

def print_table(results: dict) -> None:
    case_ids   = [m[0] for m in CASE_META]
    case_descs = {m[0]: m[1] for m in CASE_META}

    col_w  = 9
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

    rate_row = f"{'Detection rate':<{id_w}} {'':<{desc_w-5}}"
    n = len(case_ids)
    for w in WINDOW_SIZES:
        blocked = sum(1 for cid in case_ids if results[cid][w])
        pct = f"{blocked/n*100:.2f}%"
        rate_row += f"  {pct:<{col_w-2}}"
    print(rate_row)

    print("=" * total_w)


# ---------------------------------------------------------------------------
# Fixtures and tests
# ---------------------------------------------------------------------------

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