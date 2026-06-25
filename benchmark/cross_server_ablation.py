"""
Tests V3 multi-server attack cases under two session tracking architectures:

Condition A (Isolated Tracking):
  SessionState is keyed strictly by `server_id`. When an attack sequence
  (e.g., read -> read -> sample) spans multiple servers, each server only
  sees its local slice of the history.

Condition B (Unified Tracking):
  SessionState is keyed by `client_session_id`. All tool calls and resource
  reads across all servers in the deployment are appended to a single, unified
  history log.

Every case runner follows the same three-step contract regardless of whether
it does a store.clear() mid-scenario (MPS-029) or not:
  1. All engine.evaluate() calls run inside a single asyncio.run() scope on
     the event loop that owns the DB connection — no threads, no nested loops.
  2. _drain_tasks() is awaited BEFORE store.clear() so SQLite has the rows
     before in-memory state is wiped.
  3. _drain_tasks() is awaited again before returning so the _run_condition()
     finally block can safely close the DB.
"""

import asyncio
import os
import uuid
import pytest

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


async def _get_session(store: SessionStore, session_id: str) -> SessionState:
    """Tiny await gap so record_call write tasks can flush, then fetch/create."""
    await asyncio.sleep(0.02)
    return await store.get_or_create(session_id)


async def _drain_tasks() -> None:
    """Give the event loop enough cycles to flush all pending aiosqlite write tasks.

    A short real sleep guarantees every fire-and-forget record_call coroutine
    has completed before we close the DB connection or before store.clear()
    wipes in-memory state that the DB has not yet persisted.
    """
    await asyncio.sleep(0.05)


# ---------------------------------------------------------------------------
# Case definitions
# ---------------------------------------------------------------------------

CASES = [
    ("MPS-026", "Data staging via sampling",    3),
    ("MPS-027", "Cascade attack",               2),
    ("MPS-029", "Cross-session restart",        2),
    ("MPS-030", "Below window size (14-read)", 14),
]


def _sid(base: str) -> str:
    """Unique session ID per asyncio.run() scope — prevents history bleeding."""
    return f"{base}-{uuid.uuid4().hex[:8]}"


def _req(method: str, params: dict | None = None) -> JSONRPCRequest:
    return JSONRPCRequest(jsonrpc="2.0", id=1, method=method, params=params or {})


# ---------------------------------------------------------------------------
# Attack simulator
# ---------------------------------------------------------------------------

async def _simulate_cross_server_attack(
    engine: PolicyEngine,
    store: SessionStore,
    case_id: str,
    read_count: int,
    condition: str,
) -> bool:
    """
    Returns True if BLOCKED, False if MISSED (Attack Success).

    Cross-server layout:
      - Server A (compromised) performs the resource reads.
      - Server B (target/pivoted server) performs the sampling.

    MPS-029 simulates a gateway restart with _drain_tasks() + store.clear() +
    get_or_create(), all on the same event loop that owns the DB connection —
    identical contract to every other case.  No threads or nested event loops.

    Condition A: session is keyed per server_id (isolated history per server).
    Condition B: session is keyed by a shared client ID (unified history).
    """

    if case_id == "MPS-029":
        # Both conditions use the same single-session restart pattern because
        # MPS-029 tests persistence across a gateway restart, not cross-server
        # history aggregation.  The session ID is shared across both phases so
        # get_or_create can reconstruct history from the DB after store.clear().
        sid = _sid("mps029")
        session = await _get_session(store, sid)
        session.verified_capabilities = ["resources", "sampling", "tools"]
        for _ in range(read_count):
            engine.evaluate(_req("resources/read", {"name": "s1.txt"}), session)
        # Drain BEFORE clear — guarantees SQLite has the rows.
        await _drain_tasks()
        store.clear()
        session = await _get_session(store, sid)
        session.verified_capabilities = ["resources", "sampling", "tools"]
        assert len(session.call_history) >= read_count, (
            f"MPS-029: DB reconstruction failed — expected >={read_count} history rows, "
            f"got {len(session.call_history)}"
        )
        result = engine.evaluate(_req("sampling/createMessage", {}), session)
        await _drain_tasks()
        return not result.allowed

    # --- All other cases (MPS-026, MPS-027, MPS-030) ---
    # Condition A: isolated per-server sessions; Condition B: shared client session.
    session_id_A = "serverA"               if condition == "A" else "global_client_session"
    session_id_B = "serverB"               if condition == "A" else "global_client_session"

    # Stage 1: Server A performs reads.
    session_A = await _get_session(store, session_id_A)
    session_A.verified_capabilities = ["resources", "sampling", "tools"]
    if condition == "B":
        session_A.server_id = "serverA"

    for _ in range(read_count):
        engine.evaluate(_req("resources/read", {"name": "data.txt"}), session_A)

    # Drain before fetching session_B so all of session_A's writes are in the DB.
    # This matters for Condition B (same session ID) where get_or_create would
    # return a stale in-memory object if writes are still pending.
    await _drain_tasks()

    # Stage 2: Server B attempts sampling (the exfil step).
    session_B = await _get_session(store, session_id_B)
    session_B.verified_capabilities = ["resources", "sampling", "tools"]
    if condition == "B":
        session_B.server_id = "serverB"

    result = engine.evaluate(_req("sampling/createMessage", {}), session_B)
    await _drain_tasks()
    return not result.allowed


# ---------------------------------------------------------------------------
# Runner and printer
# ---------------------------------------------------------------------------

def run_ablation() -> dict:
    results = {}

    for case_id, desc, read_count in CASES:
        # Fresh engine per case: PolicyEngine may hold mutable internal state
        # (nonce cache, rate-limit counters) that would bleed across cases if
        # a single instance were shared for the entire ablation run.
        engine = PolicyEngine("config/shield_config.json")

        # UUID suffix prevents stale DB files from a prior run being read.
        run_id    = uuid.uuid4().hex[:8]
        db_path_A = f"ablation_condA_{case_id}_{run_id}.db"
        db_path_B = f"ablation_condB_{case_id}_{run_id}.db"

        # Capture loop variables as defaults to avoid late-binding closure bugs.
        async def _run_condition(
            db_path: str,
            condition: str,
            _engine: PolicyEngine = engine,
            _case_id: str = case_id,
            _read_count: int = read_count,
        ) -> bool:
            store, db = await _make_db_store_async(db_path)
            try:
                return await _simulate_cross_server_attack(
                    _engine, store, _case_id, _read_count, condition
                )
            finally:
                await _drain_tasks()
                await db.close()
                if os.path.exists(db_path):
                    os.remove(db_path)

        blocked_A = asyncio.run(_run_condition(db_path_A, "A"))
        blocked_B = asyncio.run(_run_condition(db_path_B, "B"))

        results[case_id] = {"desc": desc, "A": blocked_A, "B": blocked_B}

    return results


def print_results(results: dict):
    print("\n" + "=" * 80)
    print(" CROSS-SERVER ATTACK ABLATION: ISOLATED VS. UNIFIED SESSION TRACKING")
    print("=" * 80)
    print(f"{'Case ID':<10} {'Description':<35} {'Cond A (Isolated)':<20} {'Cond B (Unified)':<20}")
    print("-" * 80)

    total           = len(results)
    blocked_A_count = 0
    blocked_B_count = 0

    for case_id, data in results.items():
        val_A = "BLOCKED" if data["A"] else "missed"
        val_B = "BLOCKED" if data["B"] else "missed"
        if data["A"]: blocked_A_count += 1
        if data["B"]: blocked_B_count += 1
        print(f"{case_id:<10} {data['desc']:<35} {val_A:<20} {val_B:<20}")

    print("-" * 80)

    asr_A = (total - blocked_A_count) / total * 100
    asr_B = (total - blocked_B_count) / total * 100

    print(f"{'Attack Success Rate (ASR)':<46} {asr_A:.1f}%                 {asr_B:.1f}%")
    print(f"{'Detection Rate':<46} {blocked_A_count/total*100:.1f}%                {blocked_B_count/total*100:.1f}%")
    print("=" * 80 + "\n")
    print("  Condition A: Session history is siloed per server (current default behavior)")
    print("  Condition B: Session history is aggregated per client across all servers")
    print()


# ---------------------------------------------------------------------------
# pytest integration
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def ablation_results():
    return run_ablation()


def test_condition_A_isolated_tracking_misses_cross_server(ablation_results):
    assert not ablation_results["MPS-026"]["A"], "Condition A should MISS MPS-026"
    assert not ablation_results["MPS-027"]["A"], "Condition A should MISS MPS-027"
    assert not ablation_results["MPS-030"]["A"], "Condition A should MISS MPS-030"


def test_condition_B_unified_tracking_catches_cross_server(ablation_results):
    assert ablation_results["MPS-026"]["B"], "Condition B should BLOCK MPS-026"
    assert ablation_results["MPS-027"]["B"], "Condition B should BLOCK MPS-027"
    assert ablation_results["MPS-030"]["B"], "Condition B should BLOCK MPS-030"


def test_mps029_cross_session_restart_blocked_both(ablation_results):
    # MPS-029 uses store.clear() + get_or_create() inside a single asyncio.run()
    # scope, with _drain_tasks() before the clear.  This guarantees DB has the
    # rows before in-memory state is wiped, so history survives the restart on
    # both condition A and B.
    assert ablation_results["MPS-029"]["A"], "Condition A should BLOCK MPS-029"
    assert ablation_results["MPS-029"]["B"], "Condition B should BLOCK MPS-029"


def test_print_ablation_results(ablation_results):
    print_results(ablation_results)


if __name__ == "__main__":
    res = run_ablation()
    print_results(res)