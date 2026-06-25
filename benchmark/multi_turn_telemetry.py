import asyncio
import json
import os
import time
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


async def _drain_tasks() -> None:
    """Give the event loop enough cycles to flush all pending aiosqlite write tasks.

    A short real sleep guarantees every fire-and-forget record_call coroutine
    has completed before we close the DB connection or return from asyncio.run().
    """
    await asyncio.sleep(0.05)


async def _get_session(store: SessionStore, session_id: str) -> SessionState:
    """Tiny await gap so record_call write tasks can flush, then fetch/create."""
    await asyncio.sleep(0.02)
    return await store.get_or_create(session_id)


# ---------------------------------------------------------------------------
# Request helpers
# ---------------------------------------------------------------------------

def make_req(method: str, tool_name: str = None, extra_params: dict = None) -> JSONRPCRequest:
    if method == "tools/call" and tool_name:
        params = {"name": tool_name, "arguments": extra_params or {}}
    elif extra_params:
        params = extra_params
    else:
        params = {}
    return JSONRPCRequest(jsonrpc="2.0", id=1, method=method, params=params)


def state_size_kb(session: SessionState) -> float:
    raw = json.dumps(session.call_history).encode("utf-8")
    return round(len(raw) / 1024, 3)


def run_singleturn(engine, server_id, requests, caps):
    """Fresh session per request — ATTESTMCP baseline (no state carried over)."""
    result = None
    for req in requests:
        fresh = SessionState(server_id=server_id)
        fresh.verified_capabilities = caps
        result = engine.evaluate(req, fresh)
    return result


def record(collector, case_id, turns, size_kb, avg_dt, single_blocked, multi_blocked):
    collector.append({
        "case_id":        case_id,
        "turns":          turns,
        "state_kb":       size_kb,
        "avg_dt":         avg_dt,
        "single_blocked": single_blocked,
        "multi_blocked":  multi_blocked,
    })


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def engine():
    return PolicyEngine()


@pytest.fixture(scope="function")
def store():
    """DB-backed SessionStore, isolated per test function.

    scope="function" gives each test a fresh SQLite DB and empty in-memory
    session dict. Teardown drains pending aiosqlite write tasks before closing
    so no fire-and-forget coroutines hit a closed connection in the next test.
    """
    db_path = f"multi_turn_telemetry_{uuid.uuid4().hex}.db"

    async def _setup():
        return await _make_db_store_async(db_path)

    s, db = asyncio.run(_setup())
    yield s

    async def _teardown():
        await _drain_tasks()
        await db.close()

    asyncio.run(_teardown())
    if os.path.exists(db_path):
        try:
            os.remove(db_path)
        except Exception:
            pass


@pytest.fixture(scope="module")
def results_collector():
    rows = []
    yield rows
    print("\n\n" + "=" * 95)
    print("TABLE IV — STATEFUL TELEMETRY AND OPERATIONAL OVERHEAD FOR MULTI-TURN ATTACK SEQUENCES")
    print("=" * 95)
    print(f"{'Case ID':<8} {'MPS ID':<10} {'Turns':>6} {'State (KB)':>11} {'Avg Δt (ms)':>12} {'Single-turn':<14} {'Multi-turn':<12} {'Stage'}")
    print("-" * 95)
    for r in rows:
        st = "blocked" if r["single_blocked"] else "missed"
        mt = "blocked" if r["multi_blocked"]  else "missed"
        print(
            f"{r['case_id']:<8} {r['mps_id']:<10} {r['turns']:>6} {r['state_kb']:>11.3f} "
            f"{r['avg_dt']:>12.3f} {st:<14} {mt:<14} {r['stage']}"
        )
    print("=" * 95 + "\n")


def _sid(base: str) -> str:
    """Unique session ID per test invocation — prevents history bleeding across tests."""
    return f"{base}-{uuid.uuid4().hex[:8]}"


# ---------------------------------------------------------------------------
# Tests
#
# Every test runs ALL evaluates inside a single asyncio.run() scope so that
# aiosqlite write tasks fire on the same event loop that owns the DB connection.
# Each _run() coroutine:
#   1. Creates the session inside the loop.
#   2. Runs every engine.evaluate() call inside the loop.
#   3. Awaits _drain_tasks() before returning so writes flush before asyncio.run()
#      exits and the fixture's teardown closes the DB.
#
# MPS-029 follows the same pattern: store.clear() + get_or_create happen inside
# the same _run() coroutine, on the same loop, using the same store fixture DB
# connection — no special inner DB or thread needed.
# ---------------------------------------------------------------------------

def test_mt01_MPS020_gradual_escalation(engine, store, results_collector):
    reqs = [
        make_req("resources/read", extra_params={"name": "file.txt"}),
        make_req("resources/read", extra_params={"name": "file.txt"}),
        make_req("sampling/createMessage"),
    ]
    caps = ["resources", "sampling", "tools"]

    async def _run():
        session = await _get_session(store, _sid("mps020"))
        session.verified_capabilities = caps
        t0 = time.perf_counter()
        for req in reqs:
            result = engine.evaluate(req, session)
        elapsed = (time.perf_counter() - t0) * 1000.0
        await _drain_tasks()
        return result, elapsed, state_size_kb(session)

    last_result, elapsed, kb = asyncio.run(_run())
    single_result = run_singleturn(engine, "mps020-server", reqs, caps)

    record(results_collector, "MT-01", len(reqs), kb,
           elapsed / len(reqs), not single_result.allowed, not last_result.allowed)
    results_collector[-1]["mps_id"] = "MPS-020"
    results_collector[-1]["stage"] = "sequence"


def test_mt02_MPS026_data_staging_via_sampling(engine, store, results_collector):
    reqs = [
        make_req("resources/read", extra_params={"name": "secrets.txt"}),
        make_req("resources/read", extra_params={"name": "secrets.txt"}),
        make_req("resources/read", extra_params={"name": "secrets.txt"}),
        make_req("sampling/createMessage"),
    ]
    caps = ["resources", "sampling", "tools"]

    async def _run():
        session = await _get_session(store, _sid("mps026"))
        session.verified_capabilities = caps
        t0 = time.perf_counter()
        for req in reqs:
            result = engine.evaluate(req, session)
        elapsed = (time.perf_counter() - t0) * 1000.0
        await _drain_tasks()
        return result, elapsed, state_size_kb(session)

    last_result, elapsed, kb = asyncio.run(_run())
    single_result = run_singleturn(engine, "mps026-server", reqs, caps)

    record(results_collector, "MT-02", len(reqs), kb,
           elapsed / len(reqs), not single_result.allowed, not last_result.allowed)
    results_collector[-1]["mps_id"] = "MPS-026"
    results_collector[-1]["stage"] = "sequence"


def test_mt03_MPS027_cascade_attack(engine, store, results_collector):
    reqs = [
        make_req("resources/read", extra_params={"name": "trigger.txt"}),
        make_req("resources/read", extra_params={"name": "trigger.txt"}),
        make_req("sampling/createMessage"),
    ]
    caps = ["resources", "sampling", "tools"]

    async def _run():
        session = await _get_session(store, _sid("mps027"))
        session.verified_capabilities = caps
        t0 = time.perf_counter()
        for req in reqs:
            result = engine.evaluate(req, session)
        elapsed = (time.perf_counter() - t0) * 1000.0
        await _drain_tasks()
        return result, elapsed, state_size_kb(session)

    last_result, elapsed, kb = asyncio.run(_run())
    single_result = run_singleturn(engine, "mps027-server", reqs, caps)

    record(results_collector, "MT-03", len(reqs), kb,
           elapsed / len(reqs), not single_result.allowed, not last_result.allowed)
    results_collector[-1]["mps_id"] = "MPS-027"
    results_collector[-1]["stage"] = "sequence"


def test_mt04_MPS029_cross_session_restart(engine, store, results_collector):
    """MPS-029: simulates a cold gateway restart mid-session.

    Follows the same pattern as every other test: all work happens inside a
    single asyncio.run() scope using the store fixture's DB connection.
    store.clear() + get_or_create() reconstruct the session from SQLite on
    the same event loop that owns the connection — no inner DB or thread needed.
    """
    req_read   = make_req("resources/read", extra_params={"name": "s1.txt"})
    req_sample = make_req("sampling/createMessage")
    caps       = ["resources", "sampling", "tools"]
    sid        = _sid("mps029")  # one ID shared across both phases of this test

    async def _run():
        # Phase 1: seed history (pre-restart)
        s1 = await _get_session(store, sid)
        s1.verified_capabilities = caps
        t0 = time.perf_counter()
        engine.evaluate(req_read, s1)
        engine.evaluate(req_read, s1)
        dt1 = (time.perf_counter() - t0) * 1000.0

        # Drain so SQLite has the rows before wiping in-memory state
        await _drain_tasks()
        store.clear()

        # Phase 2: reconstruct from DB (post-restart) and attempt sampling
        s2 = await _get_session(store, sid)
        s2.verified_capabilities = caps
        assert len(s2.call_history) >= 2, (
            f"DB reconstruction failed: expected >=2 history rows, got {len(s2.call_history)}"
        )
        t0 = time.perf_counter()
        result = engine.evaluate(req_sample, s2)
        dt2 = (time.perf_counter() - t0) * 1000.0

        await _drain_tasks()
        return result, dt1, dt2, state_size_kb(s2)

    last_result, dt1, dt2, kb = asyncio.run(_run())
    single_result = run_singleturn(engine, "mps029-server", [req_read, req_sample], caps)

    record(results_collector, "MT-04", 2, kb, (dt1 + dt2) / 2,
           not single_result.allowed, not last_result.allowed)
    results_collector[-1]["mps_id"] = "MPS-029"
    results_collector[-1]["stage"] = "sequence"


def test_mt05_MPS030_below_window_size(engine, store, results_collector):
    reqs = [make_req("resources/read", extra_params={"name": f"f{i}.txt"}) for i in range(14)]
    reqs.append(make_req("sampling/createMessage"))
    caps = ["resources", "sampling", "tools"]

    async def _run():
        session = await _get_session(store, _sid("mps030"))
        session.verified_capabilities = caps
        t0 = time.perf_counter()
        for req in reqs:
            result = engine.evaluate(req, session)
        elapsed = (time.perf_counter() - t0) * 1000.0
        await _drain_tasks()
        return result, elapsed, state_size_kb(session)

    last_result, elapsed, kb = asyncio.run(_run())
    single_result = run_singleturn(engine, "mps030-server", reqs, caps)

    record(results_collector, "MT-05", len(reqs), kb,
           elapsed / len(reqs), not single_result.allowed, not last_result.allowed)
    results_collector[-1]["mps_id"] = "MPS-030"
    results_collector[-1]["stage"] = "sequence"


def test_mt06_MPS033_rate_limit_probe_maxtokens(engine, store, results_collector):
    reqs = [
        make_req("resources/read"),
        make_req("resources/read"),
        make_req("sampling/createMessage", extra_params={"maxTokens": 32000}),
    ]
    caps = ["resources", "sampling", "tools"]

    async def _run():
        session = await _get_session(store, _sid("mps033"))
        session.verified_capabilities = caps
        t0 = time.perf_counter()
        for req in reqs:
            result = engine.evaluate(req, session)
        elapsed = (time.perf_counter() - t0) * 1000.0
        await _drain_tasks()
        return result, elapsed, state_size_kb(session)

    last_result, elapsed, kb = asyncio.run(_run())
    single_result = run_singleturn(engine, "mps033-server", reqs, caps)

    record(results_collector, "MT-06", len(reqs), kb,
           elapsed / len(reqs), not single_result.allowed, not last_result.allowed)
    results_collector[-1]["mps_id"] = "MPS-033"
    results_collector[-1]["stage"] = "sequence"


def test_mt07_MPS034_sequential_sampling_context_buildup(engine, store, results_collector):
    reqs = [make_req("sampling/createMessage")] * 3
    caps = ["resources", "sampling", "tools"]

    async def _run():
        session = await _get_session(store, _sid("mps034"))
        session.verified_capabilities = caps
        t0 = time.perf_counter()
        for req in reqs:
            result = engine.evaluate(req, session)
        elapsed = (time.perf_counter() - t0) * 1000.0
        await _drain_tasks()
        return result, elapsed, state_size_kb(session)

    last_result, elapsed, kb = asyncio.run(_run())
    single_result = run_singleturn(engine, "mps034-server", reqs, caps)

    record(results_collector, "MT-07", len(reqs), kb,
           elapsed / len(reqs), not single_result.allowed, not last_result.allowed)
    results_collector[-1]["mps_id"] = "MPS-034"
    results_collector[-1]["stage"] = "sequence"


def test_mt08_MPS035_resource_to_sampling_exfiltration(engine, store, results_collector):
    reqs = [
        make_req("resources/read", extra_params={"name": "credentials.txt"}),
        make_req("resources/read", extra_params={"name": "credentials.txt"}),
        make_req("sampling/createMessage"),
    ]
    caps = ["resources", "sampling", "tools"]

    async def _run():
        session = await _get_session(store, _sid("mps035"))
        session.verified_capabilities = caps
        t0 = time.perf_counter()
        for req in reqs:
            result = engine.evaluate(req, session)
        elapsed = (time.perf_counter() - t0) * 1000.0
        await _drain_tasks()
        return result, elapsed, state_size_kb(session)

    last_result, elapsed, kb = asyncio.run(_run())
    single_result = run_singleturn(engine, "mps035-server", reqs, caps)

    record(results_collector, "MT-08", len(reqs), kb,
           elapsed / len(reqs), not single_result.allowed, not last_result.allowed)
    results_collector[-1]["mps_id"] = "MPS-035"
    results_collector[-1]["stage"] = "sequence"


def test_mt09_MPS037_sampling_after_tool_sequence(engine, store, results_collector):
    reqs = [
        make_req("tools/call", "get_data"),
        make_req("tools/call", "format_data"),
        make_req("tools/call", "analyze"),
        make_req("sampling/createMessage"),
    ]
    caps = ["resources", "sampling", "tools"]

    async def _run():
        session = await _get_session(store, _sid("mps037"))
        session.verified_capabilities = caps
        t0 = time.perf_counter()
        for req in reqs:
            result = engine.evaluate(req, session)
        elapsed = (time.perf_counter() - t0) * 1000.0
        await _drain_tasks()
        return result, elapsed, state_size_kb(session)

    last_result, elapsed, kb = asyncio.run(_run())
    single_result = run_singleturn(engine, "mps037-server", reqs, caps)

    record(results_collector, "MT-09", len(reqs), kb,
           elapsed / len(reqs), not single_result.allowed, not last_result.allowed)
    results_collector[-1]["mps_id"] = "MPS-037"
    results_collector[-1]["stage"] = "sequence"


def test_mt10_MPS039_slow_burn_sampling(engine, store, results_collector):
    reqs = [make_req("resources/read", extra_params={"name": f"f{i}.txt"}) for i in range(10)]
    reqs.append(make_req("sampling/createMessage"))
    caps = ["resources", "sampling", "tools"]

    async def _run():
        session = await _get_session(store, _sid("mps039"))
        session.verified_capabilities = caps
        t0 = time.perf_counter()
        for req in reqs:
            result = engine.evaluate(req, session)
        elapsed = (time.perf_counter() - t0) * 1000.0
        await _drain_tasks()
        return result, elapsed, state_size_kb(session)

    last_result, elapsed, kb = asyncio.run(_run())
    single_result = run_singleturn(engine, "mps039-server", reqs, caps)

    record(results_collector, "MT-10", len(reqs), kb,
           elapsed / len(reqs), not single_result.allowed, not last_result.allowed)
    results_collector[-1]["mps_id"] = "MPS-039"
    results_collector[-1]["stage"] = "sequence"