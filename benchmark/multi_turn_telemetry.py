"""
TABLE IV — stateful telemetry and operational overhead for multi-turn attacks.

Scenarios are NOT defined here: each row runs the corresponding attack test
from test_synthetic_benchmark.py (MULTI_TURN_ATTACK_IDS) through a recording
wrapper around the engine, which captures every request, its evaluation time,
and the session it ran in.

  Turns        number of requests and tool outputs the test processed
  State (KB)   size of the final session's call history
  Avg Δt (ms)  mean engine.evaluate() time per request
  Single-turn  the same requests replayed one at a time on fresh sessions
               (no state carried over): blocked if the last one is blocked
  Multi-turn   blocked if the benchmark test passed (attack detected)

MCP_SHIELD_ENGINE=1 (default, stock PolicyEngine), 2, 3 or 4 selects the engine.
"""

import asyncio
import inspect
import json
import os
import re
import sys
import time
import uuid

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from mcp_shield.src.policy import PolicyEngine
from mcp_shield.src.session import SessionState
from mcp_shield.src.schemas import PolicyResult
import benchmark.test_synthetic_benchmark as bench


def _engine_class():
    choice = os.environ.get("MCP_SHIELD_ENGINE", "1").strip().lower().replace("option", "")
    if choice in ("", "1", "baseline"):
        return PolicyEngine
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "option_implementations"))
    import sequence_options as so
    classes = {"2": so.PolicyEngineOption2, "3": so.PolicyEngineOption3, "4": so.PolicyEngineOption4}
    if choice not in classes:
        raise ValueError(f"MCP_SHIELD_ENGINE must be 1-4, got {choice!r}")
    return classes[choice]


ENGINE_CLASS = _engine_class()


class RecordingEngine:
    """Pass-through engine that records (request, session, result, ms) per evaluate()."""

    def __init__(self, inner):
        self._inner = inner
        self.calls = []

    def evaluate(self, request, session_state, *args, **kwargs):
        t0 = time.perf_counter()
        result = self._inner.evaluate(request, session_state, *args, **kwargs)
        self.calls.append((request, session_state, result, (time.perf_counter() - t0) * 1000.0))
        return result

    def sanitize_output(self, text):
        """Tool outputs are turns too (MPS-010, MPS-028): record them as ("output", text)."""
        t0 = time.perf_counter()
        sanitized, flagged = self._inner.sanitize_output(text)
        result = PolicyResult(allowed=not flagged, reason="output sanitizer", stage="sanitizer")
        self.calls.append((("output", text), None, result, (time.perf_counter() - t0) * 1000.0))
        return sanitized, flagged

    def __getattr__(self, name):
        return getattr(self._inner, name)


def _find_test(mps: int):
    for cls_name, cls in inspect.getmembers(bench, inspect.isclass):
        if cls_name.startswith("Test"):
            for name, _ in inspect.getmembers(cls, inspect.isfunction):
                if re.match(rf"test_MPS{mps:03d}_", name):
                    return cls, name
    raise LookupError(f"MPS-{mps:03d} not found in test_synthetic_benchmark.py")


def _run_recorded(engine, mps: int):
    """Runs the benchmark test for mps with a RecordingEngine. Returns (recorder, passed)."""
    cls, name = _find_test(mps)
    rec = RecordingEngine(engine)
    method = getattr(cls(), name)
    kwargs = {"engine": rec}
    db = db_path = None
    if "store" in inspect.signature(method).parameters:
        db_path = f"telemetry_{mps}_{uuid.uuid4().hex[:8]}.db"
        store, db = asyncio.run(bench._make_db_store_async(db_path))
        kwargs["store"] = store
    try:
        method(**kwargs)
        passed = True
    except AssertionError:
        passed = False
    finally:
        if db is not None:
            async def _close():
                await bench._drain_tasks()
                await db.close()
            asyncio.run(_close())
            if os.path.exists(db_path):
                os.remove(db_path)
    return rec, passed


def _single_turn_blocked(engine, calls) -> bool:
    """Replays each recorded request on a fresh session (no carried state)."""
    blocked = False
    for request, session, _, _ in calls:
        if isinstance(request, tuple) and request[0] == "output":
            blocked = engine.sanitize_output(request[1])[1]   # stateless either way
            continue
        fresh = SessionState(server_id=session.server_id)
        fresh.verified_capabilities = list(session.verified_capabilities)
        blocked = not engine.evaluate(request, fresh).allowed
    return blocked


@pytest.fixture(scope="module")
def engine():
    return ENGINE_CLASS()


@pytest.fixture(scope="module")
def results_collector():
    rows = []
    yield rows
    print("\n\n" + "=" * 95)
    print(f"TABLE IV — STATEFUL TELEMETRY AND OPERATIONAL OVERHEAD FOR MULTI-TURN ATTACK SEQUENCES ({ENGINE_CLASS.__name__})")
    print("=" * 95)
    print(f"{'Case ID':<8} {'MPS ID':<10} {'Turns':>6} {'State (KB)':>11} {'Avg Δt (ms)':>12} "
          f"{'Single-turn':<14} {'Multi-turn':<12} {'Stage'}")
    print("-" * 95)
    for r in sorted(rows, key=lambda r: r["idx"]):
        st = "blocked" if r["single_blocked"] else "missed"
        mt = "blocked" if r["multi_blocked"] else "missed"
        print(f"MT-{r['idx']:02d}    MPS-{r['mps']:03d}    {r['turns']:>6} {r['state_kb']:>11.3f} "
              f"{r['avg_dt']:>12.3f} {st:<14} {mt:<14} {r['stage']}")
    print("=" * 95 + "\n")


@pytest.mark.parametrize("idx,mps", list(enumerate(bench.MULTI_TURN_ATTACK_IDS, start=1)),
                         ids=[f"MPS{m:03d}" for m in bench.MULTI_TURN_ATTACK_IDS])
def test_multi_turn_telemetry(engine, results_collector, idx, mps):
    rec, passed = _run_recorded(engine, mps)
    calls = rec.calls
    last_session = next(c[1] for c in reversed(calls) if c[1] is not None)
    blocked = [c for c in calls if not c[2].allowed]
    results_collector.append({
        "idx": idx,
        "mps": mps,
        "turns": len(calls),
        "state_kb": round(len(json.dumps(last_session.call_history).encode()) / 1024, 3),
        "avg_dt": sum(c[3] for c in calls) / len(calls),
        "single_blocked": _single_turn_blocked(engine, calls),
        "multi_blocked": passed,
        "stage": blocked[-1][2].stage if blocked else "-",
    })