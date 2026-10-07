"""
Multi-turn detection and false-positive rates vs. sequence-rule window size.

Replaces multi_turn_window_size.py and false_positives_multi_turn.py. Scenarios
are NOT defined here: every case is the corresponding test in
test_synthetic_benchmark.py (MULTI_TURN_ATTACK_IDS + MULTI_TURN_BENIGN_IDS),
run once per window size against an engine whose pattern rules use that window.

  attack test passes  -> TP (blocked)      attack test fails  -> FN (missed)
  benign test passes  -> TN (allowed)      benign test fails  -> FP (wrongly blocked)
  state check passes  -> PASS              state check fails  -> FAIL
Cases come from MULTI_TURN_ATTACK_IDS, MULTI_TURN_BENIGN_IDS and MULTI_TURN_STATE_IDS.

MCP_SHIELD_ENGINE=1 (default, stock PolicyEngine), 2, 3 or 4 selects the
multi-turn option from option_implementations/sequence_options.py.
"""

import asyncio
import copy
import inspect
import json
import os
import re
import sys
import uuid

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from mcp_shield.src.policy import PolicyEngine
import benchmark.test_synthetic_benchmark as bench

WINDOW_SIZES = [2, 3, 4, 5, 7, 10]
CONFIG_PATH = "config/shield_config.json"


# ── Engine selection ──────────────────────────────────────────────────────────

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


def _make_engine(base_config: dict, window: int):
    """Engine of ENGINE_CLASS whose pattern rules all use the given window."""
    cfg = copy.deepcopy(base_config)
    seq = cfg.get("sequence_policy", {})
    for rule in seq.get("default", []):
        if "pattern" in rule:
            rule["window"] = window
    for rules in seq.get("servers", {}).values():
        for rule in rules:
            if "pattern" in rule:
                rule["window"] = window

    engine = ENGINE_CLASS.__new__(ENGINE_CLASS)
    engine.config_path = CONFIG_PATH
    engine.nonce_window = PolicyEngine(CONFIG_PATH).nonce_window
    engine.config = cfg
    engine.load_config = lambda: None

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


# ── Locate the benchmark tests ────────────────────────────────────────────────

def _benchmark_tests() -> dict:
    """MPS number -> (test class, method name, description) for every benchmark test."""
    found = {}
    for cls_name, cls in inspect.getmembers(bench, inspect.isclass):
        if not cls_name.startswith("Test"):
            continue
        for name, fn in inspect.getmembers(cls, inspect.isfunction):
            m = re.match(r"test_MPS(\d{3})_", name)
            if m:
                doc = (inspect.getdoc(fn) or name).split("\n")[0]
                desc = doc.split(":", 1)[-1].strip() if ":" in doc else doc
                found[int(m.group(1))] = (cls, name, desc)
    return found


TESTS = _benchmark_tests()
CASES = ([("attack", n) for n in bench.MULTI_TURN_ATTACK_IDS]
         + [("benign", n) for n in bench.MULTI_TURN_BENIGN_IDS]
         + [("state", n) for n in bench.MULTI_TURN_STATE_IDS])


def _run_case(engine, mps: int) -> bool:
    """Runs one benchmark test body. Returns True if the test passed."""
    cls, name, _ = TESTS[mps]
    method = getattr(cls(), name)
    kwargs = {"engine": engine}
    db = db_path = None
    if "store" in inspect.signature(method).parameters:
        db_path = f"window_sweep_{mps}_{uuid.uuid4().hex[:8]}.db"
        store, db = asyncio.run(bench._make_db_store_async(db_path))
        kwargs["store"] = store
    try:
        method(**kwargs)
        return True
    except AssertionError:
        return False
    finally:
        if db is not None:
            async def _close():
                await bench._drain_tasks()
                await db.close()
            asyncio.run(_close())
            if os.path.exists(db_path):
                os.remove(db_path)


def run_sweep(base_config: dict) -> dict:
    """results[mps][window] = True if the engine did the right thing."""
    results = {n: {} for _, n in CASES}
    for window in WINDOW_SIZES:
        engine = _make_engine(base_config, window)
        for _, n in CASES:
            results[n][window] = _run_case(engine, n)
    return results


# ── Report ────────────────────────────────────────────────────────────────────

def _short(text: str, width: int) -> str:
    """Trims a description at a word boundary (and before any em-dash note)."""
    text = text.split(" — ")[0].rstrip(" .")
    if len(text) <= width:
        return text
    cut = text[: width - 3].rsplit(" ", 1)[0]
    return cut + "..."


def print_table(results: dict) -> None:
    col_w, id_w, desc_w = 9, 9, 50
    header = "".join(f"  {'w=%d' % w:<{col_w - 2}}" for w in WINDOW_SIZES)
    total_w = id_w + desc_w + 8 + len(header)
    print()
    print("=" * total_w)
    print(f"  MULTI-TURN SUITE vs. SEQUENCE-RULE WINDOW SIZE — engine: {ENGINE_CLASS.__name__}")
    print("=" * total_w)
    print(f"{'Case':<{id_w}} {'Label':<7} {'Description':<{desc_w}}" + header)
    print("-" * total_w)
    for label, n in CASES:
        desc = _short(TESTS[n][2], desc_w)
        row = f"{'MPS-%03d' % n:<{id_w}} {label:<7} {desc:<{desc_w}}"
        for w in WINDOW_SIZES:
            ok = results[n][w]
            cell = {"attack": ("TP", "FN"), "benign": ("TN", "FP"),
                    "state": ("PASS", "FAIL")}[label][0 if ok else 1]
            row += f"  {cell:<{col_w - 2}}"
        print(row)
    print("-" * total_w)
    attacks = [n for label, n in CASES if label == "attack"]
    benign = [n for label, n in CASES if label == "benign"]
    prefix_w = id_w + 1 + 7 + 1 + desc_w
    det = f"{'Detection rate (attacks)':<{prefix_w}}"
    fpr = f"{'False-positive rate (benign)':<{prefix_w}}"
    for w in WINDOW_SIZES:
        d = sum(results[n][w] for n in attacks) / len(attacks) * 100
        f = sum(not results[n][w] for n in benign) / len(benign) * 100
        det += f"  {f'{d:.2f}%':<{col_w - 2}}"
        fpr += f"  {f'{f:.2f}%':<{col_w - 2}}"
    print(det)
    print(fpr)
    print("=" * total_w)
    state = [n for label, n in CASES if label == "state"]
    print(f"  {len(attacks)} attacks + {len(benign)} benign workflows + {len(state)} state check(s), "
          f"all defined in test_synthetic_benchmark.py")
    print("  Attack rows:  TP = blocked (correct)   FN = missed")
    print("  Benign rows:  TN = allowed (correct)   FP = wrongly blocked")
    print("  State row:    PASS = session history survived a store wipe")
    print()


# ── pytest integration ────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def base_config():
    with open(CONFIG_PATH) as f:
        return json.load(f)


@pytest.fixture(scope="module")
def sweep_results(base_config):
    return run_sweep(base_config)


def test_print_window_sweep(sweep_results):
    """Prints the full matrix. Run with -s to see output."""
    print_table(sweep_results)


if __name__ == "__main__":
    with open(CONFIG_PATH) as f:
        cfg = json.load(f)
    print_table(run_sweep(cfg))