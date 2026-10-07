import sys
import os

# Allow tests to import mcp_shield and benchmark from the project root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

"""
Confusion-matrix reporter for the option benchmarks.

Mapping (label comes from the case number, never from the engine):
  MPS-001..100  attack  -> test passed/xpassed = detected (TP), else FN
  MPS-101..     benign  -> test passed/xpassed = allowed (TN),  else FP
A test's pass/fail is exactly "did the engine do the right thing",
so xfail/xpass markers don't change the mapping.
"""
import re
from collections import Counter

from benchmark.test_synthetic_benchmark import MULTI_TURN_ATTACK_IDS, MULTI_TURN_BENIGN_IDS

SEQUENCE_ATTACKS = set(MULTI_TURN_ATTACK_IDS)
SEQUENCE_BENIGN = set(MULTI_TURN_BENIGN_IDS)
_results = {}
_ID = re.compile(r"test_MPS(\d{3})")


def pytest_runtest_logreport(report):
    m = _ID.search(report.nodeid)
    if not m:
        return
    n = int(m.group(1))
    if report.when == "call" or (report.when == "setup" and report.failed):
        ok = report.passed  # xpass reports as passed; xfail as skipped; real fail as failed
        _results[n] = ok


def _matrix(ids):
    c = Counter()
    for n in ids:
        if n not in _results:
            continue
        ok = _results[n]
        if n <= 100:
            c["TP" if ok else "FN"] += 1
        else:
            c["TN" if ok else "FP"] += 1
    return c


def _misses(ids, want):
    out = []
    for n in sorted(ids):
        if n in _results and not _results[n]:
            out.append(f"MPS{n:03d}")
    return out


def pytest_terminal_summary(terminalreporter):
    if not _results:
        return
    w = terminalreporter.write_line
    full = _matrix(_results)
    seq_ids = SEQUENCE_ATTACKS | SEQUENCE_BENIGN
    seq = _matrix(seq_ids)
    w("")
    w("=" * 64)
    w("  CONFUSION MATRIX")
    w(f"  Full suite ({sum(full.values())} cases): TP {full['TP']}  FP {full['FP']}  TN {full['TN']}  FN {full['FN']}")
    w(f"  Multi-turn suite ({sum(seq.values())} cases): TP {seq['TP']}  FP {seq['FP']}  TN {seq['TN']}  FN {seq['FN']}")
    w(f"  Multi-turn FNs: {', '.join(_misses(SEQUENCE_ATTACKS, 'TP')) or 'none'}")
    w(f"  Multi-turn FPs: {', '.join(_misses(SEQUENCE_BENIGN, 'TN')) or 'none'}")
    w("=" * 64)