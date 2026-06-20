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
"""

import os
import sys

# Bootstrap path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from mcp_shield.src.policy import PolicyEngine
from mcp_shield.src.session import SessionState, SessionStore
from mcp_shield.src.schemas import JSONRPCRequest

# The subset of cases involving sequences that can span servers
CASES = [
    ("MPS-026", "Data staging via sampling", 3),
    ("MPS-027", "Cascade attack", 2),
    ("MPS-029", "Cross-session restart", 1),
    ("MPS-030", "Below window size (14-read)", 14),
]

def _req(method: str, params: dict | None = None) -> JSONRPCRequest:
    return JSONRPCRequest(jsonrpc="2.0", id=1, method=method, params=params or {})

def simulate_cross_server_attack(
    engine: PolicyEngine,
    store: SessionStore,
    case_id: str,
    read_count: int,
    condition: str
) -> bool:
    """
    Returns True if BLOCKED, False if MISSED (Attack Success).
    
    In the cross-server variant of these attacks:
    - Server A (compromised) performs the resource reads.
    - Server B (the target/pivoted server) performs the sampling.
    """
    session_id_A = "serverA" if condition == "A" else "global_client_session"
    session_id_B = "serverB" if condition == "A" else "global_client_session"
    
    # For MPS-029, even in Condition B, the session is restarted (cleared)
    if case_id == "MPS-029":
        session_id_B = "serverB_new" if condition == "A" else "global_client_session_new"

    # Stage 1: Server A performs reads
    session_A = store.get_or_create(session_id_A)
    session_A.verified_capabilities = ["resources", "sampling", "tools"]
    
    for _ in range(read_count):
        req_read = _req("resources/read", {"name": "data.txt"})
        # We manually set server_id on the session for accuracy, though unified 
        # tracking relies on the shared history list.
        if condition == "B":
            session_A.server_id = "serverA"
        engine.evaluate(req_read, session_A)

    # Stage 2: Server B attempts sampling (the payload/exfil)
    session_B = store.get_or_create(session_id_B)
    session_B.verified_capabilities = ["resources", "sampling", "tools"]
    
    req_sample = _req("sampling/createMessage", {})
    if condition == "B":
        session_B.server_id = "serverB"
        
    result = engine.evaluate(req_sample, session_B)
    
    return not result.allowed


def run_ablation():
    engine = PolicyEngine("config/shield_config.json")
    results = {}
    
    for case_id, desc, read_count in CASES:
        # Condition A: Isolated
        store_A = SessionStore()
        blocked_A = simulate_cross_server_attack(engine, store_A, case_id, read_count, "A")
        
        # Condition B: Unified
        store_B = SessionStore()
        blocked_B = simulate_cross_server_attack(engine, store_B, case_id, read_count, "B")
        
        results[case_id] = {
            "desc": desc,
            "A": blocked_A,
            "B": blocked_B
        }
        
    return results


def print_results(results: dict):
    print("\n" + "=" * 80)
    print(" CROSS-SERVER ATTACK ABLATION: ISOLATED VS. UNIFIED SESSION TRACKING")
    print("=" * 80)
    print(f"{'Case ID':<10} {'Description':<35} {'Cond A (Isolated)':<20} {'Cond B (Unified)':<20}")
    print("-" * 80)
    
    total = len(results)
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
    
    print(f"{'Attack Success Rate (ASR)':<46} {asr_A:.1f}%               {asr_B:.1f}%")
    print(f"{'Detection Rate':<46} {blocked_A_count/total*100:.1f}%                 {blocked_B_count/total*100:.1f}%")
    print("=" * 80 + "\n")
    print("  Condition A: Session history is siloed per server (current default behavior)")
    print("  Condition B: Session history is aggregated per client across all servers")
    print()


# ── pytest integration ────────────────────────────────────────────────────────

import pytest

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
    
def test_mps029_cross_session_restart_missed_both(ablation_results):
    assert not ablation_results["MPS-029"]["A"], "Condition A should MISS MPS-029"
    assert not ablation_results["MPS-029"]["B"], "Condition B should MISS MPS-029"

def test_print_ablation_results(ablation_results):
    print_results(ablation_results)


if __name__ == "__main__":
    res = run_ablation()
    print_results(res)
