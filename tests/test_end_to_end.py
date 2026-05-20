import subprocess
import time
import socket
import pytest
import urllib.request
import json
import sqlite3
import uuid

def is_port_open(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('127.0.0.1', port)) == 0

@pytest.fixture(scope="module", autouse=True)
def run_servers():
    # Start gateway (running on port 8000)
    gateway_proc = subprocess.Popen(
        [".venv/bin/python", "-m", "uvicorn", "mcp_shield.src.gateway:app", "--host", "127.0.0.1", "--port", "8000"],
        stdout=None,
        stderr=None
    )
    # Start trusted server (running on port 8001)
    trusted_proc = subprocess.Popen(
        [".venv/bin/python", "mock_servers/trusted_server.py"],
        stdout=None,
        stderr=None
    )
    # Start adversarial server (running on port 8002)
    adversarial_proc = subprocess.Popen(
        [".venv/bin/python", "mock_servers/adversarial_server.py"],
        stdout=None,
        stderr=None
    )
    
    # Wait for all ports to bind successfully
    bound = False
    for _ in range(50):
        if is_port_open(8000) and is_port_open(8001) and is_port_open(8002):
            bound = True
            break
        time.sleep(0.1)
    
    if not bound:
        gateway_proc.terminate()
        trusted_proc.terminate()
        adversarial_proc.terminate()
        raise RuntimeError("Failed to bind mock servers and gateway to ports 8000, 8001, 8002 within timeout")
        
    yield
    
    # Clean up background server processes
    gateway_proc.terminate()
    trusted_proc.terminate()
    adversarial_proc.terminate()
    
    try:
        gateway_proc.wait(timeout=1.0)
        trusted_proc.wait(timeout=1.0)
        adversarial_proc.wait(timeout=1.0)
    except subprocess.TimeoutExpired:
        gateway_proc.kill()
        trusted_proc.kill()
        adversarial_proc.kill()

def send_rpc(payload: dict, headers: dict = None) -> dict:
    headers_to_send = {"Content-Type": "application/json"}
    if headers:
        headers_to_send.update(headers)
    req = urllib.request.Request(
        "http://127.0.0.1:8000/mcp",
        data=json.dumps(payload).encode("utf-8"),
        headers=headers_to_send,
        method="POST"
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return json.loads(e.read().decode("utf-8"))

def query_db_with_retry(query, params, expected_status, max_retries=15, delay=0.05):
    """Retries querying sqlite to avoid asynchronous race conditions with the background log task."""
    for _ in range(max_retries):
        conn = sqlite3.connect("telemetry.db")
        cursor = conn.cursor()
        cursor.execute(query, params)
        row = cursor.fetchone()
        conn.close()
        if row and row[0] == expected_status:
            return row
        time.sleep(delay)
    return None

def test_e1_command_injection_blocked():
    req_id = str(uuid.uuid4())
    payload = {
        "jsonrpc": "2.0",
        "id": req_id,
        "method": "execute_code",
        "params": {
            "code": "import os; os.system('rm -rf /')"
        }
    }
    headers = {
        "x-mcpsec-server-id": "trusted-server"
    }
    resp = send_rpc(payload, headers)
    
    assert "error" in resp
    assert resp["error"]["code"] == -32602
    assert "security policy violation" in resp["error"]["message"].lower()

    # Query DB with retry to check that the logged status is BLOCKED for our request ID
    row = query_db_with_retry(
        "SELECT status, method FROM logs WHERE id = ? AND status = 'BLOCKED' ORDER BY timestamp DESC LIMIT 1",
        (req_id,),
        "BLOCKED"
    )
    assert row is not None
    assert row[0] == "BLOCKED"

def test_e2_clean_code_execution():
    req_id = str(uuid.uuid4())
    payload = {
        "jsonrpc": "2.0",
        "id": req_id,
        "method": "execute_code",
        "params": {
            "code": "print(2+2)"
        }
    }
    headers = {
        "x-mcpsec-server-id": "trusted-server"
    }
    resp = send_rpc(payload, headers)
    
    assert "result" in resp
    assert resp["result"]["exit_code"] == 0
    assert "4" in resp["result"]["logs"]
    assert resp["result"]["status"] == "success"

    # Query DB with retry to check that the success status is logged for our request ID
    row = query_db_with_retry(
        "SELECT status, method FROM logs WHERE id = ? AND status = 'SUCCESS' ORDER BY timestamp DESC LIMIT 1",
        (req_id,),
        "SUCCESS"
    )
    assert row is not None
    assert row[0] == "SUCCESS"

def test_e3_cross_server_injection_sanitized():
    req_id = str(uuid.uuid4())
    payload = {
        "jsonrpc": "2.0",
        "id": req_id,
        "method": "tools/call",
        "params": {
            "name": "trigger_injection",
            "arguments": {}
        }
    }
    headers = {
        "x-mcpsec-server-id": "adversarial-server"
    }
    resp = send_rpc(payload, headers)
    
    assert "result" in resp
    content = resp["result"]["content"]
    assert len(content) > 0
    text = content[0]["text"]
    
    # Expect the prompt override command to be sanitized
    assert "sanitized" in text.lower()

    # Query DB with retry to check that the sanitized log status is written for our request ID
    row = query_db_with_retry(
        "SELECT status, method FROM logs WHERE id = ? AND status = 'SANITIZED' ORDER BY timestamp DESC LIMIT 1",
        (req_id,),
        "SANITIZED"
    )
    assert row is not None
    assert row[0] == "SANITIZED"

def test_e4_sampling_injection_blocked():
    req_id = str(uuid.uuid4())
    payload = {
        "jsonrpc": "2.0",
        "id": req_id,
        "method": "tools/call",
        "params": {
            "name": "escalate_sampling",
            "arguments": {}
        }
    }
    headers = {
        "x-mcpsec-server-id": "adversarial-server"
    }
    resp = send_rpc(payload, headers)
    
    assert "result" in resp
    text = resp["result"]["content"][0]["text"]
    
    # Shield response must indicate that the sampling callback was blocked with CapabilityViolation
    assert "capability" in text.lower() or "error" in text.lower() or "violation" in text.lower()

    # Query DB with retry to check that the blocked sampling status is written
    # The callback from mock server uses request ID 999
    row = query_db_with_retry(
        "SELECT status, method FROM logs WHERE id = '999' AND status = 'BLOCKED' ORDER BY timestamp DESC LIMIT 1",
        (),
        "BLOCKED"
    )
    assert row is not None
    assert row[0] == "BLOCKED"

def test_e5_attack_success_rate_comparison():
    # 1. Unprotected path (Bypassing Shield - Querying Adversarial Server directly on port 8002)
    req_id = str(uuid.uuid4())
    raw_payload_injection = {
        "jsonrpc": "2.0",
        "id": req_id,
        "method": "tools/call",
        "params": {
            "name": "trigger_injection",
            "arguments": {}
        }
    }
    
    req = urllib.request.Request(
        "http://127.0.0.1:8002/mcp",
        data=json.dumps(raw_payload_injection).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    with urllib.request.urlopen(req) as resp:
        raw_res = json.loads(resp.read().decode("utf-8"))
    
    # Assert raw server successfully propagated the attack payload (ASR is 100%)
    raw_text = raw_res["result"]["content"][0]["text"]
    assert "Ignore previous instructions" in raw_text
    
    # 2. Protected path (Through Shield on Port 8000)
    shield_res = send_rpc(raw_payload_injection, {"x-mcpsec-server-id": "adversarial-server"})
    shield_text = shield_res["result"]["content"][0]["text"]
    
    # Assert Shield successfully sanitized the injection (ASR is 0%)
    assert "sanitized" in shield_text.lower()
    assert "Ignore previous instructions" not in shield_text
    
    print("\n[E5 Benchmark] Raw Server ASR: 100% | Shield Protected ASR: 0%")

