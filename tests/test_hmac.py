import time
import hmac
import hashlib
import pytest
from mcp_shield.src.policy import PolicyEngine, ConnectionState
from mcp_shield.src.schemas import JSONRPCRequest, MCPSecHeader

@pytest.fixture
def hmac_policy_engine(monkeypatch):
    monkeypatch.setenv("MCP_KEY_FILESYSTEM", "mysecretkeyfilesystem")
    engine = PolicyEngine()
    return engine

def test_hmac_valid_passes(hmac_policy_engine):
    conn = ConnectionState(server_id="filesystem-server")
    req = JSONRPCRequest(
        jsonrpc="2.0",
        id=1,
        method="tools/call",
        params={"name": "read_file", "arguments": {}}
    )
    body_bytes = req.model_dump_json().encode("utf-8")
    
    timestamp = time.time()
    nonce = "nonce_val_1"
    
    msg = f"{timestamp}:{nonce}:".encode("utf-8") + body_bytes
    sig = hmac.new(b"mysecretkeyfilesystem", msg, hashlib.sha256).hexdigest()
    
    sec_header = MCPSecHeader(
        server_id="filesystem-server",
        timestamp=timestamp,
        nonce=nonce,
        hmac=sig
    )
    
    result = hmac_policy_engine.evaluate(req, conn, body_bytes=body_bytes, sec_header=sec_header)
    assert result.allowed is True

def test_hmac_invalid_signature_blocked(hmac_policy_engine):
    conn = ConnectionState(server_id="filesystem-server")
    req = JSONRPCRequest(
        jsonrpc="2.0",
        id=1,
        method="tools/call",
        params={"name": "read_file", "arguments": {}}
    )
    body_bytes = req.model_dump_json().encode("utf-8")
    
    timestamp = time.time()
    nonce = "nonce_val_2"
    sig = "wronghmacsignature"
    
    sec_header = MCPSecHeader(
        server_id="filesystem-server",
        timestamp=timestamp,
        nonce=nonce,
        hmac=sig
    )
    
    result = hmac_policy_engine.evaluate(req, conn, body_bytes=body_bytes, sec_header=sec_header)
    assert result.allowed is False
    assert result.stage == "hmac"
    assert "signature mismatch" in result.reason

def test_hmac_replay_blocked(hmac_policy_engine):
    conn = ConnectionState(server_id="filesystem-server")
    req = JSONRPCRequest(
        jsonrpc="2.0",
        id=1,
        method="tools/call",
        params={"name": "read_file", "arguments": {}}
    )
    body_bytes = req.model_dump_json().encode("utf-8")
    
    timestamp = time.time()
    nonce = "nonce_replay"
    
    msg = f"{timestamp}:{nonce}:".encode("utf-8") + body_bytes
    sig = hmac.new(b"mysecretkeyfilesystem", msg, hashlib.sha256).hexdigest()
    
    sec_header = MCPSecHeader(
        server_id="filesystem-server",
        timestamp=timestamp,
        nonce=nonce,
        hmac=sig
    )
    
    # First execution succeeds
    result1 = hmac_policy_engine.evaluate(req, conn, body_bytes=body_bytes, sec_header=sec_header)
    assert result1.allowed is True
    
    # Replay attempt fails
    result2 = hmac_policy_engine.evaluate(req, conn, body_bytes=body_bytes, sec_header=sec_header)
    assert result2.allowed is False
    assert result2.stage == "hmac"
    assert "nonce replay" in result2.reason

def test_hmac_outdated_timestamp_blocked(hmac_policy_engine):
    conn = ConnectionState(server_id="filesystem-server")
    req = JSONRPCRequest(
        jsonrpc="2.0",
        id=1,
        method="tools/call",
        params={"name": "read_file", "arguments": {}}
    )
    body_bytes = req.model_dump_json().encode("utf-8")
    
    timestamp = time.time() - 40.0 # Older than 30 seconds
    nonce = "nonce_old"
    
    msg = f"{timestamp}:{nonce}:".encode("utf-8") + body_bytes
    sig = hmac.new(b"mysecretkeyfilesystem", msg, hashlib.sha256).hexdigest()
    
    sec_header = MCPSecHeader(
        server_id="filesystem-server",
        timestamp=timestamp,
        nonce=nonce,
        hmac=sig
    )
    
    result = hmac_policy_engine.evaluate(req, conn, body_bytes=body_bytes, sec_header=sec_header)
    assert result.allowed is False
    assert result.stage == "hmac"
    assert "nonce replay or timestamp expired" in result.reason
