import pytest
import time
import json
import os
from mcp_shield.src.policy import PolicyEngine
from mcp_shield.src.session import SessionStore
from mcp_shield.src.schemas import JSONRPCRequest

@pytest.fixture
def policy_engine():
    return PolicyEngine()

@pytest.fixture
def session_store():
    return SessionStore()

@pytest.fixture
def short_ttl_config(tmp_path, monkeypatch):
    """Fixture that creates a temporary config with a 1-second session TTL."""
    config_data = {
        "session_policy": {
            "session_timeout_seconds": 1,
            "max_calls_per_session": 100
        },
        "sequence_policy": {
            "default": [],
            "servers": {}
        }
    }
    config_file = tmp_path / "test_config.json"
    config_file.write_text(json.dumps(config_data))

    engine = PolicyEngine(config_path=str(config_file))
    store = SessionStore(timeout_seconds=1)
    return engine, store

@pytest.mark.asyncio
async def test_session_state_persists_across_calls(policy_engine, session_store):
    """Test 1: Session state persists across sequential calls from same server."""
    req1 = JSONRPCRequest(jsonrpc="2.0", id=1, method="resources/read", params={"name": "file1.txt"})
    req2 = JSONRPCRequest(jsonrpc="2.0", id=2, method="resources/read", params={"name": "file2.txt"})

    session = await session_store.get_or_create("test-server")
    session.verified_capabilities = ["resources", "sampling", "tools"]

    res1 = policy_engine.evaluate(req1, session)
    assert res1.allowed is True

    res2 = policy_engine.evaluate(req2, session)
    assert res2.allowed is True

    assert len(session.call_history) == 2
    assert session.call_history[0]["method"] == "resources/read"
    assert session.call_history[1]["method"] == "resources/read"

@pytest.mark.asyncio
async def test_clean_calls_blocked_as_malicious_sequence(policy_engine, session_store):
    """Test 2: Clean individual calls that form a malicious sequence are blocked."""
    # The default config has a rule: resources/read x2 -> sampling/createMessage
    req_read = JSONRPCRequest(jsonrpc="2.0", id=1, method="resources/read", params={"name": "file.txt"})
    req_sample = JSONRPCRequest(jsonrpc="2.0", id=2, method="sampling/createMessage", params={})

    session = await session_store.get_or_create("test-server")
    session.verified_capabilities = ["resources", "sampling", "tools"]

    # First two reads should pass
    assert policy_engine.evaluate(req_read, session).allowed is True
    assert policy_engine.evaluate(req_read, session).allowed is True

    # The sampling request completes the malicious sequence pattern
    res = policy_engine.evaluate(req_sample, session)
    assert res.allowed is False
    assert res.stage == "sequence"

@pytest.mark.asyncio
async def test_session_expires_correctly(short_ttl_config):
    """Test 3: Session expires correctly according to TTL."""
    engine, store = short_ttl_config

    req = JSONRPCRequest(jsonrpc="2.0", id=1, method="ping")

    # First request
    session1 = await store.get_or_create("test-server")
    session1.verified_capabilities = ["resources", "sampling", "tools"]
    engine.evaluate(req, session1)
    assert len(session1.call_history) == 1

    # Wait for TTL to expire
    time.sleep(1.1)

    # Second request should get a fresh session
    session2 = await store.get_or_create("test-server")
    session2.verified_capabilities = ["resources", "sampling", "tools"]
    assert session1 is not session2
    assert len(session2.call_history) == 0
    engine.evaluate(req, session2)
    assert len(session2.call_history) == 1

@pytest.mark.asyncio
async def test_different_servers_get_different_sessions(policy_engine, session_store):
    """Test 4: Different servers get different sessions."""
    req1 = JSONRPCRequest(jsonrpc="2.0", id=1, method="ping")
    req2 = JSONRPCRequest(jsonrpc="2.0", id=2, method="ping")

    session_fs = await session_store.get_or_create("filesystem-server")
    session_fs.verified_capabilities = ["resources", "sampling", "tools"]
    policy_engine.evaluate(req1, session_fs)

    session_ts = await session_store.get_or_create("trusted-server")
    session_ts.verified_capabilities = ["resources", "sampling", "tools"]
    policy_engine.evaluate(req2, session_ts)

    assert len(session_fs.call_history) == 1
    assert len(session_ts.call_history) == 1
    assert session_fs is not session_ts

@pytest.mark.asyncio
async def test_multi_turn_indirect_injection_chain(tmp_path):
    """Test 5: Multi-turn indirect injection chain using custom sequence rule."""
    config_data = {
        "sequence_policy": {
            "default": [
                {
                    "name": "injection_context_buildup",
                    "description": "3 tool calls then a sampling request",
                    "pattern": ["tools/call:get_data", "tools/call:format_data", "tools/call:analyze", "sampling/createMessage"],
                    "window": 4,
                    "action": "block"
                }
            ],
            "servers": {}
        }
    }
    config_file = tmp_path / "test_config.json"
    config_file.write_text(json.dumps(config_data))

    engine = PolicyEngine(config_path=str(config_file))
    store = SessionStore()

    req1 = JSONRPCRequest(jsonrpc="2.0", id=1, method="tools/call", params={"name": "get_data"})
    req2 = JSONRPCRequest(jsonrpc="2.0", id=2, method="tools/call", params={"name": "format_data"})
    req3 = JSONRPCRequest(jsonrpc="2.0", id=3, method="tools/call", params={"name": "analyze"})
    req4 = JSONRPCRequest(jsonrpc="2.0", id=4, method="sampling/createMessage", params={})

    session = await store.get_or_create("test-server")
    session.verified_capabilities = ["resources", "sampling", "tools"]

    # First 3 tool calls are clean individually
    assert engine.evaluate(req1, session).allowed is True
    assert engine.evaluate(req2, session).allowed is True
    assert engine.evaluate(req3, session).allowed is True

    # 4th call matches the multi-turn buildup pattern
    res = engine.evaluate(req4, session)
    assert res.allowed is False
    assert res.stage == "sequence"
    assert res.reason == "injection_context_buildup"