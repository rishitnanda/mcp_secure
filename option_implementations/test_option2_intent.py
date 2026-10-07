"""
Option 2 cannot be measured on the 150-case benchmark: none of its cases carry
an intent attestation, so Option 2 behaves exactly like Option 1-fixed there.

These cases test what Option 2 actually claims: an attested user request is
released, and anything outside the attested scope is still blocked, even
inside an attested session.
"""
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..")))
sys.path.insert(0, HERE)

from mcp_shield.src.schemas import JSONRPCRequest
from mcp_shield.src.session import SessionState
from sequence_options import PolicyEngineOption2, mint_intent_token

KEY = "test-host-intent-key"
CAPS = ["resources", "sampling", "tools"]


@pytest.fixture
def engine(monkeypatch):
    monkeypatch.setenv("MCP_HOST_INTENT_KEY", KEY)
    return PolicyEngineOption2()


def _req(method, params=None):
    return JSONRPCRequest(jsonrpc="2.0", id=1, method=method, params=params or {})


def _session(sid, token=None):
    s = SessionState(server_id=sid)
    s.verified_capabilities = CAPS
    if token:
        s.intent_attestation = token
    return s


def _summary_flow(engine, s, a="file:///docs/api_v1.md", b="file:///docs/api_v2.md"):
    engine.evaluate(_req("resources/read", {"uri": a}), s)
    engine.evaluate(_req("resources/read", {"uri": b}), s)
    return engine.evaluate(_req("sampling/createMessage", {}), s)


def test_attested_summary_is_allowed(engine):
    tok = mint_intent_token(KEY, "sess-a", ["/docs/*"], [], sampling=True)
    assert _summary_flow(engine, _session("sess-a", tok)).allowed


def test_no_attestation_is_blocked(engine):
    r = _summary_flow(engine, _session("sess-b"))
    assert not r.allowed and "no intent attestation" in r.reason


def test_read_outside_scope_is_blocked(engine):
    """User asked to compare docs; an injected instruction reads an SSH key."""
    tok = mint_intent_token(KEY, "sess-c", ["/docs/*"], [], sampling=True)
    r = _summary_flow(engine, _session("sess-c", tok), b="file:///~/.ssh/id_rsa")
    assert not r.allowed and "outside attested scope" in r.reason


def test_encoded_traversal_out_of_scope_is_blocked(engine):
    tok = mint_intent_token(KEY, "sess-d", ["/docs/*"], [], sampling=True)
    r = _summary_flow(engine, _session("sess-d", tok), b="file:///docs/%2e%2e/etc/passwd")
    assert not r.allowed


def test_forged_signature_is_blocked(engine):
    tok = mint_intent_token("attacker-key", "sess-e", ["/**"], [], sampling=True)
    r = _summary_flow(engine, _session("sess-e", tok))
    assert not r.allowed and "bad signature" in r.reason


def test_expired_token_is_blocked(engine):
    tok = mint_intent_token(KEY, "sess-f", ["/docs/*"], [], sampling=True, ttl=-1)
    r = _summary_flow(engine, _session("sess-f", tok))
    assert not r.allowed and "expired" in r.reason


def test_token_replayed_on_other_session_is_blocked(engine):
    tok = mint_intent_token(KEY, "sess-g", ["/docs/*"], [], sampling=True)
    r = _summary_flow(engine, _session("sess-other", tok))
    assert not r.allowed and "different session" in r.reason


def test_sampling_not_attested_is_blocked(engine):
    tok = mint_intent_token(KEY, "sess-h", ["/docs/*"], [], sampling=False)
    r = _summary_flow(engine, _session("sess-h", tok))
    assert not r.allowed and "sampling not attested" in r.reason


def test_unattested_tool_in_pipeline_is_blocked(engine):
    tok = mint_intent_token(KEY, "sess-i", [], ["get_data", "format_data"], sampling=True)
    s = _session("sess-i", tok)
    for t in ("get_data", "format_data", "analyze"):
        engine.evaluate(_req("tools/call", {"name": t, "arguments": {}}), s)
    r = engine.evaluate(_req("sampling/createMessage", {}), s)
    assert not r.allowed and "'analyze' not attested" in r.reason