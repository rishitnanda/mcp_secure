import time
import pytest
import os
import tempfile
from mcp_shield.src.policy import PolicyEngine, ConnectionState
from mcp_shield.src.schemas import JSONRPCRequest, CapabilityCert
from mcp_shield.src.exceptions import CapabilityViolationException

@pytest.fixture
def temp_ca_cert_file(ca_cert_bytes, monkeypatch):
    fd, path = tempfile.mkstemp(suffix=".pem")
    os.write(fd, ca_cert_bytes)
    os.close(fd)
    monkeypatch.setenv("MCP_CA_CERT", path)
    yield path
    try:
        os.unlink(path)
    except OSError:
        pass

@pytest.fixture
def policy_engine(temp_ca_cert_file):
    return PolicyEngine()

def test_attestation_valid_cert_passes(policy_engine, filesystem_server_cert_bytes):
    # Construct cert JSON
    cert_json = {
        "server_id": "filesystem-server",
        "capabilities": ["resources/list", "tools/call"],
        "issued_by": "platform-ca",
        "issued_at": time.time() - 3600.0,
        "expires_at": time.time() + 3600.0,
        "cert_pem": filesystem_server_cert_bytes.decode("utf-8")
    }
    
    success, reason = policy_engine.verify_capability_cert(cert_json)
    assert success is True
    assert "attestation" in reason.lower()

def test_attestation_expired_cert_fails(policy_engine, adversarial_server_cert_bytes):
    # The certificate itself is signed by CA but is expired
    cert_json = {
        "server_id": "adversarial-server",
        "capabilities": ["tools/call"],
        "issued_by": "platform-ca",
        "issued_at": time.time() - 7200.0,
        "expires_at": time.time() - 3600.0, # Expired model timestamp
        "cert_pem": adversarial_server_cert_bytes.decode("utf-8")
    }
    
    success, reason = policy_engine.verify_capability_cert(cert_json)
    assert success is False
    assert "expired" in reason.lower() or "timeframe" in reason.lower()

def test_attestation_wrong_server_id_fails(policy_engine, filesystem_server_cert_bytes):
    # Certificate was generated for filesystem-server, but model server_id is wrong
    cert_json = {
        "server_id": "hacked-server",
        "capabilities": ["resources/list", "tools/call"],
        "issued_by": "platform-ca",
        "issued_at": time.time() - 3600.0,
        "expires_at": time.time() + 3600.0,
        "cert_pem": filesystem_server_cert_bytes.decode("utf-8")
    }
    
    success, reason = policy_engine.verify_capability_cert(cert_json)
    assert success is False
    assert "CN/SAN does not match" in reason or "identity does not match" in reason

def test_attestation_evaluate_checks_attested_capabilities(policy_engine, filesystem_server_cert_bytes):
    conn = ConnectionState(server_id="filesystem-server")
    # Verify that request is blocked before certificate attestation
    req = JSONRPCRequest(
        jsonrpc="2.0",
        id=1,
        method="tools/call",
        params={"name": "read_file", "arguments": {}}
    )
    result = policy_engine.evaluate(req, conn)
    # Because filesystem-server is defined in servers config, it has allowed fallback tools.
    # But let's check a server that is NOT in servers config and has no cert:
    conn_untrusted = ConnectionState(server_id="untrusted-server")
    result_untrusted = policy_engine.evaluate(req, conn_untrusted)
    assert result_untrusted.allowed is False
    assert result_untrusted.stage == "attestation"

    # Now let's simulate successful attestation
    conn_untrusted.verified_capabilities = ["tools"]
    result_attested = policy_engine.evaluate(req, conn_untrusted)
    # The attestation check should pass. (It will go to regex check which passes).
    assert result_attested.allowed is True
    assert result_attested.stage == "passed"
