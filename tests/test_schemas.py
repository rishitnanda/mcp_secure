import pytest
from pydantic import ValidationError
from mcp_shield.src.schemas import (
    JSONRPCRequest,
    JSONRPCError,
    JSONRPCResponse,
    CapabilityCert,
    MCPSecHeader,
    PolicyResult,
    ExecutionContext,
    SandboxResult,
)

def test_jsonrpc_request_valid():
    req = JSONRPCRequest(jsonrpc="2.0", id=1, method="tools/list", params={"foo": "bar"})
    assert req.jsonrpc == "2.0"
    assert req.id == 1
    assert req.method == "tools/list"
    assert req.params == {"foo": "bar"}

def test_jsonrpc_request_invalid_version():
    with pytest.raises(ValidationError) as excinfo:
        JSONRPCRequest(jsonrpc="1.0", id=1, method="tools/list")
    assert "jsonrpc version must be '2.0'" in str(excinfo.value)

def test_jsonrpc_error_valid():
    err = JSONRPCError(code=-32602, message="Invalid Params", data={"detail": "missing field"})
    assert err.code == -32602
    assert err.message == "Invalid Params"
    assert err.data == {"detail": "missing field"}

def test_jsonrpc_response_with_result_only():
    res = JSONRPCResponse(jsonrpc="2.0", id=1, result={"tools": []})
    assert res.jsonrpc == "2.0"
    assert res.id == 1
    assert res.result == {"tools": []}
    assert res.error is None

def test_jsonrpc_response_with_error_only():
    err = JSONRPCError(code=-32602, message="Invalid Params")
    res = JSONRPCResponse(jsonrpc="2.0", id=1, error=err)
    assert res.jsonrpc == "2.0"
    assert res.id == 1
    assert res.error.code == -32602
    assert res.result is None

def test_jsonrpc_response_both_present_invalid():
    err = JSONRPCError(code=-32602, message="Invalid Params")
    with pytest.raises(ValidationError) as excinfo:
        JSONRPCResponse(jsonrpc="2.0", id=1, result={"tools": []}, error=err)
    assert "JSON-RPC response cannot contain both result and error members" in str(excinfo.value)

def test_jsonrpc_response_neither_present_invalid():
    with pytest.raises(ValidationError) as excinfo:
        JSONRPCResponse(jsonrpc="2.0", id=1)
    assert "JSON-RPC response must contain either result or error member" in str(excinfo.value)

def test_capability_cert_valid():
    cert = CapabilityCert(
        server_id="filesystem-server",
        capabilities=["resources/list", "tools/call"],
        issued_by="platform-ca",
        issued_at=1700000000.0,
        expires_at=1800000000.0,
        signature="signature_hash_value"
    )
    assert cert.server_id == "filesystem-server"
    assert cert.capabilities == ["resources/list", "tools/call"]
    assert cert.issued_at == 1700000000.0

def test_capability_cert_invalid_types():
    with pytest.raises(ValidationError):
        CapabilityCert(
            server_id="filesystem-server",
            capabilities="not_a_list",  # Invalid type
            issued_by="platform-ca",
            issued_at="not_a_float",   # Invalid type
            expires_at=1800000000.0,
            signature="sig"
        )

def test_mcp_sec_header_valid():
    hdr = MCPSecHeader(
        server_id="server-a",
        timestamp=1700000000.0,
        nonce="random_nonce_value",
        hmac="hmac_sha256_hex"
    )
    assert hdr.server_id == "server-a"
    assert hdr.nonce == "random_nonce_value"

def test_policy_result_valid():
    res = PolicyResult(allowed=False, reason="Blocked due to AST import validation", stage="ast")
    assert not res.allowed
    assert res.stage == "ast"

def test_execution_context_valid():
    ctx = ExecutionContext(code="print(2+2)", server_id="sandbox-run", request_id="req-123")
    assert ctx.code == "print(2+2)"
    assert ctx.server_id == "sandbox-run"
    assert ctx.request_id == "req-123"

def test_sandbox_result_valid():
    res = SandboxResult(exit_code=0, logs="4\n", status="success", duration_ms=45.2)
    assert res.exit_code == 0
    assert res.logs == "4\n"
    assert res.status == "success"
    assert res.duration_ms == 45.2

def test_jsonrpc_request_empty_method():
    with pytest.raises(ValidationError):
        JSONRPCRequest(jsonrpc="2.0", id=1, method="")

def test_jsonrpc_request_invalid_id_type():
    with pytest.raises(ValidationError):
        JSONRPCRequest(jsonrpc="2.0", id={"not": "valid"}, method="tools/list")

def test_capability_cert_invalid_date_order():
    with pytest.raises(ValidationError) as excinfo:
        CapabilityCert(
            server_id="fs",
            capabilities=["tools/list"],
            issued_by="ca",
            issued_at=1800000000.0,
            expires_at=1700000000.0,
            signature="sig"
        )
    assert "expires_at must be strictly after issued_at" in str(excinfo.value)

def test_capability_cert_empty_capabilities():
    with pytest.raises(ValidationError):
        CapabilityCert(
            server_id="fs",
            capabilities=[],
            issued_by="ca",
            issued_at=1700000000.0,
            expires_at=1800000000.0,
            signature="sig"
        )

def test_capability_cert_whitespace_capabilities():
    with pytest.raises(ValidationError):
        CapabilityCert(
            server_id="fs",
            capabilities=["   ", "tools/list"],
            issued_by="ca",
            issued_at=1700000000.0,
            expires_at=1800000000.0,
            signature="sig"
        )

def test_mcp_sec_header_negative_timestamp():
    with pytest.raises(ValidationError):
        MCPSecHeader(
            server_id="srv",
            timestamp=-10.0,
            nonce="nonce",
            hmac="hmac"
        )

def test_mcp_sec_header_empty_fields():
    with pytest.raises(ValidationError):
        MCPSecHeader(
            server_id="",
            timestamp=123.0,
            nonce="",
            hmac="hmac"
        )

