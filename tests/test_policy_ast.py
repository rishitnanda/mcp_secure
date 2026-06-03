import pytest
from mcp_shield.src.policy import PolicyEngine
from mcp_shield.src.session import SessionState
from mcp_shield.src.schemas import JSONRPCRequest

@pytest.fixture
def policy_engine():
    return PolicyEngine()

def test_ast_safe_code_passes(policy_engine):
    conn = SessionState(server_id="trusted-server")
    req = JSONRPCRequest(
        jsonrpc="2.0",
        id=1,
        method="tools/call",
        params={
            "name": "execute_code",
            "arguments": {"code": "x = 40 + 2\nprint(f'result is {x}')"}
        }
    )
    result = policy_engine.evaluate(req, conn)
    assert result.allowed is True
    assert result.stage == "passed"

def test_ast_syntax_error_blocked(policy_engine):
    conn = SessionState(server_id="trusted-server")
    req = JSONRPCRequest(
        jsonrpc="2.0",
        id=1,
        method="tools/call",
        params={
            "name": "execute_code",
            "arguments": {"code": "if True print(42)"} # Syntax error
        }
    )
    result = policy_engine.evaluate(req, conn)
    assert result.allowed is False
    assert result.stage == "ast"
    assert "SyntaxError: unparseable code payload" in result.reason

def test_ast_blocked_module_import_blocked(policy_engine):
    conn = SessionState(server_id="trusted-server")
    req = JSONRPCRequest(
        jsonrpc="2.0",
        id=1,
        method="tools/call",
        params={
            "name": "execute_code",
            "arguments": {"code": "import os\nos.system('echo hack')"}
        }
    )
    result = policy_engine.evaluate(req, conn)
    assert result.allowed is False
    assert result.stage == "ast"
    assert "import of restricted module 'os'" in result.reason

def test_ast_blocked_module_import_from_blocked(policy_engine):
    conn = SessionState(server_id="trusted-server")
    req = JSONRPCRequest(
        jsonrpc="2.0",
        id=1,
        method="tools/call",
        params={
            "name": "execute_code",
            "arguments": {"code": "from subprocess import Popen\nPopen(['ls'])"}
        }
    )
    result = policy_engine.evaluate(req, conn)
    assert result.allowed is False
    assert result.stage == "ast"
    assert "restricted module" in result.reason or "restricted call" in result.reason

def test_ast_blocked_call_blocked(policy_engine):
    conn = SessionState(server_id="trusted-server")
    req = JSONRPCRequest(
        jsonrpc="2.0",
        id=1,
        method="tools/call",
        params={
            "name": "execute_code",
            "arguments": {"code": "eval('2+2')"}
        }
    )
    result = policy_engine.evaluate(req, conn)
    assert result.allowed is False
    assert result.stage == "ast"
    assert "restricted function 'eval'" in result.reason

def test_ast_blocked_attribute_blocked(policy_engine):
    conn = SessionState(server_id="trusted-server")
    req = JSONRPCRequest(
        jsonrpc="2.0",
        id=1,
        method="tools/call",
        params={
            "name": "execute_code",
            "arguments": {"code": "class Attacker:\n    pass\na = Attacker()\na.popen = 'val'\nprint(a.popen)"}
        }
    )
    result = policy_engine.evaluate(req, conn)
    assert result.allowed is False
    assert result.stage == "ast"
    assert "restricted attribute 'popen'" in result.reason

def test_ast_getattr_obfuscation_blocked(policy_engine):
    conn = SessionState(server_id="trusted-server")
    req = JSONRPCRequest(
        jsonrpc="2.0",
        id=1,
        method="tools/call",
        params={
            "name": "execute_code",
            "arguments": {"code": "class A:\n    pass\ngetattr(A(), 'x')"}
        }
    )
    result = policy_engine.evaluate(req, conn)
    assert result.allowed is False
    assert result.stage == "ast"
    assert "getattr" in result.reason
