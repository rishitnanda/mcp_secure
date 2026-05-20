import pytest
import time
from mcp_shield.src.policy import PolicyEngine, ConnectionState
from mcp_shield.src.schemas import JSONRPCRequest

@pytest.fixture
def policy_engine():
    return PolicyEngine()

def test_engine_integration_clean_passes(policy_engine):
    conn = ConnectionState(server_id="filesystem-server")
    req = JSONRPCRequest(
        jsonrpc="2.0",
        id=1,
        method="tools/call",
        params={
            "name": "read_file",
            "arguments": {"path": "/workspace/safe_file.txt"}
        }
    )
    result = policy_engine.evaluate(req, conn)
    assert result.allowed is True
    assert result.stage == "passed"

def test_engine_integration_regex_takes_precedence_over_ast(policy_engine):
    # If the payload violates regex and ast, regex should fire first
    conn = ConnectionState(server_id="filesystem-server")
    req = JSONRPCRequest(
        jsonrpc="2.0",
        id=1,
        method="tools/call",
        params={
            "name": "execute_code",
            "arguments": {"code": "import os\nos.system('rm -rf /')"} # Matches rm -rf (regex) and import os (AST)
        }
    )
    result = policy_engine.evaluate(req, conn)
    assert result.allowed is False
    assert result.stage == "regex" # Regex runs before AST

def test_engine_integration_ast_before_namespace(policy_engine):
    # AST runs before namespace check
    conn = ConnectionState(server_id="filesystem-server")
    req = JSONRPCRequest(
        jsonrpc="2.0",
        id=1,
        method="tools/call",
        params={
            "name": "fetch_url", # Namespace lock violation
            "arguments": {"code": "import os"} # AST violation (and "code" triggers AST scan)
        }
    )
    result = policy_engine.evaluate(req, conn)
    assert result.allowed is False
    assert result.stage == "ast" # AST runs before namespace lock
