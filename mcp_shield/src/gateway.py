import json
import time
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from mcp_shield.src.schemas import JSONRPCRequest, MCPSecHeader
from mcp_shield.src.policy import PolicyEngine, ConnectionState
from mcp_shield.src.database import DatabaseManager
from mcp_shield.src.exceptions import (
    MCPShieldException,
    PolicyViolationException,
    ASTValidationException,
    NamespaceViolationException,
    CapabilityViolationException,
    to_jsonrpc_error
)

db_manager = DatabaseManager()
policy_engine = PolicyEngine()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Lifespan: initialize database and reload configuration settings
    await db_manager.init_db()
    policy_engine.load_config()
    yield

app = FastAPI(lifespan=lifespan)

@app.exception_handler(MCPShieldException)
async def shield_exception_handler(request: Request, exc: MCPShieldException):
    # Expose exception mapper for custom exception blocks
    # Note: returns HTTP 200 containing a protocol-compliant JSON-RPC error frame.
    request_id = None
    try:
        body = await request.body()
        if body:
            raw_dict = json.loads(body)
            request_id = raw_dict.get("id")
    except Exception:
        pass
    error_frame = to_jsonrpc_error(exc, request_id=request_id)
    return JSONResponse(content=error_frame, status_code=200)

@app.post("/mcp")
async def handle_mcp_request(request: Request):
    body_bytes = await request.body()

    # 1. Parse JSON and extract Request ID before verification
    try:
        raw_dict = json.loads(body_bytes)
        if not isinstance(raw_dict, dict):
            raise json.JSONDecodeError("Not a dict", "", 0)
        request_id = raw_dict.get("id")
    except json.JSONDecodeError:
        return JSONResponse(
            status_code=200,
            content={
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": "Parse error"}
            }
        )

    # 2. Pydantic validation check
    try:
        rpc_request = JSONRPCRequest.model_validate(raw_dict)
    except ValidationError:
        return JSONResponse(
            status_code=200,
            content={
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32600, "message": "Invalid request"}
            }
        )

    # 3. Security evaluation
    server_id = request.headers.get("x-mcpsec-server-id", "default-server")
    conn_state = ConnectionState(server_id=server_id)

    # Extract HMAC / Replay security headers if present
    timestamp_str = request.headers.get("x-mcpsec-timestamp")
    nonce = request.headers.get("x-mcpsec-nonce")
    hmac_val = request.headers.get("x-mcpsec-hmac")
    sec_header: Optional[MCPSecHeader] = None
    if timestamp_str and nonce and hmac_val:
        try:
            sec_header = MCPSecHeader(
                server_id=server_id,
                timestamp=float(timestamp_str),
                nonce=nonce,
                hmac=hmac_val
            )
        except Exception:
            pass

    start_time = time.time()
    policy_res = policy_engine.evaluate(rpc_request, conn_state, body_bytes=body_bytes, sec_header=sec_header)
    duration_ms = (time.time() - start_time) * 1000.0

    if not policy_res.allowed:
        # Dispatch telemetry event for BLOCKED request
        db_manager.log_event(
            request_id=str(request_id) if request_id is not None else "unknown",
            method=rpc_request.method,
            payload=body_bytes.decode("utf-8", errors="replace"),
            status="BLOCKED",
            duration_ms=duration_ms,
            exit_code=None,
            server_id=server_id
        )

        # Raise appropriate exception to trigger handler
        if policy_res.stage == "regex":
            exc = PolicyViolationException(policy_res.reason, policy_res.reason)
        elif policy_res.stage == "ast":
            exc = ASTValidationException(policy_res.reason, policy_res.reason)
        elif policy_res.stage == "namespace":
            exc = NamespaceViolationException(
                rpc_request.params.get("name", "unknown") if isinstance(rpc_request.params, dict) else "unknown",
                server_id
            )
        elif policy_res.stage == "attestation":
            exc = CapabilityViolationException(rpc_request.method, server_id)
        else:
            exc = MCPShieldException(policy_res.reason, policy_res.stage)
        
        error_frame = to_jsonrpc_error(exc, request_id=request_id)
        return JSONResponse(content=error_frame, status_code=200)

    # 4. Log Success event and return success status (or mock dispatcher)
    db_manager.log_event(
        request_id=str(request_id) if request_id is not None else "unknown",
        method=rpc_request.method,
        payload=body_bytes.decode("utf-8", errors="replace"),
        status="SUCCESS",
        duration_ms=duration_ms,
        exit_code=0,
        server_id=server_id
    )

    return JSONResponse(
        status_code=200,
        content={
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {"status": "passed"}
        }
    )

@app.get("/metrics")
async def get_metrics():
    # Returns aggregation counts by status from logs
    return await db_manager.get_metrics()
