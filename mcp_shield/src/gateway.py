import json
import time
import os
import asyncio
import httpx
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import ValidationError

from mcp_shield.src.schemas import JSONRPCRequest, MCPSecHeader, ExecutionContext, SandboxResult
from mcp_shield.src.policy import PolicyEngine
from mcp_shield.src.database import DatabaseManager
from mcp_shield.src.exceptions import (
    MCPShieldException,
    PolicyViolationException,
    ASTValidationException,
    NamespaceViolationException,
    CapabilityViolationException,
    SequenceViolationException,
    to_jsonrpc_error
)
from mcp_shield.src.session import SessionStore
from mcp_box.src.sandbox import DockerSandbox

db_manager = DatabaseManager()
# NOTE: PolicyEngine.__init__ calls load_config() internally.
# The explicit load_config() call in lifespan is intentional for hot-reload semantics
policy_engine = PolicyEngine()
session_store = SessionStore()
sandbox_manager: Optional[DockerSandbox] = None

# Mock routing URLs mapping server_id to backend MCP server URLs
MOCK_SERVER_URLS = {
    "trusted-server": os.getenv("TRUSTED_SERVER_URL", "http://localhost:8001/mcp"),
    "adversarial-server": os.getenv("ADVERSARIAL_SERVER_URL", "http://localhost:8002/mcp")
}


async def forward_request(url: str, body_bytes: bytes, headers: dict) -> dict:
    """Forwards the JSON-RPC request to the target server URL using httpx.AsyncClient.
    
    Uses native async HTTP instead of urllib in a thread executor.
    """
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(
                url,
                content=body_bytes,
                headers={
                    "Content-Type": "application/json",
                    "x-mcpsec-server-id": headers.get("x-mcpsec-server-id", ""),
                    "x-mcpsec-timestamp": headers.get("x-mcpsec-timestamp", ""),
                    "x-mcpsec-nonce": headers.get("x-mcpsec-nonce", ""),
                    "x-mcpsec-hmac": headers.get("x-mcpsec-hmac", ""),
                },
                timeout=5.0
            )
            return resp.json()
        except Exception as e:
            return {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32603, "message": f"Connection error: {e}"}
            }


@asynccontextmanager
async def lifespan(app: FastAPI):
    global sandbox_manager
    # Lifespan: initialize database with persistent connection
    await db_manager.init_db()
    # Intentional hot-reload call — load_config() is also called in PolicyEngine.__init__
    # but re-calling here ensures any config changes since startup are reflected.
    policy_engine.load_config()
    session_policy = policy_engine.config.get("session_policy", {})
    session_store.timeout_seconds = session_policy.get("session_timeout_seconds", 1800)
    session_store.max_calls_per_session = session_policy.get("max_calls_per_session", 100)
    
    # Run blocking DockerSandbox constructor in executor to avoid blocking event loop
    loop = asyncio.get_running_loop()
    sandbox_manager = await loop.run_in_executor(None, DockerSandbox)
    yield
    # Close persistent database connection cleanly on shutdown
    await db_manager.close()


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
    conn_state = session_store.get_or_create(session_id=server_id)

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
        elif policy_res.stage == "sequence":
            exc = SequenceViolationException(policy_res.reason, server_id)
        else:
            exc = MCPShieldException(policy_res.reason, policy_res.stage)
        
        error_frame = to_jsonrpc_error(exc, request_id=request_id)
        return JSONResponse(content=error_frame, status_code=200)

    # 4. Routing Handoff: detect execute_code via both standard MCP path (tools/call with
    # name="execute_code") and the direct method path used by demo.sh and E1/E2 tests.
    is_execute_code = (
        rpc_request.method == "execute_code"
        or (
            rpc_request.method == "tools/call"
            and isinstance(rpc_request.params, dict)
            and rpc_request.params.get("name") == "execute_code"
        )
    )

    if is_execute_code:
        # Extract code parameter
        code = None
        if isinstance(rpc_request.params, dict):
            arguments = rpc_request.params.get("arguments", {}) or {}
            code_param_names = policy_engine.config.get("code_param_names", ["code", "script", "py_code", "python_code", "command"])
            
            for key in code_param_names:
                if key in rpc_request.params and isinstance(rpc_request.params[key], str):
                    code = rpc_request.params[key]
                    break
            
            if not code and isinstance(arguments, dict):
                for key in code_param_names:
                    if key in arguments and isinstance(arguments[key], str):
                        code = arguments[key]
                        break

        if not code:
            return JSONResponse(
                status_code=200,
                content={
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32602, "message": "Missing 'code' parameter"}
                }
            )

        # Build ExecutionContext
        exec_ctx = ExecutionContext(code=code, server_id=server_id, request_id=request_id)
        
        # Execute code in Box Sandbox
        sandbox_res = await sandbox_manager.execute(exec_ctx.code)
        
        # Log to DB (unified log commit: status, duration_ms, exit_code)
        db_manager.log_event(
            request_id=str(request_id) if request_id is not None else "unknown",
            method=rpc_request.method,
            payload=body_bytes.decode("utf-8", errors="replace"),
            status=sandbox_res["status"].upper(),
            duration_ms=sandbox_res["duration_ms"],
            exit_code=sandbox_res["exit_code"],
            server_id=server_id
        )

        return JSONResponse(
            status_code=200,
            content={
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "exit_code": sandbox_res["exit_code"],
                    "logs": sandbox_res["logs"],
                    "status": sandbox_res["status"],
                    "duration_ms": sandbox_res["duration_ms"]
                }
            }
        )

    # Forward other requests to the target server if configured
    target_url = MOCK_SERVER_URLS.get(server_id)
    if target_url:
        headers_dict = {
            "x-mcpsec-server-id": server_id,
            "x-mcpsec-timestamp": timestamp_str or "",
            "x-mcpsec-nonce": nonce or "",
            "x-mcpsec-hmac": hmac_val or ""
        }
        forward_start = time.time()
        response_dict = await forward_request(target_url, body_bytes, headers_dict)
        forward_duration = (time.time() - forward_start) * 1000.0

        # Check response structure to apply filtering and sanitization
        status_to_log = "SUCCESS"
        result = response_dict.get("result")
        
        # Intercept tools/list responses to apply namespace locking filter
        if rpc_request.method == "tools/list" and isinstance(result, dict) and "tools" in result:
            response_dict = policy_engine.filter_tools_list_response(server_id, response_dict)

        # Intercept tools/call responses to apply output sanitization rules
        if rpc_request.method == "tools/call" and isinstance(result, dict) and "content" in result:
            content = result.get("content", [])
            if isinstance(content, list):
                any_sanitized = False
                for item in content:
                    if isinstance(item, dict) and item.get("type") == "text":
                        text_val = item.get("text", "")
                        sanitized_text, flagged = policy_engine.sanitize_output(text_val)
                        if flagged:
                            item["text"] = sanitized_text
                            any_sanitized = True
                if any_sanitized:
                    status_to_log = "SANITIZED"

        # Intercept resources/read responses to apply output sanitization rules
        if rpc_request.method == "resources/read" and isinstance(result, dict) and "contents" in result:
            contents = result.get("contents", [])
            if isinstance(contents, list):
                any_sanitized = False
                for item in contents:
                    if isinstance(item, dict) and "text" in item:
                        text_val = item.get("text", "")
                        sanitized_text, flagged = policy_engine.sanitize_output(text_val)
                        if flagged:
                            item["text"] = sanitized_text
                            any_sanitized = True
                if any_sanitized:
                    status_to_log = "SANITIZED"

        # Intercept prompts/get responses to apply output sanitization rules
        if rpc_request.method == "prompts/get" and isinstance(result, dict) and "messages" in result:
            messages = result.get("messages", [])
            if isinstance(messages, list):
                any_sanitized = False
                for msg in messages:
                    if isinstance(msg, dict) and isinstance(msg.get("content"), dict):
                        content_dict = msg["content"]
                        if content_dict.get("type") == "text":
                            text_val = content_dict.get("text", "")
                            sanitized_text, flagged = policy_engine.sanitize_output(text_val)
                            if flagged:
                                content_dict["text"] = sanitized_text
                                any_sanitized = True
                if any_sanitized:
                    status_to_log = "SANITIZED"

        # Log unified success or sanitized event
        db_manager.log_event(
            request_id=str(request_id) if request_id is not None else "unknown",
            method=rpc_request.method,
            payload=body_bytes.decode("utf-8", errors="replace"),
            status=status_to_log,
            duration_ms=forward_duration,
            exit_code=0,
            server_id=server_id
        )

        return JSONResponse(status_code=200, content=response_dict)

    # Log Success event and return standard success status (for fallback tests)
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


@app.get("/logs")
async def get_logs():
    # Returns last 50 log rows from SQLite as JSON
    return await db_manager.get_logs(limit=50)


@app.post("/api/run-tests")
async def run_tests():
    # Define the E1-E5 test payloads matching demo.sh
    tests = [
        {
            "name": "E1: Command Injection",
            "server_id": "trusted-server",
            "payload": {
                "jsonrpc": "2.0",
                "id": "demo-e1",
                "method": "execute_code",
                "params": {
                    "code": "import os; os.system(\"rm -rf /\")"
                }
            }
        },
        {
            "name": "E2: Clean Code Execution",
            "server_id": "trusted-server",
            "payload": {
                "jsonrpc": "2.0",
                "id": "demo-e2",
                "method": "execute_code",
                "params": {"code": "print(2 + 2)"}
            }
        },
        {
            "name": "E3: Indirect Prompt Injection",
            "server_id": "adversarial-server",
            "payload": {
                "jsonrpc": "2.0",
                "id": "demo-e3",
                "method": "tools/call",
                "params": {
                    "name": "trigger_injection",
                    "arguments": {}
                }
            }
        },
        {
            "name": "E4: Unauthorized Sampling",
            "server_id": "adversarial-server",
            "payload": {
                "jsonrpc": "2.0",
                "id": "demo-e4",
                "method": "tools/call",
                "params": {
                    "name": "escalate_sampling",
                    "arguments": {}
                }
            }
        },
        {
            "name": "E5: ASR Benchmark (direct vs shielded)",
            "server_id": "adversarial-server",
            "payload": {
                "jsonrpc": "2.0",
                "id": "demo-e5",
                "method": "tools/call",
                "params": {"name": "trigger_injection", "arguments": {}}
            }
        }
    ]

    results = []
    for test in tests:
        body_bytes = json.dumps(test["payload"]).encode("utf-8")
        headers = {"x-mcpsec-server-id": test["server_id"]}

        # Evaluate directly through policy engine to avoid HTTP self-loop
        try:
            rpc = JSONRPCRequest.model_validate(test["payload"])
            conn = session_store.get_or_create(session_id=test["server_id"])
            policy_res = policy_engine.evaluate(rpc, conn)
            shield_res = {
                "allowed": policy_res.allowed,
                "stage": policy_res.stage,
                "reason": policy_res.reason
            }
        except Exception as e:
            shield_res = {"error": str(e)}

        # Request via Direct (Raw Mock Server) — external HTTP is fine here
        direct_url = MOCK_SERVER_URLS.get(test["server_id"])
        if direct_url:
            direct_res = await forward_request(direct_url, body_bytes, headers)
        else:
            direct_res = {"error": "Mock server URL not found"}

        results.append({
            "test_name": test["name"],
            "payload": test["payload"],
            "shield_response": shield_res,
            "direct_response": direct_res
        })
        
    return JSONResponse(status_code=200, content={"results": results})


@app.post("/api/replay-direct")
async def replay_direct(request: Request):
    # NOTE: The shield replay is an intentional self-loop — it re-enters the gateway via HTTP
    # so the replayed request passes through the full policy pipeline (HMAC → attestation →
    # regex → AST → namespace) and gets logged to telemetry. Calling policy_engine.evaluate()
    # directly here would skip the logging and sanitization steps that make the replay useful
    # for the dashboard's side-by-side comparison view.
    try:
        body = await request.json()
        payload = body.get("payload")
        server_id = body.get("server_id")
        
        if not payload or not server_id:
            return JSONResponse(status_code=400, content={"error": "Missing payload or server_id"})
            
        if isinstance(payload, str):
            body_bytes = payload.encode("utf-8")
        else:
            body_bytes = json.dumps(payload).encode("utf-8")
            
        headers = {"x-mcpsec-server-id": server_id}
        
        # 1. Replay against direct server
        direct_url = MOCK_SERVER_URLS.get(server_id)
        if direct_url:
            direct_res = await forward_request(direct_url, body_bytes, headers)
            direct_status = "ERROR" if "error" in direct_res else "BYPASSED"
        else:
            direct_res = {"error": f"Mock server URL not found for {server_id}"}
            direct_status = "NOT FOUND"
            
        # 2. Replay against shield (self-loop is accepted here — see comment above)
        shield_url = "http://127.0.0.1:8000/mcp"
        shield_res = await forward_request(shield_url, body_bytes, headers)
        
        return JSONResponse(status_code=200, content={
            "direct_response": direct_res,
            "direct_status": direct_status,
            "shield_response": shield_res
        })
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


# Mount the static dashboard directory at /dashboard
app.mount(
    "/dashboard",
    StaticFiles(directory="mcp_shield/src/dashboard", html=True),
    name="dashboard"
)
