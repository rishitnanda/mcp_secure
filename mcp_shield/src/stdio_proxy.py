import sys
import asyncio
import json
import time
import os
from typing import List, Optional

from pydantic import ValidationError

from mcp_shield.src.schemas import JSONRPCRequest, MCPSecHeader
from mcp_shield.src.policy import PolicyEngine
from mcp_shield.src.session import SessionStore, SessionState
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

db_manager = DatabaseManager()
engine = PolicyEngine()

def write_response(response: dict):
    """Writes a JSON-RPC response to stdout as a newline-delimited frame."""
    sys.stdout.write(json.dumps(response) + "\n")
    sys.stdout.flush()

def guess_server_id(cmd: List[str]) -> str:
    """Guesses the server ID key from command line arguments to align with config mapping."""
    cmd_str = " ".join(cmd).lower()
    if "filesystem" in cmd_str:
        return "filesystem-server"
    if "trusted" in cmd_str:
        return "trusted-server"
    return "default-server"

async def get_sys_stdin_reader() -> asyncio.StreamReader:
    """Non-blocking StreamReader linked to the process standard input."""
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda: protocol, sys.stdin)
    return reader

async def client_to_server_loop(
    client_reader: asyncio.StreamReader,
    server_writer: asyncio.StreamWriter,
    session_state: SessionState
):
    """Reads JSON-RPC requests from client stdin, evaluates policies, and forwards allowed traffic."""
    while True:
        try:
            line = await client_reader.readline()
            if not line:
                break

            raw = line.decode("utf-8").strip()
            if not raw:
                continue

            request_id = None
            request = None
            try:
                # 1. Parse JSON and extract Request ID before Pydantic validation
                raw_dict = json.loads(raw)
                if not isinstance(raw_dict, dict):
                    raise json.JSONDecodeError("Not a dict", "", 0)
                request_id = raw_dict.get("id")

                # 2. Pydantic schema validation
                request = JSONRPCRequest.model_validate(raw_dict)

                # 3. PolicyEngine evaluation
                start_time = time.time()
                policy_res = engine.evaluate(request, session_state)
                duration_ms = (time.time() - start_time) * 1000.0

                if not policy_res.allowed:
                    # Log blocked event to database
                    db_manager.log_event(
                        request_id=str(request_id) if request_id is not None else "unknown",
                        method=request.method,
                        payload=raw,
                        status="BLOCKED",
                        duration_ms=duration_ms,
                        exit_code=None,
                        server_id=session_state.server_id or "unknown"
                    )

                    # Instantiate concrete Exception corresponding to stage
                    if policy_res.stage == "regex":
                        exc = PolicyViolationException(policy_res.reason, policy_res.reason)
                    elif policy_res.stage == "ast":
                        exc = ASTValidationException(policy_res.reason, policy_res.reason)
                    elif policy_res.stage == "namespace":
                        exc = NamespaceViolationException(
                            request.params.get("name", "unknown") if isinstance(request.params, dict) else "unknown",
                            session_state.server_id or "unknown"
                        )
                    elif policy_res.stage == "attestation":
                        exc = CapabilityViolationException(request.method, session_state.server_id or "unknown")
                    elif policy_res.stage == "sequence":
                        exc = SequenceViolationException(policy_res.reason, session_state.server_id or "unknown")
                    else:
                        exc = MCPShieldException(policy_res.reason, policy_res.stage)

                    error_frame = to_jsonrpc_error(exc, request_id=request_id)
                    write_response(error_frame)
                    continue

                # Forward allowed request to target server
                server_writer.write(line)
                await server_writer.drain()

            except json.JSONDecodeError:
                write_response({
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": "Parse error"}
                })
            except ValidationError:
                write_response({
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32600, "message": "Invalid request"}
                })
            except MCPShieldException as e:
                error_frame = to_jsonrpc_error(e, request_id=request_id)
                write_response(error_frame)

        except asyncio.CancelledError:
            break
        except Exception as e:
            # Print to stderr to keep stdout clean for client communication
            print(f"[ERROR] Stdio proxy client loop error: {e}", file=sys.stderr)

async def server_to_client_loop(
    server_reader: asyncio.StreamReader,
    session_state: SessionState
):
    """Reads JSON-RPC responses from server stdout, applies sanitizers/attestations, and writes to client stdout."""
    while True:
        try:
            line = await server_reader.readline()
            if not line:
                break

            raw = line.decode("utf-8").strip()
            if not raw:
                continue

            try:
                raw_dict = json.loads(raw)
                if not isinstance(raw_dict, dict):
                    # Write non-dictionary outputs directly
                    sys.stdout.write(raw + "\n")
                    sys.stdout.flush()
                    continue

                request_id = raw_dict.get("id")
                result = raw_dict.get("result")

                # Intercept 'initialize' responses to validate capability certifications
                if isinstance(result, dict) and "capability_cert" in result:
                    cert_json = result.get("capability_cert")
                    success, reason = engine.verify_capability_cert(cert_json)
                    if not success:
                        exc = CapabilityViolationException("attestation", session_state.server_id or "unknown")
                        error_frame = to_jsonrpc_error(exc, request_id=request_id)
                        write_response(error_frame)

                        db_manager.log_event(
                            request_id=str(request_id) if request_id is not None else "unknown",
                            method="initialize",
                            payload=raw,
                            status="BLOCKED",
                            duration_ms=0.0,
                            exit_code=None,
                            server_id=session_state.server_id or "unknown"
                        )
                        # Drop session on invalid certificate attestation.
                        # Use SystemExit instead of os._exit to allow async tasks
                        # (including pending log writes) to flush cleanly (Problem 16).
                        raise SystemExit(1)
                    else:
                        session_state.verified_capabilities = cert_json.get("capabilities", [])
                        session_state.cert_expiry = cert_json.get("expires_at")

                # Intercept tools/list responses to apply namespace locking filter
                if isinstance(result, dict) and "tools" in result:
                    raw_dict = engine.filter_tools_list_response(session_state.server_id or "unknown", raw_dict)

                # Intercept tools/call responses to apply output sanitization rules
                if isinstance(result, dict) and "content" in result:
                    content = result.get("content", [])
                    if isinstance(content, list):
                        any_sanitized = False
                        for item in content:
                            if isinstance(item, dict) and item.get("type") == "text":
                                text_val = item.get("text", "")
                                sanitized_text, flagged = engine.sanitize_output(text_val)
                                if flagged:
                                    item["text"] = sanitized_text
                                    any_sanitized = True
                        if any_sanitized:
                            db_manager.log_event(
                                request_id=str(request_id) if request_id is not None else "unknown",
                                method="tools/call",
                                payload=raw,
                                status="SANITIZED",
                                duration_ms=0.0,
                                exit_code=0,
                                server_id=session_state.server_id or "unknown"
                            )

                # Intercept resources/read responses to apply output sanitization rules
                if isinstance(result, dict) and "contents" in result:
                    contents = result.get("contents", [])
                    if isinstance(contents, list):
                        any_sanitized = False
                        for item in contents:
                            if isinstance(item, dict) and "text" in item:
                                text_val = item.get("text", "")
                                sanitized_text, flagged = engine.sanitize_output(text_val)
                                if flagged:
                                    item["text"] = sanitized_text
                                    any_sanitized = True
                        if any_sanitized:
                            db_manager.log_event(
                                request_id=str(request_id) if request_id is not None else "unknown",
                                method="resources/read",
                                payload=raw,
                                status="SANITIZED",
                                duration_ms=0.0,
                                exit_code=0,
                                server_id=session_state.server_id or "unknown"
                            )

                # Intercept prompts/get responses to apply output sanitization rules
                if isinstance(result, dict) and "messages" in result:
                    messages = result.get("messages", [])
                    if isinstance(messages, list):
                        any_sanitized = False
                        for msg in messages:
                            if isinstance(msg, dict) and isinstance(msg.get("content"), dict):
                                content_dict = msg["content"]
                                if content_dict.get("type") == "text":
                                    text_val = content_dict.get("text", "")
                                    sanitized_text, flagged = engine.sanitize_output(text_val)
                                    if flagged:
                                        content_dict["text"] = sanitized_text
                                        any_sanitized = True
                        if any_sanitized:
                            db_manager.log_event(
                                request_id=str(request_id) if request_id is not None else "unknown",
                                method="prompts/get",
                                payload=raw,
                                status="SANITIZED",
                                duration_ms=0.0,
                                exit_code=0,
                                server_id=session_state.server_id or "unknown"
                            )

                write_response(raw_dict)

            except Exception as e:
                # Write original frame in case of errors
                sys.stdout.write(raw + "\n")
                sys.stdout.flush()

        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"[ERROR] Stdio proxy server loop error: {e}", file=sys.stderr)

async def async_main():
    if "--" not in sys.argv:
        print("Usage: stdio_proxy -- <server_command>", file=sys.stderr)
        sys.exit(1)

    split = sys.argv.index("--")
    server_cmd = sys.argv[split + 1:]

    # Guess server ID to load configuration rules
    server_id = guess_server_id(server_cmd)

    # Initialize Telemetry database
    await db_manager.init_db()
    engine.load_config()
    
    session_store = SessionStore(db_manager=db_manager)
    session_policy = engine.config.get("session_policy", {})
    session_store.timeout_seconds = session_policy.get("session_timeout_seconds", 1800)
    session_store.max_calls_per_session = session_policy.get("max_calls_per_session", 100)
    
    session_state = await session_store.get_or_create(server_id)

    # Spawn target subprocess server
    try:
        server_proc = await asyncio.create_subprocess_exec(
            *server_cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=sys.stderr
        )
    except Exception as e:
        print(f"Failed to spawn target server command: {e}", file=sys.stderr)
        sys.exit(1)

    client_reader = await get_sys_stdin_reader()

    # Spin up concurrent StreamReader forwarding loops
    client_task = asyncio.create_task(
        client_to_server_loop(client_reader, server_proc.stdin, session_state)
    )
    server_task = asyncio.create_task(
        server_to_client_loop(server_proc.stdout, session_state)
    )

    await asyncio.gather(client_task, server_task)
    
    # Wait for process termination
    await server_proc.wait()

def main():
    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
