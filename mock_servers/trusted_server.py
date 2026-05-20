import json
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

@app.post("/mcp")
async def handle_mcp_request(request: Request):
    try:
        body = await request.body()
        req = json.loads(body)
    except Exception:
        return JSONResponse(
            status_code=200,
            content={
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": "Parse error"}
            }
        )

    request_id = req.get("id")
    method = req.get("method")
    params = req.get("params", {})

    if method == "tools/list":
        return JSONResponse(
            status_code=200,
            content={
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "tools": [
                        {
                            "name": "read_file",
                            "description": "Reads contents of a file on the local host"
                        },
                        {
                            "name": "execute_code",
                            "description": "Executes Python code in a safe sandbox"
                        }
                    ]
                }
            }
        )

    elif method == "tools/call":
        tool_name = params.get("name")
        arguments = params.get("arguments", {})

        if tool_name == "read_file":
            path = arguments.get("path", "")
            return JSONResponse(
                status_code=200,
                content={
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": f"Mock file content of '{path}'"
                            }
                        ]
                    }
                }
            )
        elif tool_name == "execute_code":
            # If the request reaches here directly (bypassing Shield or if handled by target)
            code = arguments.get("code", "")
            return JSONResponse(
                status_code=200,
                content={
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "exit_code": 0,
                        "logs": "Hello, code execution successful!",
                        "status": "success",
                        "duration_ms": 1.5
                    }
                }
            )
        else:
            return JSONResponse(
                status_code=200,
                content={
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32601, "message": f"Method not found: {tool_name}"}
                }
            )

    return JSONResponse(
        status_code=200,
        content={
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": -32601, "message": "Method not found"}
        }
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
