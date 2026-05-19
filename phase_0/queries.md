Q1: Stdio buffering race condition
Use HTTP/SSE as your primary transport. Implement stdio as a thin wrapper that reads newline-delimited frames and feeds them into the same pipeline. This way your core logic is transport-agnostic and the race condition is a solved problem.

Q2: Consent gate UX for sampling
Default to auto-deny. Add a sampling_whitelist array to shield_config.json where users explicitly opt servers in. In your demo, show a server getting blocked, then show it working after whitelisting. This tells a better security story than a consent popup.

Q3: Global vs per-server shield_config.json
Per-server config with a "default" fallback. This also makes your namespace lock test much cleaner — you can prove that filesystem-server cannot register fetch_url because its allowed tool list is pinned, while a different server could register it legitimately.

Q4: In-Process Engine vs Network Daemon
**Query**: Does stdio mode require a running FastAPI daemon?
**Solution**: Lock in in-process execution. We will separate the security logic into `mcp_shield/core/engine.py` (a pure-Python transport-agnostic validator returning `PolicyResult`).
* `stdio_proxy.py` runs this engine directly *in-process*. Since the stdio wrapper handles bidirectional piping, it will run its own async event loop, enabling it to share the same async SQLite telemetry logger (`aiosqlite`) without requiring a separate network socket or synchronous blocking writes.
* `gateway.py` wraps the engine inside a FastAPI app to serve HTTP/SSE traffic.

Q5: Capability Cert Transmission
**Query**: How does the proxy receive the server's signed capability certificate?
**Solution**: Option A is locked in. The server embeds `capability_cert` in its standard JSON-RPC `initialize` response. The proxy intercepts the outbound response from the server, validates the certificate, and allows or drops the session before the AI client receives the response.

Q6: HMAC Key Management
**Query**: How are HMAC keys distributed and protected?
**Solution**: Option A is locked in. We will use a static PSK map in `shield_config.json` referencing environment variables (e.g., `"${MCP_KEY_FILESYSTEM}"`). The loader resolves these references at startup. For the paper, we will document that a production environment would utilize ECDH ephemeral keys, but PSK is appropriate here.

Q7: Tool Output Buffering & Sanitization
**Query**: Does output sanitization need to support streams?
**Solution**: Assume non-streaming tool outputs. Tool results are complete `CallToolResult` blocks. The proxy will parse the full JSON-RPC response, scan the text blocks, perform sanitization, and forward the result. We will add a fallback handler/comment to ignore chunked-encoding stream buffers if encountered.

Q8: Sandbox Pre-baked Docker Image & User Privileges
**Query**: Which dependencies should be available inside the air-gapped sandbox, and under what user context?
**Solution**: We will create `mcp_box/Dockerfile` building `mcp-box-sandbox:latest` based on `python:3.11-alpine`. It will pre-install `numpy`, `pandas`, `requests` (with network blocked at the container configuration level to log execution failure rather than import errors), `matplotlib`, `python-dateutil`, and `pytz`. The container will execute code under a non-root `sandboxuser` to prevent container escape vectors.

Q9: CA Trust Store and Verification Key
**Query**: How does the proxy load the trusted public key or certificate to verify the signature of `capability_cert`?
**Solution**: A trusted root CA certificate (or public key) will be placed in `config/ca_cert.pem`. At startup, `MCP-Shield` loads this PEM file. During tests, the pytest fixture generates a temporary CA certificate and writes it to `config/ca_cert.pem`, enabling seamless signature validation.

Q10: Host Directory Mount Permissions for Non-Root Sandbox User
**Query**: How do we avoid permission conflicts when mounting host-side temp directories into a container running as non-root `sandboxuser`?
**Solution**: When `MCP-Box` creates the UUID-named temporary host directory, it will explicitly change its permission mode to `0o777` (world readable/writable) via `os.chmod(temp_dir, 0o777)`. This guarantees that the container's non-root `sandboxuser` has read/write access to the mounted volume, avoiding host UID/GID mismatch failures.