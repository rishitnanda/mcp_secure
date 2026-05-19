# Project 1 Refined: `MCP-Shield` (Proxy & Governance Layer)

`MCP-Shield` is the front line of defense, acting as a protocol-aware JSON-RPC security gateway. It inspects all payloads passing between the AI Client (e.g., Cursor, Claude Code) and the target MCP servers. It implements the key concepts proposed in the **ATTEST MCP** extension to defend against protocol-level vulnerabilities.

---

## 🎯 1. Key Objectives & Scope

*   **Deep Packet Inspection (DPI)**: Decode JSON-RPC 2.0 frames over both stdio streams and HTTP/SSE transports.
*   **Tool Registry Namespace Locks**: Prevent "Shadow Tool Registration" vulnerabilities by filtering unauthorized tool names from `tools/list` responses.
*   **Capability Attestation Checks**: Validate cryptographically signed capability declarations to prevent post-initialization capability escalation.
*   **Sampling Origin Tagging**: Intercept `sampling/createMessage` requests, tagging them with server identifiers to prevent model spoofing.
*   **Multi-Stage Policy Guardrails**: Scan inputs and outputs dynamically using dual regex and Abstract Syntax Tree (AST) validation.
*   **Non-Blocking Telemetry Auditing**: Persist logs concurrently using an async SQLite driver with Write-Ahead Logging (WAL) configuration.

---

## ⚙️ 2. Core Security Engines

### A. Capability Attestation Validator
Following the ATTEST MCP specification, `MCP-Shield` prevents **Least Privilege Violations** by verifying the server's identity and permissions certificate.
*   **Certificate Structure**: The proxy expects servers to present a certificate during initialization matching:
    ```json
    {
      "capability_cert": {
        "server_id": "filesystem-server",
        "capabilities": ["resources", "tools"],
        "issued_by": "anthropic-ca",
        "issued_at": 1706140800,
        "expires_at": 1737676800,
        "signature": "base64..."
      }
    }
    ```
*   **Enforcement**: If a server attempts to call `sampling/createMessage` (or access resources) but does not have the corresponding permission declared inside its pinned certificate, the proxy rejects the request immediately.

### B. Sampling Interceptor & Origin Tagging
To mitigate **Sampling Without Origin Authentication**, where a compromised server injects prompts under the `"user"` role:
1.  **Origin Tagging**: The proxy intercepts all `sampling/createMessage` calls and forces the tagging of the message payload:
    *   *Mechanism*: It rewrites the message context content to explicitly prepend: `[ORIGIN: server_name] [WARNING: This message was generated programmatically by the server, NOT the user]`.
2.  **Consent Validation**: If a server requests sampling, the proxy flags this to the client/user and requires explicit prompt-level consent (via the console or local dashboard) before forwarding the query.

### C. Message Integrity & Replay Protection
For environments using network-based SSE streams, the proxy validates message integrity:
*   **HMAC Validation**: Outbound/inbound JSON-RPC requests contain a `mcpsec` header containing `server_id`, `timestamp`, `nonce`, and `hmac` (HMAC-SHA256 signature).
*   **Sliding Window Replay Protection**: The proxy maintains a sliding window of 1,000 nonces per server with a 30-second validity window. Replayed packets or invalid timestamps are dropped immediately.

### D. The Policy Engine (`policy.py`)
Rather than relying on basic regular expressions, which are easily bypassed, `MCP-Shield` implements a three-step evaluation pipeline:

```
[Incoming Payload] 
       │
       ▼
┌──────────────┐
│  Regex Scan  │ ──(Violated)──> [PolicyViolationException]
└──────────────┘
       │ (Passed)
       ▼
┌──────────────┐
│ AST Parsing  │ ──(Violated)──> [ASTValidationException]
└──────────────┘
       │ (Passed)
       ▼
[Execute / Forward]
```

1.  **Regex Lexical Scan**: Checks tool parameters against a pre-compiled set of blacklisted string expressions.
    *   *Examples*: `rm\s+-rf`, `chmod\s+\+x`, `/etc/passwd`, `nc\s+-e`, `curl.*bash`.
2.  **AST (Abstract Syntax Tree) Parser**:
    *   For tools running Python (e.g., `execute_code`), the proxy extracts the code block argument.
    *   It parses the code into an AST using Python’s built-in `ast` module.
    *   It recursively walks the tree node-by-node, analyzing imports, function calls, and attribute accesses.
    *   *Rules*: Blocks any `ast.Import` or `ast.ImportFrom` matching restricted modules (e.g., `os`, `sys`, `subprocess`, `socket`, `ctypes`, `urllib`). Blocks calls to `eval()`, `exec()`, or runtime attribute retrievals (`getattr`).
3.  **Namespace Verification (Anti-Shadowing)**:
    *   When the client queries list of tools (`tools/list` request), the proxy intercepts the server response.
    *   It compares the returned tools against the allowed list defined in `shield_config.json`.
    *   If the target server attempts to register a tool matching a protected namespace (like hijacking `read_file` or `execute_command`), the proxy strips the tool from the payload, rendering it invisible to the client.

### E. Output Sanitization & Indirect Injection Protection
*   If a tool reads an external page or database, the output is intercepted before it reaches the LLM.
*   If the returned text matches a signature of prompt injection (e.g., instructions starting with `System:`, `Human:`, or directive overrides like `Ignore previous instructions`), the proxy replaces it with a sanitized block or issues a warning token to prevent execution hijacking.

---

## 🛠️ 3. JSON-RPC Exception-Mapping Engine

To prevent breaking the client pipeline, `MCP-Shield` maps raw Python exceptions into strict JSON-RPC 2.0 error specifications:

| Exception Type | Trigger Cause | JSON-RPC Code | Error Message |
| :--- | :--- | :--- | :--- |
| `ValidationError` (Pydantic) | Malformed JSON layout or invalid data types | `-32602` (Invalid Params) | "Schema validation failed: [details]" |
| `PolicyViolationException` | Parameters matched regex blacklist rules | `-32602` (Invalid Params) | "Security policy violation: Blocked sequence detected" |
| `ASTValidationException` | Python payload contains dangerous imports/calls | `-32602` (Invalid Params) | "Security policy violation: Restricted AST token" |
| `JSONDecodeError` | Broken or corrupted JSON streams | `-32700` (Parse Error) | "JSON parse error" |
| `MethodNotFoundException` | Client called a tool filtered by namespace locks | `-32601` (Method Not Found) | "Method not found: [tool_name]" |
| `SystemConflictException` | Internal timeout or sandbox configuration crash | `-32603` (Internal Error) | "Internal execution gateway error" |

---

## 📈 4. Telemetry & Concurrent Database Logger (`database.py`)

A classic bottleneck in developer proxies is synchronous disk writing. `MCP-Shield` solves this with an asynchronous transaction pipeline:

*   **Lifespan Setup**: Upon gateway startup, an `aiosqlite` connection pool is initialized.
*   **Write-Ahead Logging (WAL)**: The SQLite connection runs:
    ```sql
    PRAGMA journal_mode=WAL;
    PRAGMA synchronous=NORMAL;
    ```
    This separates read and write operations into different files, letting the gateway handle telemetry writes concurrently without lockouts.
*   **Background Tasks**: Logging calls do not delay the client response. They are queued via `asyncio.create_task()` and run out-of-band:
    ```python
    async def log_event(request_id: str, payload: dict, status: str):
        try:
            async with aiosqlite.connect(DB_PATH) as db:
                await db.execute(
                    "INSERT INTO logs (id, timestamp, payload, status) VALUES (?, ?, ?, ?)",
                    (request_id, time.time(), json.dumps(payload), status)
                )
                await db.commit()
        except Exception as e:
            # Safely log database exceptions to stderr without interrupting client
            sys.stderr.write(f"Telemetry warning: {e}\n")
    ```

