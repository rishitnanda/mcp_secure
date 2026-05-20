# MCP-Secure-Suite: Week 2 Integration Summary

This document summarizes the architectural design, security mechanisms, resolved challenges, and verification results of **Week 2** (Days 8–14) for the `MCP-Shield` core security proxy engine.

---

## 🏛️ System Architecture Overview

Week 2 focused on building the core security policy engine (`policy.py`), standard exceptions (`exceptions.py`), and the two transport layers: the FastAPI HTTP/SSE gateway (`gateway.py`) and the bidirectional Stdio proxy wrapper (`stdio_proxy.py`).

```
  AI Client (Cursor / Claude)
            │
      Writes to stdin / SSE
            │
            ▼
┌─────────────────────────────────────────────────────────┐
│                    [LAYER 1] SHIELD                     │
│                                                         │
│  1. HMAC Guard      ──► Constant-time SHA256 & sliding  │
│                         nonce window replay filter      │
│  2. Attestation     ──► Cryptographic Root CA signature │
│                         & ConnectionState capabilities  │
│  3. Regex Lexical   ──► Recursive parameters scan combining│
│                         server + default blacklists     │
│  4. AST Scanner     ──► Code execution syntax scanner   │
│                         filtering imports & attributes  │
│  5. Namespace Lock  ──► Limits tools/call & filters     │
│                         tools/list responses            │
│  6. Sanitizer       ──► Line-start and whole-text prompt│
│                         injection override filter       │
└───────────────────────────┬─────────────────────────────┘
                            │
                  If Allowed / Sanitized
                            │
                            ▼
                Target Subprocess / MCP Server
```

### 1. `mcp_shield` Policy Core
*   **HMAC Replay Protection (`policy.py` / `NonceWindow`)**: Implements HMAC-SHA256 request signing and a sliding time-window filter (±30s TTL) with nonce deduplication to block replay attempts on HTTP/SSE endpoints.
*   **Capability Attestation Validator**: Inspects PEM X.509 capability certificates signed by a trusted Root CA to authorize server-level capabilities (`tools`, `sampling`, etc.).
*   **Lexical Regex Filter**: Walks nested JSON-RPC parameter objects recursively and blocks blacklisted patterns.
*   **AST Code Guard**: Parses execution script values into Abstract Syntax Trees, blocking malicious imports (e.g., `os`, `subprocess`), calls (e.g., `eval`, `exec`), attribute access (e.g., `.system`, `.popen`), and syntax obfuscation (e.g., `getattr()`).
*   **Namespace Lock**: Ensures MCP servers can only expose and execute tools listed in their allowed configurations.
*   **Prompt Injection Sanitizer**: Intercepts tool outputs for injection patterns (e.g., "Ignore previous instructions") and sanitizes output streams.

### 2. Transport Wrappers
*   **FastAPI HTTP/SSE Gateway (`gateway.py`)**: Mounts endpoints for SSE transport, captures request bodies, runs validation pipelines, maps exceptions to JSON-RPC 2.0 errors, and logs telemetry events.
*   **Stdio Interception Proxy (`stdio_proxy.py`)**: Spawns target MCP servers as subprocesses, bidirectionally pipes standard streams, runs in-process policy validations on client requests, and sanitizes server responses.

---

## 🛠️ Key Design Decisions & Resolved Challenges

### 1. Combining Default and Server-Specific Regexes
*   **Decision:** Original implementations of regex scanners either checked server-specific lists OR default fallbacks. This allowed a server to override default filters and skip system-wide blocks.
*   **Resolution:** Modified `policy.py` to compile and concatenate the server-specific blacklist list with the default blacklist list: `patterns = server_patterns + self.compiled_default_regex`.

### 2. Eliminating AST False Positives (`ast.Name` Removal)
*   **Decision:** Lexical AST checks on `ast.Name` nodes (blocking references to names like `os`, `sys`) triggered false positives on standard user variables or safe code references.
*   **Resolution:** Completely removed the `ast.Name` node scanner, delegating import blocking to `ast.Import`/`ast.ImportFrom` and call blocking to `ast.Call`/`ast.Attribute`.

### 3. Dynamic Attestation Trust Modes
*   **Decision:** Simple boolean checks on server configurations bypassed certificate requirements, leaving strict deployments vulnerable.
*   **Resolution:** Introduced `trust_mode` configuration:
    - `strict`: Rejects capability usage unless attested by a valid cryptographic certificate.
    - `permissive` / `prompt`: Allows known, pre-configured servers to fall back to whitelist authorization.

### 4. Mutation Side-Effects Prevention
*   **Decision:** Direct in-place mutation of the tools list in `filter_tools_list_response` led to downstream state bugs and dictionary corruption.
*   **Resolution:** Enforced `copy.deepcopy()` on incoming payloads before applying namespace filters.

### 5. Transport-Agnostic Error Mapping
*   **Decision:** Tying exceptions directly to FastAPI response structures made it impossible to reuse the error-mapping logic in stdio mode.
*   **Resolution:** Extracted mapping logic to a pure helper function `to_jsonrpc_error(exc, request_id)` in `exceptions.py` that outputs raw standard JSON-RPC 2.0 error payloads.

---

## 🚀 What Works

*   **Recursive Regex Validation**: Traverses deep parameter payload dicts/lists and blocks blacklisted command lines (`rm -rf`, `chmod`, `nc`).
*   **Obfuscation-Resistant AST Scanner**: Parses code scripts and blocks malicious calls, imports, and `getattr()` bypasses.
*   **Namespace & Tools Restriction**: Strips unauthorized tools from list responses and blocks shadow execution requests.
*   **Cryptographic Attestation**: Validates certificate signatures, temporal validity, and server identity fields.
*   **HMAC Integrity & Replay Guard**: Validates secret key signatures and filters replayed nonces.
*   **Bi-directional Stdio Proxy**: Seamlessly pipes stdin/stdout streams to target servers while applying live interception.
*   **Telemetry DB Logging**: Captures execution statuses, durations, and exit codes asynchronously in SQLite WAL mode.

---

## ⏭️ What We Skipped / Deferred

*   **E2E Docker Sandbox Integration**: Gateway-to-Box wiring (forwarding allowed `execute_code` payloads to Docker containers) is deferred to Week 3 (Day 15).
*   **Mock Servers & Compose Orchestration**: Mock adversarial servers and compose networking files will be set up during Week 3 integration.

---

## 🧪 Adversarial Testing Matrix (S2–S8)

Our test suites verify security boundaries under the following threat vectors:

| Test Module | Threat Checked | Security Control | Target Status |
| :--- | :--- | :--- | :--- |
| `test_policy_regex.py` | Command injection parameters | Regex blacklist match | `regex` block (`-32602`) |
| `test_policy_ast.py` | Py-code sandbox breakout / obfuscation | AST nodes import/attribute walk | `ast` block (`-32602`) |
| `test_namespace_sanitizer.py` | Shadow tool registration / prompt injection | Namespace lock & output override | `namespace` block / sanitized output |
| `test_attestation.py` | Spoofed server capabilities | Root CA chain verification | `attestation` block (`-32601`) |
| `test_hmac.py` | Man-in-the-middle / Replay attack | HMAC compare & nonce store | `hmac` block (`-32602`) |
| `test_engine.py` | Combined multi-stage vectors | Unified PolicyEngine validator | Pipeline priority evaluation |
| `test_stdio_proxy.py` | Process hijacking on CLI | Bidirectional stream interceptor | Intercepted stdin/stdout |

---

## 📈 Integration Status

*   **Total Tests**: 73 Automated tests (Week 1 + Week 2).
*   **Success Rate**: 100% (All passing).
*   **Working Tree**: Clean and fully committed.
