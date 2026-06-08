# Limitations

- **Container escape via kernel exploit** — Box uses OS-level namespaces, not hardware virtualisation (Firecracker/gVisor). A kernel vulnerability could allow host escape. Acceptable for local development; production deployments should use a VM-backed executor.
- **Persistent injection (sleeper channels)** — attacks that plant artifacts in long-term memory or filesystem cron paths and trigger later are out of scope. See Maloyan & Namiot, arXiv:2605.13471 for this threat model.
- **First-contact TOFU attacks** — on first connection from a server that has never presented ATTESTMCP credentials, the suite operates in permissive mode. Key pinning is not yet implemented.
- **Legitimately certified malicious servers** — attestation proves identity, not behaviour. A server with a valid certificate serving malicious content passes the attestation check.
- **Transport-layer attacks** (MiTM, DNS rebinding) — require TLS termination and certificate pinning at the transport layer, which is outside the current scope.
- **Host /tmp bind mount** — The Docker Compose setup binds the host's `/tmp` into the shield container so sandbox workspace directories are visible to the Docker daemon when spinning up child containers. This is a Docker-out-of-Docker constraint, not a design choice. Production deployments should run the sandbox manager on the host directly rather than inside a container.
- **Vulnerability to Advanced Obfuscated Injections** — While the output sanitizer intercepts protocol-layer payloads across tool returns, `resources/read`, and `prompts/get` channels, it relies on exact string and pattern matching. Advanced encoding bypasses (such as lookalike Unicode homographs, zero-width space disruptions, or base64 blocks embedded inside benign paragraphs) can still evade cleartext detection filters. 
- **Lack of Static Configuration and Secret Auditing** — The suite does not scan workspace configs, env files, or JSON configs for exposed API keys, credentials, or insecure HTTP endpoints prior to deployment.
- **Lack of Supply Chain / Dependency Verification** — The stdio proxy spawns server commands directly (e.g., `npx -y`) without verifying if the commands are pinned to secure, verified versions, leaving it vulnerable to dependency hijacking.
- **Lack of Tool Schema/Description Hardening** — The proxy enforces namespace permissions strictly on tool names. It does not inspect tool schemas, arguments, or descriptions to determine if the definitions themselves are structured to prevent prompt injection or LLM manipulation.
- **Sequence Rules Actions** — Sequence rules currently only support `block` actions. "Warning-only" telemetry modes are a future work item.

---

## Future Plans

1. **Build a Custom, Pure-Python Prompt Injection Guardrail:** Avoid heavy external dependencies (like Llama-Guard) by implementing a multi-tiered heuristic scoring engine directly in Python. This engine will analyze texts dynamically using:
    * *Imperative Constraint Override Detection:* Scanning for semantic combinations of override/bypass verbs (e.g., `ignore`, `bypass`, `forget`) coupled with target objects (e.g., `instructions`, `rules`, `system`).
    * *Roleplay and Persona Hijacking Scans:* Identifying attempts to establish alternative identities (e.g., `you are now`, `act as`, `DAN`).
    * *System Prompt Leaking Detection:* Flagging phrases asking the AI client to output or repeat previous instructions (e.g., `output the above`, `repeat from the beginning`).
    * *Entropy and Obfuscation Filters:* Inspecting payloads for zero-width spaces, excessive Unicode anomalies, or base64 patterns commonly used to hide injection payloads from tokenizers.

2. **Implement Command / Shell AST Parsers:** Expand AST scanning beyond Python. Implement a bash/shell command parser (e.g., using `bashlex`) to analyze arguments passed to shell execution tools, blocking dangerous redirectors (`>`), pipe constructs (`|`), or subshells (`$()`) regardless of the parameter names used.

3. **Stricter Filesystem and Workspace Sandboxing:** Control what files the client agent is allowed to read. Prevent the client from reading config or workspace rule files (like `.cursorrules`) unless explicitly trusted/signed, or execute filesystem operations inside a restricted chroot or container namespace.