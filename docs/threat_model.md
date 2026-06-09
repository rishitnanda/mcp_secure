# Threat Model

This threat model follows Maloyan and Namiot [1] and extends it to account for multi-turn attacks. It defines the adversary's capabilities and goals, the attack surfaces the suite defends, what the suite does not protect against, and how the empirical benchmark maps onto these boundaries.

---

## Adversary Capabilities

The adversary controls or has compromised **one MCP server** in a multi-server deployment. Within that constraint, they can:

- **Inject content into data sources.** Web pages, documents, and database records retrieved by the compromised server may carry attacker-controlled text. This is the primary vector for indirect prompt injection.
- **Control tool responses.** The server can return arbitrary content in the `content` field of any `tools/call`, `resources/read`, or `prompts/get` response.
- **Register tool names.** The server can advertise tools in `tools/list` responses, including names chosen to shadow or impersonate tools from other servers.
- **Control the `initialize` handshake.** The server can present any `capabilities` object and, if not using ATTESTMCP, any identity claim.
- **Operate across multiple turns.** The adversary can orchestrate a sequence of individually benign-looking calls whose collective pattern constitutes an exploit.

The adversary has **black-box access only**. They cannot modify LLM weights, alter host application code, intercept traffic between other servers and the proxy, or read the Shield configuration file.

---

## Attacker Goals

| Goal | Description |
|---|---|
| **Hijack agent behaviour** | Cause the agent to take unintended actions — delete files, call privileged tools, exfiltrate secrets — by injecting instructions into the LLM's context window. |
| **Exfiltrate sensitive data** | Extract data accessed through legitimate tool calls by routing it to an attacker-controlled endpoint or embedding it in a subsequent sampling request. |
| **Persist across sessions** | Plant injected artifacts in long-term memory, filesystem cron paths, or shared state so that the attack survives a session reset or reconnection. |

---

## Attack Surface

The suite models four attack surfaces corresponding to the vulnerability classes defined in [1].

**1. Indirect injection through resources and tool outputs.**
Attacker-controlled content returned in `resources/read` or `tools/call` responses carries prompt injection payloads. The output sanitizer scans every response frame line-by-line and as full text before it reaches the LLM context. See `test_namespace_sanitizer.py` (sanitizer tests) and `test_e3` in `test_end_to_end.py`.

**2. Tool response manipulation — shadow registration and namespace squatting.**
The adversarial server advertises tool names that overlap with or impersonate tools from trusted servers. The namespace lock intercepts every `tools/list` response and strips any tool not explicitly whitelisted for that server in `shield_config.json`. See `test_namespace_sanitizer.py` (namespace lock tests) and benchmark cases MPS-014, MPS-016, MPS-021, MPS-028.

**3. Cross-server propagation through context window contamination.**
A compromised server injects content that instructs the agent to call tools on a different server, re-routes traffic, or poisons the shared context window. The output sanitizer, namespace lock, and sequence rules collectively address this surface. See benchmark cases MPS-021 through MPS-030.

**4. Unauthorized sampling escalation.**
A server without declared sampling capabilities attempts to invoke `sampling/createMessage` to gain LLM access — either directly or after building up context through prior tool calls. Capability attestation blocks undeclared sampling calls; sequence rules detect the data-staging patterns that precede them. See `test_attestation.py`, `test_session_state.py`, and benchmark cases MPS-031 through MPS-040.

---

## Extended Threat — Multi-Turn Attacks

Standard single-turn evaluation misses attack patterns where each individual tool call appears benign but the collective sequence constitutes an exploit. The threat model is extended to cover:

**Multi-step context buildup.** A server makes *n* legitimate-appearing calls and uses the accumulated session context to mount an attack on call *n*+1. The sequence rule engine tracks the full call history per session and matches configurable patterns against a sliding window. Individual calls that would pass in isolation are blocked when they complete a declared malicious sequence.

This pattern is empirically demonstrated in cross-server propagation attacks [1]. The test suite covers it in `test_session_state.py` (`test_clean_calls_blocked_as_malicious_sequence`, `test_multi_turn_indirect_injection_chain`) and benchmark cases MPS-019, MPS-020, MPS-027, MPS-030, MPS-034, MPS-037, MPS-039.

---

## What Is Out of Scope

The following attack classes are explicitly outside the current protection boundary.

| Out-of-Scope Class | Rationale |
|---|---|
| **Transport-layer attacks** (MiTM, DNS rebinding) | Require TLS termination and certificate pinning at the transport layer. The suite operates above the transport and assumes a secure channel is provided externally. |
| **Kernel-level container escapes** | MCP-Box uses OS-level namespaces, not hardware virtualisation (Firecracker / gVisor). A kernel vulnerability could permit host escape. Acceptable for local development; production deployments should use a VM-backed executor. |
| **Social engineering** | Attacks that convince a user to manually authorize a malicious server or override a Shield block are outside the technical scope of the proxy. |
| **Attacks within a single legitimately-certified server** | Attestation proves identity, not behaviour. A server holding a valid CA-signed certificate that serves malicious content passes the attestation check. The output sanitizer provides partial mitigation but is bypassable by the encoding techniques below. |
| **Sleeper channels requiring cross-session persistence** | Artifacts planted in long-term memory or filesystem cron paths that activate in a later session are not tracked. The suite's session state is held in transient process memory and is lost on connection reset. See Maloyan and Namiot [2] for this threat model. |
| **First-contact TOFU attacks** | On the first connection from a server that has never presented ATTESTMCP credentials, the suite operates in permissive mode. Key pinning is not yet implemented. |
| **Advanced output-layer encoding bypasses** | Four techniques evade the output sanitizer's cleartext pattern matching: (1) Unicode homograph substitution (e.g. Greek Capital Iota for Latin I); (2) zero-width space insertion (`\u200b`) breaking token sequences; (3) base64-embedded payloads inside otherwise benign text blocks; (4) multi-block split injection across separate `TextContent` nodes. NFC normalisation, zero-width character stripping, base64 decode-and-scan, and block concatenation are the recommended fixes, deferred to future work. These are tracked as benchmark category A gaps: MPS-004, MPS-005, MPS-008, MPS-009. |
| **AST-layer encoding bypasses** | Three obfuscation patterns bypass the AST walker: string concatenation at the call site (`__import__('o'+'s')`), hex-encoded exec (`exec(bytes.fromhex(...).decode())`), and `vars()` / `globals()` dynamic access. Recommended fixes are `BinaryOp` node reconstruction, adding `bytes.fromhex` to blocked calls, and adding `vars` / `globals` to blocked calls. |
| **Cross-session persistence exploits** | Because session state lives in process memory, a multi-step attack that deliberately triggers a gateway restart between phases resumes on a fresh session below all rule thresholds. Persistent session storage would be required to close this gap. (Benchmark MPS-029.) |
| **Pre-shared key management** | HMAC authentication uses statically configured PSKs loaded from environment variables. Production deployments should replace PSKs with ephemeral ECDH key exchange per session to prevent long-term key compromise. |
| **Stdio mode HMAC coverage** | HMAC authentication is implemented for HTTP/SSE transport only. The stdio proxy does not carry `mcpsec` headers, so requests forwarded in stdio mode are not HMAC-authenticated. |
| **Supply chain / dependency hijacking** | The stdio proxy spawns server commands (e.g. `npx -y`) without version pinning or hash verification. A compromised upstream package would not be detected. |

---

## References

[1] Maloyan, A. & Namiot, D. (2026). *Breaking the Protocol: Exploiting and Securing the Model Context Protocol*. arXiv:2601.17549.

[2] Maloyan, A. & Namiot, D. (2026). *Sleeper Channels: Persistent Injection Threats in Agentic Systems*. arXiv:2605.13471.