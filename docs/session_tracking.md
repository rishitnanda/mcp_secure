# Session Tracking & Multi-Turn Attack Detection

Session tracking is an original contribution of this suite not present in the base ATTESTMCP paper [1]. The standard single-turn evaluation model checks each JSON-RPC request in isolation — if it passes all policy layers independently, it is forwarded. This is insufficient for a class of attacks where every individual call is benign but the *sequence* constitutes an exploit. This page explains what multi-turn state drift is, how `SessionStore` works, how sequence rules are configured, and which attacks they catch that per-request evaluation would miss.

---

## What Is Multi-Turn State Drift?

In a multi-server MCP deployment, a compromised server can spread an attack across multiple turns:

1. Make *n* individually legitimate-looking calls to build up context (reads, tool fetches, data transformations).
2. On call *n*+1, issue a privileged request (sampling, exfiltration, namespace manipulation) that the accumulated context enables or disguises.

Each call in isolation would pass every per-request check — HMAC, attestation, regex, AST, and namespace lock all operate on single frames. Only a layer that tracks the **call graph across turns** can detect that a threshold has been crossed.

This is distinct from prompt injection, which targets the LLM's context window. State drift targets the **policy engine's context window** — the sequence of method calls the proxy has observed from a given server.

---

## How `SessionStore` Works

`SessionStore` is a server-keyed in-memory dictionary. Each server gets one `SessionState` object for the lifetime of its connection.

```python
session = session_store.get_or_create("filesystem-server")
```

**`SessionState` holds:**

- `server_id` — the identity key for the session.
- `verified_capabilities` — the capability list confirmed during `initialize` attestation.
- `call_history` — an append-only list of every method call processed in this session. Each entry records the method name and, for `tools/call`, the tool name.
- `last_activity` — timestamp of the most recent call, used for TTL expiry.

**TTL expiry.** Sessions expire after a configurable idle timeout (`session_timeout_seconds`, default value set in `shield_config.json`). When `get_or_create` is called and the existing session has exceeded its TTL, it is discarded and a fresh session is returned. This means an attacker who deliberately triggers a gateway restart or connection reset loses their accumulated history — a known limitation documented in the threat model.

**Session isolation.** Each `server_id` maps to exactly one session. Two servers cannot share or read each other's call history. This prevents one server from exploiting context accumulated by another.

---

## Sequence Rules

Sequence rules are the policy primitives that act on session history. They are declared in `shield_config.json` under `sequence_policy` and evaluated by the policy engine on every call after the HMAC, attestation, regex, and AST layers pass.

### Rule Schema

```json
{
  "name": "rule_name",
  "description": "Human-readable description",
  "pattern": ["method1", "method2:tool_name", "method3"],
  "window": 4,
  "action": "block"
}
```

| Field | Description |
|---|---|
| `name` | Identifier returned in `PolicyResult.reason` when the rule fires. |
| `description` | Free-text description for documentation purposes. |
| `pattern` | Ordered list of method tokens to match against call history. `tools/call` entries can be qualified with a tool name using `tools/call:tool_name`. |
| `window` | Number of most-recent history entries to evaluate the pattern against. |
| `action` | Currently only `"block"` is supported. Warning-only telemetry mode is a planned future addition. |

### Scope

Rules can be defined at two scopes:

```json
{
  "sequence_policy": {
    "default": [ /* applies to every server */ ],
    "servers": {
      "adversarial-server": [ /* applies only to adversarial-server */ ]
    }
  }
}
```

Server-specific rules are evaluated in addition to default rules, not instead of them.

### Built-In Default Rules

The default `shield_config.json` ships with two rules covering the most common sampling exploitation patterns:

**`sampling_after_resource_read`** — blocks a `sampling/createMessage` call that follows two or more `resources/read` calls within a sliding window. This catches the classic data-staging pattern: read sensitive resources, then route their content to an LLM sampling call outside the normal tool flow.

**`sequential_sampling_context_buildup`** — blocks a rapid sequence of multiple `sampling/createMessage` calls, detecting attempts to build up LLM context incrementally through repeated sampling rather than a single large request.

---

## Attacks Caught by Sequence Rules That Single-Turn Evaluation Misses

The table below shows attacks where per-request checks would pass every individual call but the sequence engine fires.

| Attack | Individual Call Verdict | Sequence Verdict | Benchmark |
|---|---|---|---|
| Read two files, then invoke sampling to exfiltrate their content | Each `resources/read` passes; `sampling/createMessage` passes capability check | **Blocked** — `sampling_after_resource_read` pattern completes | MPS-026, MPS-035 |
| Chain `get_data → format_data → analyze → sampling/createMessage` to build injection context incrementally | Each tool call is clean; sampling call has no capability violation in isolation | **Blocked** — custom `injection_context_buildup` rule fires on the 4th call | MPS-034, MPS-037 |
| Issue rapid back-to-back sampling calls to accumulate LLM context across multiple turns | Each individual sampling call is within rate limits | **Blocked** — `sequential_sampling_context_buildup` fires on the Nth call | MPS-033 |
| 15-turn slow-burn sequence with injected payload on final turn | Every early call is benign | **Blocked** — full call log analysis covers the complete history, not a narrow window | MPS-030, MPS-039 |
| Server chain cascade: one server's output triggers a call sequence that escalates on a second server | Each hop passes individually | **Blocked** — session graph spans the full pipeline | MPS-027 |

---

## Configuring a Custom Rule

To add a rule that blocks a specific three-step tool sequence followed by a sampling call:

```json
{
  "sequence_policy": {
    "default": [
      {
        "name": "injection_context_buildup",
        "description": "3 tool calls then a sampling request",
        "pattern": [
          "tools/call:get_data",
          "tools/call:format_data",
          "tools/call:analyze",
          "sampling/createMessage"
        ],
        "window": 4,
        "action": "block"
      }
    ],
    "servers": {}
  }
}
```

When the policy engine evaluates a `sampling/createMessage` call and the last 4 entries in the session history match `get_data → format_data → analyze → sampling/createMessage`, the call is blocked with `stage == "sequence"` and `reason == "injection_context_buildup"`.

---

## Known Limitations

**Cross-session persistence.** Session state lives in process memory. A gateway restart clears all history. An attacker who deliberately triggers a restart between attack phases starts the next phase with a clean session. (Benchmark MPS-029.)

**No warning mode.** Sequence rules currently only support `"action": "block"`. A warning-only telemetry mode that logs without blocking is planned but not yet implemented.

**Single `block` action.** There is no per-rule allow-list override or rate-limit action. The only outcome when a rule fires is a JSON-RPC `-32602` error returned to the client.

---

## References

[1] Maloyan, A. & Namiot, D. (2026). *Breaking the Protocol: Exploiting and Securing the Model Context Protocol*. arXiv:2601.17549.