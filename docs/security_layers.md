# Security layers

## Layer 1 — MCP-Shield

| Check | What it does |
|---|---|
| HMAC-SHA256 | Validates request signatures per server using pre-shared keys. Blocks replayed requests via a 30-second nonce window. |
| Capability attestation | Verifies X.509 certificates presented during `initialize`. Blocks any method call not covered by the server's attested capabilities. |
| Regex scan | Checks all tool arguments against a configurable blacklist (`rm -rf`, `/etc/passwd`, `nc -e`, `curl \| bash`, etc.). |
| AST scan | Parses code arguments into an AST and walks the tree. Blocks restricted imports (`os`, `subprocess`, `socket`), dangerous calls (`eval`, `exec`, `getattr`), and restricted attribute access. Catches obfuscation that regex cannot. |
| Namespace lock | Intercepts `tools/list` responses and strips any tool not in the server's allowed list in `shield_config.json`. Prevents shadow tool registration. |
| Output sanitizer | Scans tool outputs line-by-line and as full text. Replaces prompt injection patterns (`Ignore previous instructions`, `System:`, etc.) before they reach the LLM context. |

## Layer 2 — MCP-Box

Every code execution runs in a fresh container:

- `network_mode: none` — no outbound connections possible
- `mem_limit: 128m` — OOM kill on excess allocation
- `read_only: true` — root filesystem is immutable
- `user: sandboxuser` — non-root, uid 1000
- 2-second `asyncio.wait_for` watchdog — infinite loops are killed
- `container.remove(force=True)` in `finally` — cleanup runs regardless of outcome
- Label-based orphan pruning on startup — no leftover containers from previous crashes

Pre-installed in the sandbox image: `numpy`, `pandas`, `matplotlib`, `python-dateutil`, `pytz`. No internet access so no runtime pip installs.
