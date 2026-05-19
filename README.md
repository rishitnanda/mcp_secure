# MCP-Secure-Suite

### Dual-Layer Runtime Security Architecture for the Model Context Protocol (MCP)

`MCP-Secure-Suite` is a self-contained, open-source security proxy and ephemeral sandboxing system designed to protect Model Context Protocol (MCP v1.0) integrations. It directly implements the security mitigations proposed in the academic research paper:
> **"Breaking the Protocol: Security Analysis of the Model Context Protocol Specification and Prompt Injection Vulnerabilities in Tool-Integrated LLM Agents"** (arXiv:2601.17549, Jan 2026).

---

## 🏛️ System Architecture

The suite consists of a **Dual-Layer Defense Chain** that intercept, filters, and virtualizes requests between the LLM Client (such as Cursor or Claude Desktop) and external MCP Servers:

```
                  ┌──────────────────────────────────────────────┐
                  │                 LLM Client                   │
                  │        (Cursor, Claude Desktop, etc.)        │
                  └──────────────────────┬───────────────────────┘
                                         │
                                   JSON-RPC 2.0
                                         │
                  ┌──────────────────────▼───────────────────────┐
                  │               [LAYER 1] SHIELD               │
                  │         mcp_shield (JSON-RPC Proxy)          │
                  │                                              │
                  │  1. Attestation Check  2. HMAC Replay Filter │
                  │  3. Three-Stage Policy 4. Output Sanitizer   │
                  └──────────────────────┬───────────────────────┘
                                         │
                                 Validated Context
                                         │
                  ┌──────────────────────▼───────────────────────┐
                  │                [LAYER 2] BOX                 │
                  │           mcp_box (Docker Sandbox)           │
                  │                                              │
                  │  * Ephemeral container  * Memory Caps (128M) │
                  │  * Air-gapped network   * 2.0s Watchdog Kill │
                  └──────────────────────────────────────────────┘
```

---

## 🛡️ Covered Threat Vectors & Mitigations

| Vulnerability | Attack Description | Protocol Defect (MCP v1.0) | `MCP-Secure-Suite` Mitigation |
| :--- | :--- | :--- | :--- |
| **Vulnerability 1: Least Privilege Violation** | Uncertified capability escalation (e.g. server invokes sampling out-of-band). | Handshake declarations are not validated at runtime. | **Capability Attestation**: Proxy verifies cryptographic certificates (`capability_cert`) from a trusted CA. |
| **Vulnerability 2: Sampling Injections** | Adversarial servers hijack LLM context by injecting prompts using the `user` role. | MCP Hosts do not visually distinguish client prompts from server prompts. | **Origin Tagging & Consent**: Proxy tags server-originated messages and halts for whitelist consent. |
| **Vulnerability 3: Implicit Trust Propagation** | Multi-server interaction allows a compromised server to trigger tools on other servers. | Context window is globally shared without separation of origins. | **Isolation Control**: Restricts cross-server actions and implements boundaries on context updates. |
| **Shadow Tool Registration** | Hijacked server shadows a system command or trusted tool in the registry list. | Clients merge tools lists returned by servers without checking scopes. | **Namespace Lock**: Proxy blocks and filters unauthorized tool names returned in `tools/list`. |
| **Out-of-Bounds Execution** | Sandboxed scripts consume host memory, processes, or run system calls. | Code tools run commands directly with host privileges. | **Air-gapped Box Execution**: Docker container execution, 128MB RAM caps, and 2s timeout watchdog. |

---

## 📁 Repository Layout

```
mcp-secure-suite/
│
├── config/
│   └── shield_config.json        # Declarative policies, tool namespaces, and whitelists
│
├── mcp_shield/                  # Layer 1: Runtime Proxy & Telemetry
│   ├── src/
│   │   ├── __init__.py
│   │   ├── gateway.py            # Async stdio interceptor & FastAPI Web SSE server
│   │   ├── schemas.py            # Pydantic JSON-RPC & configuration schemas
│   │   ├── database.py           # Async SQLite logger with Write-Ahead Logging (WAL)
│   │   ├── policy.py             # AST Validator & Regex guardrail policy evaluator
│   │   └── dashboard/            # Static assets for the admin metrics dashboard
│   └── requirements.txt
│
├── mcp_box/                     # Layer 2: Ephemeral Sandbox Lifecycle Engine
│   ├── src/
│   │   ├── __init__.py
│   │   └── sandbox.py            # Docker SDK orchestrator with timeout watchdog
│   └── requirements.txt
│
├── tests/                       # Pytest verification suites
│   ├── __init__.py
│   ├── test_shield_isolated.py   # Unit tests for policy scans and schemas
│   ├── test_box_isolated.py      # Unit tests for docker containers, network, and OOMs
│   └── test_end_to_end.py        # Integration tests simulating full exploit scenarios
│
├── docker-compose.yml           # Orchestrator for local deployment
├── Makefile                     # Install, run, and test utilities
└── README.md                    # This document
```

---

## 🚀 Getting Started

### Prerequisites
* Python 3.10+
* Docker Engine (configured to run without root via sudo groups)

### Installation
1. Clone the repository and navigate into the workspace.
2. Initialize a Python virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```
3. Install dependencies using the provided `Makefile`:
   ```bash
   make install
   ```
4. Build the ephemeral sandbox execution image:
   ```bash
   make build-sandbox-image
   ```

### Running Tests

To run the full automated test suite containing all validation checks:
```bash
make test
```

The test infrastructure is designed for deep adversarial testing across our architectural layers:

#### 1. Pydantic Constraints (`tests/test_schemas.py`)
Validates structural integrity and constraints:
* **JSON-RPC Mutual Exclusion**: Enforces that a response object has either `result` or `error` set, but never both.
* **Temporal Ordering**: Assures certificates with an expiration time preceding their issuance time (`expires_at <= issued_at`) are strictly blocked.
* **Empty/Whitespace Sanitization**: Rejects empty methods, empty certificates, or lists containing whitespace-only capability entries.
* **Strict Nonces**: Blocks empty nonces, empty hmac strings, and non-positive timestamps.

Run individually:
```bash
.venv/bin/pytest tests/test_schemas.py -v
```

#### 2. SQLite WAL Telemetry Backend (`tests/test_database.py`)
Validates database logging resiliency under load:
* **Concurrency Stress Check**: Launches 100 concurrent asynchronous log writes simultaneously to verify that Write-Ahead Logging (`WAL` mode) operates concurrently without throwing database locking crashes.
* **Logger Exception Isolation**: Forces telemetry write errors by pointing to non-existent directories, ensuring failure logs write to `stderr` but never propagate to crash client handlers.

Run individually:
```bash
.venv/bin/pytest tests/test_database.py -v
```

#### 3. Cryptographic CA & Signature Verification (`tests/test_certs.py`)
Validates security proxy attestation rules:
* **Valid Chain Attestation**: Verifies signatures against the Root CA public key.
* **Temporal Rejections**: Rejects expired certificates and future-dated (not-yet-valid) certificates.
* **Identity Mapping CN/SAN**: Validates that the certificate CN/SAN matches the client's `server_id`.
* **Spoofed CA Checks**: Blocks spoofed CA attempts where an attacker generates a separate root CA with a matching name.
* **Payload Tampering & Garbage Guards**: Ensures that tampered PEM strings (modified base64 payload bytes) and raw garbage strings fail validation gracefully.

Run individually:
```bash
.venv/bin/pytest tests/test_certs.py -v
```


---

## 📑 References & Citations
* Maloyan, N. & Namiot, D. (2026). *Breaking the Protocol: Security Analysis of the Model Context Protocol Specification and Prompt Injection Vulnerabilities in Tool-Integrated LLM Agents*. arXiv:2601.17549v1 [cs.CR].
