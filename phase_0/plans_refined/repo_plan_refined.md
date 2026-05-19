# Repository Blueprint: `mcp-secure-suite`

This document defines the refined architecture and directory layout for the dual-layer Model Context Protocol (MCP) security suite.

## 📁 Repository Structure

```
mcp-secure-suite/
│
├── config/
│   └── shield_config.json        # Declarative policies, tool namespaces, and regex definitions
│
├── mcp_shield/                  # Layer 1: Runtime Proxy & Telemetry
│   ├── src/
│   │   ├── __init__.py
│   │   ├── gateway.py            # Async stdio interceptor & FastAPI Web SSE server
│   │   ├── schemas.py            # Pydantic JSON-RPC & configuration schemas
│   │   ├── database.py           # Async SQLite logger with Write-Ahead Logging (WAL)
│   │   ├── policy.py             # AST Validator & Regex guardrail policy evaluator
│   │   └── dashboard/            # Static assets for the glassmorphic admin panel
│   │       ├── index.html
│   │       ├── index.css
│   │       └── index.js
│   └── requirements.txt
│
├── mcp_box/                     # Layer 2: Ephemeral Sandbox Lifecycle Engine
│   ├── src/
│   │   ├── __init__.py
│   │   └── sandbox.py            # Docker SDK orchestrator with timeout watchdog
│   └── requirements.txt
│
├── tests/                       # Integrated Verification Suite
│   ├── __init__.py
│   ├── test_shield_isolated.py   # Tests AST parsing, regex flags, namespace locks
│   ├── test_box_isolated.py      # Tests Docker timeout bounds and memory/disk caps
│   └── test_end_to_end.py       # Simulates exploits (indirect injection, command escape)
│
├── docker-compose.yml           # Local orchestrator for multi-server testing
├── README.md                    # Setup, security policy guide, and demo commands
└── plans_refined/               # Refined architectural & design planning documents
```

## 🔄 Dual-Layer Interlocking Workflow

The security suite works by intercepting the JSON-RPC standard used by the Model Context Protocol:

```mermaid
sequenceDiagram
    autonumber
    actor LLM as AI Client (Cursor/Claude)
    participant Shield as MCP-Shield Proxy
    participant Policy as Policy Engine (AST/Regex)
    participant Box as MCP-Box (Docker Sandbox)
    participant Server as Target MCP Server

    LLM->>Shield: JSON-RPC tools/call (e.g., execute_code)
    Note over Shield: Parse request & validate schemas
    Shield->>Policy: Evaluate parameters (lexical + AST check)
    alt Safe Code Call
        Policy-->>Shield: Check Passed
        Shield->>Box: Forward execution config
        Note over Box: Spawn isolated container & run code
        Box-->>Shield: Return stdout, stderr, & execution logs
        Shield->>LLM: Return execution output as JSON-RPC response
    else Policy Violation
        Policy-->>Shield: Reject (AST/Regex Violation)
        Shield->>LLM: Return standard JSON-RPC Error -32602 (Invalid Params)
    end
    Note over Shield: Asynchronously log transaction to SQLite WAL
```

## 🔐 Key Innovations in Refined Layout

1. **Dual-Transport Interface**: The gateway can run directly as a stdio proxy shim (intercepting process pipes for local IDE extensions) or as a FastAPI HTTP/SSE server mapping client-server streams.
2. **Declarative Configurations**: The centralized `shield_config.json` allows developers to lock down tool namespaces and define regular expressions without changing Python code.
3. **Write-Ahead Logging (WAL)**: SQLite is optimized for high concurrency. By running logging as asynchronous tasks (`asyncio.create_task`) and enabling SQLite's WAL mode, telemetry writing does not block JSON-RPC processing.
