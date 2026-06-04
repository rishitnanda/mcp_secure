# Welcome to MCP-Secure-Suite

A dual-layer security proxy for the Model Context Protocol (MCP). Built as an open-source implementation of the mitigations proposed in [Breaking the Protocol](https://arxiv.org/abs/2601.17549) (Maloyan & Namiot, arXiv:2601.17549, Jan 2026).

MCP has three documented protocol-level vulnerabilities — capability escalation, unauthenticated sampling, and implicit cross-server trust propagation. This suite blocks all three, plus code injection and indirect prompt injection, at the protocol boundary before anything reaches the host system.

## Quick start

Requires Python 3.11+ and Docker (required for end-to-end tests and the live demo).

```bash
make install              # install dependencies into .venv
make build-sandbox-image  # build the Alpine sandbox image (mcp-box-sandbox:latest)
make test                 # run the full test suite
```

To run the full stack with mock servers:

```bash
docker-compose up -d
# start gateway + trusted + adversarial mock servers

./demo.sh
# fire three attack payloads and show results

docker-compose down
# tear down when finished

sudo fuser -k 8000/tcp 8001/tcp 8002/tcp
# if ports are not released
```

The admin dashboard is at `http://localhost:8000/dashboard/` once the stack is running.

---

## Documentation Roadmap

**First time here?** Start with the [Demo & Walkthrough](demo.md) to see the system in action.

### For Security Researchers & Reviewers
- **[Threat Model](threat_model.md)** — What attacker we defend against and how
- **[Tests Documentation](tests.md)** — 83 tests across 5 defense layers with detailed explanations
- **[Benchmarks](benchmark.md)** — Attack Success Rate reduction (100% → 0%) and performance metrics
- **[References & Papers](references.md)** — Complete citations for all 6 academic papers

### For System Architects & DevOps
- **[API Reference](api.md)** — All 5 endpoints, authentication, integration examples
- **[Architecture](architecture.md)** — System design and data flow
- **[Configuration](configuration.md)** — Policy setup, blocklists, session tuning

### For Understanding the System
- **[Security Layers](security_layers.md)** — Five-tier defense stack explanation
- **[Session Tracking](session_tracking.md)** — Novel multi-turn attack detection
- **[Limitations](limitations.md)** — What we defend against and what we don't

---

## Key Metrics

| Metric | Result |
|--------|--------|
| **Tests** | 83 passing across 13 modules |
| **Attack Success Rate** | 0% (40 tested attack vectors) |
| **False Positive Rate** | 0.8% (acceptable) |
| **Latency Overhead** | +2.3ms per request (~8%) |
| **Threat Coverage** | 92% of documented threat model |

---

## Next Steps

1. **Try the demo:** `./demo.sh` (requires Docker)
2. **Read the tests:** See [Tests Documentation](tests.md)
3. **Integrate the API:** Follow [API Reference](api.md)
4. **Understand the threat model:** Read [Threat Model](threat_model.md)

---

See [References & Papers](references.md) for complete BibTeX entries.
