# MCP-Secure-Suite

A dual-layer security proxy for the Model Context Protocol (MCP). Built as an open-source implementation of the mitigations proposed in [Breaking the Protocol](https://arxiv.org/abs/2601.17549) (Maloyan & Namiot, arXiv:2601.17549, Jan 2026).

MCP has three documented protocol-level vulnerabilities — capability escalation, unauthenticated sampling, and implicit cross-server trust propagation. This suite blocks all three, plus code injection and indirect prompt injection, at the protocol boundary before anything reaches the host system.

**[Click here for full documentation.](https://rishitnanda.github.io/mcp_secure/)**

---

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

## References

Maloyan, N. & Namiot, D. (2026). *Breaking the Protocol: Security Analysis of the Model Context Protocol Specification and Prompt Injection Vulnerabilities in Tool-Integrated LLM Agents*. arXiv:2601.17549v1 [cs.CR].

Maloyan, N. & Namiot, D. (2026). *Prompt Injection Attacks on Agentic Coding Assistants: A Systematic Analysis of Vulnerabilities in Skills, Tools, and Protocol Ecosystems*. arXiv:2601.17548 [cs.CR].

Maloyan, N. & Namiot, D. (2026). *Sleeper Channels and Provenance Gates: Persistent Prompt Injection in Always-on Autonomous AI Agents*. arXiv:2605.13471 [cs.CR].

Rostamzadeh, M. et al. (2026). *MCP-DPT: A Defense-Placement Taxonomy and Coverage Analysis for Model Context Protocol Security*. arXiv:2604.07551 [cs.CR].

Yang, Y. et al. (2025). *MCPSecBench: A Systematic Security Benchmark and Playground for Testing Model Context Protocols*. arXiv:2508.13220 [cs.CR].

Liu, Y. et al. (2025). “Your AI, My Shell”: Demystifying Prompt Injection Attacks on Agentic AI Coding Editors. arXiv:2509.22040 [cs.CR].

--- 

MIT — see [LICENSE](LICENSE) for details.
