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
