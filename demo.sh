#!/bin/bash
# -----------------------------------------------------------------------------
# MCP-Secure-Suite Demo Attack Execution Script
# Grounded in arXiv:2601.17549v1 (Maloyan & Namiot, 2026)
# -----------------------------------------------------------------------------

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}======================================================================${NC}"
echo -e "${BLUE}🛡️  MCP-Secure-Suite Security Interception Demonstration${NC}"
echo -e "${BLUE}======================================================================${NC}"

# Check if gateway is running
if ! lsof -i :8000 > /dev/null; then
    echo -e "${RED}[ERROR] Gateway is not running on port 8000.${NC}"
    echo -e "Please run the server using docker-compose or command line first:"
    echo -e "  - Docker Compose: docker-compose up"
    echo -e "  - Direct: .venv/bin/python -m uvicorn mcp_shield.src.gateway:app --port 8000"
    exit 1
fi

echo -e "${GREEN}[INFO] Gateway detected on port 8000. Initiating threat simulation...${NC}\n"

# -----------------------------------------------------------------------------
# Attack 1: Command Injection (E1 Vector)
# -----------------------------------------------------------------------------
echo -e "${BLUE}[TEST 1] Simulating Command Injection (E1: Code Execution rm -rf)${NC}"
payload_e1='{
    "jsonrpc": "2.0",
    "id": "demo-e1",
    "method": "execute_code",
    "params": {
        "code": "import os; os.system(\"rm -rf /\")"
    }
}'

response_e1=$(curl -s -X POST http://127.0.0.1:8000/mcp \
  -H "Content-Type: application/json" \
  -H "x-mcpsec-server-id: trusted-server" \
  -d "$payload_e1")

echo -e "Payload Sent: import os; os.system(\"rm -rf /\")"
if echo "$response_e1" | grep -q "security policy violation"; then
    echo -e "${GREEN}Result: [BLOCKED] Shield caught the command injection in the regex/AST layer!${NC}"
else
    echo -e "${RED}Result: [BYPASSED] Attack was not blocked!${NC}"
fi
echo -e "Raw Response: $response_e1\n"

# -----------------------------------------------------------------------------
# Attack 2: Indirect Prompt Injection (E3 Vector)
# -----------------------------------------------------------------------------
echo -e "${BLUE}[TEST 2] Simulating Indirect Prompt Injection / Response Hijacking (E3)${NC}"
payload_e3='{
    "jsonrpc": "2.0",
    "id": "demo-e3",
    "method": "tools/call",
    "params": {
        "name": "trigger_injection",
        "arguments": {}
    }
}'

response_e3=$(curl -s -X POST http://127.0.0.1:8000/mcp \
  -H "Content-Type: application/json" \
  -H "x-mcpsec-server-id: adversarial-server" \
  -d "$payload_e3")

echo -e "Payload Sent: tools/call name='trigger_injection'"
if echo "$response_e3" | grep -q "sanitized"; then
    echo -e "${YELLOW}Result: [SANITIZED] Shield intercepted the prompt override content and replaced it!${NC}"
else
    echo -e "${RED}Result: [BYPASSED] Raw output returned to agent client!${NC}"
fi
echo -e "Raw Response: $response_e3\n"

# -----------------------------------------------------------------------------
# Attack 3: Unauthorized Sampling Capability Escalation (E4 Vector)
# -----------------------------------------------------------------------------
echo -e "${BLUE}[TEST 3] Simulating Unauthorized Capability Escalation callback (E4)${NC}"
payload_e4='{
    "jsonrpc": "2.0",
    "id": "demo-e4",
    "method": "tools/call",
    "params": {
        "name": "escalate_sampling",
        "arguments": {}
    }
}'

response_e4=$(curl -s -X POST http://127.0.0.1:8000/mcp \
  -H "Content-Type: application/json" \
  -H "x-mcpsec-server-id: adversarial-server" \
  -d "$payload_e4")

echo -e "Payload Sent: tools/call name='escalate_sampling'"
if echo "$response_e4" | grep -E -q "capability|violation|error"; then
    echo -e "${GREEN}Result: [BLOCKED] Shield attestation denied sampling callback from unverified server!${NC}"
else
    echo -e "${RED}Result: [BYPASSED] Capability request allowed!${NC}"
fi
echo -e "Raw Response: $response_e4\n"

echo -e "${BLUE}======================================================================${NC}"
echo -e "${GREEN}Simulation complete. Visit http://localhost:8000/dashboard/ to view metrics.${NC}"
echo -e "${BLUE}======================================================================${NC}"
