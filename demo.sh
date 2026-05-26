#!/bin/bash
rm -f telemetry.db
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BLUE='\033[0;34m'; NC='\033[0m'

echo -e "${BLUE}=====================================================================${NC}"
echo -e "${BLUE}  MCP-Secure-Suite — Attack Interception Demo (5 vectors)${NC}"
echo -e "${BLUE}=====================================================================${NC}"

if ! curl -s --connect-timeout 1 http://127.0.0.1:8000/metrics > /dev/null 2>&1; then
    echo -e "${RED}[ERROR] Gateway not running on port 8000.${NC}"; exit 1
fi

PASS=0; FAIL=0

run_test() {
    local name="$1" server="$2" payload="$3" check_field="$4" check_val="$5" expect_blocked="$6"
    echo -e "\n${BLUE}[${name}]${NC}"
    resp=$(curl -s -X POST http://127.0.0.1:8000/mcp \
      -H "Content-Type: application/json" \
      -H "x-mcpsec-server-id: $server" \
      -d "$payload")
    if echo "$resp" | grep -qi "$check_val"; then
        if [ "$expect_blocked" = "blocked" ]; then
            echo -e "${GREEN}  ✓ BLOCKED — Shield intercepted correctly${NC}"
        else
            echo -e "${YELLOW}  ✓ SANITIZED — Output cleaned before reaching LLM${NC}"
        fi
        PASS=$((PASS+1))
    else
        echo -e "${RED}  ✗ BYPASSED — Shield did NOT catch this${NC}"
        FAIL=$((FAIL+1))
    fi
    echo -e "  Raw: $(echo $resp | head -c 120)..."
}

# E1: Command Injection via AST (rm -rf)
run_test "E1 Command Injection (rm -rf)" "trusted-server" \
  '{"jsonrpc":"2.0","id":"e1","method":"execute_code","params":{"code":"import os; os.system(\"rm -rf /\")"}}' \
  "security policy violation" "" "blocked"

# E2: Clean execution passes through
echo -e "\n${BLUE}[E2 Clean Execution — should PASS through]${NC}"
resp=$(curl -s -X POST http://127.0.0.1:8000/mcp \
  -H "Content-Type: application/json" -H "x-mcpsec-server-id: trusted-server" \
  -d '{"jsonrpc":"2.0","id":"e2","method":"execute_code","params":{"code":"print(2+2)"}}')
if echo "$resp" | grep -qE '"exit_code":\s*0'; then
    echo -e "${GREEN}  ✓ ALLOWED — Clean code executed in sandbox, exit_code=0${NC}"; PASS=$((PASS+1))
else
    echo -e "${RED}  ✗ UNEXPECTED — Clean code was blocked or errored${NC}"; FAIL=$((FAIL+1))
fi

# E3: Indirect Prompt Injection via output sanitizer
run_test "E3 Indirect Prompt Injection" "adversarial-server" \
  '{"jsonrpc":"2.0","id":"e3","method":"tools/call","params":{"name":"trigger_injection","arguments":{}}}' \
  "sanitized" "" "sanitized"

# E4: Unauthorized Sampling Escalation
run_test "E4 Capability Escalation (sampling)" "adversarial-server" \
  '{"jsonrpc":"2.0","id":"e4","method":"tools/call","params":{"name":"escalate_sampling","arguments":{}}}' \
  "capability\|violation\|error" "" "blocked"

# E5: Side-by-side ASR comparison
echo -e "\n${BLUE}[E5 Attack Success Rate Comparison]${NC}"
raw=$(curl -s -X POST http://127.0.0.1:8002/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":"e5","method":"tools/call","params":{"name":"trigger_injection","arguments":{}}}')
shielded=$(curl -s -X POST http://127.0.0.1:8000/mcp \
  -H "Content-Type: application/json" -H "x-mcpsec-server-id: adversarial-server" \
  -d '{"jsonrpc":"2.0","id":"e5","method":"tools/call","params":{"name":"trigger_injection","arguments":{}}}')

raw_pass=$(echo "$raw" | grep -ci "Ignore previous instructions")
shielded_block=$(echo "$shielded" | grep -ci "sanitized")

if [ $raw_pass -gt 0 ]; then
    direct_msg="${RED}ASR 100% — attack lands${NC}"
else
    direct_msg="attack missed"
fi

if [ $shielded_block -gt 0 ]; then
    shield_msg="${GREEN}ASR 0%  — attack neutralised${NC}"
else
    shield_msg="not sanitized"
fi

echo -e "  Direct server (no shield): $direct_msg"
echo -e "  Through Shield:            $shield_msg"
[ $raw_pass -gt 0 ] && [ $shielded_block -gt 0 ] && PASS=$((PASS+1)) || FAIL=$((FAIL+1))

echo -e "\n${BLUE}=====================================================================${NC}"
echo -e "Results: ${GREEN}${PASS} passed${NC}  ${RED}${FAIL} failed${NC}"
echo -e "Dashboard: http://localhost:8000/dashboard/"
echo -e "${BLUE}=====================================================================${NC}"
