# Test results

83 tests, 13 modules, 7.51 seconds.

```text
tests/test_schemas.py              17 passed   Pydantic models, JSON-RPC validation
tests/test_database.py              3 passed   WAL logger, concurrent writes, unavailable DB
tests/test_certs.py                 8 passed   CA fixture, cert verification, expiry, tampering
tests/test_box_isolated.py          6 passed   Clean exec, timeout, network isolation, OOM, cleanup, read-only FS
tests/test_policy_regex.py          8 passed   Blacklist patterns, clean input pass-through
tests/test_policy_ast.py            7 passed   Import blocks, call blocks, attribute blocks, obfuscation
tests/test_namespace_sanitizer.py   7 passed   Namespace lock, output sanitizer, case-insensitive matching
tests/test_hmac.py                  4 passed   Valid HMAC, bad signature, replay, expired timestamp
tests/test_attestation.py           4 passed   Valid cert, expired cert, wrong server ID, capability check
tests/test_engine.py                3 passed   Stage ordering, clean pass, integration
tests/test_end_to_end.py            5 passed   E1–E5 against live gateway and adversarial mock server
tests/test_stdio_proxy.py           3 passed   Pass-through, block, output sanitization
tests/test_session_state.py         5 passed   Multi-turn session tracking, sequence blocks, TTL
```

## Attack success rate (E5 benchmark)

`test_e5_attack_success_rate_comparison` sends the same payload directly to the adversarial server (port 8002, no protection) and through Shield (port 8000), and compares results.

| Attack type | Without Shield | Through Shield | Mitigation triggered |
|---|---|---|---|
| Command injection (`import os; os.system(...)`) | 100% | 0% | AST scan — stage: ast |
| Indirect prompt injection (`Ignore previous instructions`) | 100% | 0% | Output sanitizer |
| Unauthorized sampling escalation | 100% | 0% | Capability attestation |
| Infinite loop / resource exhaustion | 100% | 0% | Box watchdog + OOM cap |

Consistent with the ATTESTMCP effectiveness predictions in the primary reference (arXiv:2601.17549).
