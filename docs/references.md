# References

This page provides complete citations for all research papers referenced throughout the MCP Shield documentation and implementation.

---

## Primary Defense Basis

### Breaking the Protocol: Security Analysis of the Model Context Protocol

**Citation:**  
Maloyan, N. & Namiot, D. (2026). *Breaking the Protocol: Security Analysis of the Model Context Protocol Specification and Prompt Injection Vulnerabilities in Tool-Integrated LLM Agents*. arXiv:2601.17549v1 [cs.CR].

**Relevance:** This paper identifies the three core protocol-level vulnerabilities that MCP Shield addresses: capability escalation, unauthenticated sampling, and implicit cross-server trust propagation. It provides the threat model foundation for the entire defense architecture.

**Key Sections Referenced:**
- Section II.A: MCP Protocol Architecture
- Section II.B: Threat Model and Attacker Capabilities
- Section III: Vulnerability Analysis
- Section IV: Attack Scenarios

**Implementation Basis:**
- Tier 4 (Certificate validation) addresses Section III.1 findings on capability escalation
- Tier 2 (Input filtering) addresses Section III.2 findings on injection attacks
- SessionStore (Tier 3) extends findings with multi-turn analysis

---

## Related Attack Studies

### Prompt Injection Attacks on Agentic Coding Assistants

**Citation:**  
Maloyan, N. & Namiot, D. (2026). *Prompt Injection Attacks on Agentic Coding Assistants: A Systematic Analysis of Vulnerabilities in Skills, Tools, and Protocol Ecosystems*. arXiv:2601.17548 [cs.CR].

**Relevance:** Comprehensive taxonomy of prompt injection attack vectors at the tool layer, including response-based injections and cross-tool context attacks.

**Key Sections Referenced:**
- Section III: Response Injection Taxonomy
- Section IV: Multi-turn Contextual Attacks
- Section V: Detection and Mitigation

**Implementation Basis:**
- Output sanitizer test cases (`test_output_sanitizer_*`) cover findings from Section III
- Session tracking rules address findings from Section IV

---

### Sleeper Channels and Provenance Gates

**Citation:**  
Maloyan, N. & Namiot, D. (2026). *Sleeper Channels and Provenance Gates: Persistent Prompt Injection in Always-on Autonomous AI Agents*. arXiv:2605.13471 [cs.CR].

**Relevance:** Analyzes persistence attacks and cross-session state drift in long-running agent systems, directly motivating the need for session-layer defenses.

**Key Sections Referenced:**
- Section II: State Persistence Vulnerabilities
- Section III: Cross-Session Injection Chains
- Section V: Recommended Defenses

**Implementation Basis:**
- SessionStore TTL mechanisms address findings from Section II
- Sequence rules address findings from Section III.2 on "sleeper" multi-call attacks

---

## Benchmarking and Taxonomy

### MCP-DPT: A Defense-Placement Taxonomy

**Citation:**  
Rostamzadeh, M. et al. (2026). *MCP-DPT: A Defense-Placement Taxonomy and Coverage Analysis for Model Context Protocol Security*. arXiv:2604.07551 [cs.CR].

**Relevance:** Provides the defense layering taxonomy (Tiers 1-5) used to organize MCP Shield's test suite. Offers metrics for security coverage evaluation.

**Key Sections Referenced:**
- Section III: Defense Placement Categories
- Section IV: Coverage Matrix and Metrics
- Table II: Defense vs. Attack Mapping

**Implementation Basis:**
- The five-tier test organization (Data → Filters → Sessions → Crypto → Isolation) directly corresponds to MCP-DPT taxonomy
- Test coverage metrics in [tests.md](tests.md) use MCP-DPT's attack-defense mapping

---

### MCPSecBench: A Systematic Security Benchmark

**Citation:**  
Yang, Y. et al. (2025). *MCPSecBench: A Systematic Security Benchmark and Playground for Testing Model Context Protocols*. arXiv:2508.13220 [cs.CR].

**Relevance:** Provides standardized attack scenarios and evaluation methodology for MCP security systems. Benchmarking framework for comparative analysis.

**Key Sections Referenced:**
- Section III: Attack Scenario Library
- Section IV: Evaluation Methodology
- Table I: Benchmark Test Matrix

**Implementation Basis:**
- The 40-case synthetic benchmark (in `test_synthetic_benchmark.py`) is based on MCPSecBench's test matrix
- End-to-end tests use MCPSecBench's attack scenario descriptions

---

## Practical Attack Demonstrations

### "Your AI, My Shell": Demystifying Prompt Injection Attacks

**Citation:**  
Liu, Y. et al. (2025). "Your AI, My Shell": Demystifying Prompt Injection Attacks on Agentic AI Coding Editors. arXiv:2509.22040 [cs.CR].

**Relevance:** Provides practical, reproducible attack demonstrations on real LLM coding systems. Attack scenarios directly influence MCP Shield's regex and AST filter rules.

**Key Sections Referenced:**
- Section IV: Practical Attack Walkthroughs
- Section V.2: Obfuscation Techniques
- Figure 3: Attack Chains

**Implementation Basis:**
- Regex filters include patterns from Section V.2 analysis:
  - Base64 encoding detection
  - Shell command piping (curl | bash, wget | sh)
  - Permission manipulation (chmod, chown)
- AST traversal rules include obfuscation techniques from Section IV

---

## How to Read These References

### By Research Goal

**Understanding the threat model:**  
→ Start with "Breaking the Protocol" (Maloyan & Namiot 2026, 2601.17549), Section II.B

**Understanding attack tactics:**  
→ "Prompt Injection Attacks on Agentic Coding Assistants" (Maloyan & Namiot 2026, 2601.17548), Section III-IV

**Understanding multi-turn attacks:**  
→ "Sleeper Channels and Provenance Gates" (Maloyan & Namiot 2026, 2605.13471), Section III

**Understanding evaluation methodology:**  
→ "MCPSecBench" (Yang et al. 2025), Section IV

**Understanding practical exploits:**  
→ "Your AI, My Shell" (Liu et al. 2025), Section IV-V

---

## Citation Format

### For Academic Work

**Chicago Style (Notes and Bibliography):**

Maloyan, N. & Namiot, D. "Breaking the Protocol: Security Analysis of the Model Context Protocol Specification and Prompt Injection Vulnerabilities in Tool-Integrated LLM Agents." arXiv:2601.17549v1 [cs.CR] (2026).

**BibTeX:**

```bibtex
@article{Maloyan2026breaking,
  author = {Maloyan, N. and Namiot, D.},
  title = {Breaking the Protocol: Security Analysis of the Model Context 
           Protocol Specification and Prompt Injection Vulnerabilities 
           in Tool-Integrated LLM Agents},
  journal = {arXiv preprint arXiv:2601.17549},
  archivePrefix = {arXiv},
  eprint = {2601.17549},
  primaryClass = {cs.CR},
  year = {2026}
}

@article{Rostamzadeh2026mcp,
  author = {Rostamzadeh, M. and others},
  title = {MCP-DPT: A Defense-Placement Taxonomy and Coverage Analysis 
           for Model Context Protocol Security},
  journal = {arXiv preprint arXiv:2604.07551},
  year = {2026}
}

@article{Yang2025mcpsecbench,
  author = {Yang, Y. and others},
  title = {MCPSecBench: A Systematic Security Benchmark and Playground 
           for Testing Model Context Protocols},
  journal = {arXiv preprint arXiv:2508.13220},
  year = {2025}
}

@article{Liu2025shell,
  author = {Liu, Y. and others},
  title = {{``Your AI, My Shell'': Demystifying Prompt Injection Attacks 
           on Agentic AI Coding Editors}},
  journal = {arXiv preprint arXiv:2509.22040},
  year = {2025}
}
```

---

## Full Reference List

| Paper | Authors | Year | arXiv ID | Field |
|-------|---------|------|----------|-------|
| Breaking the Protocol | Maloyan & Namiot | 2026 | 2601.17549 | MCP Security |
| Prompt Injection on Agentic Assistants | Maloyan & Namiot | 2026 | 2601.17548 | Injection Attacks |
| Sleeper Channels & Provenance Gates | Maloyan & Namiot | 2026 | 2605.13471 | Persistence Attacks |
| MCP-DPT | Rostamzadeh et al. | 2026 | 2604.07551 | Defense Taxonomy |
| MCPSecBench | Yang et al. | 2025 | 2508.13220 | Benchmarking |
| Your AI, My Shell | Liu et al. | 2025 | 2509.22040 | Practical Exploits |

---

## Accessing Papers

All papers are available on arXiv:

- https://arxiv.org/abs/2601.17549 (Breaking the Protocol)
- https://arxiv.org/abs/2601.17548 (Prompt Injection Attacks)
- https://arxiv.org/abs/2605.13471 (Sleeper Channels)
- https://arxiv.org/abs/2604.07551 (MCP-DPT)
- https://arxiv.org/abs/2508.13220 (MCPSecBench)
- https://arxiv.org/abs/2509.22040 (Your AI, My Shell)

---

## Relationship to MCP Shield

```
┌─────────────────────────────────────────────────────┐
│  Breaking the Protocol (2601.17549)                 │
│  ↓ Identifies vulnerabilities                       │
│  ├─→ Capability Escalation                         │
│  ├─→ Unauthenticated Sampling                      │
│  └─→ Cross-Server Trust Propagation                │
└──────────┬──────────────────────────────────────────┘
           │
      ┌────┴──────┬─────────────────┬──────────────────┐
      ↓           ↓                 ↓                  ↓
  ┌────────┐  ┌─────────┐  ┌──────────────┐  ┌──────────┐
  │Injection│  │Sleeper  │  │Defense       │  │Benchmark │
  │Attacks  │  │Channels │  │Taxonomy      │  │           │
  │(2601.   │  │(2605.   │  │(2604.07551)  │  │(2508.     │
  │17548)   │  │13471)   │  │              │  │13220)     │
  └──┬──────┘  └────┬────┘  │              │  │          │
     │              │       │              │  │          │
     ↓              ↓       ↓              ↓  ↓          │
  ┌──────────────────────────────────────────────────────┐
  │         MCP Shield Implementation                    │
  │  ├─ Tier 2: Regex + AST filters (Injection)        │
  │  ├─ Tier 3: Session tracking (Sleeper)             │
  │  ├─ Tier 4: Crypto validation                      │
  │  ├─ Tier 5: Isolation + E2E tests (Benchmark)      │
  │  └─ [Practical Exploits: Your AI, My Shell]        │
  └──────────────────────────────────────────────────────┘
```

---

## Contributing New References

If you identify additional relevant papers, please:

1. Open a GitHub issue with paper details and relevance to MCP security
2. Submit a PR with updated citations and implementation basis
3. Update [test_results.md](test_results.md) if new attack scenarios are added

---

## Disclaimer

MCP Shield aims to implement defenses based on the threat models identified in the cited papers. However:

- Papers may identify threats that are **not yet exploitable in practice** (research ahead of exploitation)
- Some defenses may be **incomplete or imperfect** (security is a continuous process)
- New vulnerabilities may be **discovered after this documentation is published**
- This implementation should **not be considered bulletproof** or "certified secure"

Always keep MCP Shield and dependencies updated, and monitor for new research in MCP/LLM security.
