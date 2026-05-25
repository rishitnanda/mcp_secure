# Limitations

- **Container escape via kernel exploit** — Box uses OS-level namespaces, not hardware virtualisation (Firecracker/gVisor). A kernel vulnerability could allow host escape. Acceptable for local development; production deployments should use a VM-backed executor.
- **Persistent injection (sleeper channels)** — attacks that plant artifacts in long-term memory or filesystem cron paths and trigger later are out of scope. See Maloyan & Namiot, arXiv:2605.13471 for this threat model.
- **First-contact TOFU attacks** — on first connection from a server that has never presented ATTESTMCP credentials, the suite operates in permissive mode. Key pinning is not yet implemented.
- **Legitimately certified malicious servers** — attestation proves identity, not behaviour. A server with a valid certificate serving malicious content passes the attestation check.
- **Transport-layer attacks** (MiTM, DNS rebinding) — require TLS termination and certificate pinning at the transport layer, which is outside the current scope.
