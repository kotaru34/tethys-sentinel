# Tethys Sentinel

Security-first AI infrastructure access broker for granting AI agents narrow, temporary, auditable access to infrastructure without exposing infrastructure SSH private keys.

## Core principles

- Opaque, short-lived capability tokens; only token hashes are stored.
- Human-controlled grants scoped by target, permission, purpose, and expiry.
- Authoritative read-only agent context with explicit trust levels and target-scoped inventory/runbooks.
- Operational history and agent continuity notes are explicitly non-authoritative `TRUST_2` data.
- Risky operations require policy approval even when a session is otherwise authorized.
- Control Plane, AI Gateway, Execution Worker, and SSH Signer are separate security boundaries.
- Execution uses immutable one-shot jobs rather than a separable `authorize now / execute later` flow.
- A claimed job requires an authoritative pre-execution start gate so grant revocation can still stop it before executor invocation.
- SSH credentials are short-lived OpenSSH user certificates issued by an isolated CA service only for an already-running, still-authorized job.
- Worker SSH private keys are ephemeral Ed25519 keys generated per job and retained only in worker process memory.
- SSH certificate principal, force-command, source-address restrictions, extensions and signer TTL are signer-owned policy, not caller-controlled fields.
- SSH destinations are resolved only from operator-owned logical target inventory; agent-supplied hostnames/IPs never become worker destinations.
- Real SSH execution uses literal target IPs, exact pinned host keys, job-expiry deadlines and bounded output accounting.
- Remote execution uses a deterministic job-bound envelope and direct argv execution; Sentinel does not reconstruct agent commands through `/bin/sh -c`.
- Target-side replay state enforces at-most-once execution of a job even while its short-lived certificate remains valid.
- Defense in depth: broker policy, approvals, execution-job integrity, SSH certificates, target identity, remote account permissions, forced-command wrapper, replay guard and sudo/doas policy.
- Append-oriented, tamper-evident audit trail with scoped history reads.
- Emergency session revocation and global AI-access kill switch are part of the target design.

## Status

`0.1.0-dev.6` — the capability/approval/audit/context stack, immutable execution-job protocol, isolated SSH CA/Signer, and first real SSH execution boundary are implemented and test-covered.

The worker now performs the complete job path:

```text
claim -> start -> ephemeral Ed25519 key -> short-lived certificate
      -> operator-resolved target -> pinned-key SSH -> forced wrapper
      -> direct argv execution -> complete
```

The Control Plane resolves logical targets through a protected server-side SSH registry. Registry endpoints must be literal IPs and include exact pinned host keys. The agent never supplies the SSH address, Unix account or host identity accepted by the worker.

On the target, the signer-generated certificate force-command invokes `tethys-sentinel-exec`. The wrapper verifies job ID, canonical command binding and the host's local target ID, consumes a root-protected one-shot replay marker, and then executes the exact argv directly without shell re-parsing.

The SSH client has explicit dial/handshake deadlines, execution is capped by job expiry, and stdout/stderr are hashed rather than retained by the current worker. Exceeding the configured accounting limit actively terminates the SSH transport.

`dev.6` is still **not a production release**. Before production trust, interpreter/shell/privilege-launcher risk handling needs another hardening pass, bootstrap file stores must move to production persistence, network egress must independently enforce the target set, revoke-all semantics must be completed, and the full stack must be exercised on a disposable/constrained infrastructure target.

## Documentation

- `docs/ARCHITECTURE.md` — trust boundaries and component responsibilities
- `docs/THREAT_MODEL.md` — attacker assumptions, threats and invariants
- `docs/API.md` — current development API surface
- `docs/EXECUTION_PROTOCOL.md` — staged/claim/start/complete semantics, idempotency and revocation behavior
- `docs/SSH_CA.md` — isolated SSH signer and certificate constraints
- `docs/SSH_EXECUTION.md` — real worker SSH transport, target registry, wrapper and replay boundary
- `HANDOFF.md` — development state, decisions and operator-mandated workflow rules
