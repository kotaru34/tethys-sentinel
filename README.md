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
- Defense in depth: broker policy, approvals, execution-job integrity, SSH certificates, remote account permissions, and sudo/doas policy.
- Append-oriented, tamper-evident audit trail with scoped history reads.
- Emergency session revocation and global AI-access kill switch are part of the target design.

## Status

`0.1.0-dev.5` — the capability/approval/audit/context stack, immutable execution-job protocol, and isolated SSH CA/Signer boundary are implemented and test-covered.

The Control Plane is the only signer client. Certificate issuance requires a `running` job, valid one-shot claim secret, verified immutable command binding, and another grant revalidation immediately before signing. The signer issues tightly constrained Ed25519 OpenSSH user certificates with exact worker source-address binding, no forwarding/PTY extensions, signer-generated force-command, and validity capped by the execution-job expiry.

Real SSH dialing into infrastructure, target host-key verification and the remote root-owned forced-command wrapper are intentionally **not enabled yet**. Those form the next security boundary and will be implemented/tested before any real infrastructure deployment.

**Do not expose this project to untrusted networks yet.** No release is considered deployable until it has been tested in the intended isolated infrastructure and merged as WIP according to the project workflow.

## Documentation

- `docs/ARCHITECTURE.md` — trust boundaries and component responsibilities
- `docs/THREAT_MODEL.md` — attacker assumptions, threats and invariants
- `docs/API.md` — current development API surface
- `docs/EXECUTION_PROTOCOL.md` — staged/claim/start/complete semantics, idempotency and revocation behavior
- `docs/SSH_CA.md` — isolated SSH signer, certificate constraints and credential flow
- `HANDOFF.md` — development state, decisions and operator-mandated workflow rules
