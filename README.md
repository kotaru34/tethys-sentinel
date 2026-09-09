# Tethys Sentinel

Security-first AI infrastructure access broker for granting AI agents narrow, temporary, auditable access to infrastructure without exposing infrastructure SSH private keys.

## Core principles

- Opaque, short-lived capability tokens; only token hashes are stored.
- Human-controlled grants scoped by target, permission, purpose, and expiry.
- Authoritative read-only agent context with explicit trust levels and target-scoped inventory/runbooks.
- Operational history and agent continuity notes are explicitly non-authoritative `TRUST_2` data.
- Risky operations require policy approval even when a session is otherwise authorized.
- Control plane, AI gateway, execution worker, and SSH signer are separate security boundaries.
- Execution uses immutable one-shot jobs rather than a separable `authorize now / execute later` flow.
- A claimed job requires an authoritative pre-execution start gate so grant revocation can still stop it before executor invocation.
- Defense in depth: broker policy, approvals, execution-job integrity, SSH certificates, remote account permissions, and sudo/doas policy.
- Append-oriented, tamper-evident audit trail with scoped history reads.
- Emergency session revocation and global AI-access kill switch are part of the target design.

## Status

`0.1.0-dev.4` — capability, approval, audit, Trust-0 context/continuity, and the execution-job security protocol are implemented. Command submission is idempotent and bound to grant + request ID + target + argv; jobs move through staged/pending/claimed/running states, use HMAC-protected bootstrap persistence and one-shot claim secrets, and are revalidated against the grant immediately before execution may start.

Real SSH execution and SSH certificate signing are intentionally **not enabled yet**. `dev.4` establishes the execution trust boundary first so the later SSH executor cannot bypass authorization, approval, replay or revocation semantics.

**Do not expose this project to untrusted networks yet.** No release is considered deployable until it has been tested in the intended isolated infrastructure and merged as WIP according to the project workflow.

## Documentation

- `docs/ARCHITECTURE.md` — trust boundaries and component responsibilities
- `docs/THREAT_MODEL.md` — attacker assumptions, threats and invariants
- `docs/API.md` — current development API surface
- `docs/EXECUTION_PROTOCOL.md` — staged/claim/start/complete semantics, idempotency and revocation behavior
- `HANDOFF.md` — development state, decisions and operator-mandated workflow rules
