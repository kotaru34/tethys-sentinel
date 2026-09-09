# Tethys Sentinel

Security-first AI infrastructure access broker for granting AI agents narrow, temporary, auditable access to infrastructure without exposing infrastructure SSH private keys.

## Core principles

- Opaque, short-lived capability tokens; only token hashes are stored.
- Human-controlled grants scoped by target, permission, purpose, and expiry.
- Authoritative read-only agent context with explicit trust levels and target-scoped inventory/runbooks.
- Operational history and agent continuity notes are explicitly non-authoritative `TRUST_2` data.
- Risky operations require policy approval even when a session is otherwise authorized.
- Control plane, AI gateway, execution worker, and SSH signer are separate security boundaries.
- Defense in depth: broker policy, approvals, SSH certificates, remote account permissions, and sudo policy.
- Append-oriented, tamper-evident audit trail with scoped history reads.
- Emergency session revocation and global AI-access kill switch are part of the target design.

## Status

`0.1.0-dev.3` — capability, approval and audit foundations now include a control-plane-generated read-only Trust-0 context bundle, scoped inventory/runbooks, tamper-verified history reads, and target-scoped agent continuity notes. The control plane re-authenticates and authorizes these resource reads; the public gateway cannot broaden them. Real SSH execution is intentionally not enabled yet.

**Do not expose this project to untrusted networks yet.** No release is considered deployable until it has been tested in the intended isolated infrastructure and merged as WIP according to the project workflow.

See `docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md`, `docs/API.md`, and `HANDOFF.md`.
