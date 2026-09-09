# Tethys Sentinel

Security-first AI infrastructure access broker for granting AI agents narrow, temporary, auditable access to infrastructure without exposing infrastructure SSH private keys.

## Core principles

- Opaque, short-lived capability tokens; only token hashes are stored.
- Human-controlled grants scoped by target, permission, purpose, and expiry.
- Authoritative read-only agent context with explicit trust levels.
- Risky operations require policy approval even when a session is otherwise authorized.
- Control plane, AI gateway, execution worker, and SSH signer are separate security boundaries.
- Defense in depth: broker policy, approvals, SSH certificates, remote account permissions, and sudo policy.
- Append-oriented, tamper-evident audit trail and optional agent history/notes.
- Emergency session revocation and global AI-access kill switch.

## Status

`0.1.0-dev.2` — capability and process trust boundaries now include persistent narrow approvals and a tamper-evident audit chain. The control plane, not the public gateway, makes authoritative command-authorization decisions. Real SSH execution is intentionally not enabled yet.

**Do not expose this project to untrusted networks yet.** No release is considered deployable until it has been tested and merged as WIP according to the project workflow.

See `docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md`, `docs/API.md`, and `HANDOFF.md`.
