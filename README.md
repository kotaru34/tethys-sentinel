# Tethys Sentinel

Security-first AI infrastructure access broker for granting AI agents narrow, temporary, auditable access to infrastructure without exposing infrastructure SSH private keys.

## Core principles

- Opaque, short-lived capability tokens; only token hashes are stored.
- Human-controlled grants scoped by target, permission, purpose, and expiry.
- Authoritative read-only agent context with explicit trust levels and target-scoped inventory/runbooks.
- Operational history and agent continuity notes are explicitly non-authoritative `TRUST_2` data.
- Risky operations require policy approval even when a session is otherwise authorized.
- `exec` and `shell` are separate capabilities; operator approval cannot manufacture a missing capability.
- Arbitrary-code, privilege-launcher and remote-exec classes require `shell=true` and one-shot operator approval.
- Reusable session approval is forbidden for powerful execution classes because identical argv can still reference mutable scripts, remote state or other changing inputs.
- Control Plane, AI Gateway, Execution Worker, and SSH Signer are separate security boundaries.
- Execution uses immutable one-shot jobs rather than a separable `authorize now / execute later` flow.
- A claimed job requires an authoritative pre-execution start gate so grant revocation can still stop it before executor invocation.
- SSH credentials are short-lived OpenSSH user certificates issued by an isolated CA service only for an already-running, still-authorized job.
- Before signing, the Control Plane reclassifies immutable argv under current policy and re-authenticates capability scope; stale queued policy fails closed.
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

`0.1.0-dev.7` — the real SSH execution boundary is extended with a conservative powerful-execution policy for interpreters, shells, generic command carriers, privilege launchers and remote-execution/pivot tools.

The worker path remains:

```text
claim -> start -> ephemeral Ed25519 key -> short-lived certificate
      -> operator-resolved target -> pinned-key SSH -> forced wrapper
      -> direct argv execution -> complete
```

The Control Plane resolves logical targets through a protected server-side SSH registry. Registry endpoints must be literal IPs and include exact pinned host keys. The agent never supplies the SSH address, Unix account or host identity accepted by the worker.

On the target, the signer-generated certificate force-command invokes `tethys-sentinel-exec`. The wrapper verifies job ID, canonical command binding and the host's local target ID, consumes a root-protected one-shot replay marker, and then executes the exact argv directly without shell re-parsing.

Powerful execution classes such as `bash`, Python, `sudo`, `nsenter`, SSH/Ansible pivots, `kubectl exec`, `docker run`, `find -exec` and equivalent carriers require both `exec=true` and `shell=true`. Their approval scope binds the complete argv, but they are still `allow_once` only: a reusable approval cannot be made safe merely by hashing argv because referenced scripts, images, remote systems or other external state may change.

The Gateway rejects an unreachable powerful request early when `shell=false`, but the hard enforcement point remains immediately before SSH certificate issuance. At that point the Control Plane re-runs the current classifier against immutable `job.argv`, requires category/scope consistency with the job, re-authenticates the grant, and withholds credentials if current policy or capabilities no longer permit execution.

`dev.7` is still **not a production release**. Before production trust, semantic risk coverage for additional operational mutation classes must be expanded, bootstrap file stores must move to production persistence, network egress must independently enforce the target set, revoke-all semantics must be completed, and the full stack must be exercised on a disposable/constrained infrastructure target.

## Documentation

- `docs/ARCHITECTURE.md` — trust boundaries and component responsibilities
- `docs/THREAT_MODEL.md` — attacker assumptions, threats and invariants
- `docs/API.md` — current development API surface
- `docs/EXECUTION_PROTOCOL.md` — staged/claim/start/complete semantics, idempotency and revocation behavior
- `docs/EXECUTION_POLICY.md` — `exec`/`shell` capability split, powerful execution classes and approval semantics
- `docs/SSH_CA.md` — isolated SSH signer and certificate constraints
- `docs/SSH_EXECUTION.md` — real worker SSH transport, target registry, wrapper and replay boundary
- `HANDOFF.md` — development state, decisions and operator-mandated workflow rules
