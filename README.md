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
- High-impact administrator mutations are semantically classified while known read-only inspection paths remain autonomous.
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

`0.1.0-dev.8` release candidate — the real SSH execution boundary and powerful-execution policy are extended with semantic operational-risk coverage for high-impact administration across Linux/BSD services, networking/firewalls, packages, storage, kernel/process state, containers/orchestrators, and hypervisors.

The worker path remains:

```text
claim -> start -> ephemeral Ed25519 key -> short-lived certificate
      -> operator-resolved target -> pinned-key SSH -> forced wrapper
      -> direct argv execution -> complete
```

The Control Plane resolves logical targets through a protected server-side SSH registry. Registry endpoints must be literal IPs and include exact pinned host keys. The agent never supplies the SSH address, Unix account or host identity accepted by the worker.

On the target, the signer-generated certificate force-command invokes `tethys-sentinel-exec`. The wrapper verifies job ID, canonical command binding and the host's local target ID, consumes a root-protected one-shot replay marker, and then executes the exact argv directly without shell re-parsing.

Powerful execution classes such as shells/interpreters, privilege launchers, remote pivots, container workload execution/start/build, namespace execution and guest/jail exec paths require both `exec=true` and `shell=true`. They are `allow_once` only.

`dev.8` additionally distinguishes known administrator inspection paths from state mutation. Examples such as `systemctl status`, `ip route show`, `nft list ruleset`, `iptables -nvL`, `pfctl -vvsr`, package queries, ZFS/RAID status, and PVE status reads remain ordinary `exec` operations. Mutating equivalents require scoped approval. Ambiguous sensitive forms fail conservatively.

The classifier remains a risk-routing layer, not the hard authority boundary. Unix permissions/sudo policy still determine actual file/root authority, and current risk classification is rechecked against immutable argv immediately before SSH certificate issuance.

`dev.8` is still **not a production release**. Before production trust, worker network egress must independently enforce the target set, revoke-all semantics must be completed, bootstrap file stores must move to production persistence, and the full stack must be exercised on a disposable/constrained infrastructure target.

## Documentation

- `docs/ARCHITECTURE.md` — trust boundaries and component responsibilities
- `docs/THREAT_MODEL.md` — attacker assumptions, threats and invariants
- `docs/API.md` — current development API surface
- `docs/EXECUTION_PROTOCOL.md` — staged/claim/start/complete semantics, idempotency and revocation behavior
- `docs/EXECUTION_POLICY.md` — `exec`/`shell` capability split, powerful execution classes and approval semantics
- `docs/OPERATIONAL_RISK.md` — semantic administrator mutation/read-only routing introduced in dev.8
- `docs/SSH_CA.md` — isolated SSH signer and certificate constraints
- `docs/SSH_EXECUTION.md` — real worker SSH transport, target registry, wrapper and replay boundary
- `HANDOFF.md` — development state, decisions and operator-mandated workflow rules
