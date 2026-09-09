# Tethys Sentinel

Security-first AI infrastructure access broker for granting AI agents narrow, temporary, auditable access to infrastructure without exposing infrastructure SSH private keys.

## Core principles

- Opaque, short-lived capability tokens; only token hashes are stored.
- Human-controlled grants scoped by target, permission, purpose, expiry, and global security epoch.
- Authoritative read-only agent context with explicit trust levels and target-scoped inventory/runbooks.
- Operational history and agent continuity notes are explicitly non-authoritative `TRUST_2` data.
- Risky operations require policy approval even when a session is otherwise authorized.
- `exec` and `shell` are separate capabilities; operator approval cannot manufacture a missing capability.
- Arbitrary-code, privilege-launcher and remote-exec classes require `shell=true` and one-shot operator approval.
- Reusable session approval is forbidden for powerful execution classes because identical argv can still reference mutable scripts, remote state or other changing inputs.
- High-impact administrator mutations are semantically classified while known read-only inspection paths remain autonomous.
- Control Plane, AI Gateway, Execution Worker, SSH Signer, target wrapper, emergency authority state, and worker network boundary are independent security layers.
- Execution uses immutable one-shot jobs rather than a separable `authorize now / execute later` flow.
- A claimed job requires an authoritative pre-execution start gate so grant revocation can still stop it before executor invocation.
- SSH credentials are short-lived OpenSSH user certificates issued by an isolated CA service only for an already-running, still-authorized job.
- Before signing, the Control Plane reclassifies immutable argv under current policy and re-authenticates capability scope; stale queued policy fails closed.
- Worker SSH private keys are ephemeral Ed25519 keys generated per job and retained only in worker process memory.
- SSH certificate principal, force-command, source-address restrictions, extensions and signer TTL are signer-owned policy, not caller-controlled fields.
- SSH destinations are resolved only from operator-owned logical target inventory; target endpoints are global-unicast literal IP:port values with exact pinned host keys.
- Worker runtime egress is externally restricted to the Control Plane HTTPS endpoint plus registered target SSH endpoints; the worker cannot widen this boundary itself.
- Real SSH execution uses exact pinned host keys, job-expiry deadlines and bounded output accounting.
- Remote execution uses a deterministic job-bound envelope and direct argv execution; Sentinel does not reconstruct agent commands through `/bin/sh -c`.
- Target-side replay state enforces at-most-once execution of a job even while its short-lived certificate remains valid.
- Global `REVOKE ALL` advances a monotonic security epoch, permanently invalidating every older grant even after access is re-enabled.
- Active workers continuously revalidate execution authority; explicit revocation or loss of the Control Plane cancels the executor context and SSH transport fail-closed.
- Append-oriented, tamper-evident audit trail with scoped history reads.

## Status

`0.1.0-dev.10` release candidate — the existing SSH execution, policy, and external worker-egress boundaries now include global revoke-all semantics and active execution termination.

The worker path is now:

```text
claim -> start -> ephemeral Ed25519 key -> short-lived certificate
      -> authority check -> pinned-key SSH -> periodic authority lease
      -> forced wrapper -> direct argv execution -> complete
```

The Control Plane resolves logical targets through a protected server-side SSH registry. Target endpoints must be global-unicast literal IPs with explicit ports and exact pinned host keys. The agent never supplies the SSH address, Unix account or host identity accepted by the worker.

Powerful execution classes such as shells/interpreters, privilege launchers, remote pivots, mutable container workload execution/start/build, namespace execution and guest/jail exec paths require both `exec=true` and `shell=true`. They are `allow_once` only.

Known administrator inspection paths such as service status, route/firewall inspection, package queries, ZFS/RAID status and PVE status/API reads remain ordinary `exec`; high-impact mutation forms require scoped approval.

`dev.9` added a deny-by-default external PVE worker egress boundary. `dev.10` adds the emergency authority layer:

- every grant carries the current monotonic `security_epoch`;
- `REVOKE ALL` increments that epoch and disables global AI access;
- old capabilities remain permanently stale after a later `Enable`;
- staged/pending/claimed jobs are canceled and claim secrets invalidated;
- new worker claims are suppressed while disabled;
- existing `start` and SSH-certificate gates automatically reject stale-epoch grants;
- a worker must pass an authority check before executor invocation and then periodically while the SSH execution is active;
- authority denial, timeout, broken mTLS/control connectivity, global revoke, individual grant revoke, grant expiry, or job expiry terminates the worker execution context fail-closed.

The default active-authority polling interval is 250 ms and is configurable with `SENTINEL_WORKER_AUTHORITY_POLL_MS`.

Active worker termination closes Sentinel's worker-side SSH transport but cannot promise that every already-detached/daemonized process on every target OS is killed or that completed side effects are reversed. Lower target privileges, short credential/job lifetimes, one-shot replay state and network containment remain required.

`dev.10` is still **not a production release**. File-backed bootstrap persistence must move to transactional production state, and the entire stack — including PVE egress enforcement and emergency termination — must still be exercised on disposable/constrained infrastructure before the first WIP merge.

## Documentation

- `docs/ARCHITECTURE.md` — trust boundaries and component responsibilities
- `docs/THREAT_MODEL.md` — attacker assumptions, threats and invariants
- `docs/API.md` — current development API surface
- `docs/EXECUTION_PROTOCOL.md` — staged/claim/start/complete semantics, idempotency and revocation behavior
- `docs/EXECUTION_POLICY.md` — `exec`/`shell` capability split, powerful execution classes and approval semantics
- `docs/OPERATIONAL_RISK.md` — semantic administrator mutation/read-only routing
- `docs/WORKER_EGRESS.md` — generated external worker egress policy, PVE activation/drift checks and real acceptance criteria
- `docs/EMERGENCY_CONTROLS.md` — security epoch, revoke-all, re-enable and active worker termination semantics
- `docs/SSH_CA.md` — isolated SSH signer and certificate constraints
- `docs/SSH_EXECUTION.md` — real worker SSH transport, target registry, wrapper and replay boundary
- `HANDOFF.md` — development state, decisions and operator-mandated workflow rules
