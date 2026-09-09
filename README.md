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
- Control Plane, AI Gateway, Execution Worker, SSH Signer, target wrapper and worker network boundary are independent security layers.
- Execution uses immutable one-shot jobs rather than a separable `authorize now / execute later` flow.
- A claimed job requires an authoritative pre-execution start gate so grant revocation can still stop it before executor invocation.
- SSH credentials are short-lived OpenSSH user certificates issued by an isolated CA service only for an already-running, still-authorized job.
- Before signing, the Control Plane reclassifies immutable argv under current policy and re-authenticates capability scope; stale queued policy fails closed.
- Worker SSH private keys are ephemeral Ed25519 keys generated per job and retained only in worker process memory.
- SSH certificate principal, force-command, source-address restrictions, extensions and signer TTL are signer-owned policy, not caller-controlled fields.
- SSH destinations are resolved only from operator-owned logical target inventory; target endpoints are global-unicast literal IP:port values with exact pinned host keys.
- Worker runtime egress is designed to be externally restricted to the Control Plane HTTPS endpoint plus registered target SSH endpoints; the worker cannot widen this boundary itself.
- Real SSH execution uses exact pinned host keys, job-expiry deadlines and bounded output accounting.
- Remote execution uses a deterministic job-bound envelope and direct argv execution; Sentinel does not reconstruct agent commands through `/bin/sh -c`.
- Target-side replay state enforces at-most-once execution of a job even while its short-lived certificate remains valid.
- Append-oriented, tamper-evident audit trail with scoped history reads.
- Emergency session revocation and global AI-access kill switch are part of the target design.

## Status

`0.1.0-dev.9` release candidate — the real SSH execution boundary, powerful-command policy and semantic operational-risk routing now have an independent worker egress policy layer designed for host-side Proxmox VE enforcement.

The worker path remains:

```text
claim -> start -> ephemeral Ed25519 key -> short-lived certificate
      -> operator-resolved target -> pinned-key SSH -> forced wrapper
      -> direct argv execution -> complete
```

The Control Plane resolves logical targets through a protected server-side SSH registry. Target endpoints must be global-unicast literal IPs with explicit ports and exact pinned host keys. The agent never supplies the SSH address, Unix account or host identity accepted by the worker.

Powerful execution classes such as shells/interpreters, privilege launchers, remote pivots, mutable container workload execution/start/build, namespace execution and guest/jail exec paths require both `exec=true` and `shell=true`. They are `allow_once` only.

Known administrator inspection paths such as service status, route/firewall inspection, package queries, ZFS/RAID status and PVE status/API reads remain ordinary `exec`; high-impact mutation forms require scoped approval.

`dev.9` adds `sentinel-egress-policy`, an operator-side deterministic renderer/verifier for the worker runtime network allowlist. It permits only:

- the literal-IP Control Plane HTTPS endpoint;
- registered target IP:SSH-port endpoints.

The generated PVE VM policy uses `policy_out: DROP`; it has no blanket egress allow. The tool can verify byte-for-byte policy drift plus Proxmox Datacenter firewall activation and `firewall=1` on the selected VM NIC. It does not apply firewall changes and must never be exposed to the worker/AI as a privileged reconciliation path.

The external PVE firewall is the intended hard network boundary because a compromised worker guest must not be able to widen its own egress. Guest-local nftables is optional defense in depth only.

`dev.9` is still **not a production release**. The generated policy/activation checks must still be validated with packet-level behavior from inside the intended worker VM. Global revoke-all semantics and production PostgreSQL persistence also remain before production trust.

## Documentation

- `docs/ARCHITECTURE.md` — trust boundaries and component responsibilities
- `docs/THREAT_MODEL.md` — attacker assumptions, threats and invariants
- `docs/API.md` — current development API surface
- `docs/EXECUTION_PROTOCOL.md` — staged/claim/start/complete semantics, idempotency and revocation behavior
- `docs/EXECUTION_POLICY.md` — `exec`/`shell` capability split, powerful execution classes and approval semantics
- `docs/OPERATIONAL_RISK.md` — semantic administrator mutation/read-only routing
- `docs/WORKER_EGRESS.md` — generated external worker egress policy, PVE activation/drift checks and real acceptance criteria
- `docs/SSH_CA.md` — isolated SSH signer and certificate constraints
- `docs/SSH_EXECUTION.md` — real worker SSH transport, target registry, wrapper and replay boundary
- `HANDOFF.md` — development state, decisions and operator-mandated workflow rules
