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
- Control Plane, AI Gateway, Execution Worker, SSH Signer, target wrapper, emergency authority state, PostgreSQL authority state, and worker network boundary are independent security layers.
- Execution uses immutable one-shot jobs rather than a separable authorize-now/execute-later flow.
- A claimed job requires an authoritative pre-execution start gate so grant revocation can still stop it before executor invocation.
- SSH credentials are short-lived OpenSSH user certificates issued by an isolated CA service only for an already-running, still-authorized job.
- Before signing, the Control Plane reclassifies immutable argv under current policy and re-authenticates capability scope; stale queued policy fails closed.
- Worker SSH private keys are ephemeral Ed25519 keys generated per job and retained only in worker process memory.
- SSH certificate principal, force-command, source-address restrictions, extensions and signer TTL are signer-owned policy, not caller-controlled fields.
- SSH destinations are resolved only from operator-owned logical target inventory; target endpoints are global-unicast literal IP:port values with exact pinned host keys.
- SSH host-key negotiation is constrained to algorithms compatible with the pinned raw key; RSA pins use RSA-SHA2 rather than SHA-1 `ssh-rsa` fallback.
- Worker runtime egress is externally restricted to the Control Plane HTTPS endpoint plus registered target SSH endpoints; the worker cannot widen this boundary itself.
- The generated PVE Worker policy preserves inbound behavior with `policy_in: ACCEPT` while enforcing deny-by-default outbound containment with `policy_out: DROP`.
- Real SSH execution uses exact pinned host keys, job-expiry deadlines and bounded output accounting.
- Remote execution uses a deterministic job-bound envelope and direct argv execution; Sentinel does not reconstruct agent commands through a shell.
- Target-side replay state enforces at-most-once execution of a job even while its short-lived certificate remains valid.
- Global `REVOKE ALL` advances a monotonic security epoch, permanently invalidating every older grant even after access is re-enabled.
- Active workers continuously revalidate execution authority; explicit revocation or loss of the Control Plane cancels the executor context and SSH transport fail-closed.
- Production mutable security state is PostgreSQL-backed and security-sensitive state transitions are coupled with audit in the same transaction.
- Append-oriented, tamper-evident audit trail with scoped history reads.

## Status

`0.1.0-dev.13` — pinned SSH host-key negotiation + constrained infrastructure acceptance milestone.

The Control Plane requires an explicit persistence backend:

```text
SENTINEL_PERSISTENCE_BACKEND=file      # development compatibility mode
SENTINEL_PERSISTENCE_BACKEND=postgres  # production candidate
```

For PostgreSQL, set `SENTINEL_POSTGRES_DSN`. PostgreSQL is authoritative for mutable grants, approvals, execution jobs, emergency authority state, audit/history and Trust-2 agent notes. Trust-0 context, SSH target inventory, signer CA material/policy and external PVE worker-egress policy remain separate operator-owned boundaries.

Schema version **2** adds a durable `allow_once` approval-to-job binding. Grant issue/revoke, approval request/decision, staged authorization, one-shot approval consumption, worker claim/start/complete, emergency transitions and their required audit events use transactional semantic operations. Concurrent reuse of a consumed one-shot approval is prevented by binding it to exactly one execution job.

PostgreSQL startup is fail-closed: backend selection is explicit; DSN, connection, schema version and runtime role are validated; production requires verified TLS; and PostgreSQL failure never falls back to file authority state. Fresh PostgreSQL authority starts disabled.

The PostgreSQL runtime role does not own the schema and receives no schema `CREATE`, table `DELETE`, superuser, role-administration, replication or bypass-RLS authority. Gateway, Worker and Signer receive no PostgreSQL credentials.

CI exercises the complete migration chain and integration suite against PostgreSQL 15 and 18 in addition to module tidy, `gofmt`, `go vet` and `go test -race ./...`. The accepted dev.13 release HEAD is `bd6796aae2ee192fd9d007bab39a40ab6870dbcc`; its CI run passed the Go suite and both PostgreSQL matrix jobs.

The worker path is:

```text
submit -> staged authorization -> pending -> claim -> start
       -> ephemeral Ed25519 key -> short-lived certificate
       -> authority check -> pinned-key SSH -> periodic authority lease
       -> forced wrapper -> direct argv execution -> complete
```

Powerful execution classes such as shells/interpreters, privilege launchers, remote pivots, mutable container workload execution/start/build, namespace execution and guest/jail exec paths require both `exec=true` and `shell=true`. They remain `allow_once` only.

### Real-infrastructure acceptance

The first constrained PVE acceptance for dev.13 has passed on the intended isolated topology. Direct evidence recorded in `HANDOFF.md` covers:

- deny-by-default external Worker egress with only Control HTTPS and registered target SSH allowed;
- real Gateway -> Control -> PostgreSQL -> Worker -> Signer -> pinned SSH -> target wrapper/replay -> terminal audit execution;
- `allow_once` non-reuse;
- individual active grant revoke terminating a live SSH session;
- active global `REVOKE ALL`, security epoch advancement, and old-epoch non-revival after re-enable;
- PostgreSQL state persistence and unavailable-database startup fail-closed with no file fallback/API listener;
- Worker sensitive-material separation, unprivileged service account, required Control mTLS, and no IPv6 bypass;
- exact pinned host-key negotiation against a target advertising multiple host keys.

`0.1.0-dev.13` is still a **development/WIP milestone, not a production release**. The acceptance result authorizes the first WIP merge checkpoint; further product work such as the operator UI and the deliberately narrow AI/MCP tool surface follows after that checkpoint.

## Documentation

- `docs/ARCHITECTURE.md` — trust boundaries and component responsibilities
- `docs/THREAT_MODEL.md` — attacker assumptions, threats and invariants
- `docs/API.md` — current development API surface
- `docs/EXECUTION_PROTOCOL.md` — staged/claim/start/complete semantics, idempotency and revocation behavior
- `docs/EXECUTION_POLICY.md` — `exec`/`shell` capability split, powerful execution classes and approval semantics
- `docs/OPERATIONAL_RISK.md` — semantic administrator mutation/read-only routing
- `docs/WORKER_EGRESS.md` — generated external worker egress policy, PVE activation/drift checks and real acceptance criteria
- `docs/EMERGENCY_CONTROLS.md` — security epoch, revoke-all, re-enable and active worker termination semantics
- `docs/POSTGRESQL_PERSISTENCE.md` — PostgreSQL schema, transactional invariants, roles, migration/cutover and recovery rules
- `docs/INFRASTRUCTURE_ACCEPTANCE.md` — repeatable constrained PVE deployment and pass/fail procedure
- `docs/INFRASTRUCTURE_ACCEPTANCE_REMOTE_POSTGRES.md` — acceptance profile for a pre-existing trusted PostgreSQL service
- `docs/SSH_CA.md` — isolated SSH signer and certificate constraints
- `docs/SSH_EXECUTION.md` — real worker SSH transport, target registry, pinned host-key negotiation, wrapper and replay boundary
- `HANDOFF.md` — accepted infrastructure evidence, development state, decisions and operator-mandated workflow rules
