# Tethys Sentinel

Security-first AI infrastructure access broker for granting AI agents narrow, temporary, auditable access to infrastructure without exposing infrastructure SSH private keys.

## Core principles

- Opaque, short-lived capability tokens; only token hashes are stored.
- Human-controlled grants scoped by target, permission, purpose, expiry, and global security epoch.
- Authoritative read-only agent context with explicit trust levels and target-scoped inventory/runbooks.
- Operational history, command output and agent continuity notes are explicitly non-authoritative `TRUST_2` data.
- Risky operations require policy approval even when a session is otherwise authorized.
- `exec` and `shell` are separate capabilities; operator approval cannot manufacture a missing capability.
- Arbitrary-code, privilege-launcher and remote-exec classes require `shell=true` and one-shot operator approval.
- Reusable session approval is forbidden for powerful execution classes because identical argv can still reference mutable scripts, remote state or other changing inputs.
- High-impact administrator mutations are semantically classified while known read-only inspection paths remain autonomous.
- Control Plane, AI Gateway, Execution Worker, SSH Signer, target wrapper, emergency authority state, PostgreSQL authority state, worker network boundary, and operator BFF are independent security layers.
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
- Agent-facing execution output is separately bounded and capability-gated; raw stdout/stderr never becomes authority-bearing context or silently appears in the Operator job read model.
- Append-oriented, tamper-evident audit trail with scoped history reads.
- The browser operator UI is isolated behind `sentinel-operator`: dedicated HTTPS+mTLS, server-side Control admin authority, same-origin CSRF, strict CSP, no persistent browser secret storage, and no generic admin proxy.
- Targets and `TRUST_0` context remain read-only in the browser; the UI cannot widen SSH inventory, Signer/CA policy, PVE egress or authoritative context.

## Status

The accepted execution/security baseline is `0.1.0-dev.13`. The Operator UI integration is `0.1.0-dev.15` and has passed constrained real-infrastructure acceptance on the intended PVE topology. The current development branch `wip/agent-http-cli` is `0.1.0-dev.16`, adding the canonical Agent HTTP API job/readback surface and first-party `sentinelctl`; dev.16 has **not** yet replaced the accepted infrastructure baseline.

The exact deployed dev.15 runtime source checkpoint is `41c343e83596d299af05cf92945395ec008f0fd9`; CI Actions run `34903375824` passed. The accepted deployment uses:

- `sentinel-control` dev.15 with SHA-256 `b1c3b648305a1992b442f9b01980f0fa3556adb1e62bfe63e7c252ecb4397dc6`;
- `sentinel-operator` dev.15 with SHA-256 `ea50c402b93d39e592f18106b3340b8615ede04e94e9957eb2f27abde236956c`;
- the previously accepted dev.13 Gateway/Worker/Signer/execution path unchanged except where the dev.15 Control read/operator surface is required.

Operator acceptance covered dedicated browser mTLS, certificate-derived operator identity, strict security headers, credential separation, read-only state views, CSRF/origin/spoofing negatives, one-time capability reveal, grant issue/revoke, emergency enable/revoke-all, approval deny/allow-once/session-policy semantics, allow-once non-reuse, and a real approved job completing through Worker -> Signer -> pinned SSH -> target. Final accepted authority is intentionally fail-closed at **security epoch 5, disabled=true**, reason `dev.15 approval workflow acceptance complete`.

The Control Plane requires an explicit persistence backend:

```text
SENTINEL_PERSISTENCE_BACKEND=file      # development compatibility mode
SENTINEL_PERSISTENCE_BACKEND=postgres  # production candidate
```

For PostgreSQL, set `SENTINEL_POSTGRES_DSN`. PostgreSQL is authoritative for mutable grants, approvals, execution jobs, emergency authority state, audit/history and Trust-2 agent notes. Trust-0 context, SSH target inventory, signer CA material/policy and external PVE worker-egress policy remain separate operator-owned boundaries.

The accepted dev.15 deployment is on PostgreSQL schema version **2**, which provides the durable `allow_once` approval-to-job binding. The dev.16 candidate requires schema version **3**, adding a separate bounded execution-output table without putting raw stdout/stderr into the general job read model. Grant issue/revoke, approval request/decision, staged authorization, one-shot approval consumption, worker claim/start/complete, emergency transitions and their required audit events remain transactional; PostgreSQL terminal completion with captured output commits terminal state, bounded output and completion audit together.

PostgreSQL startup is fail-closed: backend selection is explicit; DSN, connection, schema version and runtime role are validated; production requires verified TLS; and PostgreSQL failure never falls back to file authority state. Fresh PostgreSQL authority starts disabled.

The PostgreSQL runtime role does not own the schema and receives no schema `CREATE`, table `DELETE`, superuser, role-administration, replication or bypass-RLS authority. Gateway, Worker, Signer and `sentinel-operator` receive no PostgreSQL credentials.

CI exercises the complete development migration chain and integration suite against PostgreSQL 15 and 18 in addition to module tidy, `gofmt`, `go vet` and `go test -race ./...`. Operator UI CI pins the reviewed frontend dependency graph, typechecks/builds the Preact/TypeScript/Vite source, forbids browser persistent secret storage and inline runtime content, and verifies the generated files exactly match the digest-pinned frontend archive embedded in the Go binary.

The worker path is:

```text
submit -> staged authorization -> pending -> claim -> start
       -> ephemeral Ed25519 key -> short-lived certificate
       -> authority check -> pinned-key SSH -> periodic authority lease
       -> forced wrapper -> direct argv execution -> complete
```

Powerful execution classes such as shells/interpreters, privilege launchers, remote pivots, mutable container workload execution/start/build, namespace execution and guest/jail exec paths require both `exec=true` and `shell=true`. They remain `allow_once` only.

### Operator UI v1 — dev.15 accepted WIP

`sentinel-operator` is a separate privileged BFF/web process intended to run on the Control host. The browser authenticates with a dedicated operator TLS client certificate. The service replaces any browser-supplied authority with its own local Control admin credential and forwards only an identity derived from the verified client-certificate leaf.

The operator service uses its own `/etc/tethys-sentinel-operator` configuration root. It is deliberately not granted traversal of `/etc/tethys-sentinel`, which remains the `sentinel-control` security boundary.

The embedded UI provides:

- Overview with fail-closed authority freshness state;
- approval queue with exact structured argv and policy reason;
- grant issue/revoke with one-time in-memory capability reveal;
- job lifecycle/result inspection without inventing raw output;
- verified audit browsing;
- read-only protected SSH target inventory;
- read-only `TRUST_0` context/runbooks;
- emergency Security controls, with global `REVOKE ALL` reachable from every page.

The complete browser/UI code checkpoint is `aaedad5518ad296426b01af856373672a1847f2d`; the deployed dev.15 runtime source checkpoint is `41c343e83596d299af05cf92945395ec008f0fd9`. Deployment and the accepted boundary are documented in `docs/OPERATOR_DEPLOYMENT.md` and `HANDOFF.md`.

### Agent HTTP API + `sentinelctl` — dev.16 candidate

The canonical agent integration is the capability-scoped HTTPS API. `curl` is the reference/raw client and `sentinelctl` is the supported first-party CLI. This milestone deliberately does not add parallel HTTPie/xh/Hurl interfaces or an MCP-specific authority surface; a future MCP adapter must remain a thin client over the accepted HTTP contract.

Dev.16 adds:

- `GET /v1/jobs/{id}` for capability-scoped job polling/readback;
- `GET /v1/requests/{request_id}` for disconnect/idempotency recovery;
- optional per-command `timeout_seconds`, bounded to 900 seconds and grant expiry;
- `sentinelctl bootstrap`, `exec`, `exec --wait`, `job get`, `job wait`, `request get`, and `--json`;
- generated idempotent request IDs when omitted;
- approval-aware `exec --wait` that retries the exact same immutable request after an operator decision;
- no CLI `--token` argument, no insecure TLS mode, no proxy-env routing and no redirect following for capability-bearing requests;
- bounded stdout/stderr capture (256 KiB independently per stream) stored separately from jobs;
- raw output returned only for grants with `history.include_output=true`;
- explicit `stdout_b64` / `stderr_b64` JSON fields for arbitrary bytes;
- human-readable output with terminal control/Unicode-format characters escaped before display.

The full API/CLI contract, `curl` examples and output semantics are documented in `docs/AGENT_HTTP_CLI.md`.

Dev.16 remains a branch candidate. Production is still dev.15/schema v2/epoch 5 disabled until schema migration, Control/Gateway/Worker deployment and constrained real-infrastructure Agent API/CLI acceptance complete.

### Real-infrastructure acceptance

The constrained PVE acceptance has passed for the currently accepted dev.15 baseline on the intended isolated topology. Direct evidence recorded in `HANDOFF.md` covers:

- deny-by-default external Worker egress with only Control HTTPS and registered target SSH allowed;
- real Gateway -> Control -> PostgreSQL -> Worker -> Signer -> pinned SSH -> target wrapper/replay -> terminal audit execution;
- `allow_once` non-reuse;
- individual active grant revoke terminating a live SSH session;
- active global `REVOKE ALL`, security epoch advancement, and old-epoch non-revival after re-enable;
- PostgreSQL state persistence and unavailable-database startup fail-closed with no file fallback/API listener;
- Worker sensitive-material separation, unprivileged service account, required Control mTLS, and no IPv6 bypass;
- exact pinned host-key negotiation against a target advertising multiple host keys;
- browser mTLS/operator identity, CSRF/origin boundaries, one-time capability reveal and operator grant/approval/emergency mutation workflows.

`0.1.0-dev.15` remains the accepted **development/WIP release**, not a production release. The accepted environment is intentionally left at security epoch 5 with AI authority disabled. Dev.16 requires its own constrained acceptance before merge/replacement of that baseline.

## Documentation

- `docs/ARCHITECTURE.md` — trust boundaries and component responsibilities
- `docs/THREAT_MODEL.md` — attacker assumptions, threats and invariants
- `docs/API.md` — current development API surface
- `docs/AGENT_HTTP_CLI.md` — dev.16 Agent HTTP API, `curl` reference flow, `sentinelctl`, output and recovery semantics
- `docs/OPERATOR_UI.md` — Operator UI v1 product/security contract and acceptance criteria
- `docs/OPERATOR_DEPLOYMENT.md` — mTLS operator deployment, isolated configuration boundary and real acceptance procedure
- `docs/EXECUTION_PROTOCOL.md` — staged/claim/start/complete semantics, idempotency and revocation behavior
- `docs/EXECUTION_POLICY.md` — `exec`/`shell` capability split, powerful execution classes and approval semantics
- `docs/OPERATIONAL_RISK.md` — semantic administrator mutation/read-only routing
- `docs/WORKER_EGRESS.md` — generated external worker egress policy, PVE activation/drift checks and real acceptance criteria
- `docs/EMERGENCY_CONTROLS.md` — security epoch, revoke-all, re-enable and active worker termination semantics
- `docs/POSTGRESQL_PERSISTENCE.md` — PostgreSQL schema, transactional invariants, bounded output persistence, roles, migration/cutover and recovery rules
- `docs/INFRASTRUCTURE_ACCEPTANCE.md` — repeatable constrained PVE deployment and pass/fail procedure
- `docs/INFRASTRUCTURE_ACCEPTANCE_REMOTE_POSTGRES.md` — acceptance profile for a pre-existing trusted PostgreSQL service
- `docs/SSH_CA.md` — isolated SSH signer and certificate constraints
- `docs/SSH_EXECUTION.md` — real worker SSH transport, target registry, pinned host-key negotiation, wrapper and replay boundary
- `HANDOFF.md` — accepted infrastructure evidence, development state, decisions and operator-mandated workflow rules
