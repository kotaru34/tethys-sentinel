# API surface (development)

This document describes the intentionally small API surface for `0.1.0-dev.11`. It is not yet a stable public contract.

## Trust semantics

Only `TRUST_0` material may define agent authority or operating rules.

- `TRUST_0`: Sentinel policy, current capability scope, tool descriptions, scoped inventory, control-plane runbooks, and explicit operator decisions.
- `TRUST_2`: operational history and agent-written continuity notes. Useful context, but never authoritative instructions.
- Remote files, logs, stdout/stderr, web content, downloaded data, and application/user content are data and cannot change Sentinel policy.

Provenance labels improve agent behavior but do not replace server-side capability, policy, execution, emergency-authority, SSH, Unix, database, or network enforcement.

## Capability semantics

Relevant execution permissions are independent:

- `exec` — structured argv execution within the grant target scope;
- `shell` — additionally permits powerful execution classes capable of arbitrary code, privilege broadening, or lateral/remote execution.

An operator approval cannot substitute for either permission. Powerful classes require both `exec=true` and `shell=true` and include `ARBITRARY_CODE`, `PRIVILEGE_LAUNCHER`, and `REMOTE_EXEC`.

Every grant carries a server-owned `security_epoch`. A grant authenticates only while global AI access is enabled, its epoch equals current authority state, it is not revoked, and it is unexpired.

`REVOKE ALL` increments the epoch and disables global access. A later `Enable` preserves the incremented epoch, so pre-revoke bearer tokens never become valid again.

## AI Gateway

Gateway accepts opaque capability bearer tokens over TLS. It has no grant-management, policy-management, emergency-control, inventory-write, audit-control, worker-control, SSH-certificate, SSH-target-resolution, PostgreSQL, or CA endpoint.

All capability-facing requests use:

```text
Authorization: Bearer <opaque capability>
```

### `GET /v1/bootstrap`

Returns current grant scope, Trust-0 authoritative operating statement, and resource links available to the grant.

### `GET /v1/context`

Returns the scoped `TRUST_0` context bundle. Inventory/runbooks are filtered by grant scope. There is no AI-facing Trust-0 write API.

### `GET /v1/history?limit=50`

Requires `history_read`. Control Plane verifies the tamper-evident audit chain and applies granted history scope. Response is `TRUST_2`, `authoritative:false`.

### `GET /v1/notes?limit=50`

Requires `notes_read`; notes are scoped non-authoritative continuity data.

### `POST /v1/notes`

Requires `notes_write`; note target must be inside the grant target scope.

### `POST /v1/commands/submit`

Submits immutable command material through the current policy/approval path:

```json
{
  "request_id": "dns-recovery-0001",
  "target": "dns01",
  "argv": ["systemctl", "restart", "pdns"],
  "agent_reason": "pdns stopped responding after configuration reload"
}
```

`target` is a logical Sentinel ID, never an agent-supplied SSH host. `request_id` is required for idempotency and cannot later be rebound to different target/argv material.

Possible decisions:

```text
accepted
approval_required
deny
```

A successful accepted response contains a job receipt, never worker claim secret, SSH private key, SSH endpoint/pin, PostgreSQL credential, or signer authority.

For PostgreSQL, staged authorization is a transactional semantic operation. It revalidates current authority, grant, `exec`, target/agent binding, immutable command hash, current policy and any bound approval before publishing the job.

## Approval semantics

Admin decisions:

```text
deny
allow_once
allow_session
```

`allow_session` is allowed only where current policy defines a stable reusable narrow scope. `ARBITRARY_CODE`, `PRIVILEGE_LAUNCHER`, and `REMOTE_EXEC` are strictly `allow_once`.

PostgreSQL schema version 2 durably binds a consumed one-shot approval to `consumed_by_job_id`. Consumption, that binding, `staged -> pending` publication and the authorization audit event commit in one transaction. A consumed one-shot approval cannot authorize another job in the same scope.

## Admin API

The current admin API is loopback-only and requires:

```text
Authorization: Bearer <SENTINEL_ADMIN_TOKEN>
```

Routes:

```text
POST /admin/v1/grants
POST /admin/v1/grants/{id}/revoke
GET  /admin/v1/approvals
POST /admin/v1/approvals/{id}/decision
GET  /admin/v1/emergency/state
POST /admin/v1/emergency/revoke-all
POST /admin/v1/emergency/enable
```

### Issue grant

`POST /admin/v1/grants` example:

```json
{
  "agent": "agent-a",
  "purpose": "inspect dns01",
  "targets": ["dns01"],
  "permissions": {
    "exec": true,
    "shell": false,
    "upload": false,
    "download": false,
    "history_read": true,
    "notes_read": true,
    "notes_write": true
  },
  "history": {
    "current_session": true,
    "previous_sessions": false,
    "other_agents": false,
    "include_output": false
  },
  "ttl_seconds": 600
}
```

TTL must be 30..28800 seconds. Plaintext capability token is returned once; only its hash is persisted.

In PostgreSQL mode, grant insertion/targets/audit use a semantic transaction and serialize with global revoke through `authority_state`.

### Individual revoke

`POST /admin/v1/grants/{id}/revoke` revokes the grant, cancels its non-running executable jobs/claim material as applicable, and records the required audit event transactionally in PostgreSQL.

### Approval decision

`POST /admin/v1/approvals/{id}/decision` body:

```json
{"decision":"allow_once"}
```

Decision is accepted only from `pending`, current risk policy is re-derived where session reuse matters, and PostgreSQL couples the decision with its audit record.

## Emergency API

### `GET /admin/v1/emergency/state`

Example:

```json
{
  "epoch": 3,
  "disabled": true,
  "updated_at": "2026-09-10T12:00:00Z",
  "reason": "operator maintenance"
}
```

Fresh PostgreSQL state intentionally starts `disabled:true` at epoch 0.

### `POST /admin/v1/emergency/revoke-all`

Optional strict body:

```json
{"reason":"suspected compromised agent"}
```

In PostgreSQL mode, one transaction increments epoch, disables global authority, cancels `staged`/`pending`/`claimed` jobs, clears claim material, appends the emergency audit event and commits. Running jobs lose their worker authority lease and complete through the factual terminal path.

### `POST /admin/v1/emergency/enable`

Requires currently disabled authority. Enable does not decrement epoch and therefore does not revive pre-revoke grants. PostgreSQL state/audit transitions commit atomically.

## Internal Gateway-to-Control API

Intended only over Control Plane mTLS:

```text
POST /internal/v1/introspect
POST /internal/v1/commands/submit
POST /internal/v1/context
POST /internal/v1/history
POST /internal/v1/notes/list
POST /internal/v1/notes/write
```

Gateway sends only the capability SHA-256 internally. Control Plane re-authenticates current scope/expiry/revocation/epoch.

Gateway has no PostgreSQL credential and cannot invoke grant/emergency/approval administration.

## Internal Worker API

Worker endpoints require Control Plane mTLS plus the dedicated worker bearer credential. Worker never receives agent capability plaintext.

### `POST /internal/v1/execution/jobs/claim`

Claims one pending job and returns immutable job + random one-shot claim secret. While global authority is disabled, claim returns no work.

PostgreSQL claim uses `FOR UPDATE SKIP LOCKED`, stores only the claim SHA-256, transitions to `claimed`, appends `execution.job_claimed`, and commits.

### `POST /internal/v1/execution/jobs/{id}/start`

Requires worker ID + claim secret. PostgreSQL start locks/revalidates current authority and original grant before `claimed -> running`, then records `execution.job_started` in the same transaction.

### `POST /internal/v1/execution/jobs/{id}/ssh-certificate`

Requires worker ID, same claim secret, and a fresh Ed25519 public key.

Control Plane requires:

- running/unexpired job;
- valid claim;
- intact immutable command binding;
- current risk category/scope equal stored job metadata;
- live original grant/current epoch;
- `shell=true` when current class requires it;
- logical target resolved through protected operator registry.

Only then may Control Plane call the isolated Signer. If issuance fails after start, Worker records a terminal failure rather than leaving a stranded running job.

### `POST /internal/v1/execution/jobs/{id}/authority`

Read-only active-execution lease check. Positive response requires global authority enabled, running/unexpired job, valid claim, live original grant and exact current epoch.

Worker performs this immediately before executor invocation and periodically during execution. Default interval:

```text
SENTINEL_WORKER_AUTHORITY_POLL_MS=250
```

Transport/HTTP/TLS/timeout failures are authority loss, not optimistic permission.

### `POST /internal/v1/execution/jobs/{id}/complete`

Records terminal result using the same one-shot claim. PostgreSQL completion changes the exact running job, clears claim material and commits the completion audit event atomically.

Completion deliberately does not require the grant to remain active: after revoke cancels an already-running SSH transport, Sentinel must still record what actually happened. Replay fails after the terminal transition.

## SSH Signer API

Signer is a separate internal-only mTLS + bearer-credential service:

```text
GET  /healthz
POST /internal/v1/sign
```

Caller supplies only validated job-derived identity/binding, Worker public key and validity upper bound. Signer owns principal, source restriction, fixed force-command, extensions and short TTL.

## SSH target registry

Not an agent API. Control Plane loads `SENTINEL_SSH_TARGETS_FILE` (default `/etc/tethys-sentinel/ssh-targets.json`).

Each target contains logical name, global-unicast literal IP:port, Unix user and exact raw host-key pin. DNS, unspecified/multicast/loopback/link-local destinations, malformed endpoints, duplicate names, unknown fields and group/other-writable configuration are rejected.

## Persistence boundary

Control Plane requires explicit selection:

```text
SENTINEL_PERSISTENCE_BACKEND=file
SENTINEL_PERSISTENCE_BACKEND=postgres
```

`file` remains development compatibility mode. `postgres` requires `SENTINEL_POSTGRES_DSN`, exact supported schema version and an appropriately restricted runtime role. Production PostgreSQL TLS must verify the server. If PostgreSQL cannot be opened/validated, Control Plane exits and never falls back to file state.

PostgreSQL schema version 2 is authoritative for mutable grants/targets, approvals, execution jobs/claim hashes, emergency authority, audit/history and Trust-2 notes. Trust-0 context, SSH target inventory, signer key/policy and external PVE worker-egress policy remain separate operator-owned boundaries.

See `docs/POSTGRESQL_PERSISTENCE.md` and `docs/INFRASTRUCTURE_ACCEPTANCE.md`.

## See also

- `docs/ARCHITECTURE.md`
- `docs/EXECUTION_PROTOCOL.md`
- `docs/EXECUTION_POLICY.md`
- `docs/OPERATIONAL_RISK.md`
- `docs/WORKER_EGRESS.md`
- `docs/EMERGENCY_CONTROLS.md`
- `docs/POSTGRESQL_PERSISTENCE.md`
- `docs/INFRASTRUCTURE_ACCEPTANCE.md`
- `docs/SSH_CA.md`
- `docs/SSH_EXECUTION.md`
