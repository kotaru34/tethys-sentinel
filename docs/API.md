# API surface (development)

This document describes the current development API surface through the `0.1.0-dev.14` Operator UI v1 release candidate. It is not yet a stable public contract.

Sentinel deliberately has several different API boundaries. They are not interchangeable:

- the **AI Gateway** accepts agent capability tokens and exposes only capability-scoped agent operations;
- the **Control admin API** is privileged, loopback-only, and authenticated with `SENTINEL_ADMIN_TOKEN`;
- **`sentinel-operator`** is the browser-facing HTTPS+mTLS BFF with an explicit route allowlist; it is not a generic reverse proxy;
- internal Gateway/Worker/Signer APIs are service-to-service boundaries with their own credentials and transport restrictions.

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

## Control admin API

The Control admin API is intended to remain loopback-only and requires:

```text
Authorization: Bearer <SENTINEL_ADMIN_TOKEN>
```

The admin bearer credential is full operator authority. It must never be exposed to the browser or AI Gateway.

### Operator-safe read model

The read model is backend-neutral and returns only sanitized operator state. It does not expose capability hashes, worker claim hashes/secrets, database credentials, bearer credentials, private keys, or Signer CA private material.

Routes:

```text
GET /admin/v1/overview
GET /admin/v1/grants?limit=...&cursor=...&status=...
GET /admin/v1/grants/{id}
GET /admin/v1/approvals?limit=...&cursor=...&status=...
GET /admin/v1/jobs?limit=...&cursor=...&status=...
GET /admin/v1/jobs/{id}
GET /admin/v1/audit?limit=...&cursor=...&status=...
GET /admin/v1/targets
GET /admin/v1/context
GET /admin/v1/emergency/state
```

List limits are bounded server-side. Persistence implementations own cursor semantics.

`GET /admin/v1/targets` exposes the protected SSH target snapshot read-only: logical name, literal endpoint, Unix user, host-key algorithm/fingerprint and raw public host-key pin. There is no browser target mutation route in v1.

`GET /admin/v1/context` exposes a read-only Trust-0 snapshot for operator inspection. There is no browser Trust-0 mutation route in v1.

### State-changing admin routes

```text
POST /admin/v1/grants
POST /admin/v1/grants/{id}/revoke
POST /admin/v1/approvals/{id}/decision
POST /admin/v1/emergency/revoke-all
POST /admin/v1/emergency/enable
```

Calls made directly with the admin bearer credential audit as the default operator actor unless an authenticated privileged caller supplies valid accountability metadata.

`X-Tethys-Operator-Identity` is accepted only after admin authentication on this already-privileged channel. It is accountability metadata, never an independent authorization mechanism. `sentinel-operator` derives this value from the verified client-certificate leaf; browser-supplied identity headers are not trusted.

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

`POST /admin/v1/grants/{id}/revoke` revokes the grant, cancels its non-running executable jobs/claim material as applicable, and records the required audit event transactionally in PostgreSQL. Running jobs lose their authority lease through the already-accepted active-revoke path.

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
  "updated_at": "2026-09-14T19:17:03Z",
  "reason": "dev.13 acceptance complete; first WIP merge finished"
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

## Browser operator BFF (`sentinel-operator`)

The browser never talks to the Control admin listener directly.

`sentinel-operator` serves the embedded static UI and an explicit same-origin API allowlist over HTTPS with required operator client-certificate authentication. The service itself stores the Control admin bearer credential server-side and is restricted to a loopback Control upstream.

It is intentionally **not** a generic `/admin/*` proxy. Unknown API paths do not fall through to static/SPA content and unlisted Control routes are unreachable through the BFF.

### Session and authentication

```text
GET /api/v1/session
```

A successful mTLS-authenticated response returns:

- a stable operator identity derived from SHA-256 of the verified client-certificate leaf;
- a fresh CSRF token.

The matching CSRF cookie is Secure, HttpOnly and SameSite=Strict. The token returned to frontend JavaScript is held only in memory; Sentinel does not use localStorage/sessionStorage for operator secrets.

Every browser response is protected by the configured CSP/security headers. API/security responses use `Cache-Control: no-store`.

### Read routes

```text
GET /api/v1/overview
GET /api/v1/grants
GET /api/v1/grants/{id}
GET /api/v1/approvals
GET /api/v1/jobs
GET /api/v1/jobs/{id}
GET /api/v1/audit
GET /api/v1/targets
GET /api/v1/context
GET /api/v1/emergency/state
GET /healthz
```

Query strings for bounded list/filter operations are forwarded only to the corresponding fixed Control route.

### Mutation routes

```text
POST /api/v1/grants
POST /api/v1/grants/{id}/revoke
POST /api/v1/approvals/{id}/decision
POST /api/v1/emergency/revoke-all
POST /api/v1/emergency/enable
```

Mutations additionally require:

- exact configured HTTPS `Origin`;
- `Sec-Fetch-Site` either absent or `same-origin`;
- CSRF header matching the HttpOnly CSRF cookie;
- verified operator client certificate.

The BFF replaces browser-supplied `Authorization` and operator attribution with server-owned values before forwarding. Redirect following and environment proxy use are disabled so the admin credential cannot be redirected or proxied away from the loopback Control boundary.

See `docs/OPERATOR_UI.md` and `docs/OPERATOR_DEPLOYMENT.md`.

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

The Operator UI can inspect this registry through the sanitized read model but cannot mutate it.

## Persistence boundary

Control Plane requires explicit selection:

```text
SENTINEL_PERSISTENCE_BACKEND=file
SENTINEL_PERSISTENCE_BACKEND=postgres
```

`file` remains development compatibility mode. `postgres` requires `SENTINEL_POSTGRES_DSN`, exact supported schema version and an appropriately restricted runtime role. Production PostgreSQL TLS must verify the server. If PostgreSQL cannot be opened/validated, Control Plane exits and never falls back to file state.

PostgreSQL schema version 2 is authoritative for mutable grants/targets, approvals, execution jobs/claim hashes, emergency authority, audit/history and Trust-2 notes. Trust-0 context, SSH target inventory, signer key/policy and external PVE worker-egress policy remain separate operator-owned boundaries.

Gateway, Worker, Signer and `sentinel-operator` do not receive the PostgreSQL runtime credential.

See `docs/POSTGRESQL_PERSISTENCE.md` and `docs/INFRASTRUCTURE_ACCEPTANCE.md`.

## See also

- `docs/ARCHITECTURE.md`
- `docs/OPERATOR_UI.md`
- `docs/OPERATOR_DEPLOYMENT.md`
- `docs/EXECUTION_PROTOCOL.md`
- `docs/EXECUTION_POLICY.md`
- `docs/OPERATIONAL_RISK.md`
- `docs/WORKER_EGRESS.md`
- `docs/EMERGENCY_CONTROLS.md`
- `docs/POSTGRESQL_PERSISTENCE.md`
- `docs/INFRASTRUCTURE_ACCEPTANCE.md`
- `docs/SSH_CA.md`
- `docs/SSH_EXECUTION.md`
