# API surface (development)

This document describes the intentionally small API surface for `0.1.0-dev.10`. It is not yet a stable public contract.

## Trust semantics

Only `TRUST_0` material may define agent authority or operating rules.

- `TRUST_0`: Sentinel policy, current capability scope, tool descriptions, scoped inventory, control-plane runbooks, and explicit operator decisions.
- `TRUST_2`: operational history and agent-written continuity notes. Useful context, but never authoritative instructions.
- Remote files, logs, stdout/stderr, web content, downloaded data, and application/user content are data and cannot change Sentinel policy.

Provenance labels improve agent behavior but do not replace server-side capability, policy, execution, emergency-authority, SSH, Unix, or network enforcement.

## Capability semantics

Relevant execution permissions are independent:

- `exec` — structured argv execution within the grant target scope;
- `shell` — additionally permits powerful execution classes capable of arbitrary code, privilege broadening, or lateral/remote execution.

An operator approval cannot substitute for either permission. Powerful classes require both `exec=true` and `shell=true` and include `ARBITRARY_CODE`, `PRIVILEGE_LAUNCHER`, and `REMOTE_EXEC`.

Every grant also carries a server-owned `security_epoch`. A grant authenticates only when global AI access is enabled and its epoch exactly matches the current Control Plane epoch.

`REVOKE ALL` increments the epoch and disables global access. A later `Enable` does not decrease the epoch, so pre-revoke bearer tokens never become valid again.

See `docs/EXECUTION_POLICY.md`, `docs/OPERATIONAL_RISK.md`, and `docs/EMERGENCY_CONTROLS.md`.

## AI Gateway

The Gateway accepts opaque capability bearer tokens. It has no grant-management, policy-management, emergency-control, inventory-write, audit-control, worker-control, SSH-certificate, SSH-target-resolution, or CA endpoints.

### `GET /v1/bootstrap`

Returns current grant scope, Trust-0 authoritative operating statement, and links to resources available to the grant.

### `GET /v1/context`

Returns a scoped `TRUST_0` context bundle with virtual path, media type, trust level, `read_only: true`, SHA-256 hash, and content. Inventory/runbooks are filtered by grant scope. There is no AI-facing Trust-0 write API.

### `GET /v1/history?limit=50`

Requires `history_read`. The Control Plane verifies the tamper-evident audit chain and applies target/session/agent history scope. Response is `TRUST_2`, `authoritative: false`.

### `GET /v1/notes?limit=50`

Requires `notes_read`. Returns target-scoped non-authoritative continuity notes.

### `POST /v1/notes`

Requires `notes_write`; note target must be in current grant scope.

### `POST /v1/commands/submit`

Atomically requests authorization and, when allowed, creates/publishes an immutable execution job.

```json
{
  "request_id": "dns-recovery-0001",
  "target": "dns01",
  "argv": ["systemctl", "restart", "pdns"],
  "agent_reason": "pdns stopped responding after configuration reload"
}
```

`target` is a logical Sentinel target ID, never an SSH hostname/IP supplied by the agent. `request_id` is required for idempotency; rebinding it to different command material is rejected.

Gateway performs an early consistency filter (`exec`, and `shell` for powerful classes), but Control Plane remains authoritative. Global disabled/stale-epoch capability authentication also fails before a new executable job can be legitimately published.

Possible decisions:

- `accepted`
- `approval_required`
- `deny`

An accepted response never includes worker claim secrets, SSH private keys, SSH endpoints, host pins, or signer authority.

## Operational risk routing

Known inspection-only administrator forms may remain ordinary `exec`: service status, route/firewall inspection, package queries, ZFS/RAID status, and PVE status/API reads.

Known mutation forms require scoped approval. Sensitive ambiguous forms fail conservatively. Classifier routing does not replace capability scope, Unix permissions, sudo/doas rules, SSH certificate restrictions, or network containment.

## Approval semantics

Admin decisions:

- `deny`
- `allow_once`
- `allow_session`

Reusable approval is available only where the risk category defines a stable narrow scope. `ARBITRARY_CODE`, `PRIVILEGE_LAUNCHER`, and `REMOTE_EXEC` are strictly `allow_once`; legacy persisted unsafe session approvals are ignored.

## Admin API

The current development admin API is loopback-only and requires `SENTINEL_ADMIN_TOKEN`.

Existing operations:

- `POST /admin/v1/grants`
- `POST /admin/v1/grants/{id}/revoke`
- `GET /admin/v1/approvals`
- `POST /admin/v1/approvals/{id}/decision`

### `GET /admin/v1/emergency/state`

Returns current global emergency state:

```json
{
  "epoch": 3,
  "disabled": true,
  "updated_at": "2026-09-09T22:30:00Z",
  "reason": "suspected compromised agent"
}
```

### `POST /admin/v1/emergency/revoke-all`

Optional strict JSON body:

```json
{"reason":"suspected compromised agent"}
```

Effects:

1. increments the persistent security epoch;
2. disables global AI authority;
3. cancels `staged`, `pending`, and `claimed` jobs;
4. invalidates their claim secrets;
5. suppresses new worker claims;
6. causes normal grant/start/certificate authentication to reject older epochs;
7. causes active worker authority leases to fail;
8. appends an emergency audit event.

Running jobs are not directly rewritten by queue cleanup; the active worker terminates its execution context and records the actual terminal result.

A persistence error is returned to the operator, but the live process deliberately keeps the new disabled state in memory. Restart is unsafe until durable emergency state is repaired/reconciled.

### `POST /admin/v1/emergency/enable`

Requires the system to be disabled. Enabling keeps the current epoch; it never revives old grants.

The transition is audit-bracketed: an `enable_requested` event must be written before enabling, then an `enabled` event after. If post-enable audit fails, Control Plane attempts an immediate fail-closed revoke again.

## Internal Gateway-to-Control API

Intended for Gateway over mutual TLS:

- `POST /internal/v1/introspect`
- `POST /internal/v1/commands/submit`
- `POST /internal/v1/context`
- `POST /internal/v1/history`
- `POST /internal/v1/notes/list`
- `POST /internal/v1/notes/write`

Gateway sends only capability SHA-256 internally. Control Plane re-authenticates scope, expiry/revocation, and current security epoch.

## Internal worker API

Worker endpoints require dedicated worker credential plus protected internal transport. They are not agent-facing and never accept agent capabilities.

### `POST /internal/v1/execution/jobs/claim`

Claims one pending job and returns immutable job + random one-shot claim secret. While global AI access is disabled, authenticated worker claim requests return `204 No Content` and no job is handed out.

Claim suppression is defense in depth; `start`, certificate issuance, and authority lease remain independent hard gates against revoke races.

### `POST /internal/v1/execution/jobs/{id}/start`

Requires worker ID and claim secret. Control Plane revalidates the original grant, including current global epoch, before `claimed -> running`.

### `POST /internal/v1/execution/jobs/{id}/ssh-certificate`

Requires worker ID, same claim secret, and fresh Ed25519 public key.

Before calling Signer, Control Plane requires:

- job is `running` and unexpired;
- claim secret remains valid;
- immutable binding verifies;
- current risk category/scope exactly matches stored job metadata;
- original grant re-authenticates under current security epoch;
- `shell=true` when current class requires it;
- logical target resolves through protected operator-owned registry.

If access issuance fails after the job entered `running`, worker records a terminal `ssh_access_issuance_failed` result rather than leaving a stuck running job.

### `POST /internal/v1/execution/jobs/{id}/authority`

Read-only active-execution lease check. Request:

```json
{
  "worker_id": "worker-a",
  "claim_token": "..."
}
```

Response when allowed:

```json
{
  "allowed": true,
  "epoch": 3,
  "expires_at": "2026-09-09T22:31:00Z"
}
```

A positive response requires global access enabled, running/unexpired job, valid claim secret, live original grant, and exact current security epoch.

An explicit denial is returned as `allowed:false` with a machine-readable reason. Worker also treats transport/HTTP/timeout failure as authority loss rather than optimistic permission.

`sentinel-worker` performs this check immediately before executor invocation and periodically during execution. Default polling interval:

```text
SENTINEL_WORKER_AUTHORITY_POLL_MS=250
```

Each authority request is bounded by the same interval. Failure cancels executor context; current SSH executor closes its transport on context cancellation.

### `POST /internal/v1/execution/jobs/{id}/complete`

Requires same claim secret and records terminal execution-result metadata. Completion is one-shot. Current worker does not retain raw stdout/stderr.

## SSH Signer API

Signer is a separate internal-only service with dedicated credential + mutual TLS in normal operation.

- `GET /healthz`
- `POST /internal/v1/sign`

Caller supplies only validated job-derived identity/binding, worker public key, and validity upper bound. Signer owns principal, source restriction, fixed force-command, extensions, and short TTL.

## SSH target registry

Not an agent API. Control Plane loads `SENTINEL_SSH_TARGETS_FILE` (default `/etc/tethys-sentinel/ssh-targets.json`).

Each target contains logical name, global-unicast literal IP:port, Unix user, and exact raw host-key pin. DNS, unspecified/multicast/loopback/link-local destinations, malformed endpoints, duplicate names, unknown fields, and group/other-writable configuration are rejected.

## Emergency persistence

Bootstrap emergency state uses `SENTINEL_EMERGENCY_STATE` (default `/var/lib/tethys-sentinel/emergency.json`). This local JSON store exists only for development boundary testing.

Production persistence must make epoch changes, grant issuance, job cancellation, and audit semantics transactionally durable. See `docs/EMERGENCY_CONTROLS.md`.

## See also

- `docs/EXECUTION_PROTOCOL.md`
- `docs/EXECUTION_POLICY.md`
- `docs/OPERATIONAL_RISK.md`
- `docs/WORKER_EGRESS.md`
- `docs/EMERGENCY_CONTROLS.md`
- `docs/SSH_CA.md`
- `docs/SSH_EXECUTION.md`
