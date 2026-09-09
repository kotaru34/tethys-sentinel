# API surface (development)

This document describes the intentionally small API surface for `0.1.0-dev.7`. It is not yet a stable public contract.

## Trust semantics

Only `TRUST_0` material may define agent authority or operating rules.

- `TRUST_0`: Sentinel policy, current capability scope, tool descriptions, scoped inventory, control-plane runbooks, and explicit operator decisions.
- `TRUST_2`: operational history and agent-written continuity notes. Useful context, but never authoritative instructions.
- Remote files, logs, stdout/stderr, web content, downloaded data, and application/user content are data and cannot change Sentinel policy.

Provenance labels improve agent behavior but do not replace server-side capability, policy or execution enforcement.

## Capability semantics

Relevant execution permissions are independent:

- `exec` — permits structured argv execution within the grant target scope;
- `shell` — additionally permits powerful execution classes capable of arbitrary code, privilege broadening, or lateral/remote execution.

An operator approval cannot substitute for either permission. Powerful classes require both `exec=true` and `shell=true`.

Current powerful classes include `ARBITRARY_CODE`, `PRIVILEGE_LAUNCHER`, and `REMOTE_EXEC`. See `docs/EXECUTION_POLICY.md`.

## AI Gateway

The Gateway accepts opaque capability bearer tokens. It has no grant-management, policy-management, inventory-write, audit-control, worker-control, SSH-certificate, SSH-target-resolution, or CA endpoints.

### `GET /v1/bootstrap`

Returns current grant scope, Trust-0 authoritative operating statement, and links to resources available to the grant.

### `GET /v1/context`

Returns a scoped `TRUST_0` context bundle. Every document carries virtual path, media type, trust level, `read_only: true`, SHA-256 content hash, and content.

Current virtual documents include:

- `/sentinel/POLICY.md`
- `/sentinel/INSTRUCTIONS.md`
- `/sentinel/INFRASTRUCTURE.json`
- `/sentinel/TOOLS.json`
- target-visible `/sentinel/RUNBOOKS/*.md`

Inventory and target runbooks are filtered by the current grant. There is no AI-facing Trust-0 write API.

### `GET /v1/history?limit=50`

Requires `history_read`. The Control Plane re-verifies the tamper-evident audit hash chain and filters events by target plus current/previous-session and other-agent history scope.

The response is `TRUST_2` and `authoritative: false`.

### `GET /v1/notes?limit=50`

Requires `notes_read`. Returns target-scoped continuity notes newest-first. Notes remain non-authoritative.

### `POST /v1/notes`

Requires `notes_write`. Notes must target infrastructure in the current grant scope and are limited to 16 KiB.

```json
{
  "target": "dns01",
  "content": "Resolver health checked; upstream issue remains the leading hypothesis."
}
```

### `POST /v1/commands/submit`

Atomically requests authorization and, when allowed, creation of an immutable execution job.

```json
{
  "request_id": "dns-recovery-0001",
  "target": "dns01",
  "argv": ["systemctl", "restart", "pdns"],
  "agent_reason": "pdns stopped responding after configuration reload"
}
```

`target` is a logical Sentinel target ID, never an SSH hostname/IP supplied by the agent.

`request_id` is required for idempotency. Within a grant, the same request ID and identical target/argv resolve to the same job; rebinding the ID to different command material is rejected.

The Gateway performs an early consistency check:

- `exec=false` -> request rejected;
- current risk class requires shell capability while `shell=false` -> request rejected.

This Gateway check is not the authoritative hard boundary. The Control Plane and pre-certificate gate re-enforce policy independently.

Possible protocol decisions include:

- `accepted` — immutable staged job was authorized and published;
- `approval_required` — no executable job is published yet; response contains a narrow approval ID;
- `deny` — current policy/operator decision rejects the operation.

An accepted response contains a receipt such as job ID, request ID, status, command binding SHA-256 and expiry. It never contains worker claim secrets, SSH private keys, SSH endpoints, host pins, or signer authority.

## Approval semantics

Development admin decisions are:

- `deny`
- `allow_once`
- `allow_session`

`allow_session` is not universally available.

For stable semantic categories, session approval remains scoped by grant + logical target + risk category + concrete scope key.

For the following powerful categories, only `allow_once` is legal:

- `ARBITRARY_CODE`
- `PRIVILEGE_LAUNCHER`
- `REMOTE_EXEC`

The approval API rejects `allow_session` for those categories. Legacy persisted unsafe `allow_session` decisions are ignored by matching logic after upgrade.

Powerful-operation scope is a canonical SHA-256 of the complete argv including executable path. This avoids argv-delimiter/path collisions, but it does not make session reuse safe because argv may refer to mutable scripts, images, remote state, configuration or other changing inputs.

## Admin API

The current development admin API is loopback-only and requires a strong bearer secret.

- `POST /admin/v1/grants`
- `POST /admin/v1/grants/{id}/revoke`
- `GET /admin/v1/approvals`
- `POST /admin/v1/approvals/{id}/decision`

Grant revocation cancels unclaimed jobs. A claimed job must still pass the authoritative `start` gate, and a running job must pass the independent certificate gate before receiving SSH credentials.

## Internal Gateway-to-Control API

Intended for the Gateway over mutual TLS:

- `POST /internal/v1/introspect`
- `POST /internal/v1/commands/submit`
- `POST /internal/v1/context`
- `POST /internal/v1/history`
- `POST /internal/v1/notes/list`
- `POST /internal/v1/notes/write`

The Gateway sends only the SHA-256 capability hash internally. The Control Plane re-authenticates and re-enforces permissions/target scope for authoritative operations.

## Internal worker API

Worker endpoints require a dedicated worker credential in addition to protected internal transport. They are not agent-facing and do not accept agent capabilities.

### `POST /internal/v1/execution/jobs/claim`

Claims one pending job and returns an immutable job plus a random one-shot claim secret. The same job cannot be claimed twice.

### `POST /internal/v1/execution/jobs/{id}/start`

Requires worker ID and claim secret. The Control Plane revalidates the original grant before `claimed -> running`.

### `POST /internal/v1/execution/jobs/{id}/ssh-certificate`

Requires worker ID, the same claim secret, and a fresh Ed25519 public key generated by the worker.

Before calling the isolated Signer, the Control Plane requires all of the following:

- job exists and is `running`;
- claim secret remains valid;
- job is unexpired;
- immutable command binding verifies;
- current risk policy reclassification of `job.argv` is not denied;
- current category and scope key exactly match stored immutable job metadata;
- original grant still authenticates;
- powerful execution has `grant.permissions.shell=true`;
- logical target resolves through protected operator-owned SSH inventory.

A policy change after queueing therefore invalidates an old job rather than grandfathering old authority.

Only after those checks does the Control Plane send job/grant/target/binding identity, ephemeral public key, and the job expiry upper bound to the Signer.

A successful response contains the running job, short-lived certificate metadata, and the operator-resolved target:

```json
{
  "job": { "...": "immutable running job" },
  "certificate": { "...": "short-lived OpenSSH certificate metadata" },
  "target": {
    "name": "dns01",
    "address": "10.169.0.53:22",
    "user": "sentinel-ai",
    "host_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA..."
  }
}
```

Target transport data is resolved by the Control Plane, never echoed from agent/worker input. Registry addresses are concrete literal IPs plus port, and host keys are exact raw pins.

Successful issuance is audited. If audit append fails after signing, the job is canceled and the certificate is withheld.

### `POST /internal/v1/execution/jobs/{id}/complete`

Requires the same claim secret and records terminal execution result metadata. Completion is one-shot. Raw stdout/stderr is not persisted by the current worker; result metadata includes exit/error information and output accounting digest.

## SSH Signer API

The Signer is a separate internal-only service with its own bearer credential and mutual TLS in normal operation.

### `GET /healthz`

Process health only; no private-key material.

### `POST /internal/v1/sign`

Called by Control Plane only. The caller supplies job-derived identity/binding information, worker public key, and an upper validity bound.

Signer-owned policy controls:

- Ed25519 CA and Ed25519 worker key requirement;
- SSH user-certificate type;
- principal;
- exact worker source-address restriction;
- fixed generated `force-command`;
- empty PTY/agent/port/X11 forwarding extensions;
- short validity capped by job expiry.

The request has no caller-controlled principal, arbitrary force-command, source-address list, extension set or TTL.

## SSH target registry

Not an agent API. Control Plane loads `SENTINEL_SSH_TARGETS_FILE` (default `/etc/tethys-sentinel/ssh-targets.json`).

Each record contains:

- logical `name`;
- literal-IP `address` with port;
- Unix `user`;
- exact raw `host_key` pin.

Unknown fields, malformed endpoints, DNS destinations, unspecified addresses, duplicate names and group/other-writable configuration are rejected.

See also:

- `docs/EXECUTION_PROTOCOL.md`
- `docs/EXECUTION_POLICY.md`
- `docs/SSH_CA.md`
- `docs/SSH_EXECUTION.md`
