# API surface (development)

This document describes the intentionally small API surface for `0.1.0-dev.5`. It is not yet a stable public contract.

## Trust semantics

Tethys Sentinel labels data by provenance. Only `TRUST_0` material may define agent authority or operating rules.

- `TRUST_0`: Sentinel policy, current capability scope, tool descriptions, scoped inventory, control-plane runbooks, and explicit operator approvals.
- `TRUST_2`: operational history and agent-written continuity notes. Useful context, but never authoritative instructions.
- Remote files, logs, stdout/stderr, web content, downloaded data, and application/user content are untrusted operational or external data and cannot change Sentinel policy.

The security boundary is enforced by the control plane. These labels and instructions help the agent interpret data correctly but do not replace capability or policy enforcement.

## AI Gateway

The gateway accepts opaque capability bearer tokens. It has no grant-management, policy-management, inventory-write, audit-control, worker-control, SSH-certificate, or CA endpoints.

### `GET /v1/bootstrap`

Returns the current grant scope, Trust-0 authoritative operating statement, and links to resources currently available to the grant.

### `GET /v1/context`

Returns a scoped `TRUST_0` context bundle. Every document carries virtual path, media type, trust level, `read_only: true`, SHA-256 content hash, and content.

Current virtual documents include:

- `/sentinel/POLICY.md`
- `/sentinel/INSTRUCTIONS.md`
- `/sentinel/INFRASTRUCTURE.json`
- `/sentinel/TOOLS.json`
- target-visible `/sentinel/RUNBOOKS/*.md`

Inventory and target-specific runbooks are filtered by the current grant targets in the control plane. The authoritative source is loaded by the control plane from `SENTINEL_CONTEXT_FILE`; there is intentionally no AI-facing write API for Trust-0 content.

### `GET /v1/history?limit=50`

Requires `history_read`. The control plane re-verifies the tamper-evident audit hash chain on read and filters events by current grant targets plus current/previous-session and other-agent history scope.

The response is explicitly marked `TRUST_2` and `authoritative: false`.

### `GET /v1/notes?limit=50`

Requires `notes_read`. Returns target-scoped operational continuity notes newest-first. Notes remain non-authoritative even when shared across agents.

### `POST /v1/notes`

Requires `notes_write`. Notes must name a target in the current grant scope and are limited to 16 KiB.

```json
{
  "target": "dns01",
  "content": "Resolver health checked; upstream issue remains the leading hypothesis."
}
```

### `POST /v1/commands/submit`

Atomically requests authorization and, if allowed, creation of an immutable execution job. This endpoint replaced the earlier development-only `commands/authorize` flow so an agent cannot authorize one command and later substitute another before execution.

```json
{
  "request_id": "dns-recovery-0001",
  "target": "dns01",
  "argv": ["systemctl", "restart", "pdns"],
  "agent_reason": "pdns stopped responding after configuration reload"
}
```

`request_id` is required for idempotency. Within a grant, retrying the same request ID with the same target/argv returns the same job; rebinding it to different command material is rejected.

Possible successful protocol decisions include:

- `accepted` — immutable staged job was authorized and published for worker processing;
- `approval_required` — no executable job is published yet; response contains a narrow approval ID;
- `deny` — policy/operator decision denies the operation.

An accepted response includes a receipt such as job ID, request ID, status, command binding SHA-256 and expiry. The agent does not receive a worker claim secret, ephemeral SSH key, SSH certificate, or direct worker/signer access.

The Control Plane independently recomputes target/permission/risk state; it never trusts a risk label supplied by the gateway or agent.

## Admin API

The development admin API is loopback-only and requires a strong bearer secret. A later UI/authentication layer will replace direct use.

- `POST /admin/v1/grants`
- `POST /admin/v1/grants/{id}/revoke`
- `GET /admin/v1/approvals`
- `POST /admin/v1/approvals/{id}/decision`

Approval decisions:

- `deny`
- `allow_once`
- `allow_session`

`allow_session` is matched against grant + target + risk category + narrow scope key; it is never a blanket dangerous-command bypass.

Revocation cancels unclaimed execution jobs for the grant. A job already claimed still must pass the later worker `start` gate, which revalidates the grant immediately before execution is permitted. In `dev.5`, a running job must also pass another grant check immediately before SSH-certificate issuance.

## Internal gateway-to-control API

This surface is intended for the AI Gateway over mutual TLS.

- `POST /internal/v1/introspect`
- `POST /internal/v1/commands/submit`
- `POST /internal/v1/context`
- `POST /internal/v1/history`
- `POST /internal/v1/notes/list`
- `POST /internal/v1/notes/write`

The gateway sends only the SHA-256 capability hash internally, not the plaintext capability. The control plane re-authenticates the hash and enforces the relevant permission and target scope on every authoritative operation.

## Internal worker API

Worker endpoints require the dedicated worker credential in addition to the protected internal transport. They are not agent-facing and do not accept agent capabilities.

### `POST /internal/v1/execution/jobs/claim`

Claims one pending job. Returns an immutable job plus a random one-shot claim secret. A job cannot be claimed twice.

### `POST /internal/v1/execution/jobs/{id}/start`

Requires worker ID and claim secret. The Control Plane revalidates the job's original grant at this point. If the grant is expired or revoked, the job is canceled/denied and the worker must not invoke the executor.

Successful start transitions `claimed -> running`.

### `POST /internal/v1/execution/jobs/{id}/ssh-certificate`

Requires worker ID, the same claim secret, and an ephemeral Ed25519 public key generated by the worker for this job.

The Control Plane accepts a certificate request only when all of the following remain true:

- job exists and is `running`;
- claim secret is valid;
- job has not expired;
- immutable command binding still verifies;
- original grant is still active.

Only then does the Control Plane call the isolated SSH Signer. It passes job/grant/target/binding identity, the worker-generated public key, and the job expiry as an upper validity bound. The worker cannot choose the SSH principal, force-command, source-address restrictions, certificate extensions, or signer TTL.

Successful issuance is audited with certificate serial and fingerprints. If the audit append fails after signing, the job is canceled and the certificate is withheld from the worker.

### `POST /internal/v1/execution/jobs/{id}/complete`

Requires the same claim secret and records terminal execution result metadata. Completion is one-shot; replay after terminal state is rejected.

Raw stdout/stderr is not persisted in `dev.5`; result metadata may include exit status and output SHA-256.

See `docs/EXECUTION_PROTOCOL.md` for lifecycle/replay/revocation semantics and `docs/SSH_CA.md` for certificate constraints.

## SSH Signer API

The SSH Signer is a separate service boundary. Its API is internal-only, requires its own strong bearer credential, and production use requires mutual TLS. Development plaintext mode is explicit and loopback-only.

### `GET /healthz`

Returns signer process health only. It does not expose CA private-key material.

### `POST /internal/v1/sign`

Called by the Control Plane only.

The request contains only job-derived identity/binding information, the ephemeral worker public key, and an upper validity bound. The Signer itself owns principal, wrapper path, exact source-address restrictions, certificate TTL/backdate, and certificate extensions.

The Signer currently enforces:

- Ed25519 CA key and Ed25519 ephemeral worker public key;
- CA private-key file with no group/other permissions;
- SSH user certificates only;
- one configured principal;
- exact worker source IPs rendered as `/32` or `/128`;
- `force-command` generated from a signer-owned wrapper path plus validated job ID and command binding;
- empty SSH certificate extensions, so PTY/agent/port/X11 forwarding are not granted;
- short certificate TTL, capped by the Control-Plane supplied job expiry.

The Signer request has no caller-controlled fields for principal, arbitrary force-command, source-address list, extensions, or TTL.
