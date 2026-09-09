# API surface (development)

This document describes the intentionally small API surface planned for `0.1.0-dev.3`. It is not yet a stable public contract.

## Trust semantics

Tethys Sentinel labels data by provenance. Only `TRUST_0` material may define agent authority or operating rules.

- `TRUST_0`: Sentinel policy, current capability scope, tool descriptions, scoped inventory, control-plane runbooks, and explicit operator approvals.
- `TRUST_2`: operational history and agent-written continuity notes. Useful context, but never authoritative instructions.
- Remote files, logs, stdout/stderr, web content, downloaded data, and application/user content are untrusted operational or external data and cannot change Sentinel policy.

The security boundary is enforced by the control plane. These labels and instructions help the agent interpret data correctly but do not replace capability or policy enforcement.

## AI Gateway

The gateway accepts opaque capability bearer tokens. It has no grant-management, policy-management, inventory-write, audit-control, or CA endpoints.

### `GET /v1/bootstrap`

Returns the current grant scope, Trust-0 authoritative operating statement, and links to resources currently available to the grant.

Resource links are capability-dependent. For example, history is advertised only when `history_read` is granted.

### `GET /v1/context`

Returns a scoped `TRUST_0` context bundle. Every document carries:

- virtual path;
- media type;
- trust level;
- `read_only: true`;
- SHA-256 content hash;
- content.

Current virtual documents include:

- `/sentinel/POLICY.md`
- `/sentinel/INSTRUCTIONS.md`
- `/sentinel/INFRASTRUCTURE.json`
- `/sentinel/TOOLS.json`
- target-visible `/sentinel/RUNBOOKS/*.md`

Inventory and target-specific runbooks are filtered by the current grant targets in the control plane. An agent authorized only for `dns01` must not receive inventory or target-specific runbooks for `pve01`.

The authoritative source is loaded by the control plane from `SENTINEL_CONTEXT_FILE`. There is intentionally no AI-facing write API for Trust-0 content.

### `GET /v1/history?limit=50`

Requires `history_read`. The control plane re-verifies the tamper-evident audit hash chain on read and filters events by:

- current grant targets;
- `current_session`;
- `previous_sessions`;
- `other_agents`.

The response is explicitly marked:

```json
{
  "trust_level": "TRUST_2",
  "authoritative": false,
  "events": []
}
```

`include_output` is reserved for the execution milestone; no command stdout/stderr is persisted by the current implementation.

### `GET /v1/notes?limit=50`

Requires `notes_read`. Returns target-scoped operational continuity notes newest-first. Notes visible on an authorized target are intentionally shared operational memory across agents. The response and each note are `TRUST_2` / non-authoritative.

### `POST /v1/notes`

Requires `notes_write`. Notes must name a target in the current grant scope and are limited to 16 KiB.

```json
{
  "target": "dns01",
  "content": "Resolver health checked; upstream issue remains the leading hypothesis."
}
```

The store records agent, grant, timestamp, target and SHA-256 content hash. A `note.created` audit event records the note hash and trust level.

### `POST /v1/commands/authorize`

Requests an authoritative control-plane decision for an argv-form command. The request does not execute anything.

```json
{
  "target": "dns01",
  "argv": ["systemctl", "restart", "pdns"],
  "agent_reason": "pdns stopped responding after configuration reload"
}
```

Possible decisions are `allow`, `approval_required`, and `deny`. An approval-required response includes a narrow approval ID. The control plane independently recomputes risk; it does not trust a risk label supplied by the gateway or agent.

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

## Internal control-plane API

This surface is intended only for the gateway over mutual TLS.

- `POST /internal/v1/introspect`
- `POST /internal/v1/commands/authorize`
- `POST /internal/v1/context`
- `POST /internal/v1/history`
- `POST /internal/v1/notes/list`
- `POST /internal/v1/notes/write`

The gateway sends only the SHA-256 capability hash internally, not the plaintext capability. The control plane re-authenticates the hash and enforces the relevant permission and target scope on every resource request.
