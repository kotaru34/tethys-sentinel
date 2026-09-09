# API surface (development)

This document describes the intentionally small API surface of `0.1.0-dev.2`. It is not yet a stable public contract.

## AI Gateway

The gateway accepts opaque capability bearer tokens. It has no grant-management endpoints.

### `GET /v1/bootstrap`

Returns the current grant scope and Trust-0 authoritative operating statement.

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

The gateway sends only the SHA-256 capability hash internally, not the plaintext capability.
