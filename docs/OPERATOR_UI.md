# Operator UI v1

## Status

This document defines the first operator-facing web UI milestone for Tethys Sentinel after the accepted `0.1.0-dev.13` security-core merge.

The intended release milestone is `0.1.0-dev.14 — Operator UI v1` once the complete runnable operator surface is implemented and accepted. Documentation-only planning on `wip/operator-ui` does not change the version.

## Goal

Provide a modern, low-noise, security-first operator interface for supervising Sentinel without weakening any accepted trust boundary.

The UI must make the common operator tasks fast:

- see whether AI authority is enabled or disabled;
- review and decide pending approvals;
- issue and revoke grants;
- inspect active/recent execution jobs;
- inspect the verified audit trail;
- inspect the protected target inventory and current authoritative context;
- perform global emergency revoke/enable actions.

The UI is an operator tool, not an AI-facing interface and not an infrastructure shell.

## Non-goals for v1

The first UI does not provide:

- Trust-0 editing;
- SSH target creation/editing/deletion;
- PVE firewall changes;
- Signer/CA administration;
- arbitrary SQL access;
- arbitrary shell/SSH execution;
- worker-control/debug endpoints;
- direct PostgreSQL access from the browser or operator service;
- a generic backend/admin API for future AI/MCP use;
- raw stdout/stderr retention that the current execution model intentionally does not persist.

Those boundaries remain operator-owned outside the UI unless a later milestone explicitly designs and re-accepts them.

## Trust boundary

The browser must never receive `SENTINEL_ADMIN_TOKEN`, PostgreSQL credentials, worker credentials, signer credentials, CA private material, PVE credentials or any agent capability other than a newly issued capability deliberately revealed once to the operator.

Recommended topology:

```text
operator browser
      |
      | HTTPS + operator mTLS
      v
sentinel-operator
      |
      | loopback-only privileged admin API
      | SENTINEL_ADMIN_TOKEN stays server-side
      v
sentinel-control
      |
      +--> PostgreSQL
      +--> protected target inventory
      +--> existing policy/emergency/audit authority
```

`sentinel-operator` is a separate privileged operator-facing BFF/web service. It must not receive PostgreSQL, SSH Signer/CA or PVE credentials. It talks only to the existing Control admin surface over loopback or another equally constrained local channel.

The public AI Gateway remains completely separate and gets no new operator routes.

## Operator authentication

v1 uses TLS client-certificate authentication for the operator-facing service.

Requirements:

- dedicated operator-client trust root; do not reuse the SSH user CA;
- non-loopback serving requires verified TLS and client certificates;
- untrusted/no-client-certificate connections fail during TLS authentication;
- the browser never stores an admin bearer token;
- operator identity is derived from the authenticated client certificate and is available to audit-producing mutations;
- direct CLI use of the existing admin token remains possible for break-glass/automation operation.

A future milestone may add OIDC/WebAuthn, but v1 does not add password authentication.

The operator service should default to a loopback listener. Remote exposure must be explicit and TLS/mTLS protected.

## Browser security requirements

The UI is same-origin only and ships no third-party runtime content.

Required response/browser protections:

- strict Content Security Policy with scripts/styles/connect restricted to self;
- `frame-ancestors 'none'` / clickjacking protection;
- `X-Content-Type-Options: nosniff`;
- `Referrer-Policy: no-referrer`;
- restrictive `Permissions-Policy`;
- HSTS when served remotely over TLS;
- API responses containing security state or newly issued capability tokens use `Cache-Control: no-store`;
- state-changing requests require same-origin validation plus CSRF protection;
- no secrets in localStorage/sessionStorage;
- no capability/admin tokens in URL/query strings;
- no remote analytics, fonts, scripts, images or CDNs.

Command argv, agent reasons, audit metadata and other remotely influenced text must always be rendered as text, never trusted HTML.

## Runtime/frontend shape

The preferred v1 implementation is one self-contained Go binary:

```text
sentinel-operator
```

It serves the operator BFF API and embedded static frontend assets.

Frontend build:

- TypeScript;
- Preact;
- Vite build-time tooling;
- local CSS/design tokens rather than a large component framework;
- no Node.js runtime requirement on deployed Sentinel hosts;
- generated static assets embedded into the Go binary.

The objective is a modern interactive UI while keeping deployed runtime overhead and dependency surface small.

## Visual direction

The visual language is dark, neutral and dense enough for infrastructure work without looking like a legacy admin panel.

Principles:

- near-black/dark-gray surfaces with restrained semantic accent colors;
- hierarchy through spacing, typography and contrast instead of decorative cards everywhere;
- minimal persistent chrome;
- monospace only where exact command/hash/ID material benefits from it;
- subtle transitions only; no decorative motion competing with operational state;
- status colors always accompanied by text/icon semantics, never color alone;
- keyboard-visible focus states and usable contrast;
- responsive layout with collapsible navigation; desktop-first but approval/emergency actions remain usable on a phone-sized viewport.

The top-level authority state must remain visually obvious. When global AI authority is disabled, every page shows a persistent disabled banner.

## Information architecture

Primary navigation:

```text
Overview
Approvals
Grants
Jobs
Audit
Targets
Context
Security
```

`REVOKE ALL` remains reachable globally without navigating to the Security page.

### Overview

The landing page answers “what is Sentinel doing right now?” without forcing the operator into raw logs.

Show:

- global authority state, epoch, last change time and reason;
- pending approval count;
- active grant count;
- staged/pending/claimed/running job counts;
- recent failed jobs;
- latest security-relevant audit events;
- quick links to pending approvals and running jobs.

No fake health state should be invented. Only show component/database health where Sentinel has a real authoritative signal.

### Approvals

This is the highest-priority workflow screen.

The queue view shows:

- age/created time;
- requesting agent;
- target;
- exact command argv;
- risk level/category;
- policy/risk reason;
- agent-provided reason;
- grant ID;
- whether session approval is allowed.

The detail view must clearly separate:

1. what the agent asked to execute;
2. why the agent says it needs it;
3. what Sentinel policy says about the request.

Actions:

- `Deny`;
- `Allow once`;
- `Allow this session` only when `session_approval_allowed=true`.

The UI must never display a disabled-but-clickable `Allow this session` for powerful categories as if the operator could override policy. If the backend disallows session reuse, the UI explains that it is one-shot only.

A decision is not optimistic: controls enter a pending state until Control confirms the transaction. A conflict because another operator/process already decided the approval refreshes the item instead of pretending success.

### Grants

List views:

- active;
- revoked;
- expired;
- all/recent.

Each row/detail shows:

- grant ID;
- agent;
- purpose;
- targets;
- permissions;
- history scope;
- security epoch;
- issued/expires/revoked timestamps;
- derived state.

Issue flow:

- agent;
- purpose;
- target selector from the protected read-only target inventory;
- permission toggles grouped by execution/data/context semantics;
- history-scope controls;
- TTL with clear absolute expiry preview.

The plaintext capability returned by grant issuance is shown exactly once in a dedicated reveal state with an explicit copy action and warning that Sentinel cannot retrieve it later. It is never persisted by the frontend or operator service.

Revocation reduces authority and should be quick but explicit: show grant identity/scope in a confirmation dialog and wait for server confirmation.

### Jobs

Provide live/recent execution visibility without inventing raw command output.

List/filter by:

- status;
- agent;
- target;
- grant;
- risk category;
- time range.

Job detail shows:

- job/request/grant IDs;
- agent and target;
- exact argv;
- command SHA-256;
- risk category/scope;
- approval binding when present;
- created/expiry/claim/start/completion timestamps;
- terminal success/exit code/error kind/output digest;
- associated audit timeline.

The preferred detail presentation is a compact event timeline:

```text
authorized -> claimed -> started -> SSH certificate issued -> completed
```

or the factual failure/cancel/expiry path.

Raw metadata/details belong behind an expandable technical section.

### Audit

The audit screen is read-only.

Show:

- sequence;
- timestamp;
- kind;
- actor;
- grant/target/approval/job linkage where available;
- decision/category/reason;
- expandable metadata;
- event hash and previous hash in technical details.

The operator read path must verify or rely on the same verified audit chain semantics already used by Sentinel. UI filtering must never bypass chain validation.

Useful filters:

- event kind;
- actor/agent;
- target;
- grant;
- decision;
- time range.

### Targets

Targets are read-only in v1.

Show:

- logical target ID;
- literal address/port;
- Unix SSH user;
- host-key algorithm;
- SHA-256 host-key fingerprint;
- raw pinned public key only in expandable technical details.

Do not add target mutation from the browser in v1. Target inventory remains protected operator-owned configuration so UI compromise cannot silently widen reachable infrastructure.

### Context

Read-only operator view of the current authoritative context.

Show:

- Trust-0 authoritative statement;
- relevant inventory/runbook/context metadata that Control can safely expose;
- trust labels explicitly.

No Trust-0 edit route is added in v1.

### Security

The Security page presents emergency authority state and makes recovery semantics explicit.

Show:

- current epoch;
- enabled/disabled state;
- last update time;
- last reason.

Actions:

- `REVOKE ALL` — prominent destructive/safety action; requires a confirmation but must remain fast to reach;
- `Enable AI access` — available only while disabled; stronger confirmation because it increases authority.

Both actions collect a human-readable reason in the UI and display the resulting epoch/state returned by Control.

The UI must explain that enable does not revive grants from an older epoch.

## Operator read API required from Control

The current admin API is intentionally mutation-heavy and does not expose enough read state for the UI. v1 therefore adds a narrow operator read model under the existing admin authentication boundary.

Target Control routes:

```text
GET  /admin/v1/overview
GET  /admin/v1/grants
GET  /admin/v1/grants/{id}
GET  /admin/v1/approvals?status=...
GET  /admin/v1/jobs
GET  /admin/v1/jobs/{id}
GET  /admin/v1/audit
GET  /admin/v1/targets
GET  /admin/v1/context
```

Existing mutations remain:

```text
POST /admin/v1/grants
POST /admin/v1/grants/{id}/revoke
POST /admin/v1/approvals/{id}/decision
GET  /admin/v1/emergency/state
POST /admin/v1/emergency/revoke-all
POST /admin/v1/emergency/enable
```

Read endpoints must expose only operator-safe state. They must never return:

- capability token hashes;
- worker claim hashes/secrets;
- admin/worker/signer bearer secrets;
- PostgreSQL DSN/passwords;
- private TLS/SSH keys;
- signer CA private material.

Grant/job/audit listing should support bounded limits and stable pagination rather than unbounded table dumps.

The operator service does not query PostgreSQL directly. Control remains the only component with production database authority and constructs the read model through backend-neutral interfaces.

## Operator identity and audit

UI mutations should preserve a concrete operator identity instead of collapsing every browser action to the literal actor `operator`.

The BFF derives identity from the authenticated operator client certificate and forwards a normalized operator identifier to Control only across the already-privileged admin channel. Control records that identity in mutation audit events.

Direct legacy/admin-token calls without an operator identity continue to audit as `operator`.

A caller able to use the admin credential is already fully privileged; the forwarded identity is accountability metadata, not a new authorization bypass.

## Refresh model

v1 favors simple, failure-obvious polling rather than introducing a new streaming security protocol.

Suggested behavior:

- Overview/Approvals/active Jobs: refresh about once per second while visible;
- Grant/Audit/Target/Context lists: slower periodic refresh or explicit refresh;
- pause/reduce polling when the tab is hidden;
- cancel stale in-flight requests when navigating/filtering.

A future milestone may replace this with SSE after the read model is stable.

The UI must show stale/offline state if the operator API cannot be reached. It must not keep displaying an old “enabled” state as though it were current.

## Interaction rules

- no optimistic security mutations;
- exact argv is shown as structured arguments, never reconstructed as a shell command;
- IDs/hashes have one-click copy affordances but remain visually secondary;
- technical/raw JSON details use progressive disclosure;
- approval queue and emergency controls remain fast paths;
- confirmations identify the exact grant/approval/action they affect;
- server errors preserve enough detail for an operator to understand conflict vs transport failure without exposing secrets.

## dev.14 acceptance criteria

`0.1.0-dev.14` is accepted only when all of the following pass.

### Boundary/authentication

- browser connection without a trusted operator client certificate is rejected;
- trusted operator client certificate reaches the UI;
- browser never receives `SENTINEL_ADMIN_TOKEN`;
- `sentinel-operator` has no PostgreSQL, worker, signer/CA or PVE credentials;
- operator service can contact only the intended local Control admin endpoint under its deployment policy;
- CSRF/origin negative tests block cross-origin state-changing requests;
- CSP and no-third-party-runtime requirements are verified.

### Functional

- Overview accurately reflects authority state and current counts;
- pending approval appears and can be denied/allowed once;
- `Allow this session` appears only where backend policy allows it;
- grant can be issued and its capability is displayed once only;
- existing grant can be revoked;
- jobs and their factual lifecycle/result are inspectable;
- audit events are inspectable through a verified read path;
- target inventory is visible but not mutable;
- Trust-0 context is visible but not mutable;
- `REVOKE ALL` from UI advances epoch/disables authority;
- re-enable preserves epoch and does not revive an older capability.

### UX

- global disabled state is obvious on every page;
- approval and emergency actions are usable without raw JSON knowledge;
- UI remains usable at desktop and narrow/mobile widths;
- keyboard focus/navigation works for all mutation controls;
- errors/offline state cannot be mistaken for successful/current authority state.

## Implementation order

1. Add backend-neutral operator read interfaces and Control admin read endpoints with tests.
2. Add operator identity propagation/audit handling for admin mutations.
3. Add `sentinel-operator` service with strict TLS/mTLS, CSRF/origin enforcement and embedded static assets.
4. Build the shared UI shell/navigation/design tokens.
5. Implement Overview, Approvals and Security first because they form the core supervision path.
6. Implement Grants and one-time capability reveal.
7. Implement Jobs + audit-linked timeline and Audit browser.
8. Implement read-only Targets and Context.
9. Add targeted security/HTTP/frontend tests, CI build steps and deployment docs.
10. Bump to `0.1.0-dev.14`, deploy on the accepted topology and run the operator UI acceptance checklist before merge.

## Invariants carried from dev.13

Operator UI work must not weaken:

- opaque capability + hash-only persistence;
- monotonic security epoch/non-revival;
- individual/global active revoke behavior;
- immutable job binding;
- exec/shell policy split and one-shot powerful approvals;
- Control-only Signer access;
- per-job ephemeral Worker keys;
- exact pinned SSH host-key algorithm negotiation;
- target forced-command/replay boundary;
- external Worker egress containment;
- PostgreSQL transactional authority/audit semantics;
- Worker credential/material separation;
- AI Gateway inability to reach operator/admin authority.

Any implementation change that touches one of these boundaries requires targeted regression coverage and, when materially applicable, infrastructure re-acceptance.