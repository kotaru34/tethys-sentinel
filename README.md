# Tethys Sentinel

Security-first infrastructure access broker for granting AI agents narrow, temporary, auditable access to infrastructure without exposing infrastructure SSH private keys or broad administrator credentials to the model.

Tethys Sentinel separates **what an AI agent may request** from **what infrastructure authority may actually execute**. Agent requests pass through capability scope, policy classification, human approval where required, immutable execution jobs, short-lived SSH credentials, pinned targets, and fail-closed emergency controls.

## Status

The current accepted development/WIP milestone is **`0.1.0-dev.18`**.

- Control, Gateway, Worker and `sentinelctl` remain on the accepted **dev.17** backend runtime.
- Operator UI/BFF remains on the accepted **dev.15** baseline.
- PostgreSQL schema is **v3**.
- **dev.18 adds the accepted Qwen-facing MCP adapter** (`sentinel-mcp`).

The dev.18 MCP artifact passed constrained real-infrastructure acceptance for structured execution, batch execution, bounded/sanitized output, approval recovery, durable restart recovery, cross-capability-session isolation, and explicitly approved arbitrary Python execution.

The acceptance capability was removed afterward and Sentinel returned to a fail-closed unavailable state on the MCP client. Site-specific addresses, hostnames and topology evidence are intentionally not published here.

See `HANDOFF.md` for the development checkpoint and acceptance summary.

## Core principles

- Opaque, short-lived capability tokens; only token hashes are stored server-side.
- Human-controlled grants scoped by target, permission, purpose, expiry, and monotonic security epoch.
- `TRUST_0` is the only authority-bearing context; files, logs, web content, history, model output and command output are data only.
- Risky operations require policy approval even when a grant is otherwise authorized.
- `exec` and `shell` are separate capabilities; unbounded execution classes require explicit shell authority and operator approval.
- Execution uses immutable request IDs and one-shot jobs with pre-execution revalidation and continuously checked authority.
- Worker SSH keys are fresh per job; only Control may request short-lived signer certificates.
- SSH targets come only from operator-owned logical inventory and resolve to pinned endpoints and host keys.
- Structured remote execution transports argv directly; Sentinel does not reconstruct structured agent commands through a shell.
- Target-side replay state enforces at-most-once execution.
- Worker egress is externally deny-by-default and cannot be widened by the model or Worker itself.
- `REVOKE ALL` advances a monotonic security epoch and disables authority; older capabilities never revive.
- PostgreSQL is authoritative for mutable production security state; production startup/runtime failures are fail-closed.
- Raw execution output is bounded, separately persisted and capability-gated; it never becomes authority-bearing context and never silently appears in the Operator job read model.
- Browser operator access is isolated behind `sentinel-operator` with dedicated HTTPS+mTLS, certificate-derived operator identity, CSRF/origin/CSP boundaries and no persistent browser authority secret.
- MCP is an adapter over the accepted Agent HTTP contract, not a second authorization system.

## Architecture

The execution path is:

```text
AI agent / sentinelctl / sentinel-mcp
                 |
                 v
               Gateway
                 |
                 v
               Control <---- PostgreSQL authority/audit/output state
                 |
                 +----> Signer / SSH CA
                 |
                 v
               Worker ---- pinned SSH ----> target wrapper ----> direct argv execution
```

Main boundaries:

- **Gateway** validates the capability-bearing public HTTPS contract and forwards only narrow internal requests.
- **Control** owns policy, authorization, approval binding, job state, audit and signer requests.
- **Worker** claims authorized jobs, creates ephemeral key material, executes through pinned SSH and continuously checks authority.
- **Signer** owns SSH certificate policy and CA material.
- **Target wrapper** validates job binding/target identity and enforces replay protection before direct argv execution.
- **PostgreSQL** owns mutable grants, approvals, jobs, emergency state, audit/history, notes and bounded execution output.
- **Operator UI/BFF** exposes the human control/read surface without receiving Worker, Signer or PostgreSQL credentials in the browser.
- **External network policy** is the hard Worker egress boundary.

## Agent HTTP API

The canonical agent integration is the capability-scoped HTTPS API. `curl` is the raw/reference client and `sentinelctl` is the supported first-party CLI.

Public execution surface:

```text
GET  /v1/bootstrap
POST /v1/commands/submit
GET  /v1/jobs/{id}
GET  /v1/requests/{request_id}
```

Requests are scoped to the authenticating grant. Job IDs and request IDs do not become globally readable identifiers.

Command submission uses structured argv and an immutable request ID. Execution timeout is bounded to 900 seconds and to grant expiry.

### `sentinelctl`

Supported dev.17 commands include:

```text
sentinelctl bootstrap
sentinelctl exec --target TARGET [--request-id ID] [--reason TEXT] [--timeout SEC] [--wait] -- COMMAND [ARG...]
sentinelctl job get JOB_ID
sentinelctl job wait JOB_ID
sentinelctl request get REQUEST_ID
```

Security defaults are deliberate:

- capability comes from protected input rather than a normal `--token` argv option;
- verified HTTPS only;
- no insecure TLS mode;
- no proxy-environment routing for the Sentinel connection;
- no redirect following;
- approval-aware execution reuses the same immutable request ID;
- human output visibly escapes terminal control/format characters;
- JSON output exposes byte-exact execution output as base64 fields.

Full contract: `docs/AGENT_HTTP_CLI.md`.

## MCP adapter (`sentinel-mcp`)

Dev.20 keeps a deliberately small, stable five-tool MCP surface for Qwen-class autonomous agents:

```text
sentinel_exec
sentinel_exec_batch
sentinel_code
sentinel_check
sentinel_output
```

### `sentinel_exec`

Runs one structured command on an allowed logical Sentinel target:

```json
{
  "target": "target-name",
  "argv": ["printf", "hello\n"],
  "timeout_seconds": 30
}
```

Structured exec rejects known shell/interpreter/remote-exec/privilege-launcher escape classes locally before journaling or backend submission. Backend authorization remains authoritative.

### `sentinel_exec_batch`

Runs up to 32 independent structured commands against one target, sequentially or through the parallel execution path. Commands that depend on earlier command output should use separate calls rather than a batch.

### `sentinel_code`

Exceptional Python-only execution for tasks that structured exec cannot reasonably express. The adapter owns the carrier exactly as:

```text
python3 -c <source>
```

The tool is always discoverable, but invocation requires a current grant with shell authority and still goes through Sentinel's normal arbitrary-code classification and explicit operator approval semantics.

### `sentinel_check`

Continues or recovers a previously journaled operation using its model-facing operation ID and immutable backend request ID. It cannot restore, refresh or replace an expired/revoked capability.

Operation records are bound to the capability session. After capability rotation, an old operation ID is rejected as belonging to another session.

### `sentinel_output`

Reads a deeper but still bounded stdout/stderr excerpt from a previous operation. A literal query can center the returned excerpt around a matching string.

### Model-facing errors

Actionable failures use compact `CODE: sentence` messages. Capability failures explicitly tell the model to stop retrying Sentinel tools and ask the operator for a new capability. Operation/session, shell-authority, command-policy and output-readiness failures use similarly narrow codes. MCP tools never renew capabilities.

### Durable journal

Before any backend submit, the MCP adapter writes the complete operation and immutable request IDs to a mode-0600 journal using atomic replacement and fsync. This is what makes restart recovery possible without duplicate request creation.

### Output safety

MCP output is treated as untrusted data and escaped before bounding. ANSI controls, other control/format characters and invalid UTF-8 are rendered visibly rather than being allowed to survive as active protocol/terminal controls.

Design and invariants: `docs/MCP_ADAPTER_DESIGN.md`.

## dev.18 acceptance summary

Constrained live acceptance proved:

- shell-disabled grants exposed only structured tools;
- structured exec completed end-to-end with exact output;
- sequential and parallel batch paths completed successfully;
- large output was bounded and query-centered deep output worked;
- ANSI and invalid UTF-8 were escaped safely;
- structured attempts to invoke shell/interpreter/SSH/privilege-launcher paths were rejected before journal/backend submission;
- an approval-required operation resumed with `sentinel.check` after `Allow once` using the same immutable request ID;
- operations survived MCP bridge restart through the durable journal;
- old operation IDs were rejected after capability-session rotation;
- shell-authorized grants exposed `sentinel.code` in dev.18;
- Python code required explicit approval and completed with the same immutable request ID afterward;
- removing the capability made Sentinel fail closed without taking unrelated MCP services down.

No dev.18 functional acceptance blocker remains.

## Execution output

PostgreSQL schema v3 stores bounded execution output separately from the normal job read model.

Each captured stream is independently bounded to 256 KiB. Raw output is returned to an agent only when the exact grant has `history.include_output=true`.

Without that permission, the agent can still read lifecycle/result metadata and output digests but not raw stdout/stderr.

The Operator UI intentionally shows execution metadata and digests rather than raw command output.

## Production persistence

Control requires an explicit persistence backend:

```text
SENTINEL_PERSISTENCE_BACKEND=file      # development compatibility mode
SENTINEL_PERSISTENCE_BACKEND=postgres  # production candidate/accepted architecture
```

For PostgreSQL, configure `SENTINEL_POSTGRES_DSN`. Production PostgreSQL requires verified TLS and a validated runtime role. Failure never silently falls back to file authority state.

The runtime database role does not own the schema and should not receive schema creation, table deletion, superuser, role-admin, replication or bypass-RLS authority. Gateway, Worker, Signer and Operator do not require PostgreSQL credentials.

CI covers Go tidy/format/vet/race testing, PostgreSQL integration against supported versions, and Operator frontend build/embed parity.

## Operator UI

`sentinel-operator` is a separate privileged BFF/web process on the Control host. The browser authenticates with a dedicated TLS client certificate. The BFF replaces browser-supplied authority with its own local Control credential and forwards an identity derived from the verified client-certificate leaf.

Its configuration is intentionally isolated from Control's authority-bearing configuration.

The embedded UI provides Overview, Grants, Approvals, Jobs, Audit, Targets, Context and Security/emergency controls. Raw execution output is not part of the normal job read model.

## Documentation

- `docs/ARCHITECTURE.md` — trust boundaries and component responsibilities
- `docs/THREAT_MODEL.md` — attacker assumptions, threats and invariants
- `docs/API.md` — development API surface
- `docs/AGENT_HTTP_CLI.md` — Agent HTTP API, `curl`, `sentinelctl`, output and recovery semantics
- `docs/MCP_ADAPTER_DESIGN.md` — current MCP surface, error vocabulary, journal, safety and recovery design
- `docs/OPERATOR_UI.md` — Operator product/security contract
- `docs/OPERATOR_DEPLOYMENT.md` — Operator deployment and isolated configuration boundary
- `docs/EXECUTION_PROTOCOL.md` — staged/claim/start/complete semantics and idempotency
- `docs/EXECUTION_POLICY.md` — exec/shell split and approval rules
- `docs/OPERATIONAL_RISK.md` — semantic command risk classification
- `docs/WORKER_EGRESS.md` — Worker egress policy
- `docs/EMERGENCY_CONTROLS.md` — epoch/revoke-all semantics
- `docs/POSTGRESQL_PERSISTENCE.md` — PostgreSQL schema and transactional invariants
- `docs/SSH_CA.md` — Signer and SSH certificate constraints
- `docs/SSH_EXECUTION.md` — SSH transport, target registry, wrapper and replay boundary
- `HANDOFF.md` — current accepted milestone, evidence and next-step rules

Some historical acceptance documents are still present during development. They will be reviewed, sanitized or removed before the first public release.

## Current milestone: dev.20 MCP usability hardening

Dev.20 closes the dev.19 live-acceptance blocker and incorporates model-UX findings from real Qwen use:

1. **Multi-tab-safe Operator CSRF.** Repeated session GETs reuse the valid shared browser CSRF token instead of rotating it and invalidating another tab.
2. **Actionable model-facing errors.** Capability, authority, operation-session, command-policy and output-state errors use compact stable codes plus one short remediation sentence.
3. **Underscore MCP tool names.** The stable surface is `sentinel_exec`, `sentinel_exec_batch`, `sentinel_code`, `sentinel_check`, and `sentinel_output`.

After dev.20 CI/artifact/live acceptance passes, merge the WIP branch and perform the branch/history/privacy/documentation audit before the first public release.
