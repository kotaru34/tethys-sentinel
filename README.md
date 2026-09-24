# Tethys Sentinel

Security-first infrastructure access broker for granting AI agents narrow, temporary, auditable access to infrastructure without exposing infrastructure SSH private keys or broad administrator credentials to the model.

Tethys Sentinel separates **what an AI agent may request** from **what infrastructure authority may actually execute**. Requests pass through capability scope, policy classification, human approval where required, immutable execution jobs, short-lived SSH credentials, pinned targets, and fail-closed emergency controls.

## Status

Current accepted development baseline: **`0.1.0-dev.25`**.

- PostgreSQL schema: **v4**
- native loopback MCP endpoint: accepted
- one-time MCP capability claim flow: accepted
- Operator multi-tab CSRF handling: accepted
- model-facing capability/recovery error semantics: accepted

The runtime has completed constrained live acceptance. The repository is now in public-release cleanup: site-specific deployment evidence is being removed from the public tree/history and documentation is being normalized to public-safe examples.

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
- MCP is an adapter over the Agent HTTP contract, not a second authorization system.

## Architecture

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

- **Gateway** validates capability-bearing public HTTPS requests.
- **Control** owns policy, authorization, approval binding, job state, audit and signer requests.
- **Worker** claims authorized jobs, creates ephemeral key material, executes through pinned SSH and continuously checks authority.
- **Signer** owns SSH certificate policy and CA material.
- **Target wrapper** validates job binding/target identity and enforces replay protection before direct argv execution.
- **PostgreSQL** owns mutable grants, approvals, jobs, emergency state, audit/history, notes, one-time MCP claims and bounded execution output.
- **Operator UI/BFF** exposes the human control/read surface without putting Control authority secrets in the browser.
- **External network policy** is the hard Worker egress boundary.

## Agent HTTP API

The capability-scoped HTTPS API is the canonical agent integration beneath MCP:

```text
GET  /v1/bootstrap
POST /v1/commands/submit
GET  /v1/jobs/{id}
GET  /v1/requests/{request_id}
```

Requests are scoped to the authenticating grant. Job IDs and request IDs do not become globally readable identifiers.

### `sentinelctl`

Primary commands:

```text
sentinelctl bootstrap
sentinelctl exec --target TARGET [--request-id ID] [--reason TEXT] [--timeout SEC] [--wait] -- COMMAND [ARG...]
sentinelctl job get JOB_ID
sentinelctl job wait JOB_ID
sentinelctl request get REQUEST_ID
sentinelctl mcp claim
```

Security defaults include verified HTTPS only, no insecure TLS mode, no redirect following, protected capability input, immutable request-ID reuse for approval recovery, escaped human output and byte-exact base64 JSON output.

Full contract: `docs/AGENT_HTTP_CLI.md`.

## MCP adapter

`sentinel-mcp` exposes a deliberately small, stable five-tool surface:

```text
sentinel_exec
sentinel_exec_batch
sentinel_code
sentinel_check
sentinel_output
```

- **`sentinel_exec`** runs one structured argv command on an allowed logical target.
- **`sentinel_exec_batch`** runs several independent structured commands against one target.
- **`sentinel_code`** is exceptional Python-only execution and requires current shell authority plus normal operator approval.
- **`sentinel_check`** continues/recover a journaled operation; it cannot refresh or repair capability authority.
- **`sentinel_output`** reads a deeper but still bounded stdout/stderr excerpt from a prior operation.

Tool discovery is stable even when no capability is installed. Authorization remains per call and fail-closed.

### One-time capability claims

An operator can issue a short-lived one-time MCP claim. Only its hash is persisted. Redemption is single-use and creates a normal short-lived Sentinel grant bound to the current security epoch.

`sentinelctl mcp claim` accepts the claim through protected input and atomically installs the resulting capability with strict file permissions. `sentinel-mcp` reloads the capability on each call, so rotation does not require a process restart.

### Model-facing errors

Actionable failures use compact `CODE: sentence` messages. Capability failures explicitly tell the model to stop retrying Sentinel tools and ask the operator for a fresh capability. Operation/session, shell-authority, command-policy and output-readiness failures use similarly narrow codes.

### Durable journal and output safety

Before backend submission, the MCP adapter persists operation metadata and immutable request IDs in a mode-0600 journal using atomic replacement and fsync. Operations are bound to the capability session.

MCP output is untrusted data. ANSI/control/format characters and invalid UTF-8 are escaped before bounding so command output cannot become active protocol or terminal control text.

Design: `docs/MCP_ADAPTER_DESIGN.md`.

## Operator UI

`sentinel-operator` is a separate privileged BFF/web process on the Control host. The browser authenticates with a dedicated TLS client certificate. The BFF replaces browser-supplied authority with its own local Control credential and derives operator identity from the verified client certificate.

The UI provides Overview, Grants, Approvals, Jobs, Audit, Targets, Context and Security/emergency controls. Raw execution output is intentionally not part of the normal Operator job read model.

CSRF state is shared safely across tabs by reusing a valid high-entropy `__Host-tethys_csrf` cookie/token rather than rotating it on every session read; strict Origin, SameSite, Secure and HttpOnly protections remain enforced.

## Production persistence

Control requires an explicit persistence backend:

```text
SENTINEL_PERSISTENCE_BACKEND=file      # development compatibility mode
SENTINEL_PERSISTENCE_BACKEND=postgres  # production architecture
```

For PostgreSQL, configure `SENTINEL_POSTGRES_DSN`. Production PostgreSQL requires verified TLS and a validated least-privilege runtime role. Failure never silently falls back to file authority state.

Schema v4 contains mutable authority, approvals, jobs, audit/history, bounded execution output and transactional one-time MCP claim state.

## Documentation

- `docs/ARCHITECTURE.md` — trust boundaries and component responsibilities
- `docs/THREAT_MODEL.md` — attacker assumptions, threats and invariants
- `docs/API.md` — development API surface
- `docs/AGENT_HTTP_CLI.md` — Agent HTTP API and `sentinelctl`
- `docs/AGENT_HTTP_CLI_ACCEPTANCE.md` — public-safe acceptance procedure
- `docs/MCP_ADAPTER_DESIGN.md` — MCP surface, journal, errors and recovery
- `docs/OPERATOR_UI.md` — Operator product/security contract
- `docs/OPERATOR_DEPLOYMENT.md` — Operator deployment boundary
- `docs/EXECUTION_PROTOCOL.md` — staged/claim/start/complete semantics
- `docs/EXECUTION_POLICY.md` — exec/shell split and approval rules
- `docs/OPERATIONAL_RISK.md` — semantic command risk classification
- `docs/WORKER_EGRESS.md` — Worker external egress boundary
- `docs/EMERGENCY_CONTROLS.md` — epoch/revoke-all semantics
- `docs/POSTGRESQL_PERSISTENCE.md` — PostgreSQL schema and transactions
- `docs/SSH_CA.md` — Signer and SSH certificate constraints
- `docs/SSH_EXECUTION.md` — SSH transport, target registry and replay boundary
- `docs/INFRASTRUCTURE_ACCEPTANCE.md` — repeatable infrastructure acceptance
- `ansible/README.md` — repeatable Debian/Ubuntu VM and unprivileged-LXC target onboarding
- `HANDOFF.md` — current accepted baseline and public-release gate

All public examples must use documentation-only names/addresses. Real deployment topology and acceptance evidence belong in private operator records.
