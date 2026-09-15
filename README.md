# Tethys Sentinel

Security-first AI infrastructure access broker for granting AI agents narrow, temporary, auditable access to infrastructure without exposing infrastructure SSH private keys.

## Core principles

- Opaque, short-lived capability tokens; only token hashes are stored.
- Human-controlled grants scoped by target, permission, purpose, expiry, and monotonic security epoch.
- `TRUST_0` is the only authority-bearing context; files, logs, web content, history and command output are data only.
- Risky operations require policy approval even when a grant is otherwise authorized.
- `exec` and `shell` are separate capabilities; powerful execution classes require both and remain one-shot approval only.
- Execution uses immutable one-shot jobs with pre-execution revalidation and continuously checked authority.
- Worker SSH keys are fresh Ed25519 keys per job; only Control can request short-lived signer certificates.
- SSH targets come only from operator-owned logical inventory, resolve to literal IP:port endpoints and exact pinned raw host keys.
- Remote execution transports structured argv; Sentinel does not reconstruct agent commands through a shell.
- Target-side replay state enforces at-most-once execution.
- Worker egress is externally deny-by-default and cannot be widened by the agent or Worker itself.
- `REVOKE ALL` advances a monotonic security epoch and disables authority; older capabilities never revive.
- PostgreSQL is authoritative for mutable production security state; startup and runtime fail closed.
- Raw execution output is bounded, separately persisted and capability-gated; it never becomes authority-bearing context and never silently appears in the Operator job read model.
- Browser operator access is isolated behind `sentinel-operator` with dedicated HTTPS+mTLS, certificate-derived operator identity, strict CSRF/origin/CSP boundaries and no persistent browser secret storage.

## Status

The current accepted development/WIP baseline is **`0.1.0-dev.17`** for Control, Gateway, Worker and `sentinelctl`, with the previously accepted **`0.1.0-dev.15`** Operator UI retained unchanged.

The Agent HTTP API + `sentinelctl` milestone has passed constrained real-infrastructure acceptance on the intended PVE topology. PostgreSQL is schema **3**. Final authority is intentionally fail-closed at:

```text
epoch=7
disabled=true
reason=dev.17 Agent HTTP CLI acceptance complete
```

The frozen dev.17 runtime source is:

```text
4728a86abc49bf2a686c588a3878288a36f44f7d
```

CI on that exact runtime source passed in Actions `35000514153`. The reproducible artifact workflow also passed (`35000746762`), with normal CI on the artifact-workflow head passing as Actions `35000746655`.

Exact deployed dev.17 hashes:

```text
sentinel-control  89a66f2f905dabcc804a858c7fdfc5ebf3ad38ec9e425acf8fc4eeab748c9f0e
sentinel-gateway  53f6952a6a10854008486dc57ea23fcbdc3852b2cfb44ee75b799feecbad9bde
sentinel-worker   4874c0a0ae034d1b928dcaf06da72f2761c918f6255d68fb5af17ef2867e2317
sentinelctl       0df406f08f3ddd8388e6cfb5e0be33a50a7cec9195b5152f431a5f566b983bc5
```

The accepted Operator binary remains:

```text
sentinel-operator ea50c402b93d39e592f18106b3340b8615ede04e94e9957eb2f27abde236956c
```

See `HANDOFF.md` for the full deployment/acceptance evidence and rollback checkpoints.

## Architecture

The main execution path is:

```text
Agent / sentinelctl
        |
        v
      Gateway
        |
        v
      Control <---- PostgreSQL authority/audit/output state
        |
        +----> Signer/CA
        |
        v
      Worker ---- pinned SSH ----> target wrapper ----> direct argv execution
```

Important boundaries remain separate:

- **Gateway** validates the capability-bearing public HTTPS contract and forwards only narrow internal requests.
- **Control** owns policy, authorization, approval binding, job state, audit and signer requests.
- **Worker** claims authorized jobs, creates ephemeral keys, executes through pinned SSH and continuously checks authority.
- **Signer** owns SSH certificate policy and CA material.
- **Target wrapper** validates job binding/target identity and enforces replay protection before direct argv execution.
- **PostgreSQL** owns mutable grants, approvals, jobs, emergency state, audit/history, notes and bounded execution output.
- **Operator UI/BFF** exposes the human control/read surface without receiving Worker, Signer, PVE or PostgreSQL credentials.
- **PVE firewall** is the hard Worker egress boundary.

## Agent HTTP API

The canonical agent integration is the capability-scoped HTTPS API. `curl` is the reference/raw client and `sentinelctl` is the supported first-party client.

Public execution surface:

```text
GET  /v1/bootstrap
POST /v1/commands/submit
GET  /v1/jobs/{id}
GET  /v1/requests/{request_id}
```

Requests are scoped to the authenticating grant. Job IDs and request IDs do not become globally readable identifiers.

Command submission uses structured argv and an immutable request ID. Optional execution timeout is bounded to 900 seconds and to the grant expiry.

### `sentinelctl`

Supported commands:

```text
sentinelctl bootstrap
sentinelctl exec --target TARGET [--request-id ID] [--reason TEXT] [--timeout SEC] [--wait] -- COMMAND [ARG...]
sentinelctl job get JOB_ID
sentinelctl job wait JOB_ID
sentinelctl request get REQUEST_ID
```

Security defaults are deliberate:

- capability from a protected file or environment, never a normal `--token` argv option;
- verified HTTPS only;
- no insecure TLS mode;
- no proxy-environment routing for the Sentinel connection;
- no redirect following;
- `exec --wait` retries the same immutable request ID after an operator approval;
- human output visibly escapes terminal control/format characters;
- `--json` exposes byte-exact output as base64 fields.

Full contract and examples: `docs/AGENT_HTTP_CLI.md`.

## Execution output

PostgreSQL schema v3 adds `sentinel.execution_job_output`, separate from the normal job read model.

Each captured stream is independently bounded to 256 KiB. Raw output is returned to the agent only when the exact grant has:

```json
{
  "history": {
    "include_output": true
  }
}
```

Without that permission, the agent can still read lifecycle/result metadata and the output digest, but the raw output store is not exposed.

The Operator UI intentionally shows exact argv, lifecycle, result, risk/scope and output SHA-256 but not raw stdout/stderr/base64 content.

## dev.17 acceptance fix

The first dev.16 live acceptance found a completion bug for one-sided output: an empty captured stream could reach PostgreSQL as SQL `NULL`, violating the schema `NOT NULL` constraint, rolling back completion and leaving a job stuck in `running`.

dev.17 fixes that by normalizing empty captured streams to zero-length `bytea`, with PostgreSQL regression tests for stdout-only and stderr-only completion. It also reaps expired `pending`, `claimed` and `running` jobs during Worker claim processing.

Live acceptance proved:

- the old stuck dev.16 running job was automatically reaped to `expired`;
- stdout-only completion stored 18 stdout bytes and **0** stderr bytes and completed successfully;
- stderr-only execution returned the real remote exit code and persisted only stderr content;
- `history.include_output=false` hid raw output;
- `history.include_output=true` returned exact base64 output;
- ANSI escape output was visibly escaped rather than executed in the local terminal;
- approval-aware `sentinelctl exec --wait` reused the same immutable request ID after `allow_once`;
- a new request ID for the same delete scope required a fresh approval;
- Operator Jobs remained free of raw execution output;
- final `REVOKE ALL` advanced authority to epoch 7 and disabled it.

## Production persistence

The Control Plane requires an explicit persistence backend:

```text
SENTINEL_PERSISTENCE_BACKEND=file      # development compatibility mode
SENTINEL_PERSISTENCE_BACKEND=postgres  # production candidate/accepted topology
```

For PostgreSQL, set `SENTINEL_POSTGRES_DSN`. Production PostgreSQL requires verified TLS and validated schema/runtime role. Failure never silently falls back to file authority state.

The runtime role does not own the schema and does not receive schema `CREATE`, table `DELETE`, superuser, role-admin, replication or bypass-RLS authority. Gateway, Worker, Signer and `sentinel-operator` receive no PostgreSQL credentials.

CI exercises the migration/integration suite against PostgreSQL 15 and 18, Go tidy/format/vet/race tests, and the pinned Operator frontend dependency/build/embed checks.

## Operator UI

`sentinel-operator` is a separate privileged BFF/web process on the Control host. The browser authenticates with a dedicated TLS client certificate. The BFF replaces browser-supplied authority with its own local Control admin credential and forwards an identity derived from the verified client-certificate leaf.

Its separate configuration root is `/etc/tethys-sentinel-operator`; it is intentionally not granted traversal of `/etc/tethys-sentinel`.

The embedded UI provides Overview, Grants, Approvals, Jobs, Audit, Targets, Context and Security/emergency controls. Raw execution output is not part of its job read model.

## Documentation

- `docs/ARCHITECTURE.md` — trust boundaries and component responsibilities
- `docs/THREAT_MODEL.md` — attacker assumptions, threats and invariants
- `docs/API.md` — current development API surface
- `docs/AGENT_HTTP_CLI.md` — Agent HTTP API, `curl`, `sentinelctl`, output and recovery semantics
- `docs/AGENT_HTTP_CLI_ACCEPTANCE.md` — original dev.16 migration/acceptance runbook; the dev.17 blocker/fix and final evidence are recorded in `HANDOFF.md`
- `docs/OPERATOR_UI.md` — Operator UI product/security contract
- `docs/OPERATOR_DEPLOYMENT.md` — mTLS Operator deployment and isolated configuration boundary
- `docs/EXECUTION_PROTOCOL.md` — staged/claim/start/complete semantics and idempotency
- `docs/EXECUTION_POLICY.md` — exec/shell split and approval rules
- `docs/OPERATIONAL_RISK.md` — semantic command risk classification
- `docs/WORKER_EGRESS.md` — external Worker egress policy
- `docs/EMERGENCY_CONTROLS.md` — epoch/revoke-all semantics
- `docs/POSTGRESQL_PERSISTENCE.md` — PostgreSQL schema and transactional invariants
- `docs/INFRASTRUCTURE_ACCEPTANCE.md` — constrained PVE acceptance
- `docs/INFRASTRUCTURE_ACCEPTANCE_REMOTE_POSTGRES.md` — remote PostgreSQL acceptance profile
- `docs/SSH_CA.md` — Signer and SSH certificate constraints
- `docs/SSH_EXECUTION.md` — SSH transport, target registry, wrapper and replay boundary
- `HANDOFF.md` — current accepted deployment, evidence, rollback state and next-step rules

## Next milestone

After the accepted dev.17 branch is merged to `main`, the next milestone is the MCP adapter. It must be a thin adapter over the accepted HTTPS API with a deliberately small, purpose-built tool surface for Qwen-class autonomous agents. Do not expose generic Control/admin tools or a broad backend tool surface.
