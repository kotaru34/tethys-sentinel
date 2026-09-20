# Execution Protocol

This document defines the security-sensitive command execution protocol introduced in `0.1.0-dev.4` and hardened through `0.1.0-dev.13`.

## Security goal

An AI agent must never be able to authorize one command and later cause a different command to execute by changing target or argv, replaying an old request, reusing an approval, racing grant revocation, substituting an SSH destination, or reusing the same job credential repeatedly on a target.

The AI Gateway never sends an executable job directly to a worker. Only the Control Plane can create and publish execution jobs.

## Actors

- **Agent**: holds the opaque capability token and submits a requested command using a logical target ID plus argv.
- **AI Gateway**: public-facing transport. It forwards only the capability hash plus request data to the Control Plane.
- **Control Plane**: authoritative grant/policy/approval owner, execution-job issuer, target resolver and SSH-certificate eligibility gate.
- **Execution Worker**: private internal consumer. It cannot issue or broaden grants and never receives the agent capability.
- **SSH Signer**: isolated CA boundary that signs only constrained per-job certificates.
- **Target wrapper**: verifies the signer-bound job/binding against the separately transported immutable command envelope and local target identity.
- **Operator**: approves or denies sensitive requests and can revoke grants or all AI authority.

## Immutable command binding

Every execution job is bound to:

- grant ID;
- agent identity label;
- caller-supplied `request_id`;
- logical target;
- argv;
- expiry;
- applicable approval/risk metadata.

A canonical SHA-256 command binding is stored with the job. The worker verifies this binding before execution, the Signer embeds it into the certificate force-command, and the remote wrapper recomputes it from the command envelope before process start.

Changing the same request ID to different command material is rejected as a conflict.

## Request idempotency

The agent supplies a `request_id` between 8 and 128 supported characters.

Within a grant:

- retrying the same `request_id` with the same target/argv returns the same job;
- retrying the same `request_id` with different target/argv fails;
- a retry must never create a second execution job for the same logical request.

This exists both for ordinary network retries and for crash recovery around approval consumption/publication.

## Job lifecycle

```text
agent submit
    |
    v
  staged  -- not claimable by a worker
    |
    | audit / approval state durably committed
    v
  pending -- claimable
    |
    | one worker claims
    v
  claimed -- still NOT executable
    |
    | authoritative start gate revalidates authority/grant
    v
  running
    |
    | current policy/grant certificate gate
    | ephemeral Ed25519 key + short-lived certificate
    | pinned host-key algorithm + exact-key SSH
    | active authority lease
    | target replay consume + direct exec(argv)
    v
  succeeded / failed
```

Additional terminal states include `canceled` and `expired`.

### `staged`

The job exists durably, but a worker cannot see it. This closes the crash window where a worker could execute before audit or one-shot approval state had been committed.

### `pending`

The job has been published and can be claimed exactly once.

### `claimed`

The Control Plane generates a random 256-bit claim secret. Only its SHA-256 hash is persisted. The plaintext claim secret is returned only to the claiming worker.

Claiming does not grant permission to execute yet.

### `running`

The worker presents its worker credential, job ID and claim secret to the Control Plane `start` endpoint. The Control Plane revalidates global authority and the original grant immediately before changing the job to `running`.

A successful `start` still does not by itself provide SSH credentials.

### SSH credential and target gate

For a running job the worker generates a fresh Ed25519 keypair and sends only the public key to the Control Plane.

Immediately before requesting a certificate, the Control Plane re-checks:

- running state and claim secret;
- job expiry and immutable command binding;
- current global security epoch/disabled state;
- original grant activity, target scope and permissions;
- current risk classification category/scope for immutable argv;
- `shell=true` where the current execution class requires it;
- existence of the logical target in operator-owned SSH target inventory.

The Control Plane then asks the isolated Signer for a short-lived certificate and returns that certificate together with the protected target specification.

The worker verifies the certificate/private-key binding and target/job match before attempting SSH.

### remote execution

The worker connects only to the Control-Plane-resolved literal target IP/port. Before SSH handshake selection it constrains host-key algorithms to those compatible with the operator-pinned raw key, then verifies that the negotiated key is exactly the configured pin. RSA pins use RSA-SHA2 and do not re-enable SHA-1 `ssh-rsa` fallback.

The requested command is transported as a deterministic `sentinel-exec-v1` base64url JSON envelope rather than shell-quoted text.

The certificate force-command invokes `tethys-sentinel-exec --job <id> --binding <sha256>`. The wrapper verifies:

- force-command job ID equals envelope job ID;
- envelope logical target equals the host's local target ID;
- recomputed canonical binding equals the signer-bound binding.

Only then is the job consumed through target replay state and the verified argv launched directly.

### active authority lease

A running Worker checks the Control Plane execution-authority endpoint immediately before executor invocation and periodically while execution remains active. The default poll interval is 250 ms.

Explicit denial or inability to verify current authority cancels the execution context and SSH transport fail-closed. This handles individual grant revoke, global `REVOKE ALL`, stale epoch, expiry, invalid claim and Control/mTLS loss.

### completion

Completion requires the same worker path and claim secret. A completed job cannot be completed again, and the stored claim-token hash is cleared.

Completion records the factual terminal result even if the original grant has been revoked after execution started. The current result contains status/error metadata and output digest accounting, not raw stdout/stderr.

## Approval semantics

Risk classification is recomputed in the Control Plane and again before infrastructure credentials are issued.

For an approval-required operation:

- `deny` prevents job publication;
- `allow_once` is consumed for one matching narrow operation and durably bound to exactly one job;
- `allow_session` remains scoped to grant + target + risk category + concrete scope key only for classes where current policy permits reusable approval.

The command is staged before one-shot approval consumption and published only after the approval/audit path succeeds.

If the process crashes after `allow_once` has been durably consumed but before publication, retrying the same `request_id` recovers and publishes the already-staged matching job rather than requesting a second approval or creating another job.

Known arbitrary-code/interpreter, privilege-launcher and remote-exec classes require both `exec=true` and `shell=true` and are `allow_once` only. Human approval cannot manufacture a missing capability.

## Revocation behavior

Grant/global revocation is authoritative at overlapping points:

1. new agent submissions fail because the grant/global epoch no longer authenticates;
2. staged/pending/claimed work is canceled where applicable and claim material is cleared;
3. a claimed job cannot pass `start` unless current authority/grant still validates;
4. a running job cannot obtain a new SSH certificate if current grant/epoch/policy has changed;
5. after certificate issuance, the active Worker authority lease detects authority loss and cancels the SSH execution context/transport.

OpenSSH certificates themselves do not provide an instant server-side revocation list for an already-established connection. Sentinel therefore combines active Worker transport cancellation with short certificate lifetime, source-address restriction, certificate validity capped by job expiry, external Worker egress containment and target-side at-most-once replay consumption.

`REVOKE ALL` additionally increments a monotonic security epoch and disables authority. Re-enable preserves the new epoch, so pre-revoke capabilities never become valid again.

## Persistence and job-store integrity

`SENTINEL_PERSISTENCE_BACKEND=file` remains an explicit development compatibility mode. File-backed execution records use local integrity protection and are not the production durability model.

`SENTINEL_PERSISTENCE_BACKEND=postgres` is the production-candidate backend. PostgreSQL schema version 2 persists mutable grants, approvals, jobs, emergency authority, audit/history and Trust-2 notes. Security-sensitive transitions and their required audit events commit transactionally, and the runtime role has least privilege.

PostgreSQL startup is explicit and fail-closed: unavailable/invalid PostgreSQL never silently falls back to file-backed authority.

## Worker authentication

Worker endpoints are separate from agent endpoints and require a dedicated worker credential in addition to protected internal mTLS transport.

The worker credential does not grant:

- grant creation;
- grant expansion;
- policy changes;
- approvals;
- Trust-0 mutation;
- SSH CA access;
- arbitrary SSH target creation.

The worker never receives the plaintext agent capability.

## Replay protections

The protocol rejects or prevents:

- second claim of the same job;
- start with the wrong claim secret;
- repeated start after transition to running;
- certificate issuance with an invalid/expired running claim;
- completion with the wrong claim secret;
- repeated completion after terminal state;
- rebinding an existing `request_id` to different target/argv;
- reuse of a consumed `allow_once` approval for a second job;
- target execution with a mismatched local target ID;
- target execution with a different command binding;
- a second target-side consume of the same job ID;
- old security-epoch capability revival after re-enable.

The target replay semantic is deliberately at-most-once: once the root-protected marker is consumed, a process-start failure does not automatically reopen the job for remote replay.

## Connection and process bounds

- TCP dial timeout is bounded.
- SSH handshake has an explicit deadline even if the outer context has none.
- SSH host-key algorithm negotiation is bound to the configured raw pin family.
- The execution context cannot outlive the job/grant authority lifetime.
- Periodic authority loss actively cancels SSH transport.
- Stdout/stderr accounting is bounded per stream.
- Output overflow actively closes the SSH transport.
- Raw stdout/stderr is not persisted by the current worker.

## Current non-goals / remaining work

The dev.13 execution protocol and its intended infrastructure boundaries have passed constrained real-infrastructure acceptance. Current non-goals/future work include:

- a production operator UI;
- the deliberately narrow AI/MCP tool surface that will sit above the accepted broker APIs;
- external audit sealing against an attacker able to coherently rewrite all trusted database state;
- formal verification;
- a generic guarantee that every detached/daemonized descendant process on every supported target OS dies immediately when an SSH transport is canceled.

See `docs/SSH_EXECUTION.md`, `docs/EMERGENCY_CONTROLS.md`, `docs/POSTGRESQL_PERSISTENCE.md`, and `docs/THREAT_MODEL.md` for the corresponding boundaries. Real acceptance evidence is recorded in `HANDOFF.md`, while `docs/INFRASTRUCTURE_ACCEPTANCE.md` remains the repeatable procedure.
