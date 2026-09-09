# Execution Protocol

This document defines the security-sensitive command execution protocol introduced in `0.1.0-dev.4` and extended through real SSH execution in `0.1.0-dev.6`.

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
- **Operator**: approves or denies sensitive requests and can revoke grants.

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
    | authoritative start gate revalidates grant
    v
  running
    |
    | ephemeral key + certificate/target gate
    | pinned SSH + target replay consume
    | direct remote exec(argv)
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

The worker presents its worker credential, job ID and claim secret to the Control Plane `start` endpoint. The Control Plane revalidates the original grant immediately before changing the job to `running`.

A successful `start` still does not by itself provide SSH credentials.

### SSH credential and target gate

For a running job the worker generates a fresh Ed25519 keypair and sends only the public key to the Control Plane.

The Control Plane re-checks:

- running state;
- claim secret;
- job expiry;
- command binding;
- original grant activity;
- existence of the logical target in operator-owned SSH target inventory.

The Control Plane then asks the isolated Signer for a short-lived certificate and returns that certificate together with the protected target specification.

The worker verifies the certificate/private-key binding and target/job match before attempting SSH.

### remote execution

The worker connects only to the Control-Plane-resolved literal target IP/port and verifies one exact pinned host key.

The requested command is transported as a deterministic `sentinel-exec-v1` base64url JSON envelope rather than shell-quoted text.

The certificate force-command invokes `tethys-sentinel-exec --job <id> --binding <sha256>`. The wrapper verifies:

- force-command job ID equals envelope job ID;
- envelope logical target equals the host's local target ID;
- recomputed canonical binding equals the signer-bound binding.

Only then is the job consumed through target replay state and the verified argv launched directly.

### completion

Completion requires the same worker path and claim secret. A completed job cannot be completed again, and the stored claim-token hash is cleared.

The current result contains status/error metadata and output digest accounting, not raw stdout/stderr.

## Approval semantics

Risk classification is recomputed in the Control Plane.

For an approval-required operation:

- `deny` prevents job publication;
- `allow_once` is consumed for one matching narrow operation;
- `allow_session` remains scoped to grant + target + risk category + concrete scope key.

The command is staged before one-shot approval consumption and published only after the approval/audit path succeeds.

If the process crashes after `allow_once` has been durably consumed but before publication, retrying the same `request_id` recovers and publishes the already-staged matching job rather than requesting a second approval or creating another job.

Interpreter/shell arbitrary-code carriers require another policy-hardening pass before production trust; exact transport binding does not make opaque code safe to classify.

## Revocation behavior

Grant revocation is authoritative at multiple points:

1. new agent submissions fail because the grant no longer authenticates;
2. unclaimed pending/staged jobs for the grant are canceled;
3. a job already claimed by a worker still cannot execute unless the subsequent `start` gate revalidates the grant successfully;
4. a running job cannot obtain a new SSH certificate if the grant is revoked before certificate issuance.

After a certificate has been issued, OpenSSH provides no server-side instant revocation primitive for that already-issued certificate. `dev.6` limits the remaining window by:

- short certificate lifetime;
- source-address restriction;
- certificate validity capped by job expiry;
- worker execution context capped by job expiry;
- target-side at-most-once replay consumption.

A later global emergency-control milestone will add coordinated active worker/session termination semantics.

## Job-store integrity

The bootstrap file-backed execution store uses HMAC-SHA-256 records with a Control-Plane-only integrity key.

This is not encryption. It makes unauthorized modification detectable: an attacker who edits target, argv, status or other protected fields without the HMAC key cannot produce a valid record.

The production persistence migration is expected to move transactional state to PostgreSQL and preserve equivalent or stronger integrity/audit guarantees.

## Worker authentication

Worker endpoints are separate from agent endpoints and require a dedicated worker credential in addition to the protected internal transport.

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
- target execution with a mismatched local target ID;
- target execution with a different command binding;
- a second target-side consume of the same job ID.

The target replay semantic is deliberately at-most-once: once the root-protected marker is consumed, a process-start failure does not automatically reopen the job for remote replay.

## Connection and process bounds

- TCP dial timeout is bounded.
- SSH handshake has an explicit deadline even if the outer context has none.
- The execution context cannot outlive the job expiry.
- Stdout/stderr accounting is bounded per stream.
- Output overflow actively closes the SSH transport.
- Raw stdout/stderr is not persisted by the current worker.

## Current non-goals / remaining work

`0.1.0-dev.6` still does **not** provide:

- production PostgreSQL persistence;
- independent network egress enforcement of the target registry;
- complete emergency revoke-all/active-session shutdown semantics;
- a final policy model for interpreters/shells/arbitrary-code carriers;
- a production operator UI;
- formal guarantees that every remote descendant process on every supported OS is killed immediately on transport loss.

See `docs/SSH_EXECUTION.md` for the target transport/wrapper boundary and `docs/THREAT_MODEL.md` for the remaining security assumptions.
