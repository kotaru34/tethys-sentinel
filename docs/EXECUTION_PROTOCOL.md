# Execution Protocol

This document defines the security-sensitive command execution protocol introduced in `0.1.0-dev.4`.

It intentionally stops before real SSH execution. The purpose of this milestone is to make authorization, approval, queueing, worker claim, revocation and replay behavior explicit and testable before adding SSH credentials.

## Security goal

An AI agent must never be able to authorize one command and later cause a different command to execute by changing target or argv, replaying an old request, reusing an approval, or racing a grant revocation.

The AI Gateway never sends an executable job directly to a worker. Only the Control Plane can create and publish execution jobs.

## Actors

- **Agent**: holds the opaque capability token and submits a requested command.
- **AI Gateway**: public-facing transport. It forwards only the capability hash plus request data to the Control Plane.
- **Control Plane**: authoritative grant/policy/approval owner and execution-job issuer.
- **Execution Worker**: private internal consumer. It cannot issue or broaden grants and never receives the agent capability.
- **Operator**: approves or denies sensitive requests and can revoke grants.

## Immutable command binding

Every execution job is bound to:

- grant ID;
- agent identity label;
- caller-supplied `request_id`;
- target;
- argv;
- expiry;
- applicable approval/risk metadata.

A canonical SHA-256 command binding is stored with the job. The worker recomputes and verifies this binding before any executor is invoked.

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
    +-------> succeeded
    |
    +-------> failed
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

Only after a successful start response may the worker invoke the executor.

### completion

Completion requires the same worker path and one-shot claim secret. A completed job cannot be completed again, and the stored claim-token hash is cleared.

## Approval semantics

Risk classification is recomputed in the Control Plane.

For an approval-required operation:

- `deny` prevents job publication;
- `allow_once` is consumed for one matching narrow operation;
- `allow_session` remains scoped to grant + target + risk category + concrete scope key.

The command is staged before one-shot approval consumption and published only after the approval/audit path succeeds.

If the process crashes after `allow_once` has been durably consumed but before publication, retrying the same `request_id` recovers and publishes the already-staged matching job rather than requesting a second approval or creating another job.

## Revocation behavior

Grant revocation is authoritative at multiple points:

1. new agent submissions fail because the grant no longer authenticates;
2. unclaimed pending/staged jobs for the grant are canceled;
3. a job already claimed by a worker still cannot execute unless the subsequent `start` gate revalidates the grant successfully.

Therefore revocation between claim and start prevents executor invocation.

Once a job has passed the `start` gate and is already running, termination semantics will be strengthened when the real remote executor is added. The current protocol guarantees the pre-execution boundary.

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
- SSH CA access.

The worker never receives the plaintext agent capability.

## Replay protections

The protocol rejects:

- second claim of the same job;
- start with the wrong claim secret;
- repeated start after transition to running;
- completion with the wrong claim secret;
- repeated completion after terminal state;
- rebinding an existing `request_id` to different target/argv.

## Current non-goals

`0.1.0-dev.4` does **not** yet:

- connect to SSH servers;
- issue SSH certificates;
- persist stdout/stderr;
- guarantee forced termination of a command that was already running when a later revocation occurs;
- replace bootstrap file stores with production database transactions.

Those are subsequent security milestones and must not be inferred from the existence of the worker protocol.
