# PostgreSQL persistence boundary

This document defines the PostgreSQL persistence boundary introduced in `0.1.0-dev.11` and accepted on real constrained infrastructure in `0.1.0-dev.13`.

PostgreSQL is not a SQL mirror of the development JSON/JSONL stores. It is the authoritative **transaction engine** for mutable security state so security-sensitive transitions and their required audit records either commit together or do not commit at all.

## Scope

PostgreSQL owns mutable runtime records for:

- grants, token hashes, target/permission/history scope;
- approval requests, decisions and one-shot consumption binding;
- execution jobs and one-shot worker claim hashes;
- global emergency security epoch/state;
- hash-chained audit events/history;
- Trust-2 agent continuity notes.

These remain separate operator-owned boundaries:

- authoritative Trust-0 context source;
- SSH target inventory;
- SSH signer CA key and signer policy;
- external PVE worker-egress policy.

Gateway, Worker and Signer receive no PostgreSQL credentials.

## Runtime selection and startup

Persistence selection is mandatory and explicit:

```text
SENTINEL_PERSISTENCE_BACKEND=file
SENTINEL_PERSISTENCE_BACKEND=postgres
```

`file` is the development compatibility backend. PostgreSQL additionally requires:

```text
SENTINEL_POSTGRES_DSN=postgres://...
```

Production PostgreSQL connections require TLS with server verification. `SENTINEL_DEV_INSECURE_POSTGRES=1` exists only for development/CI environments.

If PostgreSQL is selected and DSN parsing, connectivity, schema-version validation or runtime-role validation fails, Control Plane exits. It never falls back to file-backed authority.

The current schema version is **2**.

## Schema and migrations

Reviewed migrations live under `db/migrations/` and are applied in zero-padded numeric order by the deployment identity, never automatically by the service:

```text
0001_core.sql
0002_allow_once_job_binding.sql
```

`0001` creates the core mutable schema and initializes global authority fail-closed:

```text
epoch=0
disabled=true
```

`0002` adds `approvals.consumed_by_job_id` and advances schema version to 2. That column is a security binding: a consumed `allow_once` approval is durably tied to exactly one execution job, so a second staged job cannot reuse the same one-shot authority.

Each migration checks the schema version it expects before advancing it. See `db/README.md` for bootstrap order.

## Database roles

### `sentinel_owner`

Owns schema objects and is not used by running services.

### `sentinel_migrator`

Deployment-only identity permitted to apply reviewed migrations through the owner role path.

### `sentinel_control`

Control Plane runtime role. It has only the table DML needed by the application and no schema ownership, schema `CREATE`, table `DELETE`, role administration, database creation, superuser, replication or bypass-RLS authority.

The running service must never receive owner/migrator credentials.

## Core invariants

1. PostgreSQL mode never silently falls back to local files.
2. Plaintext capability tokens and worker claim tokens are never persisted.
3. Fresh PostgreSQL authority starts disabled.
4. Grant issue and global revoke serialize on the same `authority_state` row.
5. Re-enable never revives a grant from an older security epoch.
6. Individual grant revoke, non-running job cleanup and its audit record commit atomically.
7. Global revoke, epoch increment/disable, non-running job cancellation and emergency audit commit atomically.
8. Approval request/decision and their required audit records commit atomically.
9. `allow_once` consumption, binding to one job, staged-job publication and authorization audit commit atomically.
10. A `(grant_id, request_id)` is immutable and cannot be rebound to different command material.
11. Claim/start/complete are compare-and-transition operations over exact prior state and claim hash.
12. Concurrent worker claims use row locking with `SKIP LOCKED`.
13. Worker start revalidates current authority/grant state inside the transaction before changing `claimed -> running`.
14. Completion can still record the factual result after a grant has been revoked; it does not pretend the already-started execution never happened.
15. Audit append is serialized by `audit_head`, preserving deterministic sequence/hash-chain order.
16. Database time is authoritative for transactional expiry/order checks.

## Canonical lock order

Security-sensitive multi-object transactions use this order where the objects are involved:

1. `authority_state`;
2. grant;
3. approval;
4. execution job;
5. `audit_head` last.

Authority and grant locks are acquired explicitly rather than relying on planner ordering across a multi-table `FOR UPDATE/SHARE`. This keeps revoke, authorization and start paths reviewable and avoids avoidable deadlock cycles.

`READ COMMITTED` remains sufficient because security preconditions are explicitly re-read/locked inside each transition; `SERIALIZABLE` is not used as a substitute for defined lock order.

## Transaction semantics

### Grant issue

One transaction locks `authority_state`, rejects disabled state, stamps the current epoch, writes grant + targets, appends `grant.issued`, and commits. Only the hash of the generated capability token enters PostgreSQL.

Because revoke-all locks the same authority row, issue and revoke have a total order. A grant cannot commit from a stale pre-revoke epoch snapshot.

### Capability authentication

Authentication joins the grant with current authority state and succeeds only when global authority is enabled, grant epoch equals current epoch, grant is not revoked, and database time is before grant expiry.

Privileged transitions do not trust an earlier authentication snapshot; they revalidate inside their own transaction.

### Individual grant revoke

One transaction locks authority/grant state, marks the grant revoked, cancels its `staged`/`pending`/`claimed` jobs where applicable, clears claim hashes, appends `grant.revoked`, then commits.

Running jobs are not falsified as already terminated. Worker authority polling observes the revoked grant and closes the active execution context; completion may later record the factual terminal result.

### Global revoke and enable

`REVOKE ALL` locks `authority_state`, increments the epoch, sets global access disabled, cancels every non-running executable job/claim, appends the emergency audit event, and commits.

Enable requires disabled state, preserves the incremented epoch, writes the enable transition and its audit events in one transaction, and never revives old grants.

If PostgreSQL itself is unavailable, SQL cannot be the emergency stop. Deployment therefore still requires an out-of-band service/network stop for database-unavailable incidents.

### Approval request and decision

Approval creation/deduplication and `approval.requested` audit are one semantic operation. A partial unique index allows only one simultaneous pending approval for a narrow `(grant, target, category, scope_key)`.

Decision is conditional on `pending`, re-derives current policy for reusable-session eligibility, records decision + actor + timestamp, appends `approval.decided`, and commits atomically.

Powerful execution classes remain one-shot only; persisted metadata cannot widen current policy.

### Staged authorization and `allow_once`

Authorization revalidates authority, grant, `permission_exec`, target, agent, immutable command binding and current risk classification before publication.

For a risky job it also locks/validates the exact approval. `allow_session` must still be active and scope-matching. `allow_once` must either be unconsumed or already consumed by **that same job**; it cannot authorize a different job.

For first use of `allow_once`, the same transaction:

1. binds `consumed_by_job_id` to the staged job;
2. marks the approval consumed;
3. publishes `staged -> pending`;
4. appends `execution.job_authorized`;
5. commits.

If any step, including audit append, cannot commit, approval consumption and job publication roll back together.

Invalid/stale authorization fails closed and the staged job is canceled with a rejection audit event where applicable.

### Worker claim

Claim selects the oldest eligible pending job using `FOR UPDATE SKIP LOCKED`, generates a fresh claim secret in process memory, persists only its SHA-256, changes the job to `claimed`, appends `execution.job_claimed`, and commits.

Concurrent workers cannot claim the same job.

### Worker start

Start locks/revalidates authority and grant before the job transition, verifies status, claim hash and expiry, then changes only `claimed -> running`, records start time, appends `execution.job_started`, and commits.

Individual/global revoke therefore cannot slip between the authoritative grant check and the running transition without acquiring the same ordered locks.

### Worker completion

Completion verifies the exact running job + claim hash, records terminal status/result, clears claim material, appends `execution.job_completed`, and commits atomically.

Completion deliberately does not require the original grant to remain live: after emergency/revoke cancellation of the active transport, Sentinel still needs to record what actually happened. Replay fails because the prior job state/claim no longer matches.

### Audit

Every state transition that requires an audit record uses the same PostgreSQL transaction and a transaction-scoped audit writer. Standalone informational audit events use their own short transaction.

Audit append locks singleton `audit_head`, derives the next sequence/hash from the canonical Go event format, inserts the event, and advances the head before commit. PostgreSQL therefore preserves the existing event-hash compatibility contract rather than inventing a second chain format.

### Notes/history

Audit history reads verify the chain before returning records. Agent notes are immutable Trust-2 data with provenance/content hash; durable storage never promotes them into Trust-0 authority.

## One-shot secrets

Capability and worker claim plaintext values exist only long enough to return them to the caller that needs them. PostgreSQL stores SHA-256 material only.

Execution jobs retain immutable command-binding hashes. The development file-store HMAC is not duplicated into PostgreSQL; database integrity relies on ownership/privileges, constraints, transactional durability, WAL and protected backups.

## Cutover from file development state

There is no automatic live import. Safe initial cutover is:

1. stop Gateway, Worker and Control Plane;
2. initialize/apply PostgreSQL migrations while authority remains disabled;
3. ensure the PostgreSQL epoch is newer than any imported historical authority if history is migrated;
4. optionally import audit/notes/terminal history for continuity;
5. never import old active bearer grants as active;
6. never import claimed/running jobs as executable work;
7. validate schema, role privileges, history and row counts offline;
8. start Control Plane with `SENTINEL_PERSISTENCE_BACKEND=postgres` while still disabled;
9. explicitly enable authority and issue fresh grants only after validation.

This intentionally sacrifices old live capabilities rather than risk duplicated authority.

## Backup and recovery

Use protected PostgreSQL base backups plus WAL/PITR appropriate to the deployment. Backups contain sensitive authority/audit data.

Restoring an older database can restore an older security epoch. A restored database must therefore come up disabled/network-isolated and receive an epoch bump/revoke-all before Gateway/Worker access is permitted.

## CI acceptance

The CI matrix applies the full migration chain and runtime privilege assertions to real PostgreSQL **15** and **18**, then runs PostgreSQL integration tests. General Go CI also requires module tidy, `gofmt`, `go vet` and `go test -race ./...`.

Current integration coverage includes:

- grant issue vs revoke-all serialization and stale-epoch non-revival;
- revoke rollback when audit cannot commit;
- approval persistence/dedup/decision semantics;
- execution idempotency and concurrent claims;
- atomic one-shot approval binding under concurrent authorization attempts;
- authorization racing individual revoke;
- one-shot authorization rollback when `audit_head` is blocked;
- transactional authorize -> claim -> start -> complete lifecycle;
- completion replay rejection;
- emergency API behavior and PostgreSQL stores;
- explicit backend selection and no PostgreSQL-to-file fallback.

## Real infrastructure acceptance

The dev.13 constrained infrastructure run completed the previously outstanding persistence acceptance. Evidence in `HANDOFF.md` proves:

- PostgreSQL 18.6 with schema version 2 and least-privilege runtime role on the intended topology;
- authority state persisted exactly across Control restart;
- real transactional end-to-end job/audit lifecycle completed through Worker/Signer/SSH target;
- `allow_once` consumption remained durable and non-reusable;
- individual and global revoke produced the expected durable/audited state while active execution later recorded the factual failure;
- epoch 1 remained permanently stale after re-enabling epoch 2;
- a second exact dev.13 Control binary with an unreachable PostgreSQL endpoint exited during startup before opening API listeners;
- deliberate file-backend trap paths remained untouched, proving no silent PostgreSQL-to-file fallback;
- the live accepted Control instance stayed active during the unavailable-database startup test.

`docs/INFRASTRUCTURE_ACCEPTANCE.md` remains the repeatable procedure. Any future change to persistence semantics must re-run the relevant CI and real-infrastructure checks before release/merge.
