# PostgreSQL persistence boundary

This document defines the production persistence target for the milestone after `0.1.0-dev.10`.

The goal is not to reproduce the development JSON/JSONL stores in SQL. PostgreSQL becomes the authoritative **transaction engine** for mutable security state so operations that currently cross several file stores can be committed or rejected as one unit.

## Scope

Move these mutable runtime records to PostgreSQL:

- grants and token hashes;
- grant target/permission/history scope;
- approval requests and decisions;
- execution jobs and one-shot claim hashes;
- global emergency security epoch/state;
- audit chain/events;
- agent continuity notes.

Keep these operator-owned, read-only configuration sources outside the database for this milestone:

- authoritative Trust-0 context source;
- SSH target inventory;
- signer CA key and signer policy;
- external PVE worker-egress policy.

Those files are configuration/secret boundaries, not mutable runtime state. Moving them into the same mutable database now would increase the blast radius without solving the current durability/transaction problem.

## Non-negotiable invariants

1. Production mode never silently falls back from PostgreSQL to local files.
2. Plaintext capability and worker claim tokens are never stored.
3. Grant issue and global revoke serialize on the same authority-state row.
4. Re-enable cannot revive an older security epoch.
5. Global revoke state change, cancellation of non-running jobs, and emergency audit record commit atomically.
6. `allow_once` consumption and publication of its bound execution job commit atomically.
7. A request ID is unique per grant and can never be rebound to different command material.
8. A pending job can be claimed by at most one worker; concurrent workers use row locking with `SKIP LOCKED`.
9. Claim/start/complete are compare-and-transition operations over exact prior state and claim hash.
10. Audit append is serialized through an audit-head row so sequence/hash-chain order is deterministic under concurrency.
11. Database time is authoritative for state-transition timestamps and expiry checks where a transaction depends on ordering.
12. Gateway, Worker and Signer receive no PostgreSQL credentials.

## Schema layout

Use one PostgreSQL schema, initially `sentinel`, owned by a migration/owner role rather than the runtime Control Plane role.

### `sentinel.authority_state`

Singleton row (`id = 1`):

- `epoch` — monotonic non-negative authority generation;
- `disabled`;
- `updated_at`;
- `reason`.

All grant issuance and emergency transitions lock this row.

PostgreSQL `BIGINT` is sufficient operationally if the implementation explicitly caps the Go `uint64` epoch at `math.MaxInt64`; alternatively a later migration may use `NUMERIC(20,0)`. Epoch exhaustion is fail-closed either way.

### `sentinel.grants`

- `id` text primary key;
- `token_hash bytea` unique, exactly 32 bytes;
- `purpose`, `agent`;
- booleans for `exec`, `shell`, `upload`, `download`, `history_read`, `notes_read`, `notes_write`;
- booleans for history scope (`current_session`, `previous`, `other_agents`, `include_output`);
- `security_epoch`;
- `issued_at`, `expires_at`, `revoked_at`.

Targets are normalized into `sentinel.grant_targets(grant_id, target)` with a composite primary key.

No plaintext token column exists.

### `sentinel.approvals`

- current `approval.Request` fields;
- argv as `text[]`;
- status/decision as text with check constraints;
- created/decided timestamps;
- decision actor;
- `session_approval_allowed` is derived policy metadata, not authority by itself.

A partial unique index prevents more than one simultaneous `pending` approval for the same `(grant_id, target, category, scope_key)`.

Reusable approval lookup is indexed by `(grant_id, target, category, scope_key, status, created_at desc)`.

### `sentinel.execution_jobs`

- current immutable job identity/binding fields;
- argv as `text[]`;
- command binding SHA-256;
- approval/risk/scope metadata;
- lifecycle timestamps and status;
- `claim_token_hash bytea` only while claimed/running;
- terminal result fields (`success`, `exit_code`, `output_sha256`, `error_kind`).

Constraints:

- unique `(grant_id, request_id)`;
- command/output hashes have exact lengths;
- known lifecycle statuses only;
- terminal result fields are only meaningful for terminal states;
- no plaintext claim token.

The file-store HMAC is not copied into PostgreSQL. Database integrity comes from DB ownership/permissions, constraints, transactions, WAL/durability and backups. HMAC does not protect against the trusted runtime role that would also possess its key.

### `sentinel.audit_head`

Singleton row:

- last sequence;
- last hash.

Every audit append transaction takes `FOR UPDATE` on this row, constructs the next event using the previous hash, inserts the event, then advances the head before commit.

### `sentinel.audit_events`

Preserve the existing event shape:

- sequence unique/primary ordering;
- ID and timestamp;
- kind/actor/grant/target/argv;
- decision/category/scope/approval/reason;
- metadata JSONB;
- previous hash;
- event hash.

The existing Go canonical event hashing format remains the compatibility contract initially. PostgreSQL stores the resulting hashes; it does not invent a second incompatible chain format.

### `sentinel.agent_notes`

Immutable rows containing current note identity/provenance:

- ID/timestamp;
- grant/agent/target;
- Trust-2 level;
- content;
- content SHA-256.

Notes remain non-authoritative even though they are durably stored.

## Transaction matrix

### Grant issue

One transaction:

1. `SELECT ... FROM authority_state WHERE id=1 FOR UPDATE`;
2. reject if disabled;
3. assign current epoch to the grant;
4. insert grant + targets;
5. commit;
6. return the plaintext token only to the caller.

The token is generated before/during the transaction in application memory and only its SHA-256 enters PostgreSQL.

Because revoke-all locks the same singleton row, issue and revoke have a total order. A newly returned grant is therefore either committed before revoke and immediately invalidated by the new epoch, or issued after a later explicit enable in the new epoch; it cannot be committed from a stale snapshot after revoke.

### Capability authentication

A single read joins grant state with `authority_state` and succeeds only when:

- global state is enabled;
- grant epoch equals current epoch;
- `revoked_at IS NULL`;
- database current time is before `expires_at`.

No lock is required for ordinary authentication; any subsequent privileged transition revalidates inside its own transaction/lease gate.

### Individual grant revoke

One transaction:

1. lock/update the grant if not already revoked;
2. cancel its `staged`/`pending`/`claimed` jobs where applicable;
3. clear claim hashes on canceled jobs;
4. append audit event using the same transaction-aware audit writer;
5. commit.

Running jobs are not falsified as already terminated. Their next active authority check sees the revoked grant and the worker closes its execution context.

### Global `REVOKE ALL`

One transaction:

1. lock `authority_state FOR UPDATE`;
2. increment epoch and set disabled;
3. cancel every `staged`/`pending`/`claimed` job and clear claim hashes;
4. append `emergency.revoke_all` audit event;
5. commit.

This removes the development file-store state where emergency state, job cleanup and audit can persist independently.

A failed transaction leaves the old database state unchanged, so the operator endpoint must return failure. Production deployment should additionally retain an out-of-band service/network emergency stop for database-unavailable incidents; SQL cannot revoke authority if the authoritative database itself is unreachable. Workers already treat inability to verify authority as fail-closed.

### Emergency enable

One transaction:

1. lock `authority_state`;
2. require `disabled=true`;
3. append `emergency.enable_requested`;
4. set `disabled=false` without decrementing epoch;
5. append `emergency.enabled`;
6. commit.

No compensating revoke is needed if all three records are in one PostgreSQL transaction: a commit failure leaves the system disabled.

### Approval request

Insert a pending approval. The partial unique index resolves concurrent duplicate requests for the same narrow scope; the application loads and returns the existing pending row when the unique constraint wins the race.

### Approval decision

Conditional update `WHERE status='pending'`. `allow_session` eligibility remains re-derived from current risk policy before accepting the decision; a persisted boolean is not trusted to broaden policy.

### Allow-once execution publication

The security-critical path must not do `consume approval` and `publish job` in independent transactions.

One transaction locks both rows and performs:

1. validate staged job and immutable binding;
2. validate bound approval scope/category/target/grant;
3. require `allow_once + decided`;
4. set approval `consumed`;
5. set staged job `pending`;
6. append authorization audit event;
7. commit.

Crash before commit consumes nothing and publishes nothing. Crash after commit publishes exactly one already-consumed authorization.

For session approval, publication still validates the exact current approval under the same job transaction but does not consume it.

### Worker claim

One short transaction selects the oldest eligible pending job with:

```sql
SELECT id
FROM sentinel.execution_jobs
WHERE status = 'pending'
  AND expires_at > clock_timestamp()
ORDER BY created_at, id
FOR UPDATE SKIP LOCKED
LIMIT 1;
```

The worker claim secret is generated in process memory, SHA-256 is stored, and the selected row changes to `claimed` before commit.

Expired pending rows may be marked `expired` in bounded cleanup batches; claim does not need a global queue mutex.

### Worker start

One transaction locks the exact job and revalidates:

- status `claimed`;
- claim hash;
- job not expired;
- original grant is active and current-epoch;
- global authority is enabled.

Then it changes only `claimed -> running`, records `started_at`, and commits.

### Worker authority lease

One read transaction/query verifies running job + claim hash + job expiry + active grant + current authority epoch. No state mutation occurs.

A result is only a short lease observation; the worker must continue polling. DB/control connectivity loss remains fail-closed.

### Worker completion/rejection

Conditional row update with exact job ID, `running`/allowed prior state and claim hash. On terminal transition claim hash is cleared. Replays fail because the prior state no longer matches.

### Audit append

Every path that must couple state and audit receives a transaction-scoped audit writer instead of calling a separate auto-commit audit store.

Standalone informational audit events use their own short transaction but still serialize `audit_head`.

## Isolation and locking

Default transaction isolation may remain `READ COMMITTED` if every security-sensitive transition explicitly locks the rows that establish its preconditions.

Do not globally switch to `SERIALIZABLE` as a substitute for defining lock order; that would add retry complexity without documenting the actual authority dependencies.

Canonical lock order for multi-object transitions:

1. `authority_state` when involved;
2. grant;
3. approval;
4. execution job;
5. `audit_head` last.

Code must not acquire these in the opposite order in another path. This reduces deadlock risk and makes transaction review tractable.

## Database roles

Deployment creates roles outside ordinary application migrations.

### `sentinel_owner`

- owns schema/tables/functions;
- `NOLOGIN` where operationally practical;
- not used by running services.

### `sentinel_migrator`

- deployment-only login/role allowed to apply reviewed migrations as/for the owner;
- no service runtime use.

### `sentinel_control`

- Control Plane runtime role;
- connect/use schema and only the DML/sequence privileges required by current tables;
- no schema ownership, `CREATE`, role administration, database creation, superuser, replication or bypass-RLS privileges.

Gateway, Worker and Signer do not receive this credential and do not connect directly to PostgreSQL.

A future physically separate audit sink may use insert-only/read roles. Splitting several passwords inside the same Control Plane process does not protect against total Control Plane RCE, so role proliferation is not treated as a substitute for process isolation.

## Connection security

Production DSN requirements:

- TLS with server identity verification (`sslmode=verify-full` or equivalent pgx TLS config);
- credentials from protected secret files/environment injection, never repository config;
- bounded pool sizes and statement/transaction timeouts;
- startup health check must fail the service if the configured production database is unavailable.

The runtime must not auto-create schema or apply migrations.

## No silent fallback

Storage backend selection must be explicit.

Suggested behavior:

```text
SENTINEL_STORE_BACKEND=file      # development only
SENTINEL_STORE_BACKEND=postgres  # production candidate
```

If `postgres` is selected and connection/schema validation fails, Control Plane exits. It must not fall back to stale local JSON authority state.

A later explicit `SENTINEL_ENV=production` mode should reject `file` entirely.

## Migration from development file state

There is no automatic live import.

Safe initial migration policy:

1. stop Gateway/Worker/Control Plane;
2. initialize PostgreSQL with global AI access **disabled**;
3. set the PostgreSQL epoch to a value newer than any imported file epoch;
4. optionally import audit, notes and terminal historical records for continuity;
5. do not import active bearer authority as active;
6. imported grants, if retained for provenance, are marked revoked/stale;
7. do not import claimed/running jobs as executable work;
8. validate row counts/hash-chain/history offline;
9. start Control Plane against PostgreSQL while still disabled;
10. explicitly enable and issue fresh grants only after validation.

This intentionally sacrifices old live capabilities rather than risking authority duplication during backend cutover.

## Backups and recovery

PostgreSQL durability does not eliminate the need for recovery rules.

- use regular base backups plus WAL/PITR appropriate to the deployment;
- protect backups as sensitive authority/audit data;
- restoration to an older point can resurrect an older authority epoch in the database.

Therefore disaster recovery must include an **epoch bump/revoke-all after restore before any worker/gateway access is permitted**. A restored database must come up behind an operator-controlled disabled/network-isolated state until this is done.

## Testing requirements

Before PostgreSQL becomes the accepted production backend, automated tests must cover at least:

- concurrent grant issue vs revoke-all;
- concurrent duplicate request IDs;
- concurrent duplicate approval requests;
- two workers racing to claim one job;
- claim token replay;
- grant revoke racing start;
- revoke-all racing claim/start;
- allow-once consume + publication crash/rollback;
- completion replay;
- audit-head concurrent appends and chain verification;
- database disconnect during active worker authority checks;
- enable transaction rollback;
- migration startup with wrong schema version;
- production backend refusing file fallback.

The PostgreSQL integration suite should run against a real PostgreSQL service in CI; SQL semantics are not meaningfully validated by a mock database.
