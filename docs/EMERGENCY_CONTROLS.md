# Emergency controls

`0.1.0-dev.10` introduced the monotonic global security epoch and active worker authority monitoring. `0.1.0-dev.11` moves the mutable emergency state and its coupled job/audit transitions into PostgreSQL transactions for the production-candidate backend.

The objective is stronger than "stop issuing new tokens": an operator emergency action must invalidate existing agent capabilities, stop jobs that have not begun executing, prevent new SSH credentials from being issued, and make active workers terminate their execution transport when authority is lost.

## Security epoch

Global authority uses a persistent monotonically increasing `security_epoch`.

Each grant is stamped with the current epoch at issuance. Authentication requires:

1. global AI access enabled;
2. grant epoch exactly equal to current epoch;
3. grant not individually revoked;
4. grant not expired.

`REVOKE ALL` increments the epoch and disables global AI access. `Enable` clears the disabled state without decreasing the epoch. Therefore every grant from the previous epoch remains permanently stale.

Repeated `REVOKE ALL` operations increment the epoch again even while already disabled; emergency authority is not a reversible boolean toggle.

## Operator API

The admin listener remains loopback-only and requires `SENTINEL_ADMIN_TOKEN`:

```text
GET  /admin/v1/emergency/state
POST /admin/v1/emergency/revoke-all
POST /admin/v1/emergency/enable
```

Optional reason body:

```json
{"reason":"suspected compromised agent"}
```

Gateway exposes no emergency mutation path.

### `REVOKE ALL`

In PostgreSQL mode, one transaction:

1. locks `authority_state`;
2. increments epoch;
3. sets global authority disabled;
4. cancels `staged`, `pending`, and `claimed` jobs;
5. clears their claim hashes;
6. appends `emergency.revoke_all` through the transaction-scoped canonical audit writer;
7. commits.

If the transaction cannot commit, the operator gets failure rather than a partially durable SQL state.

Independent runtime gates then ensure:

- no new legitimate capability use can authenticate;
- worker claims yield no work while disabled;
- `start` cannot authorize a stale/disabled grant;
- pre-certificate validation cannot issue fresh SSH authority;
- active Worker authority leases fail and cancel execution context/SSH transport.

Running jobs are deliberately not rewritten directly to `canceled` by queue cleanup. Worker owns their active lifecycle and later records the factual terminal result.

### `Enable`

Enable requires the system to be disabled and keeps the current epoch. PostgreSQL couples the enable state transition and its audit records in one transaction. Old grants are not rewritten or revived; fresh authority requires a new grant in the current epoch.

The explicit file development backend retains its legacy fail-closed compensating behavior, but it is not the production durability model.

## Worker execution-authority lease

Worker-only internal endpoint:

```text
POST /internal/v1/execution/jobs/{job_id}/authority
```

It requires the dedicated Worker credential and protected internal mTLS transport. Request contains Worker identity plus the job's one-shot claim secret.

A positive lease requires:

- global authority enabled;
- job still `running` and unexpired;
- claim secret still matching;
- original grant present, unrevoked and unexpired;
- grant epoch equal to current global epoch.

The endpoint does not mutate job state.

`sentinel-worker` checks authority immediately before executor invocation and periodically while execution remains active. Default:

```text
SENTINEL_WORKER_AUTHORITY_POLL_MS=250
```

The configured interval is also the individual authority-request timeout. Explicit denial **and inability to verify authority** are fail-closed.

A Control Plane outage, internal mTLS failure, timeout, global revoke, individual grant revoke, stale epoch, invalid claim or expiry therefore cancels the Worker execution context. The SSH executor binds transport lifetime to that context and closes its side of the connection on cancellation.

Terminal metadata can record conditions such as:

```text
execution_authority_denied
execution_authority_lost
ssh_access_issuance_failed
```

Raw stdout/stderr is not retained by the current Worker.

## Race coverage

Emergency safety does not depend on one timing-sensitive check.

### Revoke before claim

Non-running work is canceled and new claim attempts return no work while globally disabled.

### Revoke after claim, before start

Revoke clears/cancels the claim when it obtains the ordered locks first. Independently, PostgreSQL `start` revalidates current authority/grant while holding the relevant locks before `claimed -> running`.

### Revoke racing authorization

PostgreSQL staged authorization and individual/global revoke share ordered authority/grant locks. A job cannot remain newly pending under a revoked grant: either authorization commits first and revoke subsequently cancels the non-running job, or revoke wins and authorization fails closed.

### Revoke after start, before certificate

Pre-certificate policy/grant/epoch validation rejects the revoked state. Worker records a factual terminal failure rather than leaving a stuck running row.

### Revoke after certificate, before executor

Mandatory pre-executor authority check rejects execution.

### Revoke during SSH execution

Periodic authority lease fails and Worker cancels executor context/SSH transport.

These layers intentionally overlap.

## PostgreSQL durability semantics

For `SENTINEL_PERSISTENCE_BACKEND=postgres`, emergency authority state is the singleton `sentinel.authority_state` row. Fresh schema initializes:

```text
epoch=0
disabled=true
```

The application never auto-enables a fresh database.

Grant issuance locks the same authority row as global revoke, so a grant cannot commit from a stale pre-revoke epoch snapshot.

Audit append uses `audit_head` in the same transaction after authority/grant/job state locks. A blocked/failed audit append rolls back the security-state transition rather than leaving SQL state and audit history disagreeing.

The PostgreSQL runtime role is least privilege and cannot apply migrations or own the schema. Gateway, Worker and Signer hold no database credentials.

If PostgreSQL itself is unavailable, SQL cannot execute `REVOKE ALL`. Deployment must retain an out-of-band operator stop such as stopping/isolating Gateway/Worker/Control or cutting the Worker network boundary. Services that cannot verify authority fail closed; nevertheless the database-unavailable incident procedure must not depend solely on making a successful SQL mutation.

See `docs/POSTGRESQL_PERSISTENCE.md`.

## File development backend

`SENTINEL_PERSISTENCE_BACKEND=file` remains explicit development compatibility mode. Its local emergency file is `SENTINEL_EMERGENCY_STATE`.

A safety-direction revoke keeps live in-memory authority disabled even if local persistence fails; an operator must not restart that development Control Plane until durable state is reconciled. This behavior is retained for testing but is not advertised as production durability.

There is never an automatic fallback from failed PostgreSQL startup to this file state.

## What active termination does not promise

Canceling Worker SSH transport is the strongest generic transport action available without granting a broad target-side kill primitive.

It does **not** prove that every descendant process on every target has died. An explicitly authorized command can daemonize, detach, hand work to another service, schedule future work, or trigger another system before revoke arrives. Completed side effects are not reversible.

Emergency termination therefore remains defense in depth with:

- scoped/short-lived capabilities;
- one-shot approval for powerful execution;
- short SSH certificate TTL;
- job expiry;
- no forwarding extensions;
- external Worker egress containment;
- target Unix/sudo/doas restrictions;
- target one-shot replay state.

A future platform-specific target supervisor could offer stronger process-tree guarantees without exposing a general root kill primitive to the agent.

## External firewall interaction

Worker egress enforcement and active authority revocation are independent boundaries.

Changing a Proxmox firewall rule is not assumed to terminate an established stateful TCP flow. Conversely, `REVOKE ALL` does not need to mutate PVE firewall policy during an incident. Active Worker context cancellation handles Sentinel's established execution transport while the external firewall continues to bound reachable destinations.

## Recovery workflow

After `REVOKE ALL`:

1. keep authority disabled while investigating;
2. inspect verified audit/history, job state, grants and target state;
3. repair database/network/control issues first;
4. call `Enable` only when autonomous access should resume;
5. issue fresh grants in the current epoch;
6. verify pre-revoke capabilities remain invalid.

After PostgreSQL restore/PITR, treat restored authority as unsafe until the database is isolated/disabled and a new epoch/revoke is established before Gateway/Worker access resumes.

`REVOKE ALL` invalidates authority. It does not delete configuration, history, audit, runbooks, target inventory or other project data.

Real infrastructure acceptance for these semantics is defined in `docs/INFRASTRUCTURE_ACCEPTANCE.md`.
