# Emergency controls

`0.1.0-dev.10` adds a global AI-access kill switch and active worker authority monitoring.

The objective is stronger than "stop issuing new tokens": an operator emergency action must invalidate every existing agent capability, stop jobs that have not begun executing, prevent new SSH credentials from being issued, and make active workers terminate their execution transport when authority is lost.

## Security epoch

Global authority uses a persistent monotonically increasing **security epoch**.

Each grant is stamped with the current epoch when it is issued. Authentication requires both:

1. global AI access is enabled;
2. `grant.security_epoch == current security epoch`.

`REVOKE ALL` increments the epoch and disables global AI access. This permanently makes all grants from the previous epoch stale.

`Enable` clears the disabled flag but **does not roll the epoch back**. Therefore old capabilities do not become valid again after an incident is cleared. New grants must be issued in the current epoch.

Example:

```text
initial state      epoch=0 enabled
old grant          epoch=0

REVOKE ALL         epoch=1 disabled
old grant          stale + disabled

Enable             epoch=1 enabled
old grant          still stale
new grant          epoch=1 and valid
```

Repeated `REVOKE ALL` operations increment the epoch again even when the system is already disabled. This prevents an emergency action from being treated as a reversible boolean toggle.

## Operator API

The development Control Plane exposes the emergency API only on the operator/admin surface. The current admin listener remains loopback-bound and requires `SENTINEL_ADMIN_TOKEN`.

```text
GET  /admin/v1/emergency/state
POST /admin/v1/emergency/revoke-all
POST /admin/v1/emergency/enable
```

Optional reason body:

```json
{"reason":"suspected compromised agent"}
```

The agent-facing Gateway has no emergency-state mutation endpoint.

### `REVOKE ALL`

The Control Plane performs the emergency transition in the safety direction first:

1. increment security epoch;
2. set global state to disabled;
3. cancel `staged`, `pending`, and `claimed` execution jobs;
4. invalidate their claim secrets;
5. suppress new worker claims;
6. reject old/current-epoch grant authentication;
7. prevent `start` and SSH-certificate issuance through the normal grant checks;
8. append an emergency audit event;
9. active workers discover lost authority through the execution-authority lease and cancel their executor context.

Running jobs are deliberately not rewritten directly to `canceled` by the queue cleanup. The active worker owns their executor lifecycle and reports the actual terminal result after its transport has been canceled. This keeps the audit/job state aligned with what the worker really observed.

### `Enable`

Enabling is a higher-risk transition because it restores the ability to issue new authority.

The Control Plane therefore:

1. requires the system to currently be disabled;
2. writes an `emergency.enable_requested` audit event before changing state;
3. enables the current epoch without decrementing it;
4. writes `emergency.enabled` after the state transition;
5. if the post-enable audit append fails, attempts an immediate fail-closed `REVOKE ALL` again.

Existing stale grants are not rewritten or revived. The operator must create new grants after recovery.

## Worker execution-authority lease

A worker holding a short-lived SSH certificate is still not treated as permanently authorized for the remainder of the connection.

The worker-only internal API provides:

```text
POST /internal/v1/execution/jobs/{job_id}/authority
```

The request is protected by the existing worker credential and internal mTLS boundary and contains the worker identity plus the one-shot job claim secret.

An authority check succeeds only when all of the following remain true:

- global AI access is enabled;
- job is still `running`;
- claim secret still matches the running job;
- job has not expired;
- original grant still exists, is not individually revoked, and has not expired;
- grant security epoch still equals the current global epoch.

The endpoint is read-only and performs no job state transition.

## Active termination

`sentinel-worker` performs an authority check immediately before invoking the SSH executor and then periodically while execution remains active.

Default:

```text
SENTINEL_WORKER_AUTHORITY_POLL_MS=250
```

The configured value is also used as the timeout for each authority request. The CLI configuration currently requires at least 100 ms.

The worker treats **both explicit denial and inability to verify authority** as failure. A Control Plane outage, broken internal mTLS path, timeout, global revoke, individual grant revoke, stale epoch, invalid claim, or expired job therefore causes the worker to cancel the execution context rather than continue optimistically.

The SSH executor already binds its connection/session lifetime to that context, so cancellation closes the worker-side SSH transport. With the default interval, detection is normally bounded by the polling interval plus the bounded authority-request timeout, rather than the general 15-second HTTP client timeout.

Terminal job metadata records emergency/lease failures such as:

```text
execution_authority_denied
execution_authority_lost
ssh_access_issuance_failed
```

Raw stdout/stderr retention policy is unchanged.

## Races covered by independent gates

The kill switch does not depend on one timing-sensitive check.

### Revoke before claim

Non-running jobs are canceled and claim is suppressed.

### Revoke after claim, before start

The queued job is canceled when possible; independently, `start` re-authenticates the original grant and rejects the stale/disabled epoch.

### Revoke after start, before SSH certificate

The existing pre-certificate grant/policy gate rejects the old epoch. The worker now records a terminal `ssh_access_issuance_failed` result instead of leaving the job stuck as `running`.

### Revoke after certificate, before executor

The mandatory pre-executor authority check rejects execution.

### Revoke during SSH execution

The periodic authority lease fails and the worker cancels the executor context/SSH transport.

These layers intentionally overlap.

## Worker claim suppression

While global access is disabled, the exact worker claim route is guarded by the emergency state and returns `204 No Content` for an authenticated worker instead of handing out more jobs.

This is an operational consistency feature, not the only security boundary. A race that somehow obtains a claim still cannot pass the authoritative `start`, certificate, or execution-authority checks with a stale/disabled epoch.

## Persistence failure behavior

The bootstrap emergency state is stored in the Control Plane state directory (`SENTINEL_EMERGENCY_STATE`, default `/var/lib/tethys-sentinel/emergency.json`).

A revoke is a safety-direction transition. If persisting the new disabled state fails, the live Control Plane deliberately **keeps the new disabled epoch in memory** and returns an error to the operator. It does not roll back into an enabled live state merely because disk persistence failed.

An enable is the opposite direction. If enabling cannot be persisted, the in-memory state is rolled back to the prior disabled state and enabling fails.

Important limitation: file-backed bootstrap persistence cannot provide rollback-resistant durability after a storage failure. If a revoke reported a persistence failure, restarting the Control Plane is unsafe until the operator has repaired/reconciled durable emergency state. Production persistence must make the authority epoch transactional and durable rather than relying on a local JSON file.

## What active termination does not promise

Canceling the worker SSH context is the strongest generic transport action available without giving Sentinel broader target-side emergency privileges.

It does **not** prove that every descendant process on every supported operating system has died. An explicitly authorized command may daemonize, detach, hand work to another service, schedule future work, or trigger a remote system before the revoke arrives. Side effects already completed are not reversible.

Therefore emergency termination remains defense in depth with:

- narrowly scoped capabilities;
- one-shot approvals for powerful execution;
- short SSH certificate TTL;
- job expiration;
- no forwarding extensions;
- external worker egress containment;
- target Unix/sudo/doas restrictions;
- target one-shot replay state.

A future target-side supervisor could provide stronger process-tree guarantees for selected platforms, but it must not require a general root kill primitive exposed to the agent.

## External firewall interaction

`dev.9` worker egress enforcement and `dev.10` active authority are independent layers.

Changing a Proxmox firewall policy is not assumed to terminate an already-established stateful TCP flow. Conversely, the kill switch does not require mutating PVE firewall state during an incident. Active worker context cancellation handles established Sentinel execution sessions; external firewall containment continues to bound where the worker can connect.

## Recovery workflow

After `REVOKE ALL`:

1. keep global access disabled while investigating;
2. inspect audit, active/terminal jobs, grants and target state;
3. repair any persistence/network/control-plane issue first;
4. call `Enable` only when autonomous access should resume;
5. issue fresh grants in the current epoch;
6. do not expect old bearer tokens to work again.

`REVOKE ALL` invalidates authority. It does not delete configuration, history, audit records, runbooks, target inventory or other project data.
