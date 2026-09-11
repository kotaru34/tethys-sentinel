# Architecture

## Trust-boundary overview

```text
                              Operator
                                 |
                         Admin UI / API
                                 |
                    +------------v------------+
                    |      Control Plane      |
                    | grants / policy         |
                    | approvals / Trust-0     |
                    | security epoch / kill   |
                    | immutable job issuance  |
                    | SSH target resolution   |
                    | certificate gate        |
                    +---+-----------+----------+
                        |           |
          PostgreSQL TLS|           | dedicated mTLS + signer credential
                        |           |
                 +------v-----+  +--v-----------+
                 | PostgreSQL |  | SSH Signer   |
                 | authority  |  | CA boundary  |
                 | audit/jobs |  +--------------+
                 +------------+
                        ^
                        | Control Plane only
                        |
             internal mTLS
                        |
                 +------v-----+
                 | AI Gateway |
                 | public API |
                 +------------+
                        ^
                        | worker-only internal API is on
                        | the same Control Plane mTLS endpoint
                        |
                +-------+-------------+
                | External worker     |
                | network boundary    |
                | Control + SSH only  |
                +-------+-------------+
                        |
                 +------v-------+
                 | Execution    |
                 | Worker       |
                 | ephemeral key|
                 | active lease |
                 | pinned SSH   |
                 +------+-------+
                        |
                 operator-resolved literal IP
                        |
                 +------v----------------+
                 | Target sshd           |
                 | trusted Sentinel CA   |
                 | dedicated account     |
                 +------+----------------+
                        |
                 certificate force-command
                        |
                 +------v----------------+
                 | tethys-sentinel-exec  |
                 | verify binding/target |
                 | one-shot replay gate  |
                 | direct exec(argv)     |
                 +-----------------------+
```

`0.1.0-dev.11` adds PostgreSQL as the production-candidate persistence/transaction boundary. File-backed stores remain available only through explicit development selection. Trust-0 context, SSH target inventory, signer key/policy and external worker-egress policy deliberately remain separate operator-owned configuration boundaries.

## Components

### Control Plane

Human/operator authority. Owns grant creation/revocation, global security epoch, emergency enable/disable, policy decisions, approvals, Trust-0 context/inventory, history filtering, immutable execution-job authorization, SSH target resolution, certificate eligibility and transactional audit integration.

Only Control Plane receives PostgreSQL runtime credentials and only Control Plane may call SSH Signer. Gateway, Worker and Signer receive no database credential.

Production-candidate mutable state is opened through explicit `SENTINEL_PERSISTENCE_BACKEND=postgres`. Failure to connect, validate schema version or validate runtime role terminates startup; there is no fallback to file authority.

Authoritative context comes from `SENTINEL_CONTEXT_FILE`. SSH transport resolution comes from `SENTINEL_SSH_TARGETS_FILE`; jobs contain only logical target IDs.

### PostgreSQL transaction boundary

Schema version 2 persists:

- grants and target/permission/history scope;
- approvals, decisions and durable one-shot approval-to-job binding;
- execution jobs and hashed claim secrets;
- emergency authority epoch/state;
- canonical hash-chained audit/history;
- Trust-2 continuity notes.

Security-sensitive operations use semantic transactions rather than independent repository writes. Required state changes and audit events commit together.

Canonical multi-object lock order is:

```text
authority_state -> grant -> approval -> execution job -> audit_head
```

Grant issue and global revoke serialize on `authority_state`; authorization/start revalidate current authority and grant under lock. `allow_once` consumption is durably bound to exactly one job through `consumed_by_job_id` and commits together with job publication and authorization audit.

The runtime role has no schema ownership/CREATE, table DELETE, superuser, role-admin, replication or bypass-RLS authority. Schema migrations use separate deployment identities.

See `docs/POSTGRESQL_PERSISTENCE.md`.

### Global emergency authority boundary

A monotonic security epoch prevents reversible kill-switch semantics.

Every grant is stamped with current `security_epoch`. Authentication requires global authority enabled, matching epoch, unrevoked grant and unexpired lifetime.

`REVOKE ALL` increments epoch, disables access, cancels non-running executable jobs and invalidates their claim material. PostgreSQL commits this state transition and emergency audit atomically. A later `Enable` preserves the incremented epoch, so pre-revoke tokens stay stale forever.

Running jobs are stopped through the Worker active-authority lease rather than falsifying their database state as already terminated. Completion later records the factual outcome even when the original grant has been revoked.

See `docs/EMERGENCY_CONTROLS.md`.

### AI Gateway

Public capability-facing boundary. Exposes bootstrap/context/history/notes and command submission. It has no grant creation, emergency mutation, approval mutation, worker control, target mutation, certificate signing, database credential, or CA-secret path.

Gateway performs early capability/policy consistency checks for protocol behavior, but Control Plane remains authoritative.

### Execution policy boundary

`exec` and `shell` are distinct authorization dimensions.

- `exec` permits ordinary structured argv operations within logical target scope.
- `shell` additionally permits powerful classes capable of arbitrary code, privilege broadening or lateral/remote execution.

`ARBITRARY_CODE`, `PRIVILEGE_LAUNCHER`, and `REMOTE_EXEC` require `shell=true` and are one-shot approval only. Human approval never manufactures a missing capability.

See `docs/EXECUTION_POLICY.md` and `docs/OPERATIONAL_RISK.md`.

### External Worker network boundary

The Worker is independently contained even if its process/guest is compromised.

On PVE, the hard runtime egress boundary lives outside the guest on the VM-interface firewall. Normal autonomous Worker egress is only:

1. literal-IP HTTPS to Control Plane;
2. registered literal IP:port SSH endpoints.

`sentinel-egress-policy` renders/verifies deny-by-default PVE rules, installed-policy drift, Datacenter firewall activation and the VM NIC `firewall=1` requirement. It never applies policy as a Worker privilege.

Packet-level tests from inside the Worker remain mandatory for infrastructure acceptance.

See `docs/WORKER_EGRESS.md`.

### Execution Worker

Worker never receives plaintext agent capability, database credentials, target inventory, signer credential/CA material, admin authority or PVE credentials.

Current flow:

1. claim one immutable pending job;
2. locally verify immutable binding;
3. pass authoritative Control Plane start gate;
4. generate fresh per-job Ed25519 keypair in memory;
5. send only public key for certificate issuance;
6. receive short-lived certificate + operator-resolved target;
7. verify certificate/key/job lifetime and logical target;
8. perform mandatory active-authority check;
9. create executor context bounded by job/grant lifetime;
10. dial only resolved literal IP/port allowed by external egress policy;
11. verify exact pinned SSH host key;
12. periodically re-check authority while execution is active;
13. cancel executor/SSH transport on authority loss;
14. complete once with terminal result metadata/output digest.

PostgreSQL claim/start/complete are transactional semantic operations. Claim uses row locking/`SKIP LOCKED`; start serializes with revoke through authority/grant locks; completion is replay-resistant and atomically records required audit.

Default active-authority interval is 250 ms (`SENTINEL_WORKER_AUTHORITY_POLL_MS`). Explicit denial or inability to verify authority fails closed.

### Pre-certificate policy and authority gate

Immediately before infrastructure credentials are returned, Control Plane validates running job/claim/binding, re-runs current risk policy, requires category/scope equality, re-authenticates original grant/current epoch, requires `shell=true` when needed, resolves the protected target, then calls Signer.

This prevents queued jobs from freezing stale classifier or authority state.

### SSH Signer

Standalone CA boundary. `sentinel-signer` alone holds the SSH CA private key. Normal operation requires dedicated bearer credential + mutual TLS.

Caller cannot choose principal, source addresses, arbitrary force-command, extensions or TTL. Signer accepts a per-job Ed25519 public key and issues a short certificate bounded by the job lifetime.

### Target execution boundary

Signer critical `force-command` invokes `tethys-sentinel-exec` with signer-controlled job ID and command binding. Agent argv travels separately in deterministic versioned base64url JSON through `SSH_ORIGINAL_COMMAND`.

Wrapper verifies local operator-owned target ID and binding, consumes root-protected one-shot replay state through narrow `tethys-sentinel-consume`, then executes argv directly without shell reconstruction.

Target sshd/account independently disables PTY, forwarding, password/keyboard-interactive authentication, tunneling, environment injection and ordinary key bypass. Elevated operations require separate narrow target sudo/doas policy.

## Capability model

A grant contains opaque token/hash, grant/session identity, agent/purpose, logical targets, expiry/revocation state, security epoch, permissions and scoped history/notes access.

It never contains infrastructure SSH private keys, SSH transport endpoint, host-key pin, CA authority, database authority, or ability to mutate its own scope/epoch.

## Authoritative context

Gateway exposes a read-only bundle generated by Control Plane. Trust-0 policy/capability/inventory/runbook/operator material is authoritative; history/notes remain Trust-2; files/logs/web/output remain non-authoritative data. Provenance is behavioral hardening, not authorization.

## Risk approvals

Sensitive operations may require deny, allow-once or narrowly scoped allow-for-session. Powerful execution classes are never session-reusable.

In PostgreSQL, approval decision and required audit are transactional. One-shot consumption is tied to one exact execution job and cannot be reused for another job even under concurrency.

## Execution-job protocol

```text
staged -> pending -> claimed -> running -> succeeded/failed
   |         |          |
   +---------+----------+-> canceled/expired where applicable
```

Staged jobs are durable but unclaimable. Authorization publishes `staged -> pending` only after current grant/policy/approval checks. Pending jobs claim once; only claim hashes are stored. Start revalidates authority. Certificate issuance revalidates current policy/capability/target. Target consumes local replay state. Completion is terminal and one-shot.

File development mode uses local integrity protection. PostgreSQL mode instead relies on database ownership/privileges, constraints, transactions and immutable command binding; it does not duplicate the file-store HMAC as a second database integrity scheme.

## Persistent state and recovery

PostgreSQL is the production candidate. Fresh databases start globally disabled. File-to-PostgreSQL cutover never imports old live bearer authority as active.

Database backup/PITR is sensitive because restoring an older point can restore an older security epoch. A restored database must come up disabled/network-isolated and receive an operator-controlled revoke/epoch bump before Gateway/Worker authority resumes.

See `docs/POSTGRESQL_PERSISTENCE.md`.

## Defense in depth

1. Trust/provenance instructions.
2. Capability target/permission scope (`exec`/`shell`).
3. Monotonic global security epoch + emergency disable.
4. Current Control Plane risk policy.
5. Human approval with category-specific reuse rules.
6. Immutable request/job binding and idempotency.
7. PostgreSQL transactional state + audit invariants.
8. Authoritative start/grant/epoch revalidation.
9. Pre-certificate current-policy + grant/epoch revalidation.
10. Isolated SSH CA and signer-owned certificate shape.
11. Ephemeral per-job private keys.
12. Operator-owned literal-IP target registry + exact host-key pinning.
13. External Worker VM egress allowlist enforced outside guest.
14. Mandatory pre-exec + periodic active-authority lease.
15. Job-expiry/handshake/output bounds.
16. Root/operator-owned forced wrapper with binding/target verification.
17. Root-protected target at-most-once replay marker.
18. Remote Unix permissions and narrow sudo/doas policy.

No single layer is sufficient.
