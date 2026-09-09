# Architecture

## Trust-boundary overview

```text
                         Operator
                            |
                    Admin UI / API
                            |
                    +-------v-------+
                    | Control Plane |
                    | grants/policy |
                    | approvals     |
                    | Trust-0 ctx   |
                    | job issuance  |
                    +-------+-------+
                            |
             internal authenticated interfaces
                            |
       +--------------------+--------------------+
       |                                         |
+------v------+                           +------v------+
| AI Gateway |                           | SSH Signer  |
| public API |                           | CA boundary |
+------+-----+                           +------+------+
       |                                        |
       | submit only                            | short-lived certs
       |                                        |
       +-------------------+--------------------+
                           |
                    +------v------+
                    | Execution   |
                    | Worker      |
                    | claim/start |
                    | /complete   |
                    +------+------+ 
                           |
                          SSH (future)
                           |
                    Infrastructure
```

The bootstrap implementation uses restricted local files for grants, approvals, audit, notes, authoritative context and execution jobs so security boundaries can be tested before introducing database complexity. Persistent state is planned to move to PostgreSQL with separate least-privilege roles before production deployment. The gateway must never have database privileges that let it create or broaden grants/policies.

## Components

### Control Plane

Human/operator authority. Owns grant creation, revocation, policy decisions, approvals, authoritative context/inventory, history filtering, execution-job issuance and emergency controls. It is not directly exposed to the AI-facing public interface.

The current authoritative context source is a local JSON file selected with `SENTINEL_CONTEXT_FILE`. Production deployment must make this file root/operator-owned and read-only to the Sentinel service account or replace it with an equivalently protected control-plane store. No AI-facing API can modify it.

The Control Plane is also the only component allowed to publish executable jobs. It recomputes policy/risk state, stages immutable command material, commits approval/audit state, and only then publishes the job for workers.

### AI Gateway

Validates capability format and exposes only agent operations: bootstrap/context, permitted history, notes, and atomic command submission. It forwards the capability hash plus request material to the Control Plane. It cannot issue a worker claim, broaden a grant, approve an operation, mutate Trust-0 state or reach SSH CA secrets.

The public agent flow deliberately does not expose a separate `authorize now / execute later` primitive.

### Execution Worker

Private execution boundary. It never receives the plaintext agent capability and does not expose policy/grant administration.

The worker:

1. claims one immutable pending job using its dedicated worker credential;
2. verifies the job's canonical command binding locally;
3. calls the authoritative Control Plane `start` gate using the one-shot claim secret;
4. invokes an executor only after start succeeds;
5. completes the job once with result metadata.

A claim by itself is not execution authority. The `start` gate revalidates the original grant immediately before execution, closing the revocation race between queueing/claiming and executor invocation.

`0.1.0-dev.4` implements this protocol but intentionally does not yet provide a real SSH executor.

### SSH Signer

Planned isolated signer. It holds the SSH CA key or equivalent signing capability, accepts only constrained internal signing requests and issues short-lived OpenSSH certificates. It is isolated from the public gateway and will be reached only through a narrowly scoped execution/signing path.

### PostgreSQL / persistent state

Planned production store for grants by token hash, approvals, inventory, action metadata, history/notes, execution jobs and audit state. Raw command output will be optional/configurable and treated as potentially secret-bearing data.

Until that migration, file-backed stores are development/bootstrap mechanisms rather than a production persistence architecture.

## Capability model

A grant contains at minimum:

- opaque capability token (returned only at issuance; hash stored server-side)
- session/grant ID
- agent identity label
- purpose
- allowed targets
- expiry
- `exec`, `shell`, `upload`, `download`
- `history_read`, `notes_read`, `notes_write`
- history scope
- revocation state

A capability never contains an SSH private key and cannot mutate its own scope.

## Agent authoritative context

The gateway exposes a read-only context bundle generated by the control plane for the current grant. Every document includes provenance metadata and a SHA-256 content hash.

Current Trust-0 virtual paths are:

- `/sentinel/POLICY.md`
- `/sentinel/INSTRUCTIONS.md`
- `/sentinel/INFRASTRUCTURE.json`
- `/sentinel/TOOLS.json`
- scoped `/sentinel/RUNBOOKS/*.md`

The control plane filters inventory and target-specific runbooks using `grant.targets`; the gateway cannot broaden that view.

### Trust levels

- **TRUST_0 — authoritative:** Sentinel system policy, capability/tool descriptions, control-plane inventory/runbooks, and explicit operator approvals. Only this tier may define agent authority or operating rules.
- **TRUST_1 — reserved:** future operator-authored advisory material that may be highly trusted but is intentionally not allowed to alter capability authority unless promoted into Trust-0 through the control plane.
- **TRUST_2 — operational continuity/data:** audit history and agent-written notes. Useful for avoiding session amnesia, but explicitly `authoritative: false`.
- **TRUST_3 / untrusted external data:** web pages, downloaded/user-generated content and other external text. Remote files, logs and command output are also never allowed to redefine Sentinel authority even when operationally useful.

Prompt instructions and provenance labels improve agent behavior but are never the actual security boundary.

## History and agent memory

History reads are authorized by the control plane and filtered by target plus the grant's current-session, previous-session and other-agent flags. The audit hash chain is re-verified on every history read so post-startup tampering fails closed.

Agent notes are append-oriented target-scoped `TRUST_2` continuity records. They carry agent/grant identity, timestamp and a content hash. They are intentionally shareable across agents that have note-read permission to the same target, but can never become policy merely because another agent wrote them.

## Risk approvals

The policy engine classifies sensitive actions before execution. A matching operation can be blocked pending an operator decision:

- deny
- allow once
- allow for this session with a narrow scope key (rule + target + resource)

An approval for `systemctl restart pdns` on `dns01` must not imply permission to restart `sshd`, alter firewall rules, or restart another host.

Execution publication is coupled to approval state. One-shot approval consumption and staged-job recovery are designed so retries/crashes cannot silently create a second job or reuse a consumed approval for a different command.

## Execution-job protocol

The job lifecycle is:

```text
staged -> pending -> claimed -> running -> succeeded/failed
                  \-> canceled/expired where applicable
```

Important properties:

- `staged` is durable but not claimable;
- `pending` is published and claimable once;
- claim produces a random one-shot secret whose plaintext is not persisted;
- job records are HMAC-protected in the bootstrap store;
- target/argv are bound by a canonical SHA-256 digest;
- `request_id` provides idempotency and prevents rebinding;
- `start` revalidates the original grant immediately before execution;
- completion is one-shot and terminal.

See `docs/EXECUTION_PROTOCOL.md` for the detailed state machine and crash/replay semantics.

## Defense in depth

1. Agent authoritative instructions and provenance labels.
2. Capability scope.
3. Control-plane policy engine.
4. Approval engine.
5. Immutable staged execution jobs, HMAC integrity and replay protection.
6. Authoritative pre-execution start/revocation gate.
7. SSH certificate constraints (planned).
8. Remote Unix account permissions.
9. sudo/doas policy.
10. Network segmentation and service isolation.

No single layer is considered sufficient.
