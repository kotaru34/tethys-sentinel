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
                    | immutable job issuance  |
                    | SSH target resolution   |
                    | certificate gate        |
                    +------+-------------+----+
                           |             |
             internal mTLS |             | dedicated mTLS + signer credential
                           |             |
                  +--------v--+       +--v-----------+
                  | AI Gateway|       | SSH Signer   |
                  | public API|       | CA boundary  |
                  +-----------+       +--------------+
                           |
                           | worker-only internal API
                           v
                    +------+-------+
                    | Execution    |
                    | Worker       |
                    | ephemeral key|
                    | pinned SSH   |
                    +------+-------+
                           |
                           | SSH to resolved literal IP
                           | exact pinned host key
                           v
                    +------+----------------+
                    | Target sshd           |
                    | trusted Sentinel CA   |
                    | dedicated account     |
                    +------+----------------+
                           |
                           | certificate critical force-command
                           v
                    +------+----------------+
                    | tethys-sentinel-exec  |
                    | verify binding/target |
                    | one-shot replay gate  |
                    | direct exec(argv)     |
                    +-----------------------+
```

The bootstrap implementation still uses restricted local files for grants, approvals, audit, notes, authoritative context and execution jobs so security boundaries can be tested before introducing database complexity. Persistent state is planned to move to PostgreSQL with separate least-privilege roles before production deployment. The gateway must never have database privileges that let it create or broaden grants/policies.

## Components

### Control Plane

Human/operator authority. Owns grant creation, revocation, policy decisions, approvals, authoritative context/inventory, history filtering, execution-job issuance, SSH target resolution, SSH-certificate eligibility decisions, and emergency controls. It is not directly exposed to the AI-facing public interface.

The current authoritative context source is a local JSON file selected with `SENTINEL_CONTEXT_FILE`. Production deployment must make this file root/operator-owned and read-only to the Sentinel service account or replace it with an equivalently protected control-plane store. No AI-facing API can modify it.

The Control Plane is the only component allowed to publish executable jobs. It recomputes policy/risk state, stages immutable command material, commits approval/audit state, and only then publishes the job for workers.

For SSH identity issuance, the Control Plane is also the only Signer client. It accepts a worker public key only for an already-running job with a valid claim secret, re-verifies the command binding and grant, and passes only job-derived constraints plus the public key to the Signer.

For transport resolution, the Control Plane loads `SENTINEL_SSH_TARGETS_FILE` (default `/etc/tethys-sentinel/ssh-targets.json`). The job contains only a logical target ID. The server-side registry maps that ID to a literal IP/port, Unix user and exact pinned SSH host key. Agent-supplied addresses never become worker destinations.

### AI Gateway

Validates capability format and exposes only agent operations: bootstrap/context, permitted history, notes, and atomic command submission. It forwards the capability hash plus request material to the Control Plane. It cannot issue a worker claim, broaden a grant, approve an operation, mutate Trust-0 state, request SSH certificates, resolve arbitrary SSH targets, or reach SSH CA secrets.

The public agent flow deliberately does not expose a separate `authorize now / execute later` primitive.

### Execution Worker

Private execution boundary. It never receives the plaintext agent capability and does not expose policy/grant administration.

The worker:

1. claims one immutable pending job using its dedicated worker credential;
2. verifies the job's canonical command binding locally;
3. calls the authoritative Control Plane `start` gate using the one-shot claim secret;
4. generates a new Ed25519 keypair in process memory for that job;
5. submits only the ephemeral public key to the Control Plane certificate endpoint;
6. receives the short-lived certificate plus operator-resolved SSH target specification;
7. verifies the certificate belongs to the generated keypair and does not outlive the job;
8. verifies the resolved logical target still equals the immutable job target;
9. dials only the resolved literal target IP/port;
10. verifies the SSH server against the exact pinned host public key;
11. sends a deterministic job-bound command envelope through one SSH session;
12. completes the job once with result metadata/output digest.

A claim by itself is not execution authority. The `start` gate revalidates the original grant immediately before execution, and certificate issuance performs another grant check before any SSH credential is returned.

The worker execution context is capped by `job.expires_at`, so an established SSH session is actively closed when the job expires. TCP dial and SSH handshake have their own bounded deadlines. Output accounting is bounded and overflow actively terminates the SSH client.

### SSH Signer

Implemented isolated CA boundary. `sentinel-signer` owns the SSH CA private key and exposes only health plus one constrained internal signing endpoint.

The Signer is protected by a dedicated bearer credential and mutual TLS in normal operation. Plaintext operation requires an explicit development flag and loopback binding.

The Signer accepts only:

- validated job ID;
- validated grant ID;
- validated target ID;
- canonical command-binding SHA-256;
- an ephemeral Ed25519 public key;
- an upper certificate-validity bound supplied by the Control Plane.

The caller cannot choose the SSH principal, arbitrary force-command, source-address restrictions, certificate extensions, or signer TTL. These remain signer-owned configuration.

Current certificate constraints:

- OpenSSH user certificate;
- Ed25519 CA and worker key;
- one configured principal;
- exact worker source-address binding (`/32` or `/128`);
- signer-generated `force-command` pointing to a configured wrapper path plus validated job/binding arguments;
- no certificate extensions, therefore no PTY, agent forwarding, port forwarding or X11 forwarding grants;
- short signer TTL capped by job expiry;
- CA private-key file rejected if group/other permissions are present.

See `docs/SSH_CA.md` for certificate details.

### Target execution boundary

`0.1.0-dev.6` adds the target-side hard boundary.

The certificate critical `force-command` invokes `tethys-sentinel-exec` with only signer-controlled job ID and command-binding arguments. The agent command is carried separately as a versioned base64url JSON envelope in `SSH_ORIGINAL_COMMAND`.

The wrapper:

- reads a root/operator-owned local target ID;
- verifies envelope job ID equals the force-command job ID;
- verifies envelope target equals the local host target ID;
- recomputes and constant-time compares the canonical command binding;
- resolves an executable through a fixed path or clean absolute path;
- never reconstructs argv through a shell;
- supplies a reduced deterministic environment;
- consumes an at-most-once execution marker before starting the process.

Replay markers are created by the narrow root-only `tethys-sentinel-consume` helper under root-owned private state directories. The unprivileged remote account invokes only this helper through a noninteractive privilege rule; the requested infrastructure command itself remains unprivileged unless separately granted a narrow sudo/doas capability.

The target `sshd` and Unix account must independently disable PTY, forwarding, password/keyboard-interactive authentication, ordinary authorized-key escape paths, tunneling and environment injection.

See `docs/SSH_EXECUTION.md` for target requirements and transport details.

### PostgreSQL / persistent state

Planned production store for grants by token hash, approvals, inventory, action metadata, history/notes, execution jobs and audit state. Raw command output will be optional/configurable and treated as potentially secret-bearing data.

Until that migration, file-backed stores are development/bootstrap mechanisms rather than a production persistence architecture.

## Capability model

A grant contains at minimum:

- opaque capability token (returned only at issuance; hash stored server-side)
- session/grant ID
- agent identity label
- purpose
- allowed logical targets
- expiry
- `exec`, `shell`, `upload`, `download`
- `history_read`, `notes_read`, `notes_write`
- history scope
- revocation state

A capability never contains an SSH private key, SSH endpoint, host key, or authority to mutate its own scope.

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

The current classifier is not considered sufficient protection for interpreters, shell launchers and other arbitrary-code carriers; that is the next policy hardening milestone before production trust.

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
- SSH certificate issuance revalidates running-job state, claim secret, binding, expiry and grant again;
- remote target execution consumes a local one-shot marker before process start;
- completion is one-shot and terminal.

See `docs/EXECUTION_PROTOCOL.md` for the detailed state machine and `docs/SSH_EXECUTION.md` for transport/target semantics.

## Defense in depth

1. Agent authoritative instructions and provenance labels.
2. Capability scope.
3. Control-plane policy engine.
4. Approval engine.
5. Immutable staged execution jobs, HMAC integrity and request replay protection.
6. Authoritative pre-execution start/revocation gate.
7. Independent pre-certificate grant/binding/job-state gate.
8. Isolated SSH CA and signer-owned certificate constraints.
9. Ephemeral per-job worker private keys.
10. Operator-owned literal-IP target registry and exact SSH host-key pinning.
11. Job-expiry, handshake and output execution bounds.
12. Root/operator-owned remote forced-command wrapper with local target/binding verification.
13. Root-protected target-side at-most-once replay marker.
14. Remote Unix account permissions and narrow sudo/doas policy.
15. Independent VM/network segmentation and worker egress filtering.

No single layer is considered sufficient.
