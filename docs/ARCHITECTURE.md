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

Bootstrap persistence still uses restricted local files for grants, approvals, audit, notes, authoritative context and execution jobs. This is a development mechanism for testing boundaries before PostgreSQL; it is not the intended production persistence architecture.

## Components

### Control Plane

Human/operator authority. Owns grant creation/revocation, policy decisions, approvals, Trust-0 context/inventory, history filtering, immutable execution-job issuance, SSH target resolution, certificate eligibility, and emergency controls.

Only the Control Plane can publish executable jobs and call the SSH Signer. It recomputes policy/risk state instead of trusting labels supplied by an agent or Gateway.

The current authoritative context source is selected with `SENTINEL_CONTEXT_FILE`. Production deployment must make it operator-owned/read-only to runtime identities or replace it with equivalently protected persistent state.

Transport resolution comes from `SENTINEL_SSH_TARGETS_FILE` (default `/etc/tethys-sentinel/ssh-targets.json`). Jobs contain only logical target IDs. The registry maps them to literal IP/port, Unix user, and exact pinned SSH host key. Agent-supplied transport values are never accepted.

### AI Gateway

Public capability-facing boundary. Exposes bootstrap/context/history/notes and atomic command submission. It has no grant creation, approval mutation, worker control, target mutation, certificate signing, or CA-secret path.

The Gateway performs an early capability consistency filter:

- command submission requires `exec=true`;
- execution classes requiring broader/unstructured authority also require `shell=true`.

This is intentionally not the authoritative security gate. A compromised Gateway still cannot cause signing because Control Plane and credential issuance independently re-enforce current policy.

### Execution policy boundary

`0.1.0-dev.7` makes `exec` and `shell` distinct authorization dimensions.

- `exec` authorizes ordinary structured argv operations within the logical target scope.
- `shell` additionally authorizes powerful execution classes capable of carrying arbitrary code, broadening privilege, or creating a lateral/remote execution path.

Current shell-required classes:

- `ARBITRARY_CODE`
- `PRIVILEGE_LAUNCHER`
- `REMOTE_EXEC`

Examples include shells/interpreters, generic command launchers, `sudo`/`nsenter`-style privilege or namespace tools, SSH/Ansible/network pivots, Kubernetes exec/port-forward operations, container run/exec operations, and known shell-escape carriers such as `find -exec`.

Powerful classes use a canonical SHA-256 over complete argv including executable path as their approval scope. Even then they are **allow-once only**. Identical argv does not prove identical behavior when a command references mutable scripts, container images, remote hosts, configuration, or other external state.

Legacy persisted `allow_session` decisions for powerful categories are ignored after upgrade.

See `docs/EXECUTION_POLICY.md`.

### Execution Worker

Private execution boundary. Never receives plaintext agent capabilities and cannot administer grants/policy.

Worker flow:

1. claim one immutable pending job with worker credential;
2. locally verify canonical command binding;
3. call authoritative Control Plane `start` gate;
4. generate fresh per-job Ed25519 keypair in memory;
5. send only the public key to the Control Plane certificate endpoint;
6. receive short-lived certificate plus operator-resolved target;
7. verify certificate belongs to the generated keypair and does not outlive the job;
8. verify logical target matches immutable job;
9. dial only the resolved literal IP/port;
10. verify exact pinned SSH host key;
11. send deterministic job-bound command envelope;
12. complete once with result metadata/output digest.

Execution context is capped by `job.expires_at`. TCP dial and SSH handshake have bounded deadlines; output accounting is bounded and overflow terminates the SSH client.

### Pre-certificate policy gate

This is the hard execution-policy checkpoint immediately before any infrastructure credential is returned.

For a running job, Control Plane:

1. validates job and one-shot claim secret;
2. verifies immutable command binding;
3. re-runs the **current** risk classifier on immutable `job.argv`;
4. requires current category and scope key to equal stored job metadata;
5. re-authenticates the original grant;
6. requires `shell=true` when current category requires it;
7. resolves the protected logical SSH target;
8. only then calls the isolated Signer.

A queued job therefore does not freeze an old policy decision. If policy changes, stale execution fails closed rather than retaining grandfathered authority.

### SSH Signer

Standalone CA boundary. `sentinel-signer` owns the SSH CA private key and exposes one constrained internal signing operation.

Normal operation requires dedicated bearer credential plus mutual TLS. Plaintext mode is explicit loopback-only development behavior.

Signer request contains only validated job/grant/target/binding identity, ephemeral Ed25519 public key and an upper validity bound.

Signer-owned policy controls:

- OpenSSH user certificate type;
- Ed25519 CA/worker key requirement;
- principal;
- exact worker source-address binding (`/32` or `/128`);
- fixed generated `force-command`;
- empty PTY/agent/port/X11 forwarding extensions;
- short TTL capped by job expiry.

Caller cannot choose those fields.

### Target execution boundary

The signer-generated critical `force-command` invokes `tethys-sentinel-exec` with signer-controlled job ID and command binding. Agent argv travels separately in a versioned base64url JSON envelope through `SSH_ORIGINAL_COMMAND`.

The wrapper:

- loads root/operator-owned local target ID;
- verifies envelope job ID against force-command job ID;
- verifies envelope target against local target ID;
- recomputes and constant-time compares command binding;
- resolves executable through fixed safe path or clean absolute path;
- never reconstructs argv through a shell;
- supplies reduced deterministic environment;
- consumes an at-most-once marker before process start;
- directly executes argv.

Replay markers are written by the narrow root-only `tethys-sentinel-consume` helper into private root-owned state. The infrastructure process itself remains unprivileged unless separately allowed by narrow target sudo/doas policy.

Target `sshd`/account policy must independently disable PTY, forwarding, password/keyboard-interactive authentication, tunneling, environment injection and ordinary authorized-key bypasses.

## Capability model

A grant includes at minimum:

- opaque capability token; only hash persisted
- session/grant ID
- agent identity and purpose
- logical target set
- expiry/revocation state
- `exec`, `shell`, `upload`, `download`
- history/notes permissions and history scope

A capability never contains infrastructure SSH private keys, SSH endpoint, host key, or authority to mutate itself.

## Authoritative context

Gateway exposes a read-only bundle generated by Control Plane. Every document carries provenance and SHA-256 content hash.

Current Trust-0 virtual paths:

- `/sentinel/POLICY.md`
- `/sentinel/INSTRUCTIONS.md`
- `/sentinel/INFRASTRUCTURE.json`
- `/sentinel/TOOLS.json`
- scoped `/sentinel/RUNBOOKS/*.md`

Trust levels:

- **TRUST_0** — authoritative policy/capability/inventory/runbook/operator material.
- **TRUST_1** — reserved for future operator advisory material that is not authority unless promoted.
- **TRUST_2** — audit/history/agent continuity data; explicitly non-authoritative.
- **TRUST_3 / untrusted external data** — web/files/logs/output/user-generated content.

Prompt provenance is behavioral hardening, never the actual authorization boundary.

## Risk approvals

Sensitive operations can require:

- deny
- allow once
- allow for session with narrow stable scope

`allow_session` is valid only where the category defines a sufficiently stable reusable operation/resource. An approval for `systemctl restart pdns` on one target must not become authority to restart another service or host.

Powerful execution classes are not session-reusable; only `allow_once` is accepted.

Approval state, capability scope and policy are independent. Human approval cannot grant missing `exec` or `shell` permission.

## Execution-job protocol

Lifecycle:

```text
staged -> pending -> claimed -> running -> succeeded/failed
                  \-> canceled/expired where applicable
```

Properties:

- staged is durable but unclaimable;
- pending is claimable once;
- claim secret is random; plaintext not persisted;
- bootstrap job records are HMAC-protected;
- target/argv have canonical binding;
- request ID provides idempotency/rebinding protection;
- start revalidates grant;
- certificate gate revalidates job, current policy, capability and target;
- target consumes local one-shot marker before process start;
- completion is one-shot terminal state.

## Persistent state

Production state is planned for PostgreSQL with separate least-privilege roles for grants/approvals/inventory/jobs/audit/history/notes. Raw command output is potentially secret-bearing and remains independently controlled.

## Defense in depth

1. Trust/provenance instructions.
2. Capability target and permission scope (`exec`/`shell`).
3. Current Control Plane risk policy.
4. Human approval with category-specific reuse rules.
5. Immutable staged jobs + HMAC/request replay protection.
6. Authoritative start/revocation gate.
7. Pre-certificate current-policy + capability revalidation.
8. Isolated SSH CA and signer-owned certificate shape.
9. Ephemeral per-job private keys.
10. Operator-owned literal-IP target registry + exact host-key pinning.
11. Job-expiry/handshake/output bounds.
12. Root/operator-owned forced wrapper with binding/target verification.
13. Root-protected target at-most-once replay marker.
14. Remote Unix permissions and narrow sudo/doas policy.
15. Independent VM/network segmentation and worker egress filtering.

No single layer is sufficient.
