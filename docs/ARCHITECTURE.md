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
                +----------+-----------+
                | External worker      |
                | network boundary     |
                | Control + SSH only   |
                +----------+-----------+
                           |
                    +------v-------+
                    | Execution    |
                    | Worker       |
                    | ephemeral key|
                    | pinned SSH   |
                    +------+-------+
                           |
                           | SSH to externally allowed,
                           | operator-resolved literal IP
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

Transport resolution comes from `SENTINEL_SSH_TARGETS_FILE` (default `/etc/tethys-sentinel/ssh-targets.json`). Jobs contain only logical target IDs. The registry maps them to global-unicast literal IP/port, Unix user, and exact pinned SSH host key. Agent-supplied transport values are never accepted.

### AI Gateway

Public capability-facing boundary. Exposes bootstrap/context/history/notes and atomic command submission. It has no grant creation, approval mutation, worker control, target mutation, certificate signing, or CA-secret path.

The Gateway performs an early capability consistency filter:

- command submission requires `exec=true`;
- execution classes requiring broader/unstructured authority also require `shell=true`.

This is intentionally not the authoritative security gate. A compromised Gateway still cannot cause signing because Control Plane and credential issuance independently re-enforce current policy.

### Execution policy boundary

`0.1.0-dev.7` made `exec` and `shell` distinct authorization dimensions.

- `exec` authorizes ordinary structured argv operations within the logical target scope.
- `shell` additionally authorizes powerful execution classes capable of carrying arbitrary code, broadening privilege, or creating a lateral/remote execution path.

Current shell-required classes are `ARBITRARY_CODE`, `PRIVILEGE_LAUNCHER`, and `REMOTE_EXEC`.

Powerful classes use a canonical SHA-256 over complete argv including executable path and are **allow-once only**. Identical argv does not prove identical behavior when mutable scripts, images, remote state or configuration are referenced. Legacy persisted `allow_session` decisions for powerful categories are ignored.

See `docs/EXECUTION_POLICY.md`.

### Semantic operational-risk layer

`0.1.0-dev.8` adds a separate classifier stage for high-impact administrator state mutation.

It covers service/system manager changes, networking/firewall state, packages, storage/raw writes, kernel/process/log controls, container/orchestrator state, and hypervisor/jail operations across the Linux/BSD/PVE environments Sentinel is intended to administer.

The design intentionally does not classify every ordinary file write. Actual filesystem/root authority remains a target Unix/sudo/doas concern.

Where syntax has a reliable inspection path, reads stay autonomous. Examples include service status, route/interface inspection, firewall listing, package queries, ZFS/RAID status, and PVE status/API reads. Mutation forms require approval. Ambiguous forms of sensitive admin tools fail conservatively.

Stable operations may use semantic scope. Broader mutations normally use exact full-argv scope. Powerful workload-start/exec/remote forms are elevated back into the dev.7 powerful classes rather than receiving a weaker operational approval path.

See `docs/OPERATIONAL_RISK.md`.

### External worker network boundary

`0.1.0-dev.9` adds an independent runtime egress boundary for the Execution Worker.

Normal Sentinel logic already resolves jobs only to protected logical targets, but a compromised worker process or guest must not be able to ignore that application logic and open arbitrary network connections. Therefore production worker egress is enforced **outside the guest**.

For Proxmox VE deployment the intended hard boundary is the VM firewall on the worker virtual interface. Its autonomous runtime egress set is deliberately minimal:

1. one literal-IP HTTPS Control Plane endpoint;
2. global-unicast literal IP:port SSH endpoints from protected target inventory.

DNS, generic LAN access, broad RFC1918 ranges, package mirrors and unrestricted Internet/HTTPS are not part of the normal worker runtime policy.

`sentinel-egress-policy` is an operator/deployment utility that deterministically derives the external PVE policy from the protected target inventory plus Control Plane endpoint. It:

- emits `policy_out: DROP`;
- emits explicit TCP allow rules only for Control Plane and registered SSH endpoints;
- deduplicates shared target endpoints;
- includes a canonical policy SHA-256;
- verifies installed policy byte-for-byte;
- verifies Datacenter firewall `enable: 1` and `firewall=1` on the selected worker VM NIC.

The utility does **not** apply PVE configuration. Worker/AI identities must have no credentials or API/filesystem path that can modify `/etc/pve`, NIC firewall flags, or external network policy.

Guest nftables may exist as defense in depth but is not trusted as the sole boundary because a compromised guest can potentially rewrite its own firewall.

External policy configuration checks are not a substitute for packet-level validation. The first real PVE acceptance test must demonstrate from inside the worker VM that Control Plane + registered SSH endpoints work and unrelated LAN/Internet/DNS/unlisted ports are blocked.

Shrinking firewall rules is not assumed to instantly terminate already-established stateful flows. Job deadlines, short SSH certificates and the later global-revoke/active-worker termination mechanism remain independent controls.

See `docs/WORKER_EGRESS.md`.

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
9. dial only the resolved literal IP/port, which must also be allowed by the external worker boundary;
10. verify exact pinned SSH host key;
11. send deterministic job-bound command envelope;
12. complete once with result metadata/output digest.

Execution context is capped by `job.expires_at`. TCP dial and SSH handshake have bounded deadlines; output accounting is bounded and overflow terminates the SSH client.

### Pre-certificate policy gate

This is the hard execution-policy checkpoint immediately before any infrastructure credential is returned.

For a running job, Control Plane validates job/claim/binding, re-runs current risk policy, requires current category/scope equality, re-authenticates the original grant, requires `shell=true` when necessary, resolves the protected target, and only then calls the isolated Signer.

A queued job therefore does not freeze old policy authority.

### SSH Signer

Standalone CA boundary. `sentinel-signer` owns the SSH CA private key and exposes one constrained internal signing operation.

Normal operation requires dedicated bearer credential plus mutual TLS. Plaintext mode is explicit loopback-only development behavior.

Signer request contains only validated job/grant/target/binding identity, ephemeral Ed25519 public key and an upper validity bound.

Signer-owned policy controls OpenSSH user-certificate type, Ed25519 key requirements, principal, exact worker source-address binding, fixed generated `force-command`, empty PTY/agent/port/X11 forwarding extensions, and short TTL capped by job expiry. Caller cannot choose those fields.

### Target execution boundary

The signer-generated critical `force-command` invokes `tethys-sentinel-exec` with signer-controlled job ID and command binding. Agent argv travels separately in a versioned base64url JSON envelope through `SSH_ORIGINAL_COMMAND`.

The wrapper loads the root/operator-owned local target ID, verifies job/target/binding, resolves executable through a fixed safe path or clean absolute path, supplies a reduced deterministic environment, consumes an at-most-once marker, and directly executes argv without shell reconstruction.

Replay markers are written by the narrow root-only `tethys-sentinel-consume` helper into private root-owned state. The infrastructure process itself remains unprivileged unless separately allowed by narrow target sudo/doas policy.

Target `sshd`/account policy must independently disable PTY, forwarding, password/keyboard-interactive authentication, tunneling, environment injection and ordinary authorized-key bypasses.

## Capability model

A grant includes at minimum opaque capability token/hash, session/grant identity, agent/purpose, logical target set, expiry/revocation state, `exec`, `shell`, upload/download, and scoped history/notes permissions.

A capability never contains infrastructure SSH private keys, SSH endpoint, host key, or authority to mutate itself.

## Authoritative context

Gateway exposes a read-only bundle generated by Control Plane. Trust-0 policy/capability/inventory/runbook/operator material is authoritative; history/agent notes remain `TRUST_2`; files/logs/web/output remain non-authoritative data. Prompt provenance is behavioral hardening, never the actual authorization boundary.

## Risk approvals

Sensitive operations can require deny, allow-once, or allow-for-session with narrow scope.

`allow_session` is valid only where the category defines a sufficiently stable reusable operation/resource. Powerful execution classes are never session-reusable. Approval state, capability scope and policy are independent; human approval cannot grant missing `exec` or `shell` permission.

## Execution-job protocol

Lifecycle:

```text
staged -> pending -> claimed -> running -> succeeded/failed
                  \-> canceled/expired where applicable
```

Staged jobs are durable but unclaimable; pending jobs are claimable once; claim secret plaintext is not persisted; job records are HMAC-protected; target/argv are canonically bound; request IDs prevent rebinding; start revalidates grants; certificate issuance revalidates current policy/capability/target; target execution consumes a local one-shot marker; completion is terminal and one-shot.

## Persistent state

Production state is planned for PostgreSQL with separate least-privilege roles for grants/approvals/inventory/jobs/audit/history/notes. Raw command output is potentially secret-bearing and remains independently controlled.

## Defense in depth

1. Trust/provenance instructions.
2. Capability target and permission scope (`exec`/`shell`).
3. Current Control Plane powerful + operational risk policy.
4. Human approval with category-specific reuse rules.
5. Immutable staged jobs + HMAC/request replay protection.
6. Authoritative start/revocation gate.
7. Pre-certificate current-policy + capability revalidation.
8. Isolated SSH CA and signer-owned certificate shape.
9. Ephemeral per-job private keys.
10. Operator-owned global-unicast target registry + exact host-key pinning.
11. External worker VM egress allowlist enforced outside the guest.
12. Job-expiry/handshake/output bounds.
13. Root/operator-owned forced wrapper with binding/target verification.
14. Root-protected target at-most-once replay marker.
15. Remote Unix permissions and narrow sudo/doas policy.

No single layer is sufficient.
