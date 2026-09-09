# Tethys Sentinel — Handoff

Updated: 2026-09-10
Current development version: `0.1.0-dev.10`
Branch: `wip/bootstrap-security-core`
Deployment: not deployed; no merge to `main` yet

## Project goal

Tethys Sentinel is a security-first access broker between AI agents and infrastructure. An agent receives a short-lived capability, never infrastructure SSH private keys. Sentinel owns authorization, risky-action approval, authoritative context, execution-job binding, short-lived SSH identity, target resolution, remote execution constraints, continuity, audit, worker network containment, and emergency authority revocation.

## Operator-mandated development rules

1. Keep task reports short; briefly explain what needs to be done and why.
2. Every newly implemented project feature released as a new version must bump the project version.
3. Maintain this handoff when a version is released/applied, a large step completes, or an important next-step decision is reached.
4. Once a functioning infrastructure-execution version has been tested on intended infrastructure, merge the project as WIP.
5. Whenever a merge is performed, review/update README and project documentation so the merged state remains understandable and operable.

## Locked security decisions

- Agent capabilities are opaque high-entropy bearer secrets; only hashes are persisted.
- Agent-facing APIs cannot create/widen grants, change policy, add SSH targets, alter audit, control workers, request SSH certificates, or reach CA secrets.
- `TRUST_0` is the only authority-bearing context. History, notes, logs, files, command output and web content are data, never authority.
- Security never relies on prompt compliance or command classification alone.
- Main boundaries are Control Plane, AI Gateway, Execution Worker, external worker network boundary, SSH Signer/CA, target execution wrapper, persistent audit/state, and emergency authority state.
- Security-critical public/backend components should use VM isolation rather than one shared LXC boundary.
- Execution is atomic submit -> immutable job; there is no separable authorize-now/execute-later primitive.
- Jobs bind grant + request ID + logical target + argv + expiry and use staged/pending/claimed/running/terminal states.
- Worker never receives plaintext agent capability. It uses a separate worker credential and one-shot job claim secret.
- `start` revalidates the grant after claim and before execution authority.
- `exec` and `shell` are independent capability permissions. Human approval cannot manufacture a missing capability.
- Powerful execution classes (`ARBITRARY_CODE`, `PRIVILEGE_LAUNCHER`, `REMOTE_EXEC`) require `exec=true`, `shell=true`, and explicit operator approval.
- Powerful classes are `allow_once` only. Reusable session approval is forbidden even for identical argv because argv can reference mutable scripts/images/remote state/configuration.
- Legacy persisted unsafe `allow_session` decisions for powerful classes are ignored after policy upgrade.
- Powerful approval scope hashes complete argv including executable path; this prevents delimiter/path collisions but is not treated as proof of immutable behavior.
- High-impact administrator mutations are semantically classified separately from the powerful-execution capability boundary.
- Known read-only administrator forms remain autonomous where syntax is reliably distinguishable; ambiguous sensitive forms fail conservatively.
- Operational policy does not become generic file-write policy. Actual file/root authority remains bounded by Unix permissions/ACLs and narrow sudo/doas rules.
- Stable service operations use semantic executable+action+resource scopes; broader administrator mutations generally use exact full-argv scopes.
- Workload start/build, namespace/guest/jail exec and equivalent mutable execution paths are elevated into the powerful classes rather than receiving a weaker reusable operational approval.
- Gateway performs an early `exec`/`shell` consistency filter, but it is not the hard boundary.
- Immediately before SSH signing, Control Plane reclassifies immutable `job.argv` using current policy, requires category/scope equality with job metadata, re-authenticates the grant, and enforces `shell` again. Stale queued policy fails closed.
- Worker generates a fresh Ed25519 keypair per job; private key stays in process memory.
- Only Control Plane calls the isolated SSH Signer.
- Signer owns principal, source-address, force-command, extensions and TTL; caller cannot broaden certificate shape.
- Certificates have no PTY/agent/port/X11-forwarding extensions and cannot outlive the execution job.
- SSH targets are logical IDs resolved only through operator-owned server-side inventory.
- Registry endpoints must be global-unicast literal IP + port with exact raw pinned host key. Agent-supplied destinations, DNS target resolution, loopback/link-local targets and insecure host-key acceptance are forbidden.
- Remote command transport is deterministic versioned base64url JSON; Sentinel does not reconstruct argv through `/bin/sh -c`.
- Target wrapper verifies signer-bound job ID, canonical command binding and root/operator-owned local target ID before direct argv execution.
- Target replay state enforces at-most-once execution independently of certificate TTL. Replay markers are root-protected and consumed by a narrow root helper.
- SSH dial/handshake/output are bounded and execution cannot outlive `job.expires_at`.
- Worker runtime egress must be independently deny-by-default outside the guest. Normal autonomous egress is only Control Plane HTTPS plus registered target SSH endpoints.
- On PVE, the external hard boundary is the worker VM-interface firewall. Guest-local nftables is optional defense in depth, not the sole boundary.
- `sentinel-egress-policy` is operator/deployment-side render/verify only. Worker/AI identities must never gain PVE apply/reconcile credentials or access to `/etc/pve`/NIC firewall configuration.
- Generated PVE policy uses `policy_out: DROP`, explicit destination+TCP-port allows only, canonical policy SHA-256 and deterministic target deduplication.
- Egress verification must check installed policy drift, Datacenter firewall activation, and `firewall=1` on the selected worker VM NIC.
- Configuration checks alone are insufficient. Infrastructure acceptance requires packet-level tests from inside the worker VM proving unlisted LAN/Internet/DNS/ports are blocked.
- Firewall shrink is not assumed to instantly terminate an already-established stateful TCP flow; active authority revocation is independent.
- Every grant is stamped with a monotonic global `security_epoch` at issuance.
- `REVOKE ALL` increments the epoch and disables global AI access; old capabilities remain permanently stale after later re-enable.
- While globally disabled, new worker claims are suppressed and normal grant re-authentication blocks capability use, start and certificate issuance.
- Global revoke cancels `staged`, `pending` and `claimed` jobs and invalidates their one-shot claim material.
- Running jobs require a worker-side fail-closed authority lease before executor invocation and periodically during active SSH execution.
- Global revoke, individual grant revoke, stale epoch, grant/job expiry, invalid claim, authority timeout or Control Plane loss cancels the worker execution context/SSH transport.
- Emergency revoke persistence failure must not roll the live process back to enabled; current in-memory authority remains disabled and the operator receives an error.
- Re-enable is a safety-opposite transition and must fail closed if persistence/audit cannot be completed safely.
- Active transport termination does not promise instantaneous termination of every detached/daemonized target-side descendant or reversal of already-completed side effects.
- Audit is append-oriented and tamper-evident; raw stdout/stderr is not retained by the current worker.
- Emergency controls include individual revoke and global revoke-all; global revoke must not delete configuration/history/audit.
- Production mutable security state will use PostgreSQL as a transaction engine, not as independent SQL replicas of JSON stores.
- PostgreSQL production scope is grants, approvals, execution jobs, emergency authority state, audit, and agent notes. Trust-0 context, SSH target inventory, signer key/policy and external PVE egress policy remain separate operator-owned configuration boundaries for this milestone.
- Grant issuance and global revoke must serialize on the same PostgreSQL `authority_state` row so no grant can commit from a stale pre-revoke epoch snapshot.
- Global revoke + non-running job cancellation + emergency audit append must commit atomically in PostgreSQL.
- `allow_once` consumption + bound staged-job publication + authorization audit must commit atomically in PostgreSQL.
- Production PostgreSQL runtime uses a least-privilege Control Plane role with no schema ownership/CREATE/DELETE/superuser/role-admin privileges; Gateway, Worker and Signer receive no DB credentials.
- PostgreSQL backend selection must be explicit and must never silently fall back to file-backed authority after connection/schema failure.
- Fresh PostgreSQL authority starts `disabled=true`; cutover does not import old active bearer authority as active.
- When MCP/agent tools are added, keep the surface narrow and purpose-built for autonomous Qwen-class models rather than exposing backend/admin operations wholesale.

## Version history

### Through `0.1.0-dev.2` — capability, approval and audit core

- Opaque capability lifecycle, separated Control Plane/Gateway, protected transports, narrow approvals, Trust-0 bootstrap and hash-chained audit.

### `0.1.0-dev.3` — authoritative context and continuity

- Strict Control-Plane-owned Trust-0 context with scoped inventory/runbooks and scoped non-authoritative history/notes.

### `0.1.0-dev.4` — execution-job security protocol

- Atomic submit, immutable HMAC-protected jobs, request idempotency, staged/claim/start/terminal lifecycle and crash/revocation handling.
- Acceptance: commit `7d263af6bf6aa9699e2a770efc023e585ddbeb56`, Actions run `34389191377`.

### `0.1.0-dev.5` — isolated SSH CA/Signer

- Standalone constrained Ed25519 signer, dedicated mTLS/token boundary, signer-owned certificate shape and ephemeral per-job worker identity.
- Acceptance: commit `750d5d8d0ba899ff2fe45e3b39c70a8969b6a469`, Actions run `34392961793`.

### `0.1.0-dev.6` — real SSH execution boundary

- Protected logical-target registry, pinned-key real SSH worker, deterministic direct-argv wrapper, root-only replay consume helper and bounded execution/output.
- Pre-release gate: commit `c6e84402d58bb282e9d63877ba8d0807fb960310`, run `34396499517`.
- Versioned acceptance: commit `9eaa16febd801b4082221e45e7b929969e91b72c`, run `34397117715`.

### `0.1.0-dev.7` — powerful execution policy

- Added conservative `ARBITRARY_CODE`, `PRIVILEGE_LAUNCHER` and `REMOTE_EXEC` routing for interpreters/shells, command carriers, privilege/namespace launchers, remote pivots and equivalent escape paths.
- Added independent `exec`/`shell` enforcement, allow-once-only powerful approvals, complete-argv scope, legacy unsafe-session invalidation, Gateway prefilter and hard current-policy certificate gate.
- Pre-release code gate: commit `b1bbab9243fee12a1bf3e6cbb2b2a0174263e941`, Actions run `34401421958`.
- Versioned acceptance: commit `58318f7a1f0693941dce4d791ea97fac8e3d3519`, Actions run `34401911162`; all module tidy/gofmt/vet/race tests passed.

### `0.1.0-dev.8` — semantic operational-risk policy

- Split operational risk routing into focused service/network/package/storage/system/runtime/escape classifiers.
- Added high-impact mutation coverage across Linux/BSD services, network/firewall, packages, storage/raw writes, kernel/process state, containers/orchestrators, PVE/libvirt/bhyve and jails while preserving known read-only inspection paths.
- Added conservative escape coverage and retained dev.7 powerful semantics for workload start/build/exec and remote/namespace/guest/jail execution.
- Firewall regression coverage distinguishes read-only bundled flags from mutation and removes the legacy blanket rule that shadowed semantic routing.
- Added `docs/OPERATIONAL_RISK.md`; README/API/execution-policy/architecture/threat-model documentation synchronized.
- Pre-release code gate: commit `41773a133e59344f56d51a1b08317a974f1f67de`, Actions run `34405504004`.
- Versioned acceptance: commit `4fcde4fa771f5008cbd696e4889ca51b564a9507`, Actions run `34406118118`; module tidy, gofmt, vet and `go test -race ./...` passed.

### `0.1.0-dev.9` — external worker egress enforcement

- Added deterministic `sentinel-egress-policy` operator utility and `internal/egresspolicy` model.
- Runtime policy is deny-by-default and permits only literal-IP Control Plane HTTPS plus registered target SSH IP:port endpoints.
- Generated Proxmox VM firewall uses `enable: 1`, `policy_out: DROP`, explicit TCP destination/port rules and no blanket `OUT ACCEPT` fallback.
- Shared target endpoints are deduplicated while logical names remain in metadata/comments; canonical policy SHA-256 changes with destination-set changes.
- Added byte-for-byte installed-policy drift verification.
- Added fail-closed Proxmox activation audit for Datacenter firewall `enable: 1` and `firewall=1` on the selected worker VM NIC.
- Worker/AI receives no PVE apply/reconcile path; operator/Ansible owns deployment to `/etc/pve/firewall/<VMID>.fw` and activation state.
- Tightened target/control transport invariant to global-unicast literal IPv4/IPv6 endpoints; DNS, unspecified, multicast, loopback and link-local are rejected.
- Added explicit packet-level PVE acceptance criteria for allowed Control Plane/target traffic and blocked Internet, unrelated LAN SSH, unlisted target ports and DNS.
- Documented stateful-flow caveat: external rule shrink is containment, not guaranteed immediate active-session termination.
- Added `docs/WORKER_EGRESS.md`; README/architecture/threat model synchronized.
- Pre-release code gate: commit `1f8f2fd11720d23ffcc0ae0fe9e4734c39606767`, Actions run `34407324066`; module tidy, gofmt, vet and `go test -race ./...` passed.
- Versioned acceptance: commit `6a14729036b3f8cafa8f79a1855b7f54ddc2b246`, Actions run `34407900220`; module tidy, gofmt, vet and `go test -race ./...` passed.

### `0.1.0-dev.10` — global revoke-all and active execution termination

- Added persistent monotonic emergency `security_epoch`; grants are stamped with their issuance epoch and old capabilities cannot revive after `Enable`.
- Added admin emergency state/read, `REVOKE ALL`, and fail-closed re-enable semantics on the operator-only surface.
- Global revoke cancels staged/pending/claimed jobs, invalidates claim material, suppresses new worker claims, and relies on existing start/certificate grant checks for race-safe stale-epoch rejection.
- Added read-only worker authority endpoint for a running job/claim.
- Worker now performs a mandatory authority check before executor invocation and short-interval continuous authority checks while SSH execution is active.
- Explicit authority denial or inability to reach/verify the Control Plane cancels worker execution fail-closed; SSH transport is context-bound and closes on cancellation.
- Fixed `start -> revoke -> SSH certificate` cleanup so issuance failure records a terminal failed job rather than leaving `running` state stranded.
- Revoke remains live-disabled in memory even when emergency-state persistence fails; restart after such failure is explicitly unsafe until durable state is repaired.
- Added regression coverage for stale capability non-revival, claimed-job cancellation, worker auth, fail-closed authority client behavior, active executor cancellation, persistence failure, and SSH issuance races.
- Added `docs/EMERGENCY_CONTROLS.md`; README/API/architecture/threat model synchronized.
- Pre-release code gate: commit `d0922d8f3a6638b0309da8329cd42bd52d6e760b`, Actions run `34410714198`; module tidy, gofmt, vet and `go test -race ./...` passed.
- Versioned acceptance: commit `162d1f3c038ae905a4e27a419d9d4a61789466ae`, Actions run `34411432011`; module tidy, gofmt, vet and `go test -race ./...` passed.

## `0.1.0-dev.11` WIP — PostgreSQL transactional persistence

Completed foundation checkpoint:

- Defined the production persistence/transaction contract in `docs/POSTGRESQL_PERSISTENCE.md`.
- Added least-privilege PostgreSQL owner/migrator/runtime role bootstrap and explicit database bootstrap order.
- Added schema version 1 for mutable grants/targets, approvals, jobs/claim hashes, emergency authority, hash-chained audit and Trust-2 agent notes.
- Fresh PostgreSQL state starts globally disabled.
- Added DB constraints for hash sizes, lifecycle states, pending-approval scope uniqueness and grant/request idempotency.
- Added PostgreSQL 15 + 18 CI matrix using real service containers, migration execution, runtime privilege assertions and integration tests.
- Added pgx/v5 repository connection validation: production TLS required, exact schema version required, runtime role may not have schema CREATE or owner membership.
- Added first transactional authority repository for issue/authenticate, global revoke-all and enable.
- Global revoke is one PostgreSQL transaction covering epoch change, non-running job cancellation and canonical audit append.
- Grant issue locks the same authority row as revoke-all, giving issue/revoke a total order.
- Enable writes both audit events and the state transition in one transaction, removing the file-store compensating-revoke window.
- Added canonical audit event builder shared with file-backed hashing so PostgreSQL does not introduce a second event-hash format.
- Added real runtime-role integration tests for authority lifecycle, stale capability non-revival, revoke rollback when audit cannot commit, and concurrent issue vs revoke ordering.
- Foundation acceptance checkpoint: commit `e2e9ca6b6265b3bc16dbcbddc6651a06d6e9f26a`, Actions run `34413119563`; project Go tidy/gofmt/vet/race plus PostgreSQL 15 and 18 schema/integration jobs all passed.

This is **not yet a dev.11 release** and version remains `0.1.0-dev.10` until the full PostgreSQL backend is wired through the Control Plane and accepted.

## Current phase

`0.1.0-dev.10` remains the latest completed release. `0.1.0-dev.11` is actively implementing production PostgreSQL transactional persistence.

The PostgreSQL schema/role/authority foundation is now real-CI accepted, but approvals, full job lifecycle, standalone audit/history reads and notes are not yet backed by PostgreSQL in the running Control Plane.

File-backed stores remain the current wired runtime backend. PostgreSQL must not be advertised as production-active until explicit backend selection and remaining transaction paths are complete.

Do not merge to `main` yet: the operator merge rule requires a functioning constrained real-infrastructure execution test first.

## Next implementation steps

1. Extract narrow storage interfaces from Control Plane/resource/credential APIs so file and PostgreSQL backends can share business logic without concrete-store coupling.
2. Implement PostgreSQL individual grant revoke + job cleanup + audit in one transaction.
3. Implement approvals and the atomic `allow_once consume + staged-job publication + audit` transaction.
4. Implement PostgreSQL execution job enqueue/idempotency/publish/claim/start/authority/complete/reject with row locking and `SKIP LOCKED` claim semantics.
5. Implement PostgreSQL standalone audit append + fully verified history reads and Trust-2 notes persistence.
6. Add explicit `file|postgres` backend selection; PostgreSQL failure/schema mismatch must terminate Control Plane with no file fallback.
7. Define/test safe disabled cutover from file development state; never import active bearer authority as live.
8. Bump/release `0.1.0-dev.11` only after full PostgreSQL backend + CI acceptance.
9. Build a disposable constrained target profile and worker VM, apply the generated PVE egress policy, and run the first real non-destructive end-to-end + negative packet-level + active-revoke test.
10. After successful constrained infrastructure execution, perform the first WIP merge and documentation review.
11. Build operator UI after backend security flows/data model stabilize.

## Deployment state

Not deployed. No production trust should be placed in the current branch. No merge to `main` yet.
