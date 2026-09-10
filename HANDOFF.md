# Tethys Sentinel — Handoff

Updated: 2026-09-10
Current development version: `0.1.0-dev.11`
Branch: `wip/bootstrap-security-core`
Deployment: not deployed; no merge to `main` yet

## Project goal

Tethys Sentinel is a security-first access broker between AI agents and infrastructure. An agent receives a short-lived capability, never infrastructure SSH private keys. Sentinel owns authorization, risky-action approval, authoritative context, execution-job binding, short-lived SSH identity, target resolution, remote execution constraints, continuity, audit, worker network containment, persistent transactional security state, and emergency authority revocation.

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
- Main boundaries are Control Plane, AI Gateway, Execution Worker, external worker network boundary, SSH Signer/CA, target execution wrapper, persistent PostgreSQL authority/audit state, and emergency authority state.
- Security-critical public/backend components should use VM isolation rather than one shared LXC boundary.
- Execution is submit -> immutable staged job -> authorization -> pending -> claim -> start -> execution -> terminal result; there is no separable authorize-now/execute-later authority primitive.
- Jobs bind grant + request ID + logical target + argv + expiry and use staged/pending/claimed/running/terminal states.
- Worker never receives plaintext agent capability. It uses a separate worker credential and one-shot job claim secret.
- `start` revalidates authority and the grant after claim and before execution authority.
- `exec` and `shell` are independent capability permissions. Human approval cannot manufacture a missing capability.
- Powerful execution classes (`ARBITRARY_CODE`, `PRIVILEGE_LAUNCHER`, `REMOTE_EXEC`) require `exec=true`, `shell=true`, and explicit operator approval.
- Powerful classes are `allow_once` only. Reusable session approval is forbidden even for identical argv because argv can reference mutable scripts/images/remote state/configuration.
- Legacy persisted unsafe `allow_session` decisions for powerful classes are ignored after policy upgrade.
- Powerful approval scope hashes complete argv including executable path; this prevents delimiter/path collisions but is not proof of immutable behavior.
- High-impact administrator mutations are semantically classified separately from the powerful-execution capability boundary.
- Known read-only administrator forms remain autonomous where syntax is reliably distinguishable; ambiguous sensitive forms fail conservatively.
- Operational policy does not become generic file-write policy. Actual file/root authority remains bounded by Unix permissions/ACLs and narrow sudo/doas rules.
- Stable service operations use semantic executable+action+resource scopes; broader administrator mutations generally use exact full-argv scopes.
- Workload start/build, namespace/guest/jail exec and equivalent mutable execution paths are elevated into powerful classes rather than receiving weaker reusable approval.
- Gateway performs an early `exec`/`shell` consistency filter, but it is not the hard boundary.
- Immediately before SSH signing, Control Plane reclassifies immutable `job.argv` using current policy, requires category/scope equality with job metadata, re-authenticates the grant, and enforces `shell` again. Stale queued policy fails closed.
- Worker generates a fresh Ed25519 keypair per job; private key stays in process memory.
- Only Control Plane calls the isolated SSH Signer.
- Signer owns principal, source-address, force-command, extensions and TTL; caller cannot broaden certificate shape.
- Certificates have no PTY/agent/port/X11-forwarding extensions and cannot outlive the execution job.
- SSH targets are logical IDs resolved only through operator-owned server-side inventory.
- Registry endpoints must be global-unicast literal IP + port with exact raw pinned host key. Agent-supplied destinations, DNS target resolution, loopback/link-local targets and insecure host-key acceptance are forbidden.
- Remote command transport is deterministic versioned base64url JSON; Sentinel does not reconstruct argv through a shell.
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
- While globally disabled, new worker claims are suppressed and grant re-authentication blocks capability use, start and certificate issuance.
- Global revoke cancels `staged`, `pending` and `claimed` jobs and invalidates their one-shot claim material.
- Running jobs require a worker-side fail-closed authority lease before executor invocation and periodically during active SSH execution.
- Global revoke, individual grant revoke, stale epoch, grant/job expiry, invalid claim, authority timeout or Control Plane loss cancels the worker execution context/SSH transport.
- Active transport termination does not promise instantaneous termination of detached/daemonized target-side descendants or reversal of completed side effects.
- Audit is append-oriented and tamper-evident; raw stdout/stderr is not retained by the current worker.
- Emergency controls include individual revoke and global revoke-all; global revoke must not delete configuration/history/audit.
- Production mutable security state uses PostgreSQL as a transaction engine, not independent SQL replicas of file stores.
- PostgreSQL production scope is grants, approvals, execution jobs, emergency authority state, audit/history, and Trust-2 agent notes. Trust-0 context, SSH target inventory, signer key/policy and external PVE egress policy remain separate operator-owned boundaries.
- PostgreSQL backend selection is explicit through `SENTINEL_PERSISTENCE_BACKEND`; selecting PostgreSQL can never silently fall back to file-backed authority.
- Production PostgreSQL requires verified TLS, exact schema version, and a least-privilege runtime role. Gateway, Worker and Signer receive no DB credentials.
- Fresh PostgreSQL authority starts `disabled=true`; cutover never imports old active bearer authority as live.
- Grant issue and global revoke serialize on `authority_state`, preventing a stale pre-revoke issuance commit.
- Canonical PostgreSQL lock order is authority -> grant -> approval -> job -> audit head. Authority/grant locks are acquired explicitly rather than depending on planner row-lock order.
- Individual grant revoke + non-running job cleanup + audit commit atomically.
- Global revoke + epoch/state transition + non-running job cancellation + audit commit atomically.
- Approval request/decision + their required audit records commit atomically.
- `allow_once` consumption + durable `consumed_by_job_id` binding + staged-job publication + authorization audit commit atomically.
- A consumed `allow_once` approval can only be retried for the same bound job and can never authorize a second job in the same scope.
- Worker claim/start/complete are transactional semantic operations; start revalidates authority/grant under lock and completion records factual outcome even if authority was revoked after execution began.
- Audit chain ordering is serialized through `audit_head`; transaction rollback cannot leave state changed without its required audit event.
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
- Versioned acceptance: commit `9eaa16febd801b4082221e45e7b929969e91b72c`, run `34397117715`.

### `0.1.0-dev.7` — powerful execution policy

- Conservative arbitrary-code/privilege/remote-exec routing, independent `exec`/`shell`, one-shot powerful approvals, complete-argv scope, Gateway prefilter and current-policy certificate gate.
- Versioned acceptance: commit `58318f7a1f0693941dce4d791ea97fac8e3d3519`, Actions run `34401911162`.

### `0.1.0-dev.8` — semantic operational-risk policy

- Semantic service/network/package/storage/system/runtime risk routing while preserving reliably read-only inspection paths; conservative escape coverage retained.
- Versioned acceptance: commit `4fcde4fa771f5008cbd696e4889ca51b564a9507`, Actions run `34406118118`.

### `0.1.0-dev.9` — external worker egress enforcement

- Deterministic deny-by-default PVE worker-egress policy, installed-policy drift/activation verification, literal-IP target/control transport and packet-level acceptance criteria.
- Versioned acceptance: commit `6a14729036b3f8cafa8f79a1855b7f54ddc2b246`, Actions run `34407900220`.

### `0.1.0-dev.10` — global revoke-all and active execution termination

- Monotonic emergency `security_epoch`, persistent revoke-all/re-enable controls, worker authority endpoint and fail-closed continuous active-execution authority checks.
- Versioned acceptance: commit `162d1f3c038ae905a4e27a419d9d4a61789466ae`, Actions run `34411432011`.

### `0.1.0-dev.11` — PostgreSQL transactional persistence

- Added reviewed PostgreSQL role/bootstrap/migration system and schema version 2.
- Mutable grants/targets, approvals, execution jobs/claim hashes, emergency authority, canonical hash-chained audit/history and Trust-2 notes are PostgreSQL-backed.
- Added explicit `SENTINEL_PERSISTENCE_BACKEND=file|postgres`; missing/invalid PostgreSQL configuration, connectivity, schema or runtime-role checks fail startup with no file fallback.
- PostgreSQL production connections require verified TLS; insecure PostgreSQL is development-only and explicit.
- Added narrow semantic lifecycle ports for grant issue/revoke, approval request/decision, staged authorization and worker claim/start/complete; production routes use these PostgreSQL transactional implementations.
- Individual/global revoke and enable couple security-state changes, job cleanup and required audit records in single transactions.
- Added durable `allow_once -> consumed_by_job_id` binding. One-shot consumption, job publication and authorization audit commit together, preventing concurrent/replayed reuse for a second job.
- Worker start serializes authority/grant checks with revoke; completion is transactional and replay-resistant while still permitting factual result recording after later revocation.
- Audit uses the existing canonical Go hash format and serializes append ordering through `audit_head`.
- CI applies every migration in order and validates runtime privileges on PostgreSQL 15 and 18.
- Added real integration regression coverage for grant/revoke ordering, rollback on blocked audit, one-shot approval concurrency/reuse, authorize-vs-revoke, transactional worker lifecycle and completion replay.
- Code acceptance gate: commit `2900a72098a410cb6d56c058c608d347e3ffd038`, Actions run `34480201607`; module tidy, gofmt, vet, `go test -race ./...`, PostgreSQL 15 and PostgreSQL 18 all passed.
- Versioned acceptance: commit `d64e0ce2f4ff40377b37f71a05755cfa7cea7410`, Actions run `34480805323`; module tidy, gofmt, vet, `go test -race ./...`, PostgreSQL 15 and PostgreSQL 18 all passed.

## Current phase

`0.1.0-dev.11` is the latest completed development release. The PostgreSQL persistence milestone is code/CI complete but has **not** been deployed to intended infrastructure.

File persistence remains available only as an explicit development compatibility backend. PostgreSQL is the production candidate and starts fail-closed; it must not be described as production-proven until infrastructure acceptance is complete.

Do **not** merge to `main` yet. The operator merge rule requires a functioning constrained real-infrastructure execution test first.

## Next implementation steps

1. Build the disposable/constrained deployment: Control Plane with PostgreSQL, Gateway, Worker, isolated SSH Signer/CA, and a disposable target profile.
2. Apply and verify the generated external PVE worker-egress policy on the selected worker VM interface.
3. Run the first real non-destructive end-to-end command path through capability -> authorization -> job -> claim/start -> SSH certificate -> pinned-key SSH -> target wrapper -> completion.
4. Run negative packet-level tests from the worker proving unrelated LAN, Internet, DNS and unlisted target ports are blocked.
5. Exercise individual revoke and `REVOKE ALL` during a live bounded execution and verify worker transport cancellation plus audit/state behavior.
6. Validate PostgreSQL restart/persistence behavior while authority starts/returns fail-closed as designed.
7. After successful constrained infrastructure acceptance, perform the first WIP merge to `main` and review README/docs in the merged state.
8. Only then move to the operator UI/backend presentation layer; security flows and data model should stay authoritative.
9. When the MCP interface is implemented, revisit and lock down the exact narrow tool surface for Qwen-class autonomous agents; do not expose general backend/admin APIs.

## Deployment state

Not deployed. No production trust should be placed in the current branch. No merge to `main` yet.
