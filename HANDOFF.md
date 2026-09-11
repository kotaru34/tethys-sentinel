# Tethys Sentinel — Handoff

Updated: 2026-09-11
Current development version: `0.1.0-dev.12`
Branch: `wip/bootstrap-security-core`
Deployment: five acceptance VMs validated on `ai-server`; remote PostgreSQL boundary accepted; Signer SSH CA + mTLS boundary and disposable target SSH hardening accepted; dev.12 Worker PVE deny-by-default egress policy installed, verifier accepted and packet-level positive/negative tests passed; Control endpoint is reachable from Worker; Worker runtime execution acceptance, approval/revoke tests and PostgreSQL restart/loss tests remain; no merge to `main` yet

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
- Generated PVE Worker policy explicitly preserves inbound traffic with `policy_in: ACCEPT`, uses `policy_out: DROP`, explicit destination+TCP-port allows only, canonical policy SHA-256 and deterministic target deduplication.
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
- The selected first constrained infrastructure acceptance uses an existing operator-managed remote PostgreSQL service plus five separate guests: Control, Gateway, Worker, Signer and disposable target.
- The existing PostgreSQL service must use a CI-supported major (15 or 18 for dev.11/dev.12), a dedicated Sentinel database and LOGINs, verified TLS, source-restricted HBA, schema version 2, and least-privilege runtime access from Control only.
- Authority must remain disabled until TLS, target hardening and PVE Worker packet-level egress checks pass. Those infrastructure prerequisites have now passed; authority may only be enabled for the controlled end-to-end acceptance sequence after runtime service wiring is revalidated.
- When MCP/agent tools are added, keep the surface narrow and purpose-built for autonomous Qwen-class models rather than exposing backend/admin operations wholesale.

## Version history

### Through `0.1.0-dev.2` — capability, approval and audit core
- Opaque capability lifecycle, separated Control Plane/Gateway, protected transports, narrow approvals, Trust-0 bootstrap and hash-chained audit.

### `0.1.0-dev.3` — authoritative context and continuity
- Strict Control-Plane-owned Trust-0 context with scoped inventory/runbooks and scoped non-authoritative history/notes.

### `0.1.0-dev.4` — execution-job security protocol
- Immutable/idempotent execution jobs with staged/claim/start/terminal lifecycle and revocation handling.
- Acceptance: `7d263af6bf6aa9699e2a770efc023e585ddbeb56`, Actions `34389191377`.

### `0.1.0-dev.5` — isolated SSH CA/Signer
- Standalone constrained Ed25519 signer, dedicated mTLS/token boundary and ephemeral per-job Worker identity.
- Acceptance: `750d5d8d0ba899ff2fe45e3b39c70a8969b6a469`, Actions `34392961793`.

### `0.1.0-dev.6` — real SSH execution boundary
- Logical-target registry, pinned-key real SSH Worker, direct-argv forced wrapper and root-only replay consume helper.
- Acceptance: `9eaa16febd801b4082221e45e7b929969e91b72c`, Actions `34397117715`.

### `0.1.0-dev.7` — powerful execution policy
- Arbitrary-code/privilege/remote-exec routing, independent `exec`/`shell`, one-shot powerful approvals and current-policy certificate gate.
- Acceptance: `58318f7a1f0693941dce4d791ea97fac8e3d3519`, Actions `34401911162`.

### `0.1.0-dev.8` — semantic operational-risk policy
- Semantic administrator mutation/read-only routing across intended Linux/BSD/PVE operations.
- Acceptance: `4fcde4fa771f5008cbd696e4889ca51b564a9507`, Actions `34406118118`.

### `0.1.0-dev.9` — external Worker egress enforcement
- Deterministic deny-by-default PVE Worker egress rendering/verification plus packet-level acceptance criteria.
- Acceptance: `6a14729036b3f8cafa8f79a1855b7f54ddc2b246`, Actions `34407900220`.

### `0.1.0-dev.10` — global revoke-all and active execution termination
- Monotonic security epoch, persistent revoke-all/re-enable, Worker authority lease and fail-closed active transport cancellation.
- Acceptance: `162d1f3c038ae905a4e27a419d9d4a61789466ae`, Actions `34411432011`.

### `0.1.0-dev.11` — PostgreSQL transactional persistence
- PostgreSQL schema version 2 for mutable grants/targets, approvals, execution jobs/claim hashes, emergency authority, canonical audit/history and Trust-2 notes.
- Explicit `file|postgres` backend selection; PostgreSQL startup validates DSN/TLS/schema/runtime role and never silently falls back.
- Transactional semantic lifecycle operations for grant issue/revoke, approval request/decision, staged authorization and Worker claim/start/complete.
- Durable `allow_once -> consumed_by_job_id` binding makes one-shot consumption + job publication + authorization audit atomic and concurrency-safe.
- Ordered authority/grant locking serializes authorization/start with revoke.
- CI applies full migration chain and runtime privilege assertions to PostgreSQL 15 and 18.
- Code acceptance: `2900a72098a410cb6d56c058c608d347e3ffd038`, Actions `34480201607`.
- Versioned acceptance: `d64e0ce2f4ff40377b37f71a05755cfa7cea7410`, Actions `34480805323`.
- Final metadata HEAD validation: `acc4b41e755f124a20fc1029b73a2ea122e95346`, Actions `34481032244`; all Go and PostgreSQL 15/18 jobs passed.

### `0.1.0-dev.12` — preserve Worker inbound policy during PVE egress lockdown
- Real PVE deployment exposed that a generated Worker VM firewall which only specified `policy_out: DROP` did not explicitly preserve inbound policy. The renderer now emits `policy_in: ACCEPT` together with deny-by-default outbound policy so the egress boundary does not accidentally become an inbound lockdown.
- Regression test requires explicit inbound acceptance in generated PVE policy.
- Fix commit: `b46cd39bba2d6c45a01ccabf582290408a6e45dd`; versioned HEAD: `c172effb4534828ada35f1a83a66986b850ab89a`.
- CI acceptance: Actions `34553761523`, success.
- Local static `sentinel-egress-policy` acceptance on `sentinel-control`: Go `1.27.1`; targeted tests passed; binary SHA-256 `48f9d575fe65c977f79a3ef67303552f931c52a516b346a7155823a4c394fe0b`.

## Infrastructure acceptance checkpoint

- Added `docs/INFRASTRUCTURE_ACCEPTANCE.md` with the complete constrained PVE acceptance procedure and `docs/INFRASTRUCTURE_ACCEPTANCE_REMOTE_POSTGRES.md` for the selected remote-PostgreSQL topology.
- Selected acceptance topology is five separate guests: `sentinel-control`, `sentinel-gateway`, `sentinel-worker`, `sentinel-signer`, `sentinel-target-test`; PostgreSQL remains an existing operator-managed external service.
- The five acceptance VMs are on PVE node `ai-server` on VLAN 1520 / `10.169.2.0/24`: `1310 sentinel-control = 10.169.2.210`, `1320 sentinel-gateway = 10.169.2.211`, `1330 sentinel-worker = 10.169.2.212`, `1340 sentinel-signer = 10.169.2.213`, `1350 sentinel-target-test = 10.169.2.214`.
- VM cloud-init identity/network configuration was applied and all five guests were validated reachable over SSH with working QEMU Guest Agent. Their template boot disks were expanded from 3.5 GiB to 8 GiB and filesystems grown.
- Accepted dev.11 component binaries were installed and SHA-256 verified on the intended guests. dev.12 changes only `sentinel-egress-policy`; the application runtime binaries remain the accepted dev.11 artifacts while the development version is now dev.12.
- Remote PostgreSQL acceptance endpoint is `10.169.2.6:5432`, PostgreSQL `18.6`. Server TLS has SAN `IP:10.169.2.6`; Control pinned the certificate and `verify_ip 10.169.2.6` returned `Verify return code: 0 (ok)`. Certificate SHA-256 (DER) is `733d9274729649aa90fdad3e2a642108010e9cf8be98da8ff9bc98ba5aefa755`.
- Dedicated PostgreSQL roles/LOGINs and database exist: `sentinel_owner`, `sentinel_migrator`, `sentinel_control`, `sentinel_deploy`, `sentinel_control_login`, database `tethys_sentinel` owned by `sentinel_owner`.
- Runtime HBA precedence is hardened: encrypted runtime access is allowed only as `hostssl tethys_sentinel sentinel_control_login 10.169.2.210/32 scram-sha-256`, with matching `hostnossl ... reject` immediately after it and before the broader pre-existing network rule.
- Migrations `0001_core.sql` and `0002_allow_once_job_binding.sql` were SHA-256 verified and applied through `sentinel_deploy`; fresh state is schema version `2`, authority `epoch=0`, `disabled=true`.
- Runtime database credentials were rotated after an operator transcript exposed the initial generated values; only rotated credentials remain valid.
- Runtime PostgreSQL acceptance from Control passed over `sslmode=verify-full`; non-TLS access and privilege-escalation/write-negative tests were rejected as required. Gateway, Worker and Signer have no DB credentials.
- On Signer (`10.169.2.213`), the dedicated service identity and `/etc/tethys-sentinel` boundary exist, and the Ed25519 SSH user CA was generated locally. Private CA key remains only on Signer. CA fingerprint: `SHA256:pIfrpoGeNiKBtZrqzhOaFdIQknQrPsmIP3NiysW7opI`.
- On target (`10.169.2.214`), `sentinel-ai` has the forced wrapper/replay baseline; root-owned `tethys-sentinel-exec`/`tethys-sentinel-consume` are under `/usr/local/libexec`; target ID is `sentinel-target-test`; replay state is root-only; narrow consume-helper sudo rule passed validation.
- Target SSH CA/principal/effective sshd policy is accepted. `PermitUserEnvironment no` must be global rather than inside the Ubuntu/OpenSSH `Match` block; `PermitUserRC no` remains in the user match. The acceptance runbook still needs this placement corrected before merge.
- Target Ed25519 host-key registry pin is `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJiGpu8vIyouJXQvM0vGHY+ZAeImWtyK6Pplcjpur+tb`.
- Dedicated signer-mTLS CA exists; Signer holds its server leaf/key and signer client-CA certificate; Control holds only its `sentinel-control-signer` client leaf/key plus signer CA. Signer API token remains root-only operator/service material.
- `sentinel-signer.service` is enabled and active on `10.169.2.213:9443` with source-address fixed to Worker `10.169.2.212`, principal `sentinel-ai`, 45-second certificate TTL, and local SSH user CA.
- Signer mTLS acceptance from Control passed: authenticated `/healthz` succeeded over TLS 1.3 and the same request without a client certificate failed with TLS `certificate required`.
- Before dev.12 egress application, Worker runtime service was prepared but deliberately disabled/inactive while the hard external network boundary was not yet installed.
- dev.12 operator binary was copied to `ai-server` and SHA-256 reverified as `48f9d575fe65c977f79a3ef67303552f931c52a516b346a7155823a4c394fe0b`.
- Final protected target inventory contains only `sentinel-target-test -> 10.169.2.214:22` as `sentinel-ai` with the exact pinned host key above.
- Generated dev.12 PVE policy canonical destination hash is `b39ffbb97f0ad2889c38a3aa4548016931d1a485dcca701a06807e019287ed03`; generated/installed file SHA-256 is `f5f5b975b9bfdb2d6045a15318c1700b7abd4e84f7ad7c885b40bfc2c788ebba`.
- PVE node is Proxmox VE `9.2.0`, `pve-manager 9.2.11`. Datacenter firewall was previously `disabled/running`; `/etc/pve/firewall` contained no existing guest policy files and there was no node `host.fw`.
- Worker VMID `1330` `net0` is `virtio=BC:24:11:4D:73:21,bridge=ovs,firewall=1,tag=1520`.
- `/etc/pve/firewall/1330.fw` is now installed through pmxcfs and contains `enable: 1`, `policy_in: ACCEPT`, `policy_out: DROP`, with exactly two outbound allows: Control `10.169.2.210:9091/tcp` and target `10.169.2.214:22/tcp`.
- Datacenter `/etc/pve/firewall/cluster.fw` is enabled with `policy_in: ACCEPT` and `policy_out: ACCEPT`; this avoids imposing unrelated cluster-wide default-deny behavior while VMID 1330 carries the dedicated deny-by-default egress policy. `pve-firewall status` reports `enabled/running`.
- `sentinel-egress-policy -check` accepted byte-for-byte policy drift, active Datacenter firewall, VM config and `net0 firewall=1`.
- Packet-level acceptance from inside `sentinel-worker` passed after activation: Control `10.169.2.210:9091` OPEN; target `10.169.2.214:22` OPEN; Internet `1.1.1.1:443` BLOCKED; unlisted Control SSH `10.169.2.210:22` BLOCKED; unlisted target HTTP `10.169.2.214:80` BLOCKED; DNS `10.169.0.1:53` BLOCKED.
- This proves the external PVE Worker egress boundary at packet level for the selected acceptance inventory. AI authority remains disabled until runtime service wiring is revalidated and the controlled end-to-end test sequence begins.

## Current phase

`0.1.0-dev.12` is the current development release. CI passed and the real PVE Worker egress fix is installed and packet-level accepted on VMID 1330. Remote PostgreSQL, Signer mTLS/SSH CA, target SSH hardening and the external Worker network boundary are all accepted. Control is reachable from Worker on the only allowed Control transport (`10.169.2.210:9091`), but a TCP-open check alone is not treated as full runtime application acceptance. Worker service had intentionally remained disabled/inactive before egress activation and now needs to be started and validated together with Gateway/Control runtime wiring.

Fresh authority remains disabled. Do not merge to `main` yet. The operator merge rule still requires the real harmless SSH execution, approval non-reuse, individual/global active revoke, persistence/restart and PostgreSQL-loss fail-closed tests.

No production trust should be placed in the current branch yet. File persistence remains explicit development compatibility only; PostgreSQL is the production candidate.

## Next implementation/deployment steps

1. Revalidate Control service/environment and confirm the loopback admin API still reports global authority `disabled:true`.
2. Revalidate Gateway mTLS/service environment and start/validate Gateway if it is not already active.
3. Start `sentinel-worker` now that the external PVE egress boundary is accepted; confirm mTLS polling to Control succeeds without broad network access.
4. Correct the OpenSSH `PermitUserEnvironment` placement in `docs/INFRASTRUCTURE_ACCEPTANCE.md` and synchronize Worker-egress documentation with dev.12 before merge.
5. Enable authority only for the controlled acceptance window and execute the harmless real SSH path.
6. Run one-shot approval non-reuse, individual active revoke and global revoke-all/epoch non-revival tests.
7. Validate Control restart persistence and PostgreSQL-unavailable startup fail-closed behavior.
8. If every hard-boundary check passes, record final evidence in HANDOFF and perform the first WIP merge to `main` with final README/docs review.
9. If another runtime/code blocker is found, fix it on this branch, bump to the next development version, repeat affected CI/infrastructure tests, then reassess merge.
10. Operator UI follows only after this infrastructure acceptance/merge checkpoint.
11. When MCP is implemented, revisit and lock down the exact narrow tool surface for Qwen-class autonomous agents; never expose general backend/admin APIs.

## Deployment state

Five acceptance VMs are validated on PVE node `ai-server` on VLAN 1520 with final VMIDs/addresses and 8 GiB virtual disks. Remote PostgreSQL `18.6` at `10.169.2.6:5432` has pinned IP-SAN TLS, dedicated Sentinel database/roles, source-restricted TLS-only runtime HBA, schema version 2, fresh fail-closed authority state `epoch=0, disabled=true`, and an accepted least-privilege runtime boundary from Control. Signer owns the local Ed25519 SSH user CA and runs an accepted TLS 1.3 mTLS service on `.213:9443`; target `.214` has the hardened `sentinel-ai` wrapper/replay/CA/sshd baseline with pinned host key. dev.12 PVE external Worker policy is installed on VMID `1330`, verifier-clean and packet-level accepted; autonomous Worker egress is limited to Control `.210:9091` and target `.214:22`. Worker application service remains to be started/validated after this newly accepted hard boundary, followed by controlled authority enable and end-to-end execution/revocation/persistence acceptance. No merge to `main` yet.