# Tethys Sentinel — Handoff

Updated: 2026-09-09
Current development version: `0.1.0-dev.9`
Branch: `wip/bootstrap-security-core`
Deployment: not deployed; no merge to `main` yet

## Project goal

Tethys Sentinel is a security-first access broker between AI agents and infrastructure. An agent receives a short-lived capability, never infrastructure SSH private keys. Sentinel owns authorization, risky-action approval, authoritative context, execution-job binding, short-lived SSH identity, target resolution, remote execution constraints, continuity, audit, and worker network containment.

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
- Main boundaries are Control Plane, AI Gateway, Execution Worker, external worker network boundary, SSH Signer/CA, target execution wrapper, and persistent audit/state.
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
- Firewall shrink is not assumed to instantly terminate an already-established stateful TCP flow; global revoke/active termination remains a separate control.
- Audit is append-oriented and tamper-evident; raw stdout/stderr is not retained by the current worker.
- Emergency controls must include individual revoke and global revoke-all.
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

## Current phase

`0.1.0-dev.9` is complete and CI-accepted. It remains a development build and has not yet been exercised on the intended PVE worker VM.

File-backed stores remain bootstrap/development persistence, not final production state.

Do not merge to `main` yet: the operator merge rule requires a functioning constrained real-infrastructure execution test first.

The next separated milestone is global revoke-all and active worker termination. Revocation must stop new capability use, job publication/claim/start, certificate issuance, and terminate in-flight worker execution/connections where feasible rather than relying only on TTL expiry.

## Next implementation steps

1. Add global revoke-all semantics that block new signing/execution and actively terminate worker activity/connections where feasible.
2. Move grants/approvals/jobs/audit/notes to PostgreSQL with separate least-privilege roles and transactional semantics.
3. Build a disposable constrained target profile and worker VM, apply the generated PVE egress policy, and run the first real non-destructive end-to-end + negative packet-level test.
4. After successful constrained infrastructure execution, perform the first WIP merge and documentation review.
5. Build operator UI after backend security flows/data model stabilize.

## Deployment state

Not deployed. No production trust should be placed in the current branch. No merge to `main` yet.
