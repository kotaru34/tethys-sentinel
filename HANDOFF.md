# Tethys Sentinel — Handoff

Updated: 2026-09-09
Current development version: `0.1.0-dev.7`
Branch: `wip/bootstrap-security-core`
Deployment: not deployed; no merge to `main` yet

## Project goal

Tethys Sentinel is a security-first access broker between AI agents and infrastructure. An agent receives a short-lived capability, never infrastructure SSH private keys. Sentinel owns authorization, risky-action approval, authoritative context, execution-job binding, short-lived SSH identity, target resolution, remote execution constraints, continuity, and audit.

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
- Main boundaries are Control Plane, AI Gateway, Execution Worker, SSH Signer/CA, target execution wrapper, and persistent audit/state.
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
- Gateway performs an early `exec`/`shell` consistency filter, but it is not the hard boundary.
- Immediately before SSH signing, Control Plane reclassifies immutable `job.argv` using current policy, requires category/scope equality with job metadata, re-authenticates the grant, and enforces `shell` again. Stale queued policy fails closed.
- Worker generates a fresh Ed25519 keypair per job; private key stays in process memory.
- Only Control Plane calls the isolated SSH Signer.
- Signer owns principal, source-address, force-command, extensions and TTL; caller cannot broaden certificate shape.
- Certificates have no PTY/agent/port/X11-forwarding extensions and cannot outlive the execution job.
- SSH targets are logical IDs resolved only through operator-owned server-side inventory.
- Registry endpoints must be concrete literal IP + port and exact raw pinned host key. Agent-supplied destinations, DNS target resolution and insecure host-key acceptance are forbidden.
- Remote command transport is deterministic versioned base64url JSON; Sentinel does not reconstruct argv through `/bin/sh -c`.
- Target wrapper verifies signer-bound job ID, canonical command binding and root/operator-owned local target ID before direct argv execution.
- Target replay state enforces at-most-once execution independently of certificate TTL. Replay markers are root-protected and consumed by a narrow root helper.
- SSH dial/handshake/output are bounded and execution cannot outlive `job.expires_at`.
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

- Added conservative `ARBITRARY_CODE`, `PRIVILEGE_LAUNCHER` and `REMOTE_EXEC` classification for known interpreters/shells, generic command carriers, privilege/namespace launchers, SSH/Ansible/network pivots, Kubernetes remote operations, container run/exec, `find -exec`, tar checkpoint exec and related escape patterns.
- Powerful command approval scope is SHA-256 of canonical complete argv including executable path.
- Added `exec`/`shell` separation: powerful classes require explicit `shell=true` in addition to `exec=true` and approval.
- Gateway rejects unreachable powerful submissions early when `shell=false`.
- Hard certificate gate reclassifies immutable argv with current policy immediately before signing, checks category/scope freshness, re-authenticates grant, and requires `shell` again before signer invocation.
- Old queued jobs whose risk classification changes fail closed rather than retaining grandfathered authority.
- `ARBITRARY_CODE`, `PRIVILEGE_LAUNCHER`, and `REMOTE_EXEC` are `allow_once` only; `allow_session` is rejected.
- Legacy persisted unsafe session approvals are ignored by matching after upgrade.
- Stable semantic categories such as narrowly scoped service restart can still support constrained session approval.
- Added regression coverage for full-argv collision/path separation, shell capability enforcement, Gateway prefilter, certificate-time policy freshness, one-shot powerful approval, and legacy unsafe approval invalidation.
- Added `docs/EXECUTION_POLICY.md`; README/API/architecture/threat model synchronized.
- Pre-release code gate: commit `b1bbab9243fee12a1bf3e6cbb2b2a0174263e941`, Actions run `34401421958`; all module tidy/gofmt/vet/race tests passed.
- Versioned acceptance: commit `58318f7a1f0693941dce4d791ea97fac8e3d3519`, Actions run `34401911162`; all module tidy/gofmt/vet/race tests passed.

## Current phase

`0.1.0-dev.7` is complete and CI-accepted. It remains a development build and has not been exercised on intended PVE infrastructure.

File-backed stores remain bootstrap/development persistence, not final production state.

Do not merge to `main` yet: the operator merge rule requires a functioning constrained real-infrastructure execution test first.

The next separated milestone is `0.1.0-dev.8`: semantic operational-risk coverage for high-impact administrative state mutation. This should not devolve into approval for every ordinary file operation; Unix permissions/sudo remain the file-authority boundary. The classifier should focus on administrator primitives with large blast radius and use stable semantic resource scopes where reusable approval is genuinely safe enough.

## Next implementation steps

1. `0.1.0-dev.8`: cover broader service lifecycle, network/routing/link changes, package state, storage topology/raw writes, kernel controls, container/orchestrator state and hypervisor state.
2. Add independent worker VM egress enforcement for registered target IPs/ports plus required Control Plane endpoints.
3. Add global revoke-all semantics that block new signing/execution and actively terminate worker activity where feasible.
4. Move grants/approvals/jobs/audit/notes to PostgreSQL with separate least-privilege roles and transactional semantics.
5. Build a disposable constrained target profile and run the first real PVE end-to-end test using non-destructive commands.
6. After successful constrained infrastructure execution, perform the first WIP merge and documentation review.
7. Build operator UI after backend security flows/data model stabilize.

## Deployment state

Not deployed. No production trust should be placed in the current branch. No merge to `main` yet.
