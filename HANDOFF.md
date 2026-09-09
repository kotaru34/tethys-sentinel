# Tethys Sentinel — Handoff

Updated: 2026-09-09
Current development version: `0.1.0-dev.6`
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
- Approval choices are `deny`, `allow_once`, and narrow `allow_session`; a session approval is scoped to risk rule + logical target + concrete resource/operation.
- Security never relies on prompt compliance or regex classification alone.
- Main boundaries are Control Plane, AI Gateway, Execution Worker, SSH Signer/CA, target execution wrapper, and persistent audit/state.
- Security-critical public/backend components should use VM isolation rather than one shared LXC boundary.
- Execution is atomic submit -> immutable job; there is no separable authorize-now/execute-later primitive.
- Jobs bind grant + request ID + logical target + argv + expiry and use staged/pending/claimed/running/terminal states.
- Worker never receives the plaintext agent capability. It uses a separate worker credential and one-shot job claim secret.
- `start` revalidates the grant after claim and before execution authority is granted.
- Worker generates a fresh Ed25519 keypair per job; private key stays in process memory.
- Only Control Plane calls the isolated SSH Signer.
- Signer owns principal, source-address, force-command, extensions and TTL; caller cannot broaden certificate shape.
- Certificates have no PTY/agent/port/X11-forwarding extensions and cannot outlive the execution job.
- SSH targets are logical IDs resolved only through operator-owned server-side inventory.
- Registry endpoints must be concrete literal IP + port and exact raw pinned host key. Agent-supplied destinations, DNS target resolution and insecure host-key acceptance are forbidden.
- Remote command transport is a deterministic versioned base64url JSON envelope; Sentinel does not reconstruct argv through `/bin/sh -c`.
- Target wrapper verifies signer-bound job ID, canonical command binding and root/operator-owned local target ID before direct argv execution.
- Target replay state enforces at-most-once execution independently of certificate TTL. Replay markers are root-protected and consumed by a narrow root helper.
- SSH dial/handshake/output are bounded and execution cannot outlive `job.expires_at`.
- Audit is append-oriented and tamper-evident; raw stdout/stderr is not retained by the current worker.
- Emergency controls must include individual revoke and global revoke-all.
- Known pre-production policy gap after dev.6: interpreters, shells, remote-exec tools and privilege launchers can carry behavior that a top-level executable classifier cannot safely understand. They require a dedicated conservative policy before production trust.
- When the MCP/agent tool interface is implemented, keep it narrow and purpose-built for autonomous Qwen-class models rather than exposing backend/admin surfaces wholesale.

## Version history

### Through `0.1.0-dev.2` — capability, approval and audit core

- Opaque 256-bit capability lifecycle with hashed-at-rest lookup, expiry and revocation.
- Separate Control Plane and AI Gateway; gateway physically lacks grant administration.
- TLS 1.3/mTLS internal transport; insecure plaintext only explicit loopback development mode.
- Risk classification and persistent narrow approvals.
- Read-only Trust-0 bootstrap.
- Append-only hash-chained JSONL audit with startup verification and fail-closed authorization on audit failure.

### `0.1.0-dev.3` — authoritative context and continuity

- Control-plane-owned strict authoritative context store.
- Scoped Trust-0 POLICY/INSTRUCTIONS/INFRASTRUCTURE/TOOLS/runbooks.
- Target-filtered context and history.
- Trust-2 history and target-scoped agent continuity notes.
- Unknown/trailing authoritative JSON rejected and document/source hashes recorded.

### `0.1.0-dev.4` — execution-job security protocol

- Atomic `/commands/submit` and canonical command binding.
- HMAC-protected bootstrap execution-job store.
- Request-ID idempotency/rebinding rejection.
- `staged -> pending -> claimed -> running -> terminal` lifecycle.
- One-shot 256-bit worker claim secrets; hashes persisted.
- Authoritative `start` revalidation and revocation race handling.
- Crash recovery around one-shot approval consumption/publication.
- Acceptance: commit `7d263af6bf6aa9699e2a770efc023e585ddbeb56`, Actions run `34389191377`.

### `0.1.0-dev.5` — isolated SSH CA/Signer

- Constrained Ed25519 OpenSSH user-certificate signer and standalone `sentinel-signer`.
- Dedicated signer mTLS client CA + bearer credential.
- Signer-owned principal/source/force-command/extensions/TTL.
- Control Plane certificate gate requires running job, valid claim, binding, expiry and active grant.
- Per-job in-memory worker Ed25519 identity; issued certificate must match it and job expiry.
- Certificate issuance audited with serial/fingerprints.
- Acceptance: commit `750d5d8d0ba899ff2fe45e3b39c70a8969b6a469`, Actions run `34392961793`.

### `0.1.0-dev.6` — real SSH execution boundary

- Added protected `SENTINEL_SSH_TARGETS_FILE` registry: logical target -> literal IP/port + Unix user + exact pinned raw SSH host key.
- Rejects DNS targets, malformed/unspecified endpoints, duplicate targets, unknown fields and writable registry configuration.
- Control Plane resolves target only after job/claim/binding/grant checks; agent input never becomes arbitrary worker transport data.
- Added standalone `sentinel-worker` and complete flow: `claim -> start -> ephemeral key -> certificate+target -> pinned SSH -> target wrapper -> complete`.
- Real `x/crypto/ssh` executor uses `ssh.FixedHostKey`; wrong pin aborts before exec.
- TCP/SSH handshake deadlines are explicit; execution context is capped by job expiry.
- stdout/stderr are SHA-256 accounted without raw retention; configured overflow actively closes SSH transport.
- Added deterministic `sentinel-exec-v1` envelope carrying immutable job/grant/request/target/argv material without shell quoting.
- Added root/operator-owned `tethys-sentinel-exec` wrapper: validates job, local target ID and canonical binding, uses fixed safe environment, then direct `exec(argv)` semantics.
- Added `tethys-sentinel-consume`: narrow root-only helper with private replay-state ownership/permission validation and atomic `O_EXCL` marker creation.
- Target execution is at-most-once even while a short-lived certificate remains valid.
- Added real in-process SSH integration coverage for correct pin, wrong pin, envelope preservation, stalled handshake bound and active output-limit cutoff.
- Added replay concurrency/permission tests, target registry tests, wrapper/binding/target-ID tests, worker cert lifecycle tests.
- Added/synchronized `docs/SSH_EXECUTION.md`, README, API, architecture, threat model, signer docs and execution protocol.
- Pre-release security gate: commit `c6e84402d58bb282e9d63877ba8d0807fb960310`, Actions run `34396499517`, all module tidy/gofmt/vet/race tests passed.
- Versioned acceptance gate: commit `9eaa16febd801b4082221e45e7b929969e91b72c`, Actions run `34397117715`, all CI checks passed.

## Current phase

`0.1.0-dev.6` is complete and CI-accepted. It is the first version with a real test-covered SSH transport and target execution boundary, but it is still a development build and has not been exercised on the intended PVE infrastructure.

File-backed stores remain bootstrap/development persistence, not final production storage.

Do not merge to `main` yet: the operator merge rule requires a functioning constrained real-infrastructure execution test first.

## Next implementation steps

1. `0.1.0-dev.7`: conservative risk policy for arbitrary-code carriers, privilege launchers and remote-exec/pivot tools. Approval scope must bind exact argv/operation so `allow_session` cannot become blanket future arbitrary-code authority.
2. Add independent worker VM egress enforcement for registered target IPs/ports plus required Control Plane endpoints.
3. Add global revoke-all semantics that stop new signing/execution and actively terminate worker activity where feasible.
4. Move grants/approvals/jobs/audit/notes to PostgreSQL with separate least-privilege service roles and transactional semantics.
5. Build a disposable constrained target profile and run the first real PVE end-to-end test using non-destructive commands.
6. After successful constrained infrastructure execution, perform the first WIP merge and documentation review.
7. Build the operator UI after backend security flows/data model stabilize.

## Deployment state

Not deployed. No production trust should be placed in the current branch. No merge to `main` yet.
