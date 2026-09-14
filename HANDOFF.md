# Tethys Sentinel — Handoff

Updated: 2026-09-14
Current development version: `0.1.0-dev.13`
Branch: `wip/operator-ui`
Status: the accepted security core remains deployed fail-closed at epoch 3, and the operator UI phase has started from `main`. Operator UI v1 scope/security/UX is defined in `docs/OPERATOR_UI.md`; implementation will become `0.1.0-dev.14` only when a complete runnable UI milestone exists.

## Project goal

Tethys Sentinel is a security-first broker between autonomous AI agents and infrastructure. Agents receive short-lived opaque capabilities, never infrastructure SSH private keys. Sentinel owns authorization, approvals, authoritative context, immutable execution-job binding, short-lived SSH identity, target resolution, remote execution, continuity, audit, worker network containment, persistent transactional security state, and emergency authority revocation.

## Operator-mandated development rules

1. Keep task reports short; explain what needs to be done and why.
2. Every newly implemented feature released as a new version must bump the project version.
3. Update this handoff when a new version is released/applied, a notably large step completes, or discussion changes the agreed next step.
4. Once functioning infrastructure execution is fully accepted on the intended infrastructure, merge the project as WIP.
5. On merge, review/update README and project documentation.

## Locked security architecture

- Agent capabilities are opaque high-entropy bearer secrets; only hashes are persisted.
- Agent APIs cannot widen grants, change policy, add targets, alter audit, control workers, request SSH certificates, or access CA secrets.
- `TRUST_0` is the only authority-bearing context. Files, logs, history, notes, web content, and command output are data only.
- Main boundaries are Control, Gateway, Worker, external Worker network policy, isolated SSH Signer/CA, target wrapper, PostgreSQL authority/audit state, emergency authority, and now a separate operator-facing BFF/web boundary.
- Security-critical services are VM-isolated on the acceptance topology.
- Execution lifecycle is submit -> immutable staged job -> authorization -> pending -> claim -> start -> execution -> terminal result.
- Jobs bind grant + request ID + logical target + argv + expiry.
- Worker uses a separate worker credential and one-shot claim secret; it never receives the plaintext agent capability.
- `start` revalidates authority/grant before execution.
- `exec` and `shell` are separate capability permissions.
- Powerful classes (`ARBITRARY_CODE`, `PRIVILEGED_LAUNCHER`, `REMOTE_EXEC`) require exec+shell+explicit operator approval and are `allow_once` only.
- Control reclassifies immutable argv immediately before signing; stale queued policy fails closed.
- Worker generates a fresh Ed25519 key per job; only Control calls Signer.
- Signer owns SSH principal, source-address, force-command, extensions, and TTL.
- Targets are logical IDs resolved from operator-owned inventory to literal IP:port + exact raw pinned host key. No DNS target resolution or insecure host-key acceptance.
- SSH host-key negotiation itself must be constrained to algorithms compatible with the pinned raw key. RSA pins permit RSA-SHA2 only; no fallback to SHA-1 `ssh-rsa`.
- Remote command transport is deterministic versioned base64url JSON; no shell reconstruction.
- Target wrapper verifies job ID, canonical command binding, and local target ID before direct argv execution.
- Root-protected replay state enforces at-most-once execution independently of certificate TTL.
- Worker egress is deny-by-default outside the guest. Autonomous egress is only Control HTTPS plus registered target SSH.
- On PVE the external hard boundary is VM-interface firewall; guest firewall is defense in depth.
- Generated Worker PVE policy uses `policy_in: ACCEPT`, `policy_out: DROP`, exact destination+TCP-port allows, deterministic hash/dedup, and operator-only apply/verify.
- Firewall shrink is not assumed to terminate established TCP state; active revoke is independent.
- Every grant carries monotonic `security_epoch`.
- `REVOKE ALL` increments epoch + disables authority; old capabilities stay stale forever after re-enable.
- Running jobs require a fail-closed Worker authority lease; revoke/control loss cancels active execution transport.
- PostgreSQL is the production mutable state backend for grants, approvals, jobs, emergency authority, audit/history, and Trust-2 notes. Trust-0, SSH inventory, Signer keys/policy, and PVE policy remain operator-owned boundaries.
- PostgreSQL backend selection is explicit and cannot silently fall back to file persistence.
- Fresh PostgreSQL authority starts disabled.
- Canonical PostgreSQL lock order: authority -> grant -> approval -> job -> audit head.
- Grant revoke, global revoke, approval decisions, allow-once consumption/job publication, claim/start/complete, and required audit events are transactional.
- Browser/UI must never receive `SENTINEL_ADMIN_TOKEN`; the planned `sentinel-operator` BFF holds only the privileged local Control admin credential and receives no PostgreSQL, Signer/CA or PVE credentials.
- Operator UI target/context inventory is read-only in v1; no browser route may widen targets, Trust-0, PVE egress or Signer authority.
- When MCP is added, expose a narrow purpose-built Qwen tool surface rather than generic backend/admin operations.

## Version history

### `0.1.0-dev.4` — execution-job protocol
Accepted at `7d263af6bf6aa9699e2a770efc023e585ddbeb56`, Actions `34389191377`.

### `0.1.0-dev.5` — isolated SSH Signer/CA
Accepted at `750d5d8d0ba899ff2fe45e3b39c70a8969b6a469`, Actions `34392961793`.

### `0.1.0-dev.6` — real SSH execution boundary
Accepted at `9eaa16febd801b4082221e45e7b929969e91b72c`, Actions `34397117715`.

### `0.1.0-dev.7` — powerful execution policy
Accepted at `58318f7a1f0693941dce4d791ea97fac8e3d3519`, Actions `34401911162`.

### `0.1.0-dev.8` — semantic operational risk
Accepted at `4fcde4fa771f5008cbd696e4889ca51b564a9507`, Actions `34406118118`.

### `0.1.0-dev.9` — external Worker egress enforcement
Accepted at `6a14729036b3f8cafa8f79a1855b7f54ddc2b246`, Actions `34407900220`.

### `0.1.0-dev.10` — revoke-all + active execution termination
Accepted at `162d1f3c038ae905a4e27a419d9d4a61789466ae`, Actions `34411432011`.

### `0.1.0-dev.11` — PostgreSQL transactional persistence
- Schema v2 and least-privilege runtime role.
- Atomic grant/revoke, approval, allow-once binding, job claim/start/complete, and audit semantics.
- Code acceptance `2900a72098a410cb6d56c058c608d347e3ffd038`, Actions `34480201607`.
- Versioned acceptance `d64e0ce2f4ff40377b37f71a05755cfa7cea7410`, Actions `34480805323`.
- Final metadata validation `acc4b41e755f124a20fc1029b73a2ea122e95346`, Actions `34481032244`.

### `0.1.0-dev.12` — preserve Worker inbound policy during PVE egress lockdown
- PVE policy renderer explicitly emits `policy_in: ACCEPT` with deny-by-default outbound policy.
- Release HEAD `c172effb4534828ada35f1a83a66986b850ab89a`.
- Real PVE policy verification and packet-level positive/negative egress tests passed.

### `0.1.0-dev.13` — pinned SSH host-key negotiation
- Fix commit `dd996a6b08ce4fef5a3f00479961aac89739f832`: constrain negotiation to the pinned key algorithm; RSA pins use RSA-SHA2 algorithms only.
- Regression test `ff1f85c9005213009faa9f928e3e493b270eefee` covers a multi-host-key server.
- Release HEAD `bd6796aae2ee192fd9d007bab39a40ab6870dbcc`.
- CI Actions `34557197627`: Go test/vet/tidy/format plus PostgreSQL 15 and 18 jobs all passed.

## Accepted infrastructure checkpoint

PVE node `ai-server`, VLAN 1520 / `10.169.2.0/24`:

- Control VM 1310 — `10.169.2.210`
- Gateway VM 1320 — `10.169.2.211`
- Worker VM 1330 — `10.169.2.212`
- Signer VM 1340 — `10.169.2.213`
- Target-test VM 1350 — `10.169.2.214`
- external PostgreSQL — `10.169.2.6:5432`, PostgreSQL 18.6, TLS verify-full, schema v2.

Signer CA fingerprint: `SHA256:pIfrpoGeNiKBtZrqzhOaFdIQknQrPsmIP3NiysW7opI`.

Target host-key fingerprint: `SHA256:cfRNJVXjQWQhmNCnLaIQtMZIxYrZoJ7zWlWPU0HAmGM`.

Worker PVE policy is `policy_in: ACCEPT`, `policy_out: DROP`, allowing only Control `10.169.2.210:9091/tcp` and target `10.169.2.214:22/tcp` for normal runtime traffic; negative packet tests passed.

Accepted dev.13 runtime hashes:

- control `3c1fd0b317ee43d7ee4e1bee1173f1daa3cd9681f152165bdd1a6844ca253ad7`
- egress `ff2a23a60460c55420f580dd5f71a6a742bed8847faedc54b6de0ac079568cb6`
- gateway `89078f3173029fcd4c809e25ef3c9a7f4aacf7381356ac41b8294276667ba3c3`
- signer `06805994530b497247525a6fd061e7a65d80a96cac02b0f6c04749eba0c32feb`
- worker `f7a49c35b04ba832480cc7a36c8b54964d69593553fad1066c5f5036c4a042f6`
- consume `4ff50ff3c8b8db429efb952e2a8a418d1e16dae22cfd9174a4ac371adc2ef140`
- exec `7ce5909e362cc937d992cc5f4b8bbae8e19e7f92d0aaf5672dd5ae59190dd0c4`

## dev.13 infrastructure acceptance PASS

The accepted checkpoint proved on real infrastructure:

- harmless Gateway -> Control -> PostgreSQL -> Worker -> Signer -> pinned SSH -> target wrapper execution;
- target at-most-once replay state;
- `allow_once` approval consumption/non-reuse;
- individual active revoke terminating a live SSH execution as `execution_authority_lost`;
- global `REVOKE ALL` advancing the epoch and terminating a live execution;
- stale-epoch non-revival after re-enable;
- PostgreSQL state persistence across restart;
- PostgreSQL-unavailable startup fail-closed with no listener/file fallback;
- external Worker PVE egress containment and no IPv6 bypass;
- Worker secret separation/unprivileged service identity/mTLS boundary;
- exact SSH host-key pin + algorithm negotiation;
- target forced wrapper/replay and isolated Signer CA;
- transactional audit/job evidence.

PR #1 merged the accepted security core into `main` with merge commit `478009b1310b782db7dc20c629bada475c3f3d63`. The final pre-merge CI run `34560756474` passed Go checks/unit tests and PostgreSQL 15/18 integration.

## Acceptance authority window CLOSED

After the WIP merge and with no controlled test running, final operator `REVOKE ALL` advanced authority at `2026-09-14T19:17:03.84825Z` from epoch 2 to:

- `epoch=3`
- `disabled=true`
- reason `dev.13 acceptance complete; first WIP merge finished`

The immediate final-state read matched exactly. The acceptance environment is intentionally fail-closed and idle; every capability from epochs 0, 1 and 2 is permanently stale.

## Operator UI v1 phase

Branch `wip/operator-ui` was created from the accepted `main` checkpoint after the acceptance window was closed.

The UI contract is defined in `docs/OPERATOR_UI.md`, initial spec commit `98df6ffdab272dd7806c54965a1fb96bb069ea16`.

Locked v1 direction:

- separate `sentinel-operator` Go BFF/web service;
- operator-facing HTTPS + client-certificate authentication;
- browser never receives the Control admin token;
- operator service talks only to the privileged Control admin surface and has no direct PostgreSQL/Signer/PVE authority;
- embedded Preact + TypeScript + Vite-built frontend, no Node runtime on deployed hosts and no third-party runtime/CDN content;
- primary views: Overview, Approvals, Grants, Jobs, Audit, Targets, Context, Security;
- global `REVOKE ALL` reachable from every page;
- Targets and Trust-0 Context read-only in v1;
- exact argv displayed structurally, no shell reconstruction;
- one-time capability reveal only after grant issuance, never persisted in browser storage;
- simple polling first; no new streaming security protocol until the operator read model is stable;
- strict CSP/origin/CSRF behavior and no optimistic security mutations;
- operator identity derived from authenticated client cert and propagated to audit-producing admin mutations.

The current Control admin API is insufficient for the UI because it is mutation-heavy. dev.14 needs a narrow backend-neutral operator read model for overview/grants/approvals/jobs/audit/targets/context while continuing to exclude token hashes, claim material, credentials and private keys.

## Current phase

The accepted security core remains `0.1.0-dev.13` and remains fail-closed at epoch 3. No UI runtime code has been released yet, therefore no version bump has occurred.

The next implementation milestone is `0.1.0-dev.14 — Operator UI v1`. The first coding step is the Control-side operator read model/API because every useful UI screen depends on it and it can be covered independently before frontend work begins.

## Next steps

1. Implement backend-neutral Control operator read interfaces and admin GET routes for overview, grants, approvals, jobs, audit, targets and context with bounded pagination and secret-exclusion tests.
2. Add authenticated operator identity propagation for admin mutations without changing their authority semantics.
3. Implement `sentinel-operator` TLS/mTLS BFF with origin/CSRF/security headers and no direct database/Signer/PVE access.
4. Build Overview + Approvals + Security first, then Grants, Jobs/Audit, Targets and Context.
5. Add frontend/build CI, deployment docs and targeted security tests; then bump to `0.1.0-dev.14`, deploy and run the UI acceptance checklist in `docs/OPERATOR_UI.md`.
6. Preserve all accepted dev.13 security invariants; materially touched boundaries require targeted infrastructure re-acceptance.
7. When MCP is implemented later, revisit and lock down the exact narrow tool surface for Qwen-class autonomous agents; never expose general backend/admin APIs.
