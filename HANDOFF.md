# Tethys Sentinel — Handoff

Updated: 2026-09-11
Current development version: `0.1.0-dev.13`
Branch: `wip/bootstrap-security-core`
Status: constrained infrastructure acceptance in progress; real end-to-end SSH execution and `allow_once` non-reuse have passed on the intended PVE topology; active revocation and PostgreSQL-loss tests remain; no merge to `main` yet.

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
- Main boundaries are Control, Gateway, Worker, external Worker network policy, isolated SSH Signer/CA, target wrapper, PostgreSQL authority/audit state, and emergency authority.
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
- PVE policy renderer now explicitly emits `policy_in: ACCEPT` with deny-by-default outbound policy.
- Fix `b46cd39bba2d6c45a01ccabf582290408a6e45dd`; release HEAD `c172effb4534828ada35f1a83a66986b850ab89a`.
- CI Actions `34553761523` passed.
- Real PVE policy verification and packet-level positive/negative egress tests passed.

### `0.1.0-dev.13` — pinned SSH host-key negotiation
- First real dev.12 SSH execution reached target but failed before auth with `ssh_handshake_failed: host key mismatch`.
- Target advertised RSA, ECDSA, and Ed25519 host keys while inventory correctly pinned Ed25519. `ssh.FixedHostKey` validated the negotiated key but the client did not constrain host-key algorithm negotiation, allowing a different advertised server key to be selected.
- Fix commit `dd996a6b08ce4fef5a3f00479961aac89739f832`: constrain negotiation to the pinned key algorithm; RSA pins use RSA-SHA2 algorithms only.
- Regression test commit `ff1f85c9005213009faa9f928e3e493b270eefee`: multi-host-key test server proves a pinned Ed25519 key succeeds even when another host key is also advertised.
- Version bump commits `55acd72967cf08413307ab441239e53a81557300` and `bd6796aae2ee192fd9d007bab39a40ab6870dbcc`.
- CI Actions `34557197627`: Go test/vet/tidy/format plus PostgreSQL 15 and 18 jobs all passed.

## Acceptance infrastructure

PVE node: `ai-server`, PVE `9.2.0`, `pve-manager 9.2.11`.

VLAN 1520 / `10.169.2.0/24`:
- VM 1310 `sentinel-control` — `10.169.2.210`
- VM 1320 `sentinel-gateway` — `10.169.2.211`
- VM 1330 `sentinel-worker` — `10.169.2.212`
- VM 1340 `sentinel-signer` — `10.169.2.213`
- VM 1350 `sentinel-target-test` — `10.169.2.214`

External PostgreSQL: `10.169.2.6:5432`, PostgreSQL `18.6`, dedicated database/roles, TLS `verify-full`, source-restricted runtime HBA, schema version 2. TLS certificate SHA-256 DER: `733d9274729649aa90fdad3e2a642108010e9cf8be98da8ff9bc98ba5aefa755`.

Signer CA fingerprint: `SHA256:pIfrpoGeNiKBtZrqzhOaFdIQknQrPsmIP3NiysW7opI`.

Target host key pin:
`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJiGpu8vIyouJXQvM0vGHY+ZAeImWtyK6Pplcjpur+tb`
Fingerprint: `SHA256:cfRNJVXjQWQhmNCnLaIQtMZIxYrZoJ7zWlWPU0HAmGM`.

Worker PVE firewall on VMID 1330:
- `policy_in: ACCEPT`
- `policy_out: DROP`
- allow Control `10.169.2.210:9091/tcp`
- allow target `10.169.2.214:22/tcp`
- Internet, DNS, unlisted Control/target ports blocked in packet tests.

## dev.13 deployed artifact hashes

Built from exact release HEAD `bd6796aae2ee192fd9d007bab39a40ab6870dbcc` with Go `1.27.1`, `CGO_ENABLED=0`, `-trimpath`:

- `sentinel-control` — `3c1fd0b317ee43d7ee4e1bee1173f1daa3cd9681f152165bdd1a6844ca253ad7`
- `sentinel-egress-policy` — `ff2a23a60460c55420f580dd5f71a6a742bed8847faedc54b6de0ac079568cb6`
- `sentinel-gateway` — `89078f3173029fcd4c809e25ef3c9a7f4aacf7381356ac41b8294276667ba3c3`
- `sentinel-signer` — `06805994530b497247525a6fd061e7a65d80a96cac02b0f6c04749eba0c32feb`
- `sentinel-worker` — `f7a49c35b04ba832480cc7a36c8b54964d69593553fad1066c5f5036c4a042f6`
- `tethys-sentinel-consume` — `4ff50ff3c8b8db429efb952e2a8a418d1e16dae22cfd9174a4ac371adc2ef140`
- `tethys-sentinel-exec` — `7ce5909e362cc937d992cc5f4b8bbae8e19e7f92d0aaf5672dd5ae59190dd0c4`

Control, Gateway, Worker, Signer, and both target helpers are installed at these exact dev.13 hashes. Services report `0.1.0-dev.13` and are active. Control -> Signer authenticated mTLS health check passes. Worker polling is clean while authority is disabled.

## dev.12 blocker and epoch transition

The failed dev.12 harmless execution job was:
- job `1d2dc244acedb4cc3cb1991dc4fcfcfa`
- request `acceptance-true-0001`
- terminal state `failed`
- `result_success=false`, `result_exit_code=-1`, `error_kind=ssh_handshake_failed`
- target replay state remained empty.

Target and inventory Ed25519 pins matched exactly; target `sshd -T` advertised RSA + ECDSA + Ed25519, confirming the dev.13 negotiation fix was required.

After finding the blocker, `REVOKE ALL` moved authority from epoch 0 to epoch 1 and disabled access:
- time `2026-09-11T03:11:02.944644Z`
- reason `dev.12 acceptance blocked by SSH host-key algorithm negotiation bug`

The old epoch-0 dev.12 capability can never become valid again.

Control was then restarted on dev.13 while authority remained `epoch=1, disabled=true`; PostgreSQL persisted that state exactly. This is positive restart-persistence evidence.

## First real end-to-end execution PASS

Authority was re-enabled at epoch 1 for dev.13 acceptance. Fresh grant:
- grant `3dc529728e7fef948aef780a43392093`
- agent `acceptance-agent`
- target `sentinel-target-test`
- `exec=true`, `shell=false`
- `security_epoch=1`
- issued `2026-09-11T03:23:04.574940107Z`
- bearer remained root-only and was not printed.

Harmless command submission:
- request `acceptance-true-dev13-0001`
- argv `["true"]`
- job `e27bc8b013c31670da2fa67294814bb9`
- risk `DEFAULT`, decision `allow`
- command SHA-256 `62c9522d29395105a7707ebc2409e70d07df940c80c490907b4770368bf7c288`

Terminal PostgreSQL result:
- status `succeeded`
- claimed `2026-09-11 03:23:40.435864+00`
- started `2026-09-11 03:23:40.452006+00`
- completed `2026-09-11 03:23:41.068235+00`
- `result_success=true`
- `result_exit_code=0`
- empty `error_kind`
- output SHA-256 `b159a1103fa6908ab6b9eb8b048569e1e08e78b6e710564f55079fbd0572925e`

Audit sequence 13-17 contains, in order:
1. `execution.job_authorized`
2. `execution.job_claimed`
3. `execution.job_started`
4. `ssh.certificate_issued`
5. `execution.job_completed` with decision `succeeded`.

Issued SSH certificate evidence includes:
- serial `2743784816575149100`
- CA fingerprint `SHA256:pIfrpoGeNiKBtZrqzhOaFdIQknQrPsmIP3NiysW7opI`
- target `10.169.2.214:22`
- ephemeral public-key fingerprint `SHA256:c3+0cwdLu/0KY+o7QB1atFeK72GKm3471i7lYh+dixY`.

Target evidence:
- sshd accepted `ED25519-CERT` from Worker `10.169.2.212`
- certificate ID bound job + grant + target
- CA fingerprint matched the isolated Signer CA
- session opened and closed normally
- root-only replay marker exists at `/var/lib/tethys-sentinel/executed/e27bc8b013c31670da2fa67294814bb9`.

This proves the full intended path on real infrastructure:
Gateway -> Control -> PostgreSQL authorization/job -> Worker claim/start -> Control current-authority revalidation -> Signer certificate -> pinned SSH negotiation -> target forced wrapper/replay consume -> direct command execution -> terminal PostgreSQL/audit completion.

## allow_once non-reuse PASS

Disposable target command `rm /tmp/sentinel-acceptance-delete-me` was classified as high-risk `FILESYSTEM_DELETE`, scope `argv-sha256:d60ae195eac9e520c07e8c1aece64b7c3f8fc66f45cfa1feb070c36b448ae4a2`.

First request `acceptance-delete-dev13-0001` returned `approval_required` with approval `2e8e148052890690352befedcfe8420b`; the file remained present before operator decision. Control decided that approval as `allow_once`.

Retrying the same request ID and identical argv created job `c3c1fad4270ec219afb3f605af84ab6a`, bound to that approval. PostgreSQL terminal result was `succeeded`, `result_success=true`, `result_exit_code=0`; target file was deleted and replay marker `/var/lib/tethys-sentinel/executed/c3c1fad4270ec219afb3f605af84ab6a` exists.

Submitting the identical command with new request ID `acceptance-delete-dev13-0002` did not reuse the consumed approval. It returned `approval_required` and created a distinct approval `ecc19afad1b5f5a55bc6664fde1bfe35`. This proves `allow_once` cannot authorize a second job even for the same grant/target/category/scope.

## Operational notes / documentation debt before merge

- Do not `source /etc/tethys-sentinel/service.env` for acceptance DB inspection. It is a systemd EnvironmentFile and the PostgreSQL DSN contains `&`; shell sourcing can corrupt/unset the DSN. Retrieve `SENTINEL_POSTGRES_DSN` silently from the running Control process environment or parse the EnvironmentFile with a non-shell parser.
- `PermitUserEnvironment no` must be global in Ubuntu/OpenSSH, not inside the target `Match` block; update `docs/INFRASTRUCTURE_ACCEPTANCE.md` accordingly.
- Synchronize Worker-egress docs with dev.12/dev.13 `policy_in: ACCEPT` behavior.
- Update stale documentation references that still call the harmless execution test a dev.11/dev.12 step.
- Empty successful-request journals on Worker/Signer are not treated as missing execution evidence: canonical Control audit recorded `ssh.certificate_issued`, and target sshd independently recorded accepted certificate authentication. Do not infer that Signer was not called solely from an empty journal.

## Current phase

`0.1.0-dev.13` is deployed across the complete acceptance runtime. Real harmless SSH execution and one-shot approval non-reuse have passed on the intended infrastructure. Worker external egress, Signer mTLS/CA, pinned host-key verification, target forced wrapper/replay, PostgreSQL transaction lifecycle, restart persistence, and durable one-shot approval consumption now have direct infrastructure evidence.

Do not merge to `main` yet. Remaining hard acceptance must prove active individual revoke, active global revoke + epoch non-revival, PostgreSQL-unavailable startup fail-closed, sensitive-material boundary, and final documentation consistency.

Authority is currently enabled at epoch 1 for the controlled dev.13 acceptance window. Use a fresh short-lived grant for each revocation scenario and close the window with revoke-all when appropriate.

## Next acceptance steps

1. Run individual active revoke with a fresh grant and `sleep 30`; wait until running, revoke that grant, verify Worker authority lease cancels SSH and job does not remain stuck.
2. Run global active revoke with another fresh grant and `sleep 30`; wait running, `REVOKE ALL`, verify epoch increments from 1, authority disables, running transport is canceled, old capability remains stale after re-enable.
3. Validate PostgreSQL-unavailable Control startup fails closed and never falls back to file persistence.
4. Recheck Worker contains no agent capabilities, admin token, PostgreSQL credentials, Signer credentials/CA signing material, target inventory, or PVE credentials; complete final IPv6 bypass check.
5. Correct acceptance documentation debts listed above.
6. Record final evidence in this handoff.
7. If all hard-boundary checks pass, perform the first WIP merge to `main` and review/update README/docs.
8. If a new runtime/code blocker appears, fix on this branch, bump the next dev version, repeat affected CI/infrastructure tests, then reassess merge.
9. Operator UI follows only after this acceptance/merge checkpoint.
10. When MCP is implemented, revisit and lock down the exact narrow tool surface for Qwen-class autonomous agents; never expose general backend/admin APIs.
