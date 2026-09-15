# Tethys Sentinel — Handoff

Updated: 2026-09-16
Current development version: `0.1.0-dev.18`
Branch: `wip/mcp-adapter`

Status: `0.1.0-dev.17` remains the deployed and accepted runtime and is merged to `main` via PR #3. PostgreSQL remains schema v3 and `sentinel-operator` remains the accepted `0.1.0-dev.15` binary. Production authority is deliberately fail-closed at **security epoch 7, disabled=true**, reason `dev.17 Agent HTTP CLI acceptance complete`. The dev.18 narrow Qwen-facing MCP adapter is implemented on `wip/mcp-adapter`; branch CI and its frozen reproducible MCP artifact build are green. It is **not deployed or live-accepted yet**. The next gate is constrained MCP acceptance before merge/deployment.

## Operator-mandated development rules

1. Keep task reports short; explain what needs to be done and why.
2. Every newly implemented feature released as a new version must bump the project version.
3. Update this handoff when a new version is released/applied, a notably large step completes, or discussion changes the agreed next step.
4. Once functioning infrastructure execution is fully accepted on the intended infrastructure, merge the project as WIP.
5. On merge, review/update README and project documentation.
6. Acceptance blocker => fix branch + bump next dev version; do not merge until constrained acceptance passes.
7. MCP must expose a narrow purpose-built Qwen tool surface, never generic backend/admin APIs.

## Locked security architecture

- Agent capability is a high-entropy opaque bearer; only its hash persists.
- Agent APIs cannot widen grants/policy/targets/audit, control Worker, request certificates, access CA authority or mutate `TRUST_0`.
- `TRUST_0` is the only authority-bearing context. Files, logs, command output, web content and history are data only.
- Execution jobs bind grant + request ID + logical target + argv + expiry and use staged -> pending -> claimed -> running -> terminal transitions.
- Worker uses its own credential and one-shot claim secret; it never receives plaintext agent capabilities.
- `start` revalidates grant and authority. Running jobs require a fail-closed authority lease.
- `exec` and `shell` remain separate. Powerful categories require exec+shell+explicit operator approval and are allow-once only.
- Control reclassifies immutable argv before signing.
- Worker generates a fresh Ed25519 key per job; only Control may call Signer.
- Logical targets resolve only through operator-owned inventory to literal global-unicast IP:port plus an exact pinned raw host key; no DNS or insecure host-key bypass.
- Remote command transport is deterministic structured argv; Sentinel does not reconstruct commands through a shell.
- Target wrapper validates binding/target and enforces at-most-once consumption.
- Worker PVE egress is deny-by-default; guest firewalling is defense-in-depth.
- `REVOKE ALL` monotonically advances `security_epoch` and disables authority; older capabilities never revive.
- PostgreSQL is the authoritative mutable production state. There is no silent file fallback.
- Security-sensitive PostgreSQL transitions remain transactional; canonical lock order is authority -> grant -> approval -> job -> audit head.
- Browser never receives Control admin bearer authority. `sentinel-operator` has no PostgreSQL/Worker/Signer/PVE credentials.
- Operator identity derives from the verified client-certificate leaf; browser-supplied Authorization/identity is ignored.
- Operator BFF has an explicit route allowlist, loopback Control upstream, strict CSRF/origin/CSP/no-store boundaries and no generic proxy.
- Agent execution output is `TRUST_2`, persisted separately from the job read model, bounded to 256 KiB per stream and returned only when the exact grant has `history.include_output=true`.
- Agent bearer clients require verified HTTPS. `sentinelctl` deliberately has no `--token`, no insecure TLS mode, no proxy-environment routing and no redirect following.

## Accepted topology

PVE `ai-server`, VLAN 1520 / `10.169.2.0/24`:

- Control VM 1310 — `10.169.2.210`
- Gateway VM 1320 — `10.169.2.211`
- Worker VM 1330 — `10.169.2.212`
- Signer VM 1340 — `10.169.2.213`
- Target-test VM 1350 — `10.169.2.214`
- PostgreSQL — `10.169.2.6:5432`, PostgreSQL 18.6, TLS verify-full, schema v3

Signer CA fingerprint: `SHA256:pIfrpoGeNiKBtZrqzhOaFdIQknQrPsmIP3NiysW7opI`.
Target host-key fingerprint: `SHA256:cfRNJVXjQWQhmNCnLaIQtMZIxYrZoJ7zWlWPU0HAmGM`.
Worker PVE policy remains `policy_in=ACCEPT`, `policy_out=DROP`, with outbound runtime access only to Control `10.169.2.210:9091/tcp` and target-test `10.169.2.214:22/tcp`.

## Accepted/deployed runtime

Frozen dev.17 runtime source:

`4728a86abc49bf2a686c588a3878288a36f44f7d`

CI on that source: Actions `35000514153` PASS. The artifact workflow commit is `d32145acab45139123b4996e1fc5b0a93b0979de`; normal CI Actions `35000746655` PASS and reproducible artifact Actions `35000746762` PASS. Artifact ID `10409765901`, name `tethys-sentinel-dev17-linux-amd64-4728a86a`.

Deployed hashes:

- `sentinel-control` dev.17: `89a66f2f905dabcc804a858c7fdfc5ebf3ad38ec9e425acf8fc4eeab748c9f0e`
- `sentinel-gateway` dev.17: `53f6952a6a10854008486dc57ea23fcbdc3852b2cfb44ee75b799feecbad9bde`
- `sentinel-worker` dev.17: `4874c0a0ae034d1b928dcaf06da72f2761c918f6255d68fb5af17ef2867e2317`
- `sentinelctl` dev.17: `0df406f08f3ddd8388e6cfb5e0be33a50a7cec9195b5152f431a5f566b983bc5`
- `sentinel-operator` remains accepted dev.15: `ea50c402b93d39e592f18106b3340b8615ede04e94e9957eb2f27abde236956c`

The deterministic dev.17 tarball used for deployment had SHA-256 `d9ed43c237b85046a3c6913354154354cff75aa36201d4b95078aa9bcae0c058`.

Preserved local rollback binaries include the exact dev.16 Control/Gateway/Worker binaries:

- Control dev.16 `d9708e74b9e05124d2bd1304ee1736faf1e58b0e72fe8b0d1956337697ab1db2`
- Gateway dev.16 `a1971546ebe36ddfa07f88c07d48139f013fdc749a931e52547cc3ab37aa5fcb`
- Worker dev.16 `014f0f22be23724cbd3de5a534323831acb5abfcfcd3a55749b42a31101ea9dd`

The original pre-schema-v3 rollback dump remains `/var/backups/tethys-sentinel/pre-dev16-schema-v2-20260915_160623.dump`, SHA-256 `6cdd756ae979753695becc9627b095f7a1cd35ed79bd8774ec198c6076416cf4`. A sealed same-cluster pre-dev16 clone also exists; its exact name is recorded on the database host rather than duplicated here.

## Agent HTTP API + `sentinelctl`

Canonical agent integration is the capability-scoped HTTPS Gateway API. `curl` is the raw/reference client and `sentinelctl` is the first-party convenience client. MCP wraps this accepted contract rather than creating another authority model.

Accepted surface includes:

- `GET /v1/bootstrap`
- `POST /v1/commands/submit`
- `GET /v1/jobs/{id}`
- `GET /v1/requests/{request_id}`
- optional per-command timeout, default 30 seconds, explicit 1..900 seconds and clamped to grant expiry
- idempotent immutable request IDs
- `sentinelctl bootstrap`, `exec`, `exec --wait`, `job get`, `job wait`, `request get`, `--json`
- approval-aware `exec --wait` that retries the same immutable request ID
- bounded stdout/stderr capture, separately persisted and permission-gated
- byte-exact JSON base64 fields and safe human terminal rendering

Contract: `docs/AGENT_HTTP_CLI.md`.

## dev.16 acceptance blocker and dev.17 fix

The initial dev.16 live acceptance found job `732318c707a961fa3061e0fb55ccac03` stuck in `running` after a harmless stdout-only `printf`. Worker logged `execution job completion rejected with status 409`.

Root cause: one-sided captured output could carry a nil `[]byte` for the empty stream; the PostgreSQL driver represented it as SQL `NULL`, while `sentinel.execution_job_output.stdout/stderr` are `NOT NULL`. The completion transaction rolled back, leaving the job running.

dev.17 fixes this by normalizing one-sided output to zero-length `bytea` and adds PostgreSQL regression coverage for stdout-only and stderr-only completion. It also reaps expired `pending`, `claimed` and `running` jobs during Worker claim processing so a failed terminalization cannot remain permanently running.

## dev.17 real-infrastructure acceptance evidence

All acceptance was performed against the topology above with no insecure TLS bypass and with authority deliberately constrained.

- PostgreSQL remained schema v3 after the dev.17 binary-only redeploy.
- Control/Gateway/Worker started as `0.1.0-dev.17`; Operator remained `0.1.0-dev.15`.
- Authority began epoch 6 disabled after the dev.16 blocker closure.
- On controlled epoch-6 enable, the old dev.16 stuck job automatically transitioned `running -> expired`, set `completed_at`, `result_success=false`, `result_exit_code=-1`, `error_kind=job_expired`, and cleared the claim hash without creating an output row.
- stdout-only job `6270561830345b37b41948b4c90b840f` completed `succeeded`, exit 0. PostgreSQL stored `stdout_bytes=18`, `stderr_bytes=0`, both non-truncated. This directly proves the original NULL/409 defect is fixed.
- A grant with `history.include_output=false` could read status/result but received no `output`, `stdout_b64` or `stderr_b64` fields.
- Output-enabled job `057b1288b8d76062ff29bddf5d4c6838` returned `dev17-visible` in human mode and exact base64 `ZGV2MTctdmlzaWJsZQo=` in JSON mode.
- ANSI test job `ce3ddba7c4473d697173dc76312373f1` rendered escape bytes visibly as `\x1b[31mRED\x1b[0m`; the terminal sequence was not executed.
- stderr-only job `d2dad44b89fbc530765f044c0a0c0234` completed as a normal remote failure with exit 2, `error_kind=remote_exit_nonzero`, `stderr_b64` present and stdout absent.
- `sentinelctl exec --wait` on `FILESYSTEM_DELETE` request `dev17-allowonce-bcd53b541465740f` waited for approval `d82905fb1484ed5a6a32bdf66c404539`, reused the same request ID after `allow_once`, and completed job `19b00dcaa048774266e5982f74517ea6` successfully.
- A fresh request for the same delete scope returned a fresh approval `a687d0337939978c769a69fc82748fbe`, proving allow-once non-reuse. The later global revoke made all epoch-6 authority stale regardless of any remaining undecided record.
- Operator Jobs screenshots confirmed the read model exposes exact argv, lifecycle, result and output SHA-256 only; raw stdout/stderr/base64 content did not appear, including for the visible-output, ANSI and stderr-only jobs.
- Capability files were removed from the acceptance client.
- Final global `REVOKE ALL` reason `dev.17 Agent HTTP CLI acceptance complete` advanced authority to **epoch 7, disabled=true**. Every epoch-6 capability is permanently stale.

This closes the Agent HTTP/CLI constrained acceptance. No dev.17 runtime acceptance blocker remains.

## Merge checkpoint

- PR #3 `WIP: Agent HTTP API + sentinelctl accepted as dev.17` passed PR CI Actions `35007376760` across Go test/vet/tidy/format, PostgreSQL 15, PostgreSQL 18 and Operator frontend checks.
- The final pre-merge frontend graph drift was reviewed before changing the guard: only `baseline-browser-mapping` `2.11.23 -> 2.11.24` and `electron-to-chromium` `1.5.428 -> 1.5.429` changed. The reviewed graph SHA-256 is `7a60e35fc4ab70216dd4b7c2073d545f78c7f9f7ea2aabdf20b95e2a6a4981d2`.
- The frontend job then rebuilt/typechecked successfully and verified the generated Operator UI remained byte-for-byte identical to embedded archive SHA-256 `9ae64c375e26d76d101cbdfe3db916296ff39237a5fc67bef4bf7aff99cef711`.
- PR #3 merged to `main` at `a8a3a31452739620a6f56817b933320f30b38919`.
- Post-merge `main` CI Actions `35007585656` passed all four jobs, including PostgreSQL 15/18 and frontend embed parity.
- The deployed runtime remains the frozen source `4728a86abc49bf2a686c588a3878288a36f44f7d`; later CI/docs commits are not runtime-source changes.

## dev.18 MCP adapter implementation checkpoint

The Qwen-facing v1 contract is implemented in `cmd/sentinel-mcp` + `internal/mcpadapter` and documented in `docs/MCP_ADAPTER_DESIGN.md`.

- Model-facing tools: `sentinel.exec`, `sentinel.exec_batch`, conditional `sentinel.code`, `sentinel.check`, `sentinel.output`.
- Inputs are deliberately small: `exec(target, argv, timeout_seconds?)`, `exec_batch(target, commands, parallel?)`, `code(target, source, timeout_seconds?)`, `check(id)`, `output(id, step?, query?)`.
- Results expose the MCP operation `id`, compact status, and only when applicable job ID, exit code and bounded stdout/stderr. Request/approval/grant IDs, risk metadata, epochs, hashes and backend HTTP mechanics are not normal model-facing state.
- `exec` and every `exec_batch` child run the shared Sentinel classifier locally and fail closed for all classes where `risk.RequiresShell(...)` is true. This blocks known shell/interpreter, remote-exec and privilege-launcher escape routes without maintaining a second classifier in MCP.
- `code` is Python-only, implemented as adapter-owned `python3 -c <source>`, registered only when the capability has backend `shell` authority, and asserts that the shared classifier still categorizes the carrier as requiring that authority. Backend approval semantics remain authoritative.
- A versioned 0600 durable operation journal records the complete operation and all immutable request IDs before any submit, using temp write + fsync + atomic rename + directory fsync. Records bind to the exact Sentinel bootstrap session/grant ID.
- `check(id)` rejects cross-session operation IDs, revalidates the stored operation against the MCP structured/code boundary, resubmits the same immutable request ID(s), then reconciles jobs from Sentinel.
- `output(id, step?, query?)` is strictly read-only and also revalidates the stored operation before resolving its request.
- Model output is escaped before bounding: 8 KiB/stream for exec/code, 2 KiB/stream/step for batch, 12 KiB total for explicit output; deeper reads use head+tail or literal query context. ANSI/control/format/invalid-UTF-8 bytes cannot survive as active control sequences.
- Official Go MCP SDK `v1.8.0`; stdio transport input frame cap is explicitly 1 MiB. Stdout is reserved for protocol traffic.
- Initial regression tests cover journal durability/session binding, output escaping/bounds, immutable request reuse through approval, complete batch journaling before first submit, structured-exec escape rejection, code carrier classification, cross-session recovery rejection, tampered journal revalidation and read-only output inspection.
- The journal deliberately does **not** content-deduplicate a completely lost MCP response followed by a brand-new identical tool call. Recovery requires the original model-facing `id`.
- Frozen dev.18 MCP runtime source is `6723380e3bc469d45d94ced1d6d96fc4b786eed9` (implementation commit `355e8440f845dfe59e73c6f57c95ea88667d4e1a` plus module-tidy follow-up).
- Branch CI Actions `35025729363` passed module tidy, format, `go vet`, `go test -race ./...`, PostgreSQL 15, PostgreSQL 18 and Operator frontend/embed parity. After adding the artifact workflow, full branch CI Actions `35032534729` also passed.
- Reproducible MCP-only artifact workflow commit `6178aa5db317c1a1537f2343e15157f98104b9e9`; artifact Actions `35032534792` PASS. The workflow checks out the frozen source SHA, builds `sentinel-mcp` twice with Go 1.27.1 / `CGO_ENABLED=0` / `-trimpath -buildvcs=true`, requires byte-identical binaries and clean embedded VCS metadata, then creates a deterministic tarball.
- Artifact ID `10421722605`, name `tethys-sentinel-mcp-dev18-linux-amd64-6723380e`, uploaded artifact ZIP digest `sha256:46e6069d9afaa93210821aaa2204a787f9f5c85db98109f201b8ecabb898e9a0`.
- Deterministic MCP tarball `tethys-sentinel-mcp-0.1.0-dev.18-linux-amd64-6723380e.tar.gz` SHA-256: `afa53ab0f89fad9c1079e12ab885849764010ee6ac7d797b590a4e88fed91ce3`.
- `sentinel-mcp` binary SHA-256: `08a6c1a64db097fb87e00fcc9789433582102f0b17f85253f654f34309070c50`.
- dev.18 has not yet been deployed or live-accepted. Production authority remains epoch 7 disabled.

## Previous accepted milestones

- Core execution/security baseline merged as PR #1 at `478009b1310b782db7dc20c629bada475c3f3d63`.
- Operator UI dev.15 passed browser mTLS, cert-derived identity, credential separation, read-only views, CSRF/origin/spoofing negatives, grant/emergency mutation and approval semantics. PR #2 merged at `0cbe1e4dbb2d7beb0feb751ca1e42872064578ea`.
- Operator configuration remains isolated under `/etc/tethys-sentinel-operator`; `/etc/tethys-sentinel` remains the Control boundary.

## Current phase / next step

1. Keep production authority at epoch 7 disabled unless an explicit operator task requires a new constrained window.
2. dev.18 code CI and frozen reproducible MCP artifact are green (`35032534729` and `35032534792` respectively); do not merge solely on CI because the MCP behavior has not yet been accepted against the intended infrastructure.
3. Perform constrained MCP acceptance with a fresh short-lived capability: harmless structured exec, batch sequential/parallel, approval wait + `check(id)`, output bounds/escaping/query, structured-exec escape negatives, code conditional exposure/approval, restart recovery and cross-session old-ID rejection.
4. On successful acceptance, globally revoke/disable authority again, record evidence, review README/docs, then merge the WIP branch. Any acceptance blocker requires the next dev bump rather than merging dev.18.
5. Grow the model-facing surface only from observed Qwen pain; keep arbitrary `code` exceptional.
