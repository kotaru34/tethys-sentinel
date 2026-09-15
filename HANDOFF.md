# Tethys Sentinel — Handoff

Updated: 2026-09-15
Current development version: `0.1.0-dev.16`
Branch: `wip/agent-http-cli` from accepted `main` base `a4b30f0b418359e6a14c0fc271b464919aa07c66`

Status: dev.15 Operator UI remains the accepted/deployed baseline. Dev.16 Agent HTTP API + `sentinelctl` is implemented and frozen for constrained infrastructure acceptance at runtime source `d9f688f5cd97bd932a4b9b99c243f0fb11361137`; CI `34920564170` passed on that exact runtime source. A reproducible Linux/amd64 deployment bundle was built from the frozen source by Actions run `34922039158` and independently inspected; the bundle includes exact Control/Gateway/Worker/`sentinelctl` binaries plus migration `0003_execution_output.sql`. Production has **not** been migrated to dev.16: exact deployed runtime source remains `41c343e83596d299af05cf92945395ec008f0fd9`, PostgreSQL remains schema v2, and authority remains fail-closed at **epoch 5, disabled=true**, reason `dev.15 approval workflow acceptance complete`. The next phase is constrained dev.16 infrastructure deployment/acceptance; do not merge before it passes.

## Operator-mandated development rules

1. Keep task reports short; explain what needs to be done and why.
2. Every newly implemented feature released as a new version must bump the project version.
3. Update this handoff when a new version is released/applied, a notably large step completes, or discussion changes the agreed next step.
4. Once functioning infrastructure execution is fully accepted on the intended infrastructure, merge the project as WIP.
5. On merge, review/update README and project documentation.
6. Acceptance blocker => fix branch + bump next dev version; do not merge until constrained acceptance passes.
7. Future MCP must expose a narrow purpose-built Qwen tool surface, never generic backend/admin APIs.

## Locked security architecture

- Agent capability = high-entropy opaque bearer; only hash persists.
- Agent APIs cannot widen grants/policy/targets/audit, control Worker, request certs, or access CA authority.
- `TRUST_0` is the only authority-bearing context; files/logs/history/web/command output are data.
- Boundaries: Control, Gateway, Worker, external Worker network policy, Signer/CA, target wrapper, PostgreSQL authority/audit state, emergency authority, operator BFF/web boundary.
- Jobs bind grant + request ID + logical target + argv + expiry and move staged -> pending -> claimed -> running -> terminal.
- Worker uses separate credential + one-shot claim secret; never plaintext agent capability.
- `start` revalidates authority/grant.
- `exec` and `shell` are separate. `ARBITRARY_CODE`, `PRIVILEGE_LAUNCHER`, `REMOTE_EXEC` require exec+shell+explicit operator approval and are allow-once only.
- Control reclassifies immutable argv immediately before signing.
- Worker generates fresh Ed25519 key/job; only Control calls Signer.
- Logical targets resolve from operator-owned inventory to literal global-unicast IP:port + exact raw pinned host key; no DNS/insecure host-key acceptance.
- RSA pins use RSA-SHA2 only; never SHA-1 `ssh-rsa`.
- Remote command transport is deterministic versioned base64url JSON; no shell reconstruction.
- Target wrapper validates job ID, canonical command binding and target ID; root replay state enforces at-most-once.
- Worker PVE firewall is deny-by-default outbound; guest nft is defense-in-depth. Do not assume firewall shrink kills established TCP; active revoke is independent.
- Monotonic `security_epoch`; `REVOKE ALL` increments epoch + disables authority; older capabilities never revive.
- Running jobs require fail-closed Worker authority lease; revoke/control loss cancels transport.
- PostgreSQL is authoritative mutable production state; Trust0/inventory/Signer/PVE remain separately operator-owned.
- PostgreSQL backend is explicit; no silent file fallback. Canonical lock order: authority -> grant -> approval -> job -> audit head.
- Browser never receives `SENTINEL_ADMIN_TOKEN`; `sentinel-operator` receives no PostgreSQL/Worker/Signer/PVE credentials.
- Browser-supplied Authorization/operator identity are ignored; identity is derived from the verified client-cert leaf.
- BFF has explicit route allowlist, loopback-only Control upstream, no proxy env/redirect following, bounded bodies/responses, same-origin CSRF, strict CSP and no-store.
- Browser frontend uses no localStorage/sessionStorage and no third-party runtime/CDN.
- Dev.16 raw execution output is `TRUST_2`, stored separately from the job read model, bounded to 256 KiB per stream and returned only when the exact grant has `history.include_output=true`.
- Dev.16 agent bearer clients must use verified HTTPS. First-party `sentinelctl` deliberately has no `--token`, no insecure TLS mode, no proxy-env routing and no redirect following.

## Accepted infrastructure baseline — dev.13

PVE `ai-server`, VLAN 1520 / `10.169.2.0/24`:

- Control VM 1310 — `10.169.2.210`
- Gateway VM 1320 — `10.169.2.211`
- Worker VM 1330 — `10.169.2.212`
- Signer VM 1340 — `10.169.2.213`
- Target-test VM 1350 — `10.169.2.214`
- PostgreSQL — `10.169.2.6:5432`, PostgreSQL 18.6, TLS verify-full, schema v2

Signer CA fingerprint: `SHA256:pIfrpoGeNiKBtZrqzhOaFdIQknQrPsmIP3NiysW7opI`.
Target host-key fingerprint: `SHA256:cfRNJVXjQWQhmNCnLaIQtMZIxYrZoJ7zWlWPU0HAmGM`.
Worker PVE policy: `policy_in: ACCEPT`, `policy_out: DROP`, runtime egress only to Control `10.169.2.210:9091/tcp` and target `10.169.2.214:22/tcp`.

Accepted dev.13 runtime hashes:

- control `3c1fd0b317ee43d7ee4e1bee1173f1daa3cd9681f152165bdd1a6844ca253ad7`
- egress `ff2a23a60460c55420f580dd5f71a6a742bed8847faedc54b6de0ac079568cb6`
- gateway `89078f3173029fcd4c809e25ef3c9a7f4aacf7381356ac41b8294276667ba3c3`
- signer `06805994530b497247525a6fd061e7a65d80a96cac02b0f6c04749eba0c32feb`
- worker `f7a49c35b04ba832480cc7a36c8b54964d69593553fad1066c5f5036c4a042f6`
- consume `4ff50ff3c8b8db429efb952e2a8a418d1e16dae22cfd9174a4ac371adc2ef140`
- exec `7ce5909e362cc937d992cc5f4b8bbae8e19e7f92d0aaf5672dd5ae59190dd0c4`

PR #1 merged the accepted core to `main` at `478009b1310b782db7dc20c629bada475c3f3d63`.

## Operator UI implementation / merge checkpoints

- UI contract: `docs/OPERATOR_UI.md`
- backend/BFF checkpoint: `f5d37bec113c35efebc72ecc639e275f50161a10`, Actions `34892851385`
- complete eight-page UI: `aaedad5518ad296426b01af856373672a1847f2d`, Actions `34898343292`
- dev.14 RC: `15513074c4ae30edbbd74b7c676562d2fb5c0e77`, Actions `34900078873`
- dev.15 deployment-boundary/runtime source: `41c343e83596d299af05cf92945395ec008f0fd9`, Actions `34903375824` PASS
- README dev.15 acceptance sync: `32328c49c1a37463aa08af4940031f2ab30b3b8c`
- deployment-guide isolated-root sync: `62ec7d53f60ba596d00c26737b193fbf230bf572`
- documentation-complete WIP head: `6aaf813e87f8ed84ae062b7d5dcc95b73bdff986`
- final push CI: Actions `34910290003` PASS
- PR #2 CI: Actions `34910423543` PASS
- PR #2 merge commit: `0cbe1e4dbb2d7beb0feb751ca1e42872064578ea`
- post-merge `main` CI: Actions `34910609193` PASS
- embedded frontend archive SHA-256 `9ae64c375e26d76d101cbdfe3db916296ff39237a5fc67bef4bf7aff99cef711`
- accepted dev.15 CI pins Node `24.20.0`, npm `11.19.0`, historical resolved package-lock graph SHA-256 `9521cb1e1dab401e0ca9d81653adfd82d1459fe725ebaa5b26a663eff7f5ba95`

## dev.15 deployed operator boundary

Acceptance found the dev.14 blocker that `/etc/tethys-sentinel` is correctly `0750 root:sentinel-control`. The fix is a separate `/etc/tethys-sentinel-operator` root; Control permissions were not weakened.

- `/etc/tethys-sentinel` remains inaccessible to `tethys-operator`.
- `/etc/tethys-sentinel-operator` is `0750 root:tethys-operator`.
- admin token and server key are `0400 tethys-operator:tethys-operator`.
- public server cert/client CA/env are root-owned and group-readable.
- `sentinel-operator.service` uses `/etc/tethys-sentinel-operator/operator.env`.

Dedicated Operator TLS PKI fingerprints:

- CA `07:BA:71:23:DB:7A:4A:1D:B1:02:F5:A4:6E:36:EA:6A:BF:89:1A:8D:F8:31:4B:02:B6:C8:10:1B:43:F6:F5:C4`
- server `CE:A9:15:CC:E1:B8:9F:2C:67:7B:CC:84:88:FB:5E:54:4D:B5:FF:F8:D8:4B:0F:F1:1B:38:F6:8F:F3:8E:5C:B3`
- client `3A:69:61:86:70:6E:DF:71:0D:9D:AC:52:72:84:6E:5C:CC:05:B9:51:47:E3:52:8E:3E:98:A3:DA:11:C9:AF:1C`

CA/client private material was removed from Control after verified Windows import.

Exact deployed dev.15 binaries:

- `sentinel-operator`: `ea50c402b93d39e592f18106b3340b8615ede04e94e9957eb2f27abde236956c`
- `sentinel-control`: `b1c3b648305a1992b442f9b01980f0fa3556adb1e62bfe63e7c252ecb4397dc6`
- Gateway remains accepted dev.13: `89078f3173029fcd4c809e25ef3c9a7f4aacf7381356ac41b8294276667ba3c3`

Control listeners: `127.0.0.1:8081` admin + `10.169.2.210:9091` internal. Operator UI: `10.169.2.210:8444` mTLS. Gateway: `10.169.2.211:8443` with public CA validation. `sentinel-operator.service` is enabled at boot after successful acceptance.

## dev.15 acceptance evidence

### mTLS/browser

- no client cert => TLS 1.3 `certificate required`, curl exit 56;
- trusted Windows client cert => HTTP 200 without insecure bypass;
- security headers: self-only CSP, HSTS 31536000, nosniff, no-referrer, restrictive Permissions-Policy.

### Credential/process boundary

- `sentinel-operator` runs as `tethys-operator:tethys-operator`;
- no PostgreSQL/Worker/Signer/PVE/admin bearer secret in its process environment;
- Control config root remains inaccessible;
- upstream exactly `http://127.0.0.1:8081`.

### Read-only UI/API

- Overview, Grants, Approvals, Jobs, Audit, Targets, Context and emergency state work through mTLS BFF;
- Trust0 top-level fields: `version, trust_level, policy, instructions, hosts, runbooks`.

### Security negatives

- session identity exactly cert-derived `cert-sha256:3a696186706edf710d9dac5272846e5ccc05b95147e3528e3e98a3da11c9af1c`;
- spoofed browser Authorization/identity ignored;
- missing/mismatched CSRF, wrong Origin and cross-site Sec-Fetch-Site => HTTP 403;
- valid CSRF + intentionally invalid ID => safe HTTP 400 before mutation;
- unknown API route => 404; no generic proxy;
- authority unchanged during negative tests.

### Grant/emergency mutation acceptance

- controlled enable at epoch 3 succeeded with operator-client identity propagated to audit;
- test grant ID `e3c5bc4e39c31f81bc5cdf770ef49e9f`, agent `operator-ui-acceptance`;
- grant issued at security epoch 3 and revoked successfully;
- plaintext capability appeared only in immediate one-time reveal and did not return after dismiss/refresh;
- browser localStorage/sessionStorage remained empty;
- audit events `emergency.enable_requested`, `emergency.enabled`, `grant.issued`, `grant.revoked`, `emergency.revoke_all` used cert-derived actor `operator:cert-sha256:3a696186706edf710d9dac5272846e5ccc05b95147e3528e3e98a3da11c9af1c`;
- final revoke advanced authority to epoch 4, disabled=true.

### Approval workflow acceptance

Epoch 4 was enabled only for this controlled acceptance window using grant agent `operator-ui-approval-acceptance`.

- `FILESYSTEM_DELETE` request `allowonce-f130ae61d6bd8187` created approval `75a37ca3b0f57862e3117630740d657a`; UI correctly offered Deny / Allow once / Allow this session.
- Operator chose `allow_once`; resubmitting the same immutable request returned HTTP 200, `accepted=true`, decision `accepted`, approval binding unchanged, and job `acc11c099b7a2cf09b519255beccc459`.
- The approval read model later showed that record as `status=consumed`, `decision=allow_once`; the job completed successfully with `status=succeeded`, exit code 0.
- A new request ID with the same scope, `allowonce-reuse-7ba509bdde64650c`, did **not** reuse the consumed allow-once decision; it returned `approval_required` with new approval `5bbc64acd76077bac8c22797e53da013`.
- That new approval was subsequently denied while authority remained disabled; final readback showed `status=decided`, `decision=deny`, cert-derived decision actor.
- `ARBITRARY_CODE` request `powerful-b6ed2a2888ba4c08` created approval `74152333bd78c150ba6eaf28ddb85f53`; UI correctly showed one-shot-only policy and did **not** offer session approval.
- Operator denied the powerful request; resubmission returned HTTP 200 with `accepted=false`, decision `deny`, and no job receipt.
- `session_approval_allowed=false` was confirmed for the powerful request, while `FILESYSTEM_DELETE` correctly reported it as true.
- Gateway capability material was kept only in a `0600` temporary cache during retry and then removed.
- Final `REVOKE ALL` completed with reason `dev.15 approval workflow acceptance complete`, advancing authority from epoch 4 to **epoch 5, disabled=true**.
- Audit showed cert-derived operator actors for approval decisions/emergency transitions and the expected agent/worker actors for request, authorization, claim/start/certificate/completion events.

Epochs 0/1/2/3/4 capabilities are permanently stale after the epoch-5 revoke. Do not enable authority casually.

## dev.16 Agent HTTP API + `sentinelctl` WIP checkpoint

The canonical agent integration is now the capability-scoped HTTPS API. `curl` is the raw/reference interface and first-party Go `sentinelctl` is the supported convenient CLI. Do not add parallel convenience protocols in this milestone. MCP comes later as a thin purpose-built adapter over the accepted HTTP contract with a deliberately narrow Qwen tool surface.

Implemented dev.16 surface:

- Gateway `GET /v1/jobs/{id}` and `GET /v1/requests/{request_id}` with exact capability/grant isolation;
- public bootstrap advertises job/request resource templates;
- command submission accepts optional `timeout_seconds`, defaulting to the existing TTL and capped at 900 seconds/grant expiry;
- request IDs remain immutable idempotency keys; disconnect recovery does not permit rebinding target/argv;
- `sentinelctl bootstrap`, `exec`, `exec --wait`, `job get`, `job wait`, `request get`, `--json`;
- generated request IDs when omitted;
- `exec --wait` survives `approval_required` by retrying the exact same immutable request, then polls the authorized job to terminal state;
- CLI capability comes from `SENTINEL_CAP` or a protected cap file; there is intentionally no `--token` argv option;
- first-party client requires HTTPS, verifies TLS, ignores proxy environment routing and refuses redirects/insecure convenience modes;
- Worker captures bounded stdout/stderr prefixes independently at max 256 KiB per stream while preserving the larger existing output-accounting/abort limit;
- output is a separate persistence object rather than a field in the general job store/Operator UI read model;
- output readback is gated by `grant.History.IncludeOutput`; without it the output backend is not consulted at all;
- JSON uses explicit `stdout_b64` / `stderr_b64` names because arbitrary bytes are base64-encoded;
- human CLI rendering decodes captured bytes but visibly escapes invalid UTF-8, terminal control sequences and Unicode format/control characters;
- file-mode output persistence requires a regular non-symlink private store and writes mode `0600`;
- PostgreSQL schema v3 adds one-to-one `sentinel.execution_job_output` with independent 256 KiB bytea constraints and only SELECT/INSERT/UPDATE for `sentinel_control`;
- PostgreSQL terminal job state + bounded output + completion audit commit in one transaction; raw output itself is not copied into audit.

Key dev.16 checkpoints:

- branch base: `a4b30f0b418359e6a14c0fc271b464919aa07c66` (`main`);
- first job/readback + CLI slice passed full Go race tests before output persistence work;
- output-store/Worker/PostgreSQL hardening checkpoint `69c1de20e3fdf7b81dcbc7524dafff5f43acffed`, Actions `34918635619` PASS;
- human-safe CLI output and explicit permission-boundary tests added after that checkpoint;
- PostgreSQL 15/18 runs on `e514d270821f7e35b7d524508395d4c15093cbee` both PASS, as did Go race tests; that CI run failed only in the independent frontend dependency-graph guard;
- frontend drift diagnostic proved the reviewed graph change was only transitive `electron-to-chromium` `1.5.427 -> 1.5.428`; dev.16 reviewed graph SHA-256 is `9b6d418cebaaed94c674ea66429e7d1c9e4f92f269eb53f2bea666109373b964`;
- embedded Operator frontend archive remains pinned to SHA-256 `9ae64c375e26d76d101cbdfe3db916296ff39237a5fc67bef4bf7aff99cef711`; final frontend build/parity guard passed unchanged;
- documentation-complete pre-acceptance checkpoint `6ff46102e10d86cbcc3035f4a2232a9f548321dc`, Actions `34920370513` PASS across Go race/vet/tidy/format, PostgreSQL 15, PostgreSQL 18 and full frontend/embed checks;
- frozen runtime source `d9f688f5cd97bd932a4b9b99c243f0fb11361137`, Actions `34920564170` PASS;
- reproducible bundle workflow final commit `5b4576860489fca9c5dde6e315d0bd8f3ae49d4a`; normal CI `34922039066` PASS and artifact Actions run `34922039158` PASS;
- artifact ID `10378691542`, name `tethys-sentinel-dev16-linux-amd64-d9f688f5`, retention through 2026-09-22;
- deterministic tarball SHA-256 `4336026365683215191520650157d4480f23d36d7ba6f2caa685b772e83424a6`;
- frozen bundle manifest:
  - `sentinel-control` `d9708e74b9e05124d2bd1304ee1736faf1e58b0e72fe8b0d1956337697ab1db2`;
  - `sentinel-gateway` `a1971546ebe36ddfa07f88c07d48139f013fdc749a931e52547cc3ab37aa5fcb`;
  - `sentinel-worker` `014f0f22be23724cbd3de5a534323831acb5abfcfcd3a55749b42a31101ea9dd`;
  - `sentinelctl` `a2c67c056f5801f9719ead0d22d354f7bc5fc15ee860d0e452fdfe4c9a28d28f`;
  - `db/migrations/0003_execution_output.sql` `813668ee447ba0c9767c6cab22535b28be6fbd8fa2e7062ffa9dc0d9650dbb99`;
- the bundle was independently downloaded and verified: outer checksum PASS, all five manifest entries PASS, BUILDINFO source SHA exact, and all four Go binaries report `go1.27.1`, exact VCS revision `d9f688...`, `vcs.modified=false`;
- API/CLI contract: `docs/AGENT_HTTP_CLI.md`;
- acceptance delta/rollback procedure: `docs/AGENT_HTTP_CLI_ACCEPTANCE.md`;
- schema-v3 development docs: `db/README.md`, `docs/POSTGRESQL_PERSISTENCE.md`;
- README distinguishes dev.16 candidate state from the still-deployed dev.15/schema-v2 baseline.

The dev.16 candidate must not be merged merely because CI passes. It materially touches Control/Gateway/Worker/result persistence and therefore requires constrained real-infrastructure acceptance.

## Current phase / next steps

1. Obtain the verified `tethys-sentinel-dev16-linux-amd64-d9f688f5` artifact from Actions run `34922039158` and verify outer tar SHA-256 `4336026365683215191520650157d4480f23d36d7ba6f2caa685b772e83424a6` plus internal `SHA256SUMS` before deployment. No separate build host is required.
2. Keep production authority at epoch 5 disabled during deployment preparation.
3. Stop Worker -> Gateway -> Operator -> Control, create both the quiescent schema-v2 rollback clone and custom `pg_dump`, and save accepted rollback binaries before touching schema/runtime.
4. Apply the bundled reviewed `db/migrations/0003_execution_output.sql` while authority remains disabled, verify schema v3/privileges/epoch 5 disabled, then install exact bundled dev.16 Control, Gateway and Worker binaries. Signer/target wrappers/PVE policy remain unchanged unless evidence requires otherwise.
5. Start Control -> Operator -> Gateway while disabled, verify UI/listeners/health, then start Worker and recheck the hard egress boundary.
6. Prove both raw `curl` and `sentinelctl` against the real Gateway with CA verification: bootstrap, submit, job polling, request-ID recovery and terminal result.
7. Use narrowly scoped acceptance grants to prove output hidden with `include_output=false`, visible with `include_output=true`, human terminal sanitization, JSON base64 contract, and one real `exec --wait` end-to-end execution.
8. Recheck Operator UI after the Control/schema upgrade to ensure raw output did not leak into its job read model.
9. Finish with grant revoke + global `REVOKE ALL`; accepted authority must again be disabled. If this acceptance window begins by enabling epoch 5, the final revoke should advance to epoch 6.
10. Any acceptance blocker => fix on branch, bump next development version to dev.17, and repeat relevant acceptance; do not merge dev.16.
11. Once dev.16 passes constrained acceptance, update README/HANDOFF with exact deployed hashes/evidence, open WIP PR, run PR CI and merge.
12. Only after HTTP API + `sentinelctl` are accepted/merged should the MCP adapter milestone begin; at that point revisit and lock the exact narrow tool surface for Qwen-class autonomous agents.
