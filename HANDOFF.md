# Tethys Sentinel — Handoff

Updated: 2026-09-15
Current development version: `0.1.0-dev.15`
Branch: `wip/operator-ui`

Status: the dev.13 execution/security core remains the accepted baseline. Operator UI code is `0.1.0-dev.15`. Exact deployed runtime source checkpoint is `41c343e83596d299af05cf92945395ec008f0fd9`, CI Actions `34903375824` PASS. Real mTLS deployment, Control/BFF integration, read-only UI acceptance, credential-boundary acceptance, CSRF/origin/spoofing negatives, and grant issue/reveal/revoke plus emergency enable/revoke-all now pass. Authority is currently fail-closed at epoch 4. Approval workflow acceptance and final documentation/merge remain pending.

## Operator-mandated development rules

1. Keep task reports short; explain what needs to be done and why.
2. Every newly implemented feature released as a new version must bump the project version.
3. Update this handoff when a new version is released/applied, a notably large step completes, or discussion changes the agreed next step.
4. Once functioning infrastructure execution is fully accepted on the intended infrastructure, merge the project as WIP.
5. On merge, review/update README and project documentation.
6. Acceptance blocker => fix branch + bump next dev version; do not merge until constrained acceptance passes.
7. Future MCP must expose a narrow purpose-built Qwen tool surface, never generic backend/admin APIs.

## Locked security architecture

- Agent capabilities are opaque high-entropy bearer secrets; only hashes persist.
- Agent APIs cannot widen grants, policy, targets, audit, Worker, SSH certificate, or CA authority.
- `TRUST_0` is the only authority-bearing context; files/logs/history/web/command output are data.
- Main boundaries: Control, Gateway, Worker, external Worker network policy, Signer/CA, target wrapper, PostgreSQL authority/audit state, emergency authority, operator BFF/web boundary.
- Jobs bind grant + request ID + logical target + argv + expiry and move staged -> pending -> claimed -> running -> terminal.
- Worker uses separate credential + one-shot claim secret; never plaintext agent capability.
- `start` revalidates authority/grant.
- `exec` and `shell` are separate. Powerful classes require exec+shell+explicit operator approval and are `allow_once` only.
- Control reclassifies immutable argv before signing. Worker generates fresh Ed25519 key/job; only Control calls Signer.
- Targets are operator-owned logical IDs resolving to literal global-unicast IP:port + exact raw pinned host key; no DNS/insecure host-key acceptance.
- RSA pins use RSA-SHA2 only; no SHA-1 `ssh-rsa` fallback.
- Remote command transport is deterministic versioned base64url JSON; no shell reconstruction.
- Target wrapper validates job ID, canonical command binding and target ID; root replay state enforces at-most-once.
- Worker PVE firewall is deny-by-default outbound; guest nft is defense-in-depth.
- Monotonic `security_epoch`; `REVOKE ALL` increments epoch + disables authority; older capabilities never revive.
- Running jobs require fail-closed Worker authority lease; revoke/control loss cancels transport.
- PostgreSQL is authoritative mutable production state; Trust0/inventory/Signer/PVE remain separately operator-owned.
- PostgreSQL backend is explicit; no silent file fallback. Canonical lock order: authority -> grant -> approval -> job -> audit head.
- Browser never receives `SENTINEL_ADMIN_TOKEN`; `sentinel-operator` receives no PostgreSQL/Worker/Signer/PVE credentials.
- Browser-supplied Authorization/operator identity are ignored; identity is derived from the verified client-cert leaf.
- BFF has an explicit route allowlist, loopback-only Control upstream, no proxy env/redirect following, bounded bodies/responses, same-origin CSRF, strict CSP and no-store.
- Browser frontend uses no localStorage/sessionStorage and no third-party runtime/CDN.

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
Worker PVE policy: `policy_in: ACCEPT`, `policy_out: DROP`, normal runtime egress only to Control `10.169.2.210:9091/tcp` and target `10.169.2.214:22/tcp`.

Accepted dev.13 runtime hashes:

- control `3c1fd0b317ee43d7ee4e1bee1173f1daa3cd9681f152165bdd1a6844ca253ad7`
- egress `ff2a23a60460c55420f580dd5f71a6a742bed8847faedc54b6de0ac079568cb6`
- gateway `89078f3173029fcd4c809e25ef3c9a7f4aacf7381356ac41b8294276667ba3c3`
- signer `06805994530b497247525a6fd061e7a65d80a96cac02b0f6c04749eba0c32feb`
- worker `f7a49c35b04ba832480cc7a36c8b54964d69593553fad1066c5f5036c4a042f6`
- consume `4ff50ff3c8b8db429efb952e2a8a418d1e16dae22cfd9174a4ac371adc2ef140`
- exec `7ce5909e362cc937d992cc5f4b8bbae8e19e7f92d0aaf5672dd5ae59190dd0c4`

PR #1 merged the accepted core to `main` at `478009b1310b782db7dc20c629bada475c3f3d63`.

## Operator UI implementation checkpoints

- UI contract: `docs/OPERATOR_UI.md`
- backend/BFF: `f5d37bec113c35efebc72ecc639e275f50161a10`, Actions `34892851385`
- complete eight-page UI: `aaedad5518ad296426b01af856373672a1847f2d`, Actions `34898343292`
- dev.14 RC: `15513074c4ae30edbbd74b7c676562d2fb5c0e77`, Actions `34900078873`
- dev.15 deployment-boundary/runtime source: `41c343e83596d299af05cf92945395ec008f0fd9`, Actions `34903375824` PASS
- embedded frontend archive SHA-256 `9ae64c375e26d76d101cbdfe3db916296ff39237a5fc67bef4bf7aff99cef711`
- CI pins Node `24.20.0`, npm `11.19.0`, package-lock graph SHA-256 `9521cb1e1dab401e0ca9d81653adfd82d1459fe725ebaa5b26a663eff7f5ba95`

## dev.15 deployed operator boundary

Acceptance found the dev.14 blocker that `/etc/tethys-sentinel` is correctly `0750 root:sentinel-control`. The fix is an isolated `/etc/tethys-sentinel-operator` root, not weakened Control permissions.

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

Control listener topology remains `127.0.0.1:8081` admin + `10.169.2.210:9091` internal. Operator UI is `10.169.2.210:8444` mTLS. `sentinel-operator` remains boot-disabled during acceptance.

## dev.15 acceptance evidence

mTLS/browser:

- no client cert => TLS 1.3 `certificate required`, curl exit 56;
- trusted Windows client cert => HTTP 200 without insecure bypass;
- security headers: self-only CSP, HSTS 31536000, nosniff, no-referrer, restrictive Permissions-Policy.

Credential/process boundary:

- `sentinel-operator` runs as `tethys-operator:tethys-operator`;
- no PostgreSQL/Worker/Signer/PVE/admin bearer secret in its process environment;
- Control config root remains inaccessible;
- upstream exactly `http://127.0.0.1:8081`.

Read-only UI/API:

- Overview, Grants, Approvals, Jobs, Audit, Targets, Context and emergency state work through mTLS BFF;
- before mutation acceptance, Overview/emergency both reported epoch 3 disabled;
- Trust0 top-level fields: `version, trust_level, policy, instructions, hosts, runbooks`.

Security negatives:

- session identity exactly cert-derived `cert-sha256:3a696186706edf710d9dac5272846e5ccc05b95147e3528e3e98a3da11c9af1c`;
- spoofed browser Authorization/identity ignored;
- missing/mismatched CSRF, wrong Origin and cross-site Sec-Fetch-Site => HTTP 403;
- valid CSRF + intentionally invalid ID => safe HTTP 400 before mutation;
- unknown API route => 404; no generic proxy;
- authority unchanged during negative tests.

Grant/emergency mutation acceptance:

- controlled enable at epoch 3 succeeded with operator-client identity propagated to audit;
- test grant ID `e3c5bc4e39c31f81bc5cdf770ef49e9f`, agent `operator-ui-acceptance`, purpose `dev.15 grant issue/reveal/revoke acceptance`;
- grant issued at security epoch 3 and revoked successfully;
- plaintext capability appeared only in the immediate one-time reveal and did not return after dismiss/refresh;
- browser localStorage/sessionStorage remained empty;
- grant state read back as `revoked` with authoritative timestamps;
- audit events `emergency.enable_requested`, `emergency.enabled`, `grant.issued`, `grant.revoked`, `emergency.revoke_all` all used cert-derived actor `operator:cert-sha256:3a696186706edf710d9dac5272846e5ccc05b95147e3528e3e98a3da11c9af1c`;
- final `REVOKE ALL` advanced authority from epoch 3 to **epoch 4, disabled=true**.

Epochs 0/1/2/3 capabilities are now permanently stale after the epoch-4 revoke. Do not enable authority except for a controlled remaining acceptance step.

## Current phase / next steps

1. Create a fresh short-lived epoch-4 acceptance grant only when ready to test approvals.
2. Exercise approval `deny` and `allow_once`, including powerful-category policy that forbids reusable session approval.
3. If a session-reusable risk category is available, verify `allow_session` is shown only for policy-permitted categories.
4. End approval acceptance with explicit `REVOKE ALL`; record final epoch/reason and verify older capability non-revival.
5. Fix remaining deployment documentation/README examples to dev.15 and `/etc/tethys-sentinel-operator`.
6. Run exact-head CI on final docs/release metadata as needed, then decide merge/release of `wip/operator-ui`.
7. Preserve accepted dev.13 execution/credential invariants; materially touched execution paths require targeted re-acceptance.
8. When MCP is implemented later, revisit and lock down the exact narrow tool surface for Qwen-class autonomous agents.
