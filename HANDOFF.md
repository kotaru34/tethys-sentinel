# Tethys Sentinel — Handoff

Updated: 2026-09-15
Current development version: `0.1.0-dev.15`
Branch: `wip/operator-ui`

Status: the dev.13 execution/security core remains the accepted baseline. Operator UI code is now `0.1.0-dev.15` after fixing a real deployment blocker: operator credentials/config must live under an isolated `/etc/tethys-sentinel-operator` root rather than inside the Control-only `/etc/tethys-sentinel` directory. Exact deployed dev.15 source checkpoint is `41c343e83596d299af05cf92945395ec008f0fd9`, CI Actions `34903375824` PASS. Real mTLS deployment and read-only operator integration are now working on the acceptance Control VM; mutation/emergency acceptance is still pending.

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
- Agent APIs cannot widen grants, change policy, add targets, alter audit, control Worker, request SSH certificates, or access CA material.
- `TRUST_0` is the only authority-bearing context; files/logs/history/web/command output are data.
- Main boundaries: Control, Gateway, Worker, external Worker network policy, Signer/CA, target wrapper, PostgreSQL authority/audit state, emergency authority, operator BFF/web boundary.
- Jobs are immutable: grant + request ID + logical target + argv + expiry; lifecycle staged -> pending -> claimed -> running -> terminal.
- Worker uses separate credential + one-shot claim secret; never plaintext agent capability.
- `start` revalidates authority/grant.
- `exec` and `shell` are separate; powerful classes require exec+shell+explicit operator approval and are `allow_once` only.
- Control reclassifies immutable argv immediately before signing.
- Worker generates a fresh Ed25519 key/job; only Control calls Signer.
- Signer controls principal/source-address/force-command/extensions/TTL.
- Logical targets resolve from operator-owned inventory to literal global-unicast IP:port + exact raw pinned host key; no DNS/insecure host-key acceptance.
- SSH host-key negotiation is constrained to the pinned key algorithm; RSA pins use RSA-SHA2 only, never SHA-1 `ssh-rsa`.
- Remote command transport is deterministic versioned base64url JSON; no shell reconstruction.
- Target wrapper validates job ID, command hash/canonical command, target ID; root replay consume enforces at-most-once.
- Worker PVE firewall is a hard deny-by-default egress boundary; guest nft is defense-in-depth.
- Monotonic `security_epoch`; `REVOKE ALL` increments epoch + disables authority; older caps never revive.
- Running jobs require fail-closed Worker authority lease; revoke/control loss cancels transport.
- PostgreSQL is authoritative mutable production state; Trust0/inventory/Signer/PVE remain operator-owned separately.
- PostgreSQL backend selection is explicit; no silent file fallback; fresh DB authority starts disabled.
- Canonical lock order: authority -> grant -> approval -> job -> audit head; security transitions are transactional.
- Browser never receives `SENTINEL_ADMIN_TOKEN`; `sentinel-operator` receives no PostgreSQL/Worker/Signer/PVE credentials.
- Operator targets/context are read-only in v1.
- Browser-supplied Authorization/operator identity are ignored; identity is derived from verified client-cert leaf.
- BFF uses explicit route allowlist, loopback-only Control upstream, no proxy env, no redirects, bounded bodies/responses, same-origin+CSRF, strict CSP/no-store.
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

Real dev.13 acceptance proved harmless end-to-end execution, target at-most-once replay, allow-once non-reuse, individual/global active revoke, stale-epoch non-revival, PostgreSQL persistence/fail-closed behavior, external Worker egress containment, Worker secret separation/mTLS, pinned SSH algorithm negotiation, target wrapper and transactional audit/job evidence.

PR #1 merged the accepted security core to `main` at `478009b1310b782db7dc20c629bada475c3f3d63`.

## Authority final baseline

Final dev.13 `REVOKE ALL` at `2026-09-14T19:17:03.84825Z` left:

- `epoch=3`
- `disabled=true`
- reason `dev.13 acceptance complete; first WIP merge finished`

Epochs 0/1/2 are permanently stale. Do not enable authority merely to install or inspect Operator UI.

## Operator UI implementation

UI contract: `docs/OPERATOR_UI.md`.
Primary views: Overview, Approvals, Grants, Jobs, Audit, Targets, Context, Security. Global `REVOKE ALL` is always reachable. One-time capability reveal is RAM-only. Polling-first.

Backend/BFF milestones:

- operator read model for overview/grants/approvals/jobs/audit/targets/context;
- cert-derived operator identity propagation for audit-producing mutations;
- explicit browser route allowlist and same-origin CSRF;
- loopback-only privileged Control upstream;
- embedded digest-pinned frontend archive SHA-256 `9ae64c375e26d76d101cbdfe3db916296ff39237a5fc67bef4bf7aff99cef711`;
- exact Node `24.20.0`, npm `11.19.0`, package-lock graph SHA-256 `9521cb1e1dab401e0ca9d81653adfd82d1459fe725ebaa5b26a663eff7f5ba95` in CI.

Important checkpoints:

- backend/BFF `f5d37bec113c35efebc72ecc639e275f50161a10`, Actions `34892851385`
- complete UI `aaedad5518ad296426b01af856373672a1847f2d`, Actions `34898343292`
- dev.14 release candidate `15513074c4ae30edbbd74b7c676562d2fb5c0e77`, Actions `34900078873`
- dev.15 deployment-boundary fix source `41c343e83596d299af05cf92945395ec008f0fd9`, Actions `34903375824` PASS

## dev.15 real deployment checkpoint

Acceptance found a real dev.14 deployment blocker: `/etc/tethys-sentinel` is correctly `0750 root:sentinel-control`, so `tethys-operator` could not traverse it. The correct fix is an isolated operator config root, not weakening Control permissions or adding the operator account to the Control group.

Deployed layout on Control VM:

- `/etc/tethys-sentinel` remains `0750 root:sentinel-control` and inaccessible to `tethys-operator`.
- `/etc/tethys-sentinel-operator` is `0750 root:tethys-operator`.
- `operator-admin.token` is `0400 tethys-operator:tethys-operator`.
- `operator-server.key` is `0400 tethys-operator:tethys-operator`.
- public server cert/client-CA/env are root-owned, group-readable by `tethys-operator`.
- `sentinel-operator.service` uses `/etc/tethys-sentinel-operator/operator.env`.

Dedicated Operator TLS PKI:

- CA SHA-256 cert fingerprint `07:BA:71:23:DB:7A:4A:1D:B1:02:F5:A4:6E:36:EA:6A:BF:89:1A:8D:F8:31:4B:02:B6:C8:10:1B:43:F6:F5:C4`
- server SHA-256 fingerprint `CE:A9:15:CC:E1:B8:9F:2C:67:7B:CC:84:88:FB:5E:54:4D:B5:FF:F8:D8:4B:0F:F1:1B:38:F6:8F:F3:8E:5C:B3`
- operator client SHA-256 fingerprint `3A:69:61:86:70:6E:DF:71:0D:9D:AC:52:72:84:6E:5C:CC:05:B9:51:47:E3:52:8E:3E:98:A3:DA:11:C9:AF:1C`
- server SAN is IP `10.169.2.210`; client cert subject `CN=Kotaru Tethys Operator`, EKU clientAuth.
- CA/client private material was removed from Control after verified Windows import; only server key + public certificates remain.

Exact deployed dev.15 binaries:

- `sentinel-operator`: `ea50c402b93d39e592f18106b3340b8615ede04e94e9957eb2f27abde236956c`
- `sentinel-control`: `b1c3b648305a1992b442f9b01980f0fa3556adb1e62bfe63e7c252ecb4397dc6`

Control upgrade preserved listener topology (`127.0.0.1:8081` admin, `10.169.2.210:9091` internal) and preserved authority exactly at epoch 3 disabled. A verified dev.13 rollback binary was staged before the upgrade.

mTLS/browser acceptance completed so far:

- request without client cert fails TLS 1.3 with `certificate required` (`curl` exit 56);
- trusted Windows client cert reaches UI with HTTP 200 and no insecure bypass;
- browser cert picker shows `Kotaru Tethys Operator` issued by dedicated Operator CA;
- response headers include self-only CSP, HSTS 31536000, `nosniff`, `no-referrer`, restrictive Permissions-Policy;
- Overview now reads real Control/PostgreSQL state after Control dev.15 upgrade;
- Overview shows authority disabled at epoch 3, pending approvals 1, active grants 0, active jobs 0, failed jobs 4, and real audit/failure history.

`sentinel-operator` remains running but boot-disabled during acceptance. AI authority remains fail-closed at epoch 3.

## Current phase / next steps

1. Complete read-only UI acceptance while authority stays disabled: Targets, Context, Audit, Jobs, Grants/Approvals read views, and credential/process boundary checks.
2. Run negative browser/BFF tests: missing/mismatched CSRF, cross-origin mutation, spoofed Authorization/operator identity.
3. Only then open a controlled authority window for mutation workflows that genuinely require it: grant issue/revoke, approval deny/allow_once/session policy, emergency revoke/re-enable/non-revival.
4. End acceptance with an explicit final authority state, preferably disabled, and record exact epoch/reason.
5. Fix remaining deployment documentation examples to the isolated `/etc/tethys-sentinel-operator` root before merge.
6. Only after constrained acceptance passes, decide merge/release of `wip/operator-ui`.
7. Preserve every accepted dev.13 execution/credential invariant; materially touched execution paths require targeted re-acceptance.
8. When MCP is implemented later, revisit and lock down the exact narrow tool surface for Qwen-class autonomous agents.
