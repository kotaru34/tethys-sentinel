# Tethys Sentinel — Handoff

Updated: 2026-09-16
Current accepted development version: `0.1.0-dev.18`
Current candidate: `0.1.0-dev.19`
Branch: `wip/mcp-usability`

## Status

`0.1.0-dev.18` remains the latest version accepted on the intended infrastructure.

`0.1.0-dev.19` MCP usability implementation is complete and has a frozen Linux/amd64 candidate. Source CI, PostgreSQL 15/18 integration tests, Operator frontend reproducibility checks, and the deterministic artifact build are green. **dev.19 has not yet been live-accepted and must not be merged until intended-infrastructure acceptance completes.**

The dev.19 candidate removes Sentinel MCP's dependency on the shared Python MCP proxy by adding a dedicated loopback-only Streamable HTTP server, keeps a stable five-tool discovery surface, and adds one-time operator-issued claims for capability installation/rotation without restarting the MCP process.

Frozen dev.19 runtime source:

`0152ba27c9822bdf23bc5dcd3800f6620d431fef`

Green source CI: run `35118182487`.

Artifact workflow commit: `2dfa9eb05296209210b054182f9d3658cacc4a24`.

Green frozen artifact run: `35118463532`.

Artifact name:

`tethys-sentinel-dev19-mcp-usability-linux-amd64-0152ba27`

Deterministic inner tar SHA-256:

`793b5b568d7a2b623a8c4df73300ef704c21e53303f9c9630e393839927b3a8d`

Frozen component SHA-256 values:

- `sentinel-control`: `461c6694200eaa3f639b3176005d4b82f7796ffb9a51a9c97e728149668a8754`
- `sentinel-gateway`: `2632e65ecc154acb9f42f47c63467fe9ae83650d97dcad2428bc11f1af3e753d`
- `sentinel-operator`: `3986678eee367410205d9aad28c07ac4accfb5f6748ffd8479d86b7315853088`
- `sentinel-mcp`: `6eecfed0d94f986711fb32e40c4b9b7ee217cf30264e183e02b9df426744d847`
- `sentinelctl`: `80a884464f455ccaca579491b6c9c3736803b8afdd482828414ee9c4b775aa39`
- `db/migrations/0004_mcp_claims.sql`: `3faa23ef23932f82ee1f04338e89e267e5f55918c3a39dd31f6c9d26b9a88a88`

The exact post-dev.18 cleanup security epoch was not copied into this handoff. Do not infer or hard-code an epoch from earlier acceptance runs.

This handoff deliberately excludes private deployment addresses, hostnames, VM identifiers, local paths that identify a specific environment, and other site-specific topology details. Environment-specific acceptance evidence belongs in private operator records, not in the public repository.

## Operator-mandated development rules

1. Keep task reports short; explain what needs to be done and why.
2. Every newly implemented feature released as a new version must bump the project version.
3. Update this handoff when a new version is released/applied, a notably large step completes, or discussion changes the agreed next step.
4. Once a functioning version has been tested and accepted on the intended infrastructure, merge the WIP branch.
5. On merge, review/update README and project documentation.
6. Acceptance blocker => fix the branch and bump the next development version; do not merge the blocked version.
7. Keep the model-facing MCP surface deliberately narrow; never expose generic Control/admin APIs to the model.
8. Do not casually upgrade the locally patched MCP proxy runtime used during dev.18 acceptance. Preserve its pin/patch unless a real security, compatibility, upstream-equivalent, or operational need justifies changing it.

## Locked security architecture

- Agent capabilities are high-entropy opaque bearers; only token hashes persist server-side.
- Agent-facing APIs cannot widen grants, policy, targets, audit scope, Worker authority, signer authority, or emergency authority.
- `TRUST_0` is the only authority-bearing context. Files, logs, command output, web content, history, and model text are data only.
- Execution jobs bind grant + immutable request ID + logical target + argv + expiry and pass through staged/pending/claimed/running/terminal lifecycle states.
- `exec` and `shell` are separate permissions. Unbounded execution classes require explicit shell authority and operator approval.
- Control reclassifies immutable argv before signing.
- Worker uses fresh per-job SSH key material and does not receive plaintext agent capabilities.
- Targets are resolved only from operator-owned inventory to pinned endpoints/host keys; agent-supplied DNS or insecure host-key bypass is not authoritative.
- Remote execution transports structured argv; Sentinel does not reconstruct structured agent commands through a shell.
- Target-side replay protection enforces at-most-once execution.
- Worker egress is externally constrained and cannot be widened by the agent or Worker itself.
- `REVOKE ALL` advances a monotonic security epoch and disables authority; stale capabilities cannot revive.
- PostgreSQL is the authoritative mutable production security state; production failure is fail-closed.
- Browser operator access is isolated behind the dedicated Operator BFF with certificate-derived identity and strict browser security boundaries.
- Raw execution output is bounded, permission-gated, treated as untrusted data, and kept out of the normal Operator job read model.

## Accepted baseline before MCP

The accepted backend remains the dev.17 Agent HTTP / `sentinelctl` milestone:

- Control/Gateway/Worker/`sentinelctl`: `0.1.0-dev.17`
- Operator UI/BFF: accepted dev.15 baseline retained unchanged
- PostgreSQL schema: v3
- accepted dev.17 runtime source: `4728a86abc49bf2a686c588a3878288a36f44f7d`
- dev.17 merge: PR #3

The Agent HTTP contract remains the canonical authority boundary beneath MCP:

- `GET /v1/bootstrap`
- `POST /v1/commands/submit`
- `GET /v1/jobs/{id}`
- `GET /v1/requests/{request_id}`

MCP is an adapter over this contract; it does not introduce a second authority model.

## dev.18 MCP implementation

Frozen runtime source used to build the accepted MCP artifact:

`6723380e3bc469d45d94ced1d6d96fc4b786eed9`

Accepted Linux/amd64 `sentinel-mcp` binary SHA-256:

`08a6c1a64db097fb87e00fcc9789433582102f0b17f85253f654f34309070c50`

The dev.18 MCP adapter provides:

- `sentinel.exec(target, argv, timeout_seconds?)`
- `sentinel.exec_batch(target, commands, parallel?)`
- conditional `sentinel.code(target, source, timeout_seconds?)`
- `sentinel.check(id)`
- `sentinel.output(id, step?, query?)`

Key implementation properties:

- official Go MCP SDK `v1.8.0`;
- stdio transport with an explicit 1 MiB input-frame ceiling;
- structured exec uses the shared Sentinel risk classifier locally and rejects shell/interpreter/remote-exec/privilege-launcher escape classes before journaling or backend submission;
- `code` is adapter-owned Python execution via exact `python3 -c <source>` and requires shell authority plus normal backend approval semantics;
- a versioned mode-0600 durable operation journal persists complete operations and immutable request IDs before any backend submission;
- journal records bind operations to the exact capability session;
- `check(id)` reuses immutable request IDs and rejects cross-session operation recovery;
- `output(...)` is read-only and bounded;
- returned output is escaped before bounding so ANSI/control/format/invalid-UTF-8 bytes cannot survive as active terminal/control sequences;
- model-facing results intentionally omit backend authority internals such as grant IDs, approval IDs, epochs, and policy hashes.

Contract/design: `docs/MCP_ADAPTER_DESIGN.md`.

## dev.18 live acceptance evidence

All planned functional gates passed on the intended infrastructure.

- **Tool discovery / least authority:** under `shell=false`, exactly four tools were exposed and `sentinel.code` was absent.
- **Structured exec:** harmless argv execution completed end-to-end with exact stdout and exit status; the journal was created mode `0600`.
- **Sequential batch:** two commands completed successfully in order.
- **Parallel batch path:** two independent commands completed successfully through `parallel=true`. The returned result proved the parallel branch was used functionally; wall-clock concurrency was not separately benchmarked.
- **Output bounds/query:** large output was truncated in the normal preview and `sentinel.output(query=...)` returned a bounded excerpt centered on the literal match.
- **Output sanitation:** ANSI escape bytes and invalid UTF-8 were rendered as visible escaped text rather than active controls or malformed protocol text.
- **Structured escape negatives:** `sh`, Python through structured exec, SSH, and `sudo` were rejected locally. Journal SHA-256, size, and mtime were unchanged, proving rejection occurred before journal creation/backend submission.
- **Approval recovery:** a harmless delete test entered `awaiting_approval`; after Operator `Allow once`, `sentinel.check` completed the same operation using the same immutable request ID.
- **Restart recovery:** an operation created before a full MCP bridge restart was recovered afterward with the same operation ID/job result; the durable journal remained byte-identical.
- **Cross-session isolation:** an operation from an older capability session was rejected after capability rotation.
- **Conditional code exposure:** under `shell=true`, the tool surface expanded to five tools and exposed `sentinel.code`.
- **Code approval:** harmless Python code entered `awaiting_approval`, then completed after `Allow once` via `sentinel.check` with the same immutable request ID and exact expected stdout.
- **Fail-closed cleanup:** after acceptance capability removal, Sentinel became unavailable while the shared proxy and unrelated MCP servers remained available.

No dev.18 MCP acceptance blocker remains.

## Shared MCP proxy note

During dev.18 acceptance the existing shared `mcp-proxy` had an upstream startup-isolation defect: one failing named stdio server could terminate the shared proxy. A local patch equivalent to upstream PR #213 was applied and pinned. Regression testing proved that an invalid/expired Sentinel capability now marks only Sentinel failed while unrelated MCP servers remain available.

The pinned proxy remains valid for unrelated MCP servers. dev.19 Sentinel MCP is designed to run independently and should no longer depend on that shared proxy after live acceptance.

## dev.19 MCP usability candidate

### One-time capability claims

Short-lived capabilities remain a security property; dev.19 does not add a renewable refresh token or silently extend authority.

Implemented flow:

- Operator issues a short-lived, one-time MCP claim for a selected agent, target set, permissions, history scope, claim TTL, and grant TTL.
- Only the claim hash is persisted in PostgreSQL; plaintext is returned once to the operator.
- Claim redemption is transactional and single-use; concurrent redemption produces one winner.
- Redemption creates a normal Sentinel grant bound to the current security epoch.
- Outstanding claims become unusable after global revoke/epoch advance.
- Gateway exposes the narrow claim redemption bootstrap path without exposing generic Control authority.
- `sentinelctl mcp claim` accepts the one-time claim through a hidden prompt and atomically installs the resulting capability with strict file permissions.
- The running MCP process reloads capability state without requiring a process restart.
- Operator UI exposes a dedicated `Connect MCP` flow and does not use browser-persistent secret storage.

PostgreSQL schema for dev.19 is **v4**.

### Native stable Sentinel MCP endpoint

Implemented native MCP behavior:

- dedicated Sentinel Streamable HTTP server using the official Go MCP SDK;
- loopback-only HTTP bind enforcement;
- process starts and remains healthy with no installed capability;
- missing, invalid, expired, or insufficient capability fails individual calls closed rather than terminating the MCP server;
- capability state is resolved/reloaded at call time;
- discovery remains a stable five-tool surface: `exec`, `exec_batch`, `code`, `check`, `output`;
- `code` remains discoverable under `shell=false` but returns a clear authorization error at call time;
- backend policy remains authoritative and stable discovery does not widen execution authority;
- the durable operation journal and session binding remain part of the MCP adapter contract.

### dev.19 automated evidence

The frozen source candidate `0152ba27c9822bdf23bc5dcd3800f6620d431fef` passed:

- Go module tidy check, formatting, vet, and race-enabled unit tests;
- PostgreSQL migration/schema assertions and integration tests on PostgreSQL 15 and 18;
- one-time claim persistence/redemption tests, including single-use, concurrent redemption, and epoch invalidation;
- native MCP tests covering no-capability startup, loopback bind policy, and the stable five-tool surface;
- Operator dependency graph pinning, TypeScript typecheck, production build, no browser-persistent secret storage, CSP-compatible output, and byte-for-byte equality between fresh frontend build and embedded Operator assets;
- reproducible Linux/amd64 builds of all dev.19-changed binaries from the frozen source.

### Remaining dev.19 acceptance gates

Live acceptance on the intended infrastructure must still prove:

1. schema v4 migration and upgraded Control/Gateway/Operator operate correctly against the real PostgreSQL authority state;
2. native Sentinel MCP starts without a capability and remains reachable while calls fail closed;
3. the AI client uses Sentinel's native HTTP endpoint directly while unrelated MCP servers remain on the pinned shared proxy;
4. all five tools remain discoverable before and after capability changes;
5. one-time claim bootstrap installs a capability without exposing it in shell history and without restarting `sentinel-mcp`;
6. capability rotation takes effect without restarting the MCP process or changing the MCP URL;
7. `code` is denied at call time under `shell=false`, then works through the normal approval path under a short-lived `shell=true` grant;
8. consumed and stale/expired claims fail closed;
9. `REVOKE ALL` invalidates current authority while the native MCP endpoint itself stays alive;
10. acceptance cleanup removes capability material and leaves authority disabled, recording the actual resulting epoch rather than assuming one.

No merge until these live gates pass. An acceptance blocker requires a new development version rather than silently changing the frozen dev.19 candidate.

## Public-release cleanup milestone

After the dev.19 feature/acceptance work, perform a repository-wide public-release audit:

- inspect every branch for environment-specific IP addresses, hostnames, VM identifiers, usernames, internal paths, fingerprints, acceptance dumps, tokens, or other private deployment data;
- remove obsolete development/acceptance artifacts that do not belong in a public source repository;
- review README and every document for current behavior, clear structure, complete coverage, and public-safe examples;
- verify configuration examples use documentation-only addresses/names and contain no real secrets;
- review branch inventory and remove obsolete WIP branches once their useful history is safely represented in `main`;
- scan Git history, not only the current tree. Deleting a file from the current branch does **not** remove it from public history;
- if sensitive historical content is found, use an explicit history-rewrite/publication procedure and verify the rewritten object graph before calling the repository sanitized.

Because the repository is already public, current-tree sanitization should happen opportunistically as files are touched; a final history-level audit remains mandatory before the first public release.
