# Tethys Sentinel — Handoff

Updated: 2026-09-16
Current accepted development version: `0.1.0-dev.18`
Branch: `wip/mcp-adapter`

## Status

`0.1.0-dev.18` MCP acceptance is complete. The frozen `sentinel-mcp` artifact was installed on the intended AI/MCP client host and exercised against the accepted dev.17 backend. All planned functional gates passed without an acceptance blocker.

The acceptance capability material was removed from the client afterward. The shared MCP proxy remained alive with unrelated MCP servers configured while the Sentinel named server correctly moved to `failed` once its capability was removed. This is the expected fail-closed state.

The exact post-cleanup security epoch was not copied into this handoff. Do not infer or hard-code an epoch from earlier acceptance runs.

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

This patch was necessary for dev.18 acceptance, but the next architecture should remove Sentinel from the shared proxy dependency entirely rather than building more coupling around it.

## Next milestone — dev.19 MCP usability

The next implementation milestone is `0.1.0-dev.19` and addresses two observed usability/robustness problems.

### 1. Capability issue/rotation without MCP restart

Short-lived capabilities remain a security property; the solution must not silently turn them into renewable long-lived authority.

Target UX:

- Operator creates/rotates a narrow MCP grant/profile.
- A short-lived one-time claim mechanism transfers the resulting capability to the MCP client without exposing it in shell history or logs.
- The client stores capability material atomically with strict file permissions.
- Capability replacement is detected/loaded by the running Sentinel MCP process; no process restart is required.
- Capability expiry remains visible and fail-closed; no hidden refresh token automatically extends authority.

### 2. Native stable Sentinel MCP endpoint

Sentinel should run its own long-lived Streamable HTTP MCP endpoint using the official Go MCP SDK instead of being a stdio child of the shared Python proxy.

Requirements:

- dedicated Sentinel MCP process and stable HTTP URL;
- no shared-proxy restart when a Sentinel capability changes;
- no outage for unrelated MCP servers when Sentinel is unavailable;
- Sentinel process remains alive when no capability is installed or a capability expires;
- capability/bootstrap state is resolved at tool-call time or through a reloadable capability manager;
- **stable five-tool surface** throughout a chat session: `exec`, `exec_batch`, `code`, `check`, `output` remain discoverable;
- `sentinel.code` must return a clear authorization error when the current capability lacks shell authority instead of appearing/disappearing from tool discovery;
- backend policy remains authoritative; stable discovery must not widen execution authority;
- session-bound journal recovery semantics remain intact across capability rotations.

This stable surface avoids stale tool-schema/model hallucination problems when permissions change after the model has already cached MCP tool discovery.

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
