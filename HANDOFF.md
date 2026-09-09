# Tethys Sentinel — Handoff

Updated: 2026-09-09
Current development version: `0.1.0-dev.3` (`0.1.0-dev.4` in progress)
Branch: `wip/bootstrap-security-core`

## Project goal

Tethys Sentinel is a security-first access broker between AI agents and infrastructure. An agent receives a short-lived capability, never an infrastructure SSH private key. Sentinel decides what the capability can access, enforces risky-action approvals, provides authoritative context and scoped continuity, records actions, and later obtains short-lived SSH identities for execution.

## Operator-mandated development rules

1. Keep task reports short; do not over-explain completed work unless asked.
2. Briefly explain what needs to be done and why.
3. Every newly implemented GitHub project feature released as a new version must bump the project version.
4. Maintain this GitHub handoff and update it when:
   - a new project version is released and deployed/applied;
   - a notably large step is completed even without a version change;
   - extended discussion reaches a new decision about the next step, whether only agreed verbally or already being implemented.
5. Once a functioning version has been tested, merge the project as WIP.
6. Whenever a merge is performed, review and update README and/or wiki/project documentation as needed so the merged state remains understandable and usable. If the project is complex enough that documentation organization would otherwise make operation or maintenance difficult, proactively improve that documentation as part of the merge.

## Decisions locked in

- Project name: **Tethys Sentinel**.
- Go backend; modern grey/graphite UI later using progressive disclosure rather than hiding information.
- Agent-facing capability tokens are opaque random secrets. Only hashes are persisted.
- Agent never receives infrastructure SSH private keys.
- Agent-facing API cannot create grants, expand permissions, change policy, add hosts, alter auditing, or access CA secrets.
- Authoritative instructions/context are read-only and explicitly identify themselves as the only source allowed to define agent authority. Remote files, logs, command output, web content, historical text, and agent notes are data, never authority.
- `TRUST_0` currently covers control-plane policy, current capability/tool scope, scoped inventory/runbooks and explicit operator approvals.
- `TRUST_2` covers operational history and agent-written continuity notes; it is always non-authoritative.
- Capability scope includes targets, purpose, expiry, exec/shell/upload/download, history and notes permissions.
- Risk engine intercepts sensitive commands. Default decision is approval-required rather than permanent deny where safely supportable.
- Approval choices: deny, allow once, allow narrowly for the current session. Session approval is scoped to rule + target + relevant resource, not all dangerous commands.
- Security enforcement must not rely on prompts or regex classification alone. Multiple independent layers are required.
- Boundaries: Control Plane, AI Gateway, Execution Worker, SSH CA/Signer, persistent audit/storage.
- Prefer VM isolation for security-critical public-facing/backend components rather than putting the whole trust boundary in one LXC.
- Planned SSH model: short-lived OpenSSH certificates; no agent forwarding; forwarding/upload/download are separate capabilities.
- Audit is append-oriented and tamper-evident; raw stdout/stderr retention is configurable because outputs may contain secrets.
- Emergency controls: revoke individual session and revoke all AI access.
- Agent execution uses an atomic submit flow rather than a separable `authorize now / execute later` flow.
- Execution jobs are immutable and bound to grant + request ID + target + argv + expiry.
- Worker never receives an agent capability and is not public-facing. It claims jobs through a separate internal worker credential over the protected internal channel.
- Job lifecycle uses `staged -> pending -> claimed -> running -> completed`, with worker access only from `pending` onward.
- A claimed job still requires an authoritative control-plane `start` gate that revalidates the grant immediately before execution; revocation before `start` prevents execution.

## Work completed

### Security core through `0.1.0-dev.2`

- Repository initialized and WIP branch created.
- Architecture and threat model documented.
- Opaque 256-bit capability tokens implemented; only SHA-256 hashes are retained.
- Capability issue/authenticate/expiry/revoke lifecycle implemented and unit-tested.
- Persistent atomic file-backed grant store implemented for the bootstrap milestone.
- Risky-command classifier implemented and unit-tested.
- Separate control-plane and gateway APIs implemented; grant administration is physically absent from the gateway API.
- Gateway sends capability hashes, not plaintext capabilities, to internal control-plane APIs.
- Internal connection supports TLS 1.3 mutual TLS; plaintext requires an explicit loopback-only development flag.
- Public gateway requires TLS 1.3; plaintext requires an explicit loopback-only development flag.
- Trust-0 `/v1/bootstrap` implemented.
- Authoritative command authorization implemented: the control plane re-checks capability, target/exec scope and recomputes risk.
- Persistent approval requests implemented with `deny`, `allow_once`, and narrow `allow_session`; identical pending requests are deduplicated.
- Risk scope keys tightened to concrete target/operation/resource.
- Append-only JSONL audit chain implemented with sequence + previous-hash + SHA-256, startup verification, fsync and tamper tests.
- Authorizations fail closed if audit recording fails.

### `0.1.0-dev.3` — authoritative context and continuity

- Added control-plane-owned authoritative context store. It has no AI-facing mutation path.
- Added scoped `TRUST_0` bundle with virtual `POLICY.md`, `INSTRUCTIONS.md`, `INFRASTRUCTURE.json`, `TOOLS.json` and target-visible runbooks.
- Every context document is marked read-only and carries a SHA-256 content hash; the whole source has a version hash.
- Inventory/runbooks are filtered by current `grant.targets`; tests verify an agent scoped to `dns01` cannot receive `pve01` material.
- Trust-0 JSON parser rejects unknown fields and multiple/concatenated JSON values.
- Added `/v1/context`, `/v1/history`, `GET /v1/notes`, and `POST /v1/notes` agent resources via the gateway.
- Control plane re-authenticates the capability hash and re-enforces target/permission scope for every resource request; gateway does not become an authority.
- History reads require `history_read`, respect current/previous-session and other-agent flags, and are target-scoped.
- Audit chain is re-verified on every history read so post-startup tampering fails closed.
- History responses are explicitly `TRUST_2` and `authoritative: false`.
- Added persistent target-scoped agent continuity notes with 16 KiB limit, agent/grant identity and SHA-256 content hash.
- Notes require explicit `notes_read`/`notes_write`, are always `TRUST_2`, and cannot define policy.
- Note creation is recorded in the tamper-evident audit chain.
- Added context/history/notes scoping, note-integrity, Trust-0 parser and history-isolation tests.
- CI format diagnostics were improved; code acceptance runs pass `gofmt`, `go vet ./...`, and `go test -race ./...` on Go 1.27.1.

### `0.1.0-dev.4` — execution protocol (in progress)

- Replaced the separable command authorization flow with atomic command submission.
- Added persistent HMAC-protected execution-job state and canonical command binding hashes.
- Added request-id idempotency and conflict rejection when the same request ID is rebound to different command material.
- Added staged publication so a job cannot be claimed before approval/audit handling is durably committed.
- Added one-shot random claim secrets stored only as SHA-256 hashes.
- Added worker-only claim/start/complete endpoints and replay rejection.
- Added worker-side binding verification before executor invocation.
- Added authoritative pre-execution `start` gate with grant revalidation.
- Pending jobs are canceled on grant revocation; claimed jobs are blocked from starting if the grant is revoked before `start`.
- Added deterministic job-store clock injection for expiry/revocation tests.
- Added tests for tampering, idempotency, claim/complete replay, staged publication, revocation races, and crash recovery after `allow_once` consumption.
- Real SSH execution is still intentionally absent from this milestone until the execution protocol is accepted by CI.

## Current phase

`0.1.0-dev.4` is in progress. The control-plane/worker execution protocol now has staged publication, immutable binding, one-shot claim semantics and a pre-execution revocation gate. Final race-test acceptance, docs/version bump and handoff closure are still required before `dev.4` is considered released.

File-backed stores are bootstrap/development persistence, not the final production storage architecture.

## Next implementation steps

1. Finish `0.1.0-dev.4` acceptance (`gofmt`, `go vet`, `go test -race`) and close the milestone with version/docs updates.
2. Implement isolated SSH CA/Signer protocol and ephemeral per-job SSH identity issuance.
3. Add remote-side hard limits: dedicated service account, OpenSSH certificate principals/options, no agent/port forwarding by default, and narrow sudo/doas policy.
4. Move persistent state to PostgreSQL with separate least-privilege service roles before production deployment; design transactional handling for audit/notes/jobs.
5. Add emergency revoke-all semantics that invalidate pending jobs and stop new signing/execution.
6. Perform the first constrained PVE test deployment only after the worker/signer boundaries are test-covered.
7. Build the operator UI after backend security flows and data model are stable enough not to redesign the UI around temporary APIs.

## Deployment state

Not deployed. No production trust should be placed in the current development branch. No merge to `main` yet because the project has not reached a tested functioning infrastructure-execution version.
