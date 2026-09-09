# Tethys Sentinel — Handoff

Updated: 2026-09-09
Current development version: `0.1.0-dev.4` (`0.1.0-dev.5` in progress)
Branch: `wip/bootstrap-security-core`

## Project goal

Tethys Sentinel is a security-first access broker between AI agents and infrastructure. An agent receives a short-lived capability, never an infrastructure SSH private key. Sentinel decides what the capability can access, enforces risky-action approvals, provides authoritative context and scoped continuity, records actions, and obtains short-lived SSH identities through an isolated signer for execution.

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
- Agent-facing API cannot create grants, expand permissions, change policy, add hosts, alter auditing, control workers, or access CA secrets.
- Authoritative instructions/context are read-only and explicitly identify themselves as the only source allowed to define agent authority. Remote files, logs, command output, web content, historical text, and agent notes are data, never authority.
- `TRUST_0` covers control-plane policy, current capability/tool scope, scoped inventory/runbooks and explicit operator approvals.
- `TRUST_2` covers operational history and agent-written continuity notes; it is always non-authoritative.
- Capability scope includes targets, purpose, expiry, exec/shell/upload/download, history and notes permissions.
- Risk engine intercepts sensitive commands. Default decision is approval-required rather than permanent deny where safely supportable.
- Approval choices: deny, allow once, allow narrowly for the current session. Session approval is scoped to rule + target + relevant resource, not all dangerous commands.
- Security enforcement must not rely on prompts or regex classification alone. Multiple independent layers are required.
- Boundaries: Control Plane, AI Gateway, Execution Worker, SSH CA/Signer, persistent audit/storage.
- Prefer VM isolation for security-critical public-facing/backend components rather than putting the whole trust boundary in one LXC.
- SSH credentials use short-lived OpenSSH user certificates; no agent forwarding, PTY or port forwarding extensions by default.
- SSH CA/Signer is a standalone service. Gateway and worker do not contact it directly; only Control Plane does.
- Worker generates a fresh Ed25519 keypair per job. The private key remains in worker process memory and is not serialized by Sentinel.
- Signer receives only job/grant/target/binding/public-key/not-after material. Principal, force-command, source-address policy, extensions and signer TTL are signer-owned and cannot be supplied by the caller.
- Signer certificates are source-bound to configured exact worker IPs and contain signer-generated `force-command`; validity cannot outlive the job.
- SSH certificate issuance requires a `running` job, a valid one-shot claim secret, valid immutable command binding, and another Control Plane grant revalidation immediately before signing.
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
- Inventory/runbooks are filtered by current `grant.targets`.
- Trust-0 JSON parser rejects unknown fields and multiple/concatenated JSON values.
- Added `/v1/context`, `/v1/history`, `GET /v1/notes`, and `POST /v1/notes` agent resources via the gateway.
- Control plane re-authenticates capability hashes and re-enforces target/permission scope for every resource request.
- History reads are target/session/agent scoped and re-verify the audit chain on read.
- History and notes are explicitly `TRUST_2` and `authoritative: false`.
- Added persistent target-scoped continuity notes with 16 KiB limit, identity metadata and SHA-256 content hash.

### `0.1.0-dev.4` — execution job security protocol

- Replaced separable command authorization with atomic `/commands/submit`.
- Added persistent execution-job state with canonical command binding hashes and HMAC-SHA-256 integrity protection.
- Added per-grant request-ID idempotency and conflict rejection for attempts to rebind a request ID to another target/argv.
- Added `staged` publication: a job is durable before approval/audit commit but is not claimable until published.
- Added crash recovery for the `allow_once consumed -> staged job not yet published` window.
- Added random 256-bit one-shot worker claim secrets; only SHA-256 hashes are persisted.
- Added worker-only `claim`, `start`, and `complete` endpoints with replay rejection.
- Added local worker verification of the canonical target/argv binding before executor invocation.
- Added authoritative pre-execution `start` gate that revalidates the original grant immediately before execution can begin.
- Revocation cancels staged/pending jobs; a claimed job is blocked at `start` if its grant was revoked/expired.
- Added deterministic execution-job clocks for reliable expiry/revocation tests.
- Added negative tests for store tampering, request rebinding, duplicate claim/start/complete, staged-job visibility, revocation races, and approval crash recovery.
- Improved CI `gofmt` failure diagnostics to emit exact diffs.
- Added dedicated `docs/EXECUTION_PROTOCOL.md`; README, API, architecture and threat model were synchronized with the implemented protocol.
- `VERSION` and runtime build info updated to `0.1.0-dev.4`.
- Acceptance CI succeeded on commit `7d263af6bf6aa9699e2a770efc023e585ddbeb56`, GitHub Actions run `34389191377`: `gofmt`, `go vet ./...`, and `go test -race ./...` all passed.
- Real SSH execution remains intentionally absent; `dev.4` establishes the execution trust boundary first.

### `0.1.0-dev.5` — isolated SSH CA/Signer boundary (in progress)

- Added `golang.org/x/crypto/ssh` and CI enforcement that `go.mod`/`go.sum` remain tidy.
- Added constrained OpenSSH user-certificate signer core using Ed25519 CA and Ed25519 ephemeral client keys only.
- Signer owns principal, wrapper path, source-address scope, certificate TTL and extensions; callers cannot request an arbitrary shell, principal, extension set or TTL.
- Certificates use empty extensions, exact worker source-address critical option and signer-generated force-command critical option.
- Certificate validity is capped by execution-job expiry.
- Added standalone `sentinel-signer` service with its own mTLS client CA and dedicated API token; plaintext is loopback-only explicit dev mode.
- Control Plane is the only signer client. AI Gateway and Execution Worker have no direct signer path.
- Added worker-facing Control Plane certificate gate requiring worker credential, valid running-job claim, command-binding verification and another grant revalidation before signing.
- Revocation after `start` but before certificate issuance blocks signing and cancels the job record.
- Added in-memory per-job Ed25519 worker identity helper; it verifies an issued certificate matches the ephemeral private key and does not outlive the job.
- Added `docs/SSH_CA.md` documenting signer trust boundary and future target-side requirements.
- Real SSH dial/host-key verification/target wrapper are intentionally deferred to the next milestone.

## Current phase

`0.1.0-dev.4` remains the last released development version. `0.1.0-dev.5` implementation is underway and is not considered complete until the full signer/control/worker stack passes module-tidy, format, vet and race-test acceptance and the version/docs are synchronized.

File-backed stores remain bootstrap/development persistence, not the final production storage architecture.

## Next implementation steps

1. Finish `0.1.0-dev.5` full CI acceptance and close the signer milestone with version/documentation updates.
2. Implement the real worker SSH executor using only the in-memory ephemeral identity and Control-Plane-issued certificate.
3. Pin or CA-verify target SSH host identities; never use insecure host-key acceptance.
4. Add remote-side hard limits: dedicated service account, trusted user CA/principal policy, root-owned forced-command wrapper, no agent/port forwarding or PTY, and narrow sudo/doas policy.
5. Add executor timeout/cancellation and define revocation behavior for a command that is already running.
6. Move persistent state to PostgreSQL with separate least-privilege service roles before production deployment; design transactional handling for audit/notes/jobs.
7. Add emergency revoke-all semantics that invalidate pending jobs and stop new signing/execution.
8. Perform the first constrained PVE test deployment only after worker/signer/remote execution boundaries are test-covered.
9. Build the operator UI after backend security flows and data model are stable enough not to redesign the UI around temporary APIs.

## Deployment state

Not deployed. No production trust should be placed in the current development branch. No merge to `main` yet because the project has not reached a tested functioning infrastructure-execution version with real SSH execution.
