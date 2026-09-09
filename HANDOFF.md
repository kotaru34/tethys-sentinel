# Tethys Sentinel — Handoff

Updated: 2026-09-09
Current development version: `0.1.0-dev.5` (`0.1.0-dev.6` release candidate)
Branch: `wip/bootstrap-security-core`

## Project goal

Tethys Sentinel is a security-first access broker between AI agents and infrastructure. An agent receives a short-lived capability, never an infrastructure SSH private key. Sentinel decides what the capability can access, enforces risky-action approvals, provides authoritative context and scoped continuity, records actions, and obtains short-lived SSH identities through an isolated signer for tightly bound execution.

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
- Agent-facing API cannot create grants, expand permissions, change policy, add hosts, alter auditing, control workers, request SSH certificates, or access CA secrets.
- Authoritative instructions/context are read-only and explicitly identify themselves as the only source allowed to define agent authority. Remote files, logs, command output, web content, historical text, and agent notes are data, never authority.
- `TRUST_0` covers control-plane policy, current capability/tool scope, scoped inventory/runbooks and explicit operator approvals.
- `TRUST_2` covers operational history and agent-written continuity notes; it is always non-authoritative.
- Capability scope includes targets, purpose, expiry, exec/shell/upload/download, history and notes permissions.
- Risk engine intercepts sensitive commands. Default decision is approval-required rather than permanent deny where safely supportable.
- Approval choices: deny, allow once, allow narrowly for the current session. Session approval is scoped to rule + target + relevant resource, not all dangerous commands.
- Security enforcement must not rely on prompts or regex classification alone. Multiple independent layers are required.
- Boundaries: Control Plane, AI Gateway, Execution Worker, SSH CA/Signer, target execution wrapper, persistent audit/storage.
- Prefer VM isolation for security-critical public-facing/backend components rather than putting the whole trust boundary in one LXC.
- SSH credentials use short-lived OpenSSH user certificates; no agent forwarding, PTY, port forwarding or X11-forwarding extensions by default.
- SSH CA/Signer is a standalone service. Gateway and worker do not contact it directly; only Control Plane does.
- Worker generates a fresh Ed25519 keypair per job. The private key remains in worker process memory and is not serialized by Sentinel.
- Signer receives only job/grant/target/binding/public-key/not-after material. Principal, force-command, source-address policy, extensions and signer TTL are signer-owned and cannot be supplied by the caller.
- Signer certificates are source-bound to configured exact worker IPs and contain signer-generated `force-command`; validity cannot outlive the job.
- SSH certificate issuance requires a `running` job, a valid one-shot claim secret, valid immutable command binding, and another Control Plane grant revalidation immediately before signing.
- Target SSH endpoint/user/host-key data is resolved from operator-owned server-side inventory using only the logical job target. Agent-supplied hostnames/IPs never become arbitrary worker SSH destinations.
- SSH target registry requires concrete literal IPs plus port and an exact raw pinned host key; DNS destinations and insecure host-key acceptance are rejected.
- Real SSH execution uses the in-memory per-job private key plus short-lived certificate and exact host-key pinning.
- Remote command transport is a deterministic versioned base64url JSON envelope. Sentinel never reconstructs the agent argv through `/bin/sh -c`.
- The target wrapper verifies force-command job ID, canonical command binding and root/operator-owned local target ID before direct argv execution.
- Target replay state enforces at-most-once job execution independently of certificate TTL. Replay markers are root-protected and consumed through a narrow helper.
- Worker SSH dial/handshake/output are bounded and the execution context cannot outlive `job.expires_at`.
- Audit is append-oriented and tamper-evident; raw stdout/stderr retention is configurable because outputs may contain secrets.
- Emergency controls: revoke individual session and revoke all AI access.
- Agent execution uses an atomic submit flow rather than a separable `authorize now / execute later` flow.
- Execution jobs are immutable and bound to grant + request ID + target + argv + expiry.
- Worker never receives an agent capability and is not public-facing. It claims jobs through a separate internal worker credential over the protected internal channel.
- Job lifecycle uses `staged -> pending -> claimed -> running -> completed`, with worker access only from `pending` onward.
- A claimed job still requires an authoritative control-plane `start` gate that revalidates the grant immediately before execution; revocation before `start` prevents execution.
- Known pre-production gap: interpreters/shells/privilege launchers can carry arbitrary code that a top-level executable classifier cannot safely understand. This must receive a dedicated conservative risk policy before production trust.

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

### `0.1.0-dev.5` — isolated SSH CA/Signer boundary

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
- Added certificate issuance audit records with serial and key/certificate/CA fingerprints.
- Added `docs/SSH_CA.md`; README, API, architecture and threat model were synchronized with the implemented signer flow.
- `VERSION` and runtime build info updated to `0.1.0-dev.5`.
- Acceptance CI succeeded on commit `750d5d8d0ba899ff2fe45e3b39c70a8969b6a469`, GitHub Actions run `34392961793`: module tidy check, `gofmt`, `go vet ./...`, and `go test -race ./...` all passed.

### `0.1.0-dev.6` — real SSH execution boundary (release candidate)

- Added operator-owned SSH target registry selected by `SENTINEL_SSH_TARGETS_FILE`.
- Registry maps logical target -> literal IP/port + Unix account + exact raw pinned SSH host key.
- Unknown fields, DNS endpoints, malformed/unspecified addresses, duplicate targets and writable target configuration fail closed.
- Control Plane resolves transport details only after running-job/claim/binding/grant checks and returns them with the certificate; agent input can never become an arbitrary worker destination.
- Added full standalone `sentinel-worker` process and wired `claim -> start -> ephemeral key -> certificate+target -> SSH -> complete`.
- Added real `golang.org/x/crypto/ssh` executor using exact `ssh.FixedHostKey`; no TOFU/insecure fallback exists.
- Added explicit TCP/handshake deadlines; established execution context is capped by job expiry.
- Added bounded stdout/stderr SHA-256 accounting without retaining raw output; overflow actively closes the SSH client.
- Added versioned deterministic `sentinel-exec-v1` base64url JSON envelope carrying immutable job/grant/request/target/argv material without shell quoting.
- Added root/operator-owned `tethys-sentinel-exec` forced-command wrapper with local target-ID and canonical binding verification and direct argv execution.
- Added reduced deterministic remote environment (`PAGER=cat`, fixed PATH, no inherited agent environment).
- Added root-only `tethys-sentinel-consume` helper and private replay-state validation; concurrent reuse of one job allows exactly one target consume.
- Target execution therefore has at-most-once semantics independent of worker claim/completion state and short certificate TTL.
- Added real in-process SSH integration tests proving correct pin success, wrong pin rejection before exec, envelope preservation, handshake bounds and output-limit termination.
- Added replay concurrency/permission tests, target registry tests, wrapper/binding/target-ID tests and worker certificate lifecycle tests.
- Pre-release CI succeeded on commit `c6e84402d58bb282e9d63877ba8d0807fb960310`, GitHub Actions run `34396499517`: module tidy, `gofmt`, `go vet ./...`, and `go test -race ./...` all passed.
- Added `docs/SSH_EXECUTION.md` and synchronized README/API/architecture/threat/execution/signer documentation with the real SSH path.

## Current phase

`0.1.0-dev.6` code and documentation are complete as a release candidate. The remaining release step is to bump `VERSION`/runtime build info and obtain a clean versioned acceptance CI on the final documentation head.

File-backed stores remain bootstrap/development persistence, not the final production storage architecture.

The project is not yet ready for production trust because the current risk classifier still needs a conservative policy for arbitrary-code carriers such as shells/interpreters/privilege launchers.

## Next implementation steps

1. Finalize the `0.1.0-dev.6` version/build-info bump and acceptance CI.
2. Implement conservative `ARBITRARY_CODE` / interpreter / launcher policy with exact narrow approval semantics; do not allow a generic session-wide approval to become future arbitrary-code authority.
3. Add worker VM egress enforcement so the network independently permits only registered target IPs/ports plus required control-plane endpoints.
4. Add emergency revoke-all semantics that block new signing/execution and terminate active worker execution where possible.
5. Move persistent state to PostgreSQL with separate least-privilege service roles and transactional handling for grants/approvals/jobs/audit/notes.
6. Build a disposable constrained target profile and run the first real PVE end-to-end test with a non-destructive command set.
7. Once that functioning infrastructure-execution version has been tested, merge WIP and update README/docs as required by the operator merge rule.
8. Build the operator UI after backend security flows and data model are stable enough not to redesign the UI around temporary APIs.
9. When the MCP/agent tool interface is implemented, keep it purpose-built and narrow for autonomous Qwen-class models rather than exposing every backend/admin operation.

## Deployment state

Not deployed. No production trust should be placed in the current development branch. No merge to `main` yet because the project has not completed a constrained real-infrastructure end-to-end deployment test.
