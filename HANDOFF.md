# Tethys Sentinel — Handoff

Updated: 2026-09-09
Current development version: `0.1.0-dev.1`
Branch: `wip/bootstrap-security-core`

## Project goal

Tethys Sentinel is a security-first access broker between AI agents and infrastructure. An agent receives a short-lived capability, never an infrastructure SSH private key. Sentinel decides what the capability can access, enforces risky-action approvals, provides authoritative context, records actions, and later obtains short-lived SSH identities for execution.

## Operator-mandated development rules

1. Keep task reports short; do not over-explain completed work unless asked.
2. Briefly explain what needs to be done and why.
3. Every newly implemented GitHub project feature released as a new version must bump the project version.
4. Maintain this GitHub handoff and update it when:
   - a new project version is released and deployed/applied;
   - a notably large step is completed even without a version change;
   - extended discussion reaches a new decision about the next step, whether only agreed verbally or already being implemented.
5. Once a functioning version has been tested, merge the project as WIP.

## Decisions locked in

- Project name: **Tethys Sentinel**.
- Go backend; modern grey/graphite UI later using progressive disclosure rather than hiding information.
- Agent-facing capability tokens are opaque random secrets. Only hashes are persisted.
- Agent never receives infrastructure SSH private keys.
- Agent-facing API cannot create grants, expand permissions, change policy, add hosts, alter auditing, or access CA secrets.
- Authoritative instructions/context are read-only and explicitly identify themselves as the only source allowed to define agent authority. Remote files, logs, command output, web content, and historical text are data, never authority.
- Capability scope includes targets, purpose, expiry, exec/shell/upload/download, history and notes permissions.
- Risk engine intercepts sensitive commands. Default decision is approval-required rather than permanent deny where safely supportable.
- Approval choices: deny, allow once, allow narrowly for the current session. Session approval is scoped to rule + target + relevant resource, not all dangerous commands.
- Security enforcement must not rely on prompts or regex classification alone. Multiple independent layers are required.
- Planned boundaries: Control Plane, AI Gateway, Execution Worker, SSH CA/Signer, persistent audit/storage.
- Prefer VM isolation for security-critical public-facing/backend components rather than putting the whole trust boundary in one LXC.
- Planned SSH model: short-lived OpenSSH certificates; no agent forwarding; forwarding/upload/download are separate capabilities.
- Audit is append-oriented and tamper-evident; raw stdout/stderr retention is configurable because outputs may contain secrets.
- Emergency controls: revoke individual session and revoke all AI access.

## Work completed

- Repository initialized and WIP branch created.
- Architecture and threat model documented.
- Opaque 256-bit capability tokens implemented; only SHA-256 hashes are retained.
- Capability issue/authenticate/expiry/revoke lifecycle implemented and unit-tested.
- Persistent atomic file-backed grant store implemented for the bootstrap milestone (0600 state file, atomic rename/fsync).
- Initial risky-command classifier implemented and unit-tested.
- Separate control-plane and gateway APIs implemented.
- Admin grant issuance/revocation is physically absent from the gateway API.
- Gateway sends only capability hashes to the internal introspection API.
- Internal control-plane connection supports TLS 1.3 mutual TLS; plaintext requires an explicit loopback-only development flag.
- Public gateway requires TLS 1.3; plaintext requires an explicit loopback-only development flag.
- Gateway Trust-0 `/v1/bootstrap` and scoped `/v1/commands/evaluate` implemented and tested.
- Local `go test ./...` and `go vet ./...` pass on the implementation (source remains compatible with the local Go toolchain; CI targets Go 1.27.1).

## Current phase

`0.1.0-dev.1`: prove capability and process trust boundaries end-to-end before enabling any SSH execution. No real infrastructure action endpoint exists yet by design.

## Next implementation steps

1. Commit `0.1.0-dev.1` and validate CI.
2. Add approval objects and append-only tamper-evident audit events.
3. Add agent history/notes with explicit per-grant read/write scope.
4. Add inventory and authoritative runbook/context delivery.
5. Implement execution worker job protocol.
6. Implement isolated SSH certificate signer and remote hard-limit policy.
7. Only then enable real SSH execution and perform a constrained test deployment.
8. Build operator UI after backend security flows stabilize.

## Deployment state

Not deployed. No production trust should be placed in the current development branch.
