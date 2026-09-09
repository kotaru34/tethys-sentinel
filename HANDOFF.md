# Tethys Sentinel — Handoff

Updated: 2026-09-09
Current development version: `0.1.0-dev.0`
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
- Planned boundaries: Control Plane, AI Gateway, Execution Worker, SSH CA/Signer, PostgreSQL/audit storage.
- Prefer VM isolation for security-critical public-facing/backend components rather than putting the whole trust boundary in one LXC.
- Planned SSH model: short-lived OpenSSH certificates; no agent forwarding; forwarding/upload/download are separate capabilities.
- Audit is append-oriented and tamper-evident; raw stdout/stderr retention is configurable because outputs may contain secrets.
- Emergency controls: revoke individual session and revoke all AI access.

## Work completed

- Repository initialized.
- WIP development branch created.
- Initial architecture/threat model documents added in this phase.
- Core opaque-token and capability lifecycle implementation prepared and locally unit-tested.
- Initial risk classifier implementation prepared and locally unit-tested.

## Current phase

Phase 0/1: establish security invariants and implement the capability/policy core before any real SSH execution path is enabled.

## Next implementation steps

1. Commit the tested capability/risk core and CI.
2. Add persistent PostgreSQL model for grants, approvals, audit events, inventory and notes.
3. Split runnable services into control-plane, gateway and worker APIs with least-privilege DB roles/internal interfaces.
4. Implement approval workflow and tamper-evident audit chain.
5. Implement SSH certificate signer and worker only after policy enforcement is covered by tests.
6. Build the operator UI after backend security boundaries and flows are stable.

## Deployment state

Not deployed. No production trust should be placed in the current development branch.
