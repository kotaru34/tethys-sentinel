# Architecture

## Trust-boundary overview

```text
                              Operator
                                 |
                         Admin UI / API
                                 |
                    +------------v------------+
                    |      Control Plane      |
                    | grants / policy         |
                    | approvals / Trust-0     |
                    | security epoch / kill   |
                    | immutable job issuance  |
                    | SSH target resolution   |
                    | certificate gate        |
                    +------+-------------+----+
                           |             |
             internal mTLS |             | dedicated mTLS + signer credential
                           |             |
                  +--------v--+       +--v-----------+
                  | AI Gateway|       | SSH Signer   |
                  | public API|       | CA boundary  |
                  +-----------+       +--------------+
                           |
                           | worker-only internal API
                           v
                +----------+-----------+
                | External worker      |
                | network boundary     |
                | Control + SSH only   |
                +----------+-----------+
                           |
                    +------v-------+
                    | Execution    |
                    | Worker       |
                    | ephemeral key|
                    | active lease |
                    | pinned SSH   |
                    +------+-------+
                           |
                           | externally allowed,
                           | operator-resolved literal IP
                           v
                    +------+----------------+
                    | Target sshd           |
                    | trusted Sentinel CA   |
                    | dedicated account     |
                    +------+----------------+
                           |
                           | certificate critical force-command
                           v
                    +------+----------------+
                    | tethys-sentinel-exec  |
                    | verify binding/target |
                    | one-shot replay gate  |
                    | direct exec(argv)     |
                    +-----------------------+
```

Bootstrap persistence still uses restricted local files for grants, approvals, audit, notes, authoritative context, execution jobs, and emergency authority state. These are development mechanisms for testing security boundaries before PostgreSQL; they are not intended production persistence.

## Components

### Control Plane

Human/operator authority. Owns grant creation/revocation, global security epoch, emergency enable/disable state, policy decisions, approvals, Trust-0 context/inventory, history filtering, immutable execution-job issuance, SSH target resolution, certificate eligibility, and audit integration.

Only Control Plane can publish executable jobs and call SSH Signer. It recomputes policy/risk state instead of trusting agent/Gateway labels.

Authoritative context comes from `SENTINEL_CONTEXT_FILE`. SSH transport resolution comes from `SENTINEL_SSH_TARGETS_FILE` (default `/etc/tethys-sentinel/ssh-targets.json`); jobs contain only logical target IDs, while the registry maps them to global-unicast literal IP/port, Unix user, and exact pinned raw host key.

Emergency authority state comes from `SENTINEL_EMERGENCY_STATE` (default `/var/lib/tethys-sentinel/emergency.json`) in the bootstrap implementation.

### Global emergency authority boundary

`0.1.0-dev.10` introduces a monotonic security epoch rather than a reversible boolean kill switch.

Every newly issued grant is stamped with current `security_epoch`. Grant authentication requires:

1. global AI access is enabled;
2. grant epoch exactly equals current epoch;
3. grant itself is not revoked or expired.

`REVOKE ALL` increments the epoch and disables access. A later `Enable` leaves the incremented epoch intact. Therefore every pre-revoke token stays stale forever and recovery requires fresh grants.

The emergency transition also cancels all non-running execution jobs (`staged`, `pending`, `claimed`), clears claim-secret hashes, suppresses new worker claims, and is audited. Existing `start` and pre-certificate checks inherit epoch validation through the capability service.

A revoke is a safety-direction transition. If bootstrap-state persistence fails, the live Control Plane deliberately keeps the new disabled epoch in memory and reports an error; an operator must not restart until durable emergency state is repaired/reconciled. Enabling behaves oppositely: persistence failure restores the prior disabled state.

See `docs/EMERGENCY_CONTROLS.md`.

### AI Gateway

Public capability-facing boundary. Exposes bootstrap/context/history/notes and atomic command submission. It has no grant creation, emergency mutation, approval mutation, worker control, target mutation, certificate signing, or CA-secret path.

Gateway performs early `exec`/`shell` consistency checks for better protocol behavior, but Control Plane remains authoritative. A compromised Gateway cannot bypass epoch, grant, policy, target, signer, worker, or network boundaries.

### Execution policy boundary

`dev.7` made `exec` and `shell` distinct authorization dimensions.

- `exec` permits ordinary structured argv operations within logical target scope.
- `shell` additionally permits powerful execution classes capable of arbitrary code, privilege broadening, or lateral/remote execution.

`ARBITRARY_CODE`, `PRIVILEGE_LAUNCHER`, and `REMOTE_EXEC` require `shell=true` and are allow-once only. Their approval scope includes a canonical hash of complete argv including executable path, but identical argv is not treated as immutable behavior.

See `docs/EXECUTION_POLICY.md`.

### Semantic operational-risk layer

`dev.8` adds separate semantic classification for high-impact administrator mutation: services/system managers, network/firewall state, packages, storage/raw writes, kernel/process/log controls, containers/orchestrators, hypervisors and jails across intended Linux/BSD/PVE environments.

Reliable inspection-only forms stay autonomous; mutation forms require approval; ambiguous sensitive forms fail conservatively. Generic filesystem writes are not treated as a substitute for Unix permissions/sudo/doas enforcement.

See `docs/OPERATIONAL_RISK.md`.

### External worker network boundary

`dev.9` independently contains the worker network even if worker application logic is compromised.

For PVE, hard runtime egress enforcement lives outside the guest on the VM-interface firewall. Normal worker egress is only:

1. literal-IP HTTPS Control Plane endpoint;
2. registered global-unicast literal IP:port SSH endpoints.

`sentinel-egress-policy` deterministically renders/verifies `policy_out: DROP` policy, explicit destination+TCP-port allows, target deduplication, canonical policy SHA-256, installed-file drift, Datacenter firewall activation, and `firewall=1` on the selected VM NIC. It does not apply firewall configuration and is never an AI/worker privilege.

Guest nftables may exist only as defense in depth. Packet-level behavior from inside the worker VM remains mandatory for infrastructure acceptance.

See `docs/WORKER_EGRESS.md`.

### Execution Worker

Private execution boundary. Never receives plaintext agent capability and cannot administer grants/policy/emergency state/CA/network policy.

Current worker flow:

1. claim one immutable pending job with worker credential;
2. locally verify command binding;
3. call authoritative Control Plane `start` gate;
4. generate a fresh per-job Ed25519 keypair in memory;
5. send only public key for certificate issuance;
6. receive short-lived certificate plus operator-resolved target;
7. verify certificate/key/job lifetime and logical target;
8. perform a mandatory active-authority check;
9. create executor context bounded by remaining authoritative job lifetime;
10. dial only resolved literal IP/port allowed by external egress policy;
11. verify exact pinned SSH host key;
12. while execution remains active, re-check authority periodically;
13. on authority failure cancel executor context/SSH transport;
14. complete once with terminal result metadata/output digest.

Default active-authority interval is 250 ms (`SENTINEL_WORKER_AUTHORITY_POLL_MS`). Each check uses the same interval as its request timeout. Explicit denial **or inability to verify authority** is fail-closed.

Authority check requires global access enabled, running/unexpired job, valid claim secret, active original grant, and exact current security epoch. Individual grant revoke therefore terminates active execution through the same path as global revoke.

If SSH access issuance fails after `start` (for example, revoke arrives before certificate issuance), worker completes the running job with `ssh_access_issuance_failed` rather than leaving it stuck.

Active cancellation closes Sentinel's worker-side SSH transport. It cannot generically prove that a command which already daemonized/detached/scheduled work on the target has no surviving descendant. Target privilege restrictions and command design remain independent controls.

### Pre-certificate policy and authority gate

Immediately before infrastructure credentials are returned, Control Plane validates running job/claim/binding, re-runs current risk policy, requires category/scope equality, re-authenticates original grant under current epoch, requires `shell=true` when needed, resolves protected target, and only then calls Signer.

This prevents queued jobs from freezing either an old classifier decision or a pre-revoke authority epoch.

### SSH Signer

Standalone CA boundary. `sentinel-signer` owns CA private key. Normal operation requires dedicated bearer credential + mutual TLS.

Caller cannot choose principal, source addresses, arbitrary force-command, extensions, or TTL. Signer requires per-job Ed25519 key, fixed wrapper, empty PTY/agent/port/X11 forwarding extensions, exact source binding and short validity capped by job expiry.

### Target execution boundary

Signer-generated critical `force-command` invokes `tethys-sentinel-exec` with signer-controlled job ID and command binding. Agent argv travels separately in deterministic versioned base64url JSON through `SSH_ORIGINAL_COMMAND`.

Wrapper verifies local operator-owned target ID and binding, uses fixed executable-resolution/environment rules, consumes root-protected one-shot replay state via narrow `tethys-sentinel-consume`, then direct-executes argv without shell reconstruction.

Target account/sshd independently disables PTY, forwarding, password/keyboard-interactive authentication, tunneling, environment injection and ordinary key bypasses. Elevated operations require explicit narrow target sudo/doas policy.

## Capability model

A grant includes opaque token/hash, grant/session identity, agent/purpose, logical targets, expiry/revocation state, `security_epoch`, `exec`, `shell`, upload/download, and scoped history/notes permissions.

Capability never contains infrastructure SSH private keys, transport endpoint, host key, CA authority, or ability to mutate itself/global epoch.

## Authoritative context

Gateway exposes read-only bundle generated by Control Plane. Trust-0 policy/capability/inventory/runbook/operator material is authoritative; history/notes remain `TRUST_2`; files/logs/web/output remain non-authoritative data. Provenance is behavioral hardening, not authorization.

## Risk approvals

Sensitive operations may require deny, allow-once, or narrowly scoped allow-for-session. Powerful execution classes are never session-reusable. Human approval cannot manufacture missing capability or override global disabled/stale-epoch state.

## Execution-job protocol

```text
staged -> pending -> claimed -> running -> succeeded/failed
                  \-> canceled/expired where applicable
```

Staged jobs are durable but unclaimable; pending jobs claim once; claim plaintext is not persisted; job records are HMAC-protected; target/argv are canonically bound; request IDs prevent rebinding; start revalidates authority; certificate issuance revalidates current policy/capability/epoch/target; target consumes local replay marker; completion is terminal and one-shot.

Global revoke additionally cancels staged/pending/claimed jobs. Running jobs are terminated via active worker lease and complete through the normal terminal path.

## Persistent state

Production state is planned for PostgreSQL with separate least-privilege roles and transactional semantics for grants, security epoch, approvals, jobs, audit/history and notes. Raw command output remains independently controlled because it can contain secrets.

## Defense in depth

1. Trust/provenance instructions.
2. Capability target/permission scope (`exec`/`shell`).
3. Monotonic global security epoch + emergency disable state.
4. Current Control Plane powerful + operational risk policy.
5. Human approval with category-specific reuse rules.
6. Immutable staged jobs + HMAC/request replay protection.
7. Authoritative start/grant/epoch revalidation.
8. Pre-certificate current-policy + grant/epoch revalidation.
9. Isolated SSH CA and signer-owned certificate shape.
10. Ephemeral per-job private keys.
11. Operator-owned global-unicast target registry + exact host-key pinning.
12. External worker VM egress allowlist enforced outside guest.
13. Mandatory pre-exec + periodic active-authority lease.
14. Job-expiry/handshake/output bounds.
15. Root/operator-owned forced wrapper with binding/target verification.
16. Root-protected target at-most-once replay marker.
17. Remote Unix permissions and narrow sudo/doas policy.

No single layer is sufficient.
