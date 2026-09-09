# Threat Model

## Security objective

Permit useful autonomous infrastructure operations while assuming the AI client can become confused, prompt-injected, malicious, compromised, or strategically adversarial.

The system must constrain what the client can physically cause, not merely instruct it to behave.

## Primary threats

### Prompt injection through operational data

Logs, files, tickets, web pages, history, notes and command output can contain hostile instructions. They are non-authoritative data. Only `TRUST_0` system material and explicit operator decisions may define authority.

The Gateway has no Trust-0 write API. Prompt provenance is behavioral hardening; server-side capabilities and policy are the actual boundary.

### Authoritative-context tampering

If an attacker can alter Trust-0 source material, prompt-level provenance is defeated even though lower capability boundaries remain. Current parsers reject unknown/trailing JSON and hash authoritative content. Production state must be operator-owned/read-only to service identities or stored in equivalently protected persistent state.

### Stolen capability token

Capabilities are high-entropy opaque bearer secrets. Mitigations: short TTL, narrow targets/permissions, server-side revocation, hashes at rest, TLS and later optional proof-of-possession.

`dev.10` additionally stamps every grant with the current monotonic emergency authority epoch. Global revoke-all increments the epoch and disables AI access. Re-enabling access does not make any older capability valid again.

### Gateway compromise

Gateway compromise must not become grant issuance, target mutation, worker control, arbitrary SSH destination selection or CA compromise.

Gateway has no such APIs. It forwards capability hashes, not plaintext tokens, and Control Plane re-authenticates/re-enforces authoritative operations.

The early Gateway `exec`/`shell` consistency filter is not the hard boundary; signing rechecks current policy and grant permissions independently.

### Authorize/execute substitution (TOCTOU)

A separable authorize-now/execute-later design permits target/argv substitution. Sentinel instead atomically submits and creates one immutable job bound to grant + request ID + logical target + argv.

### Request replay and rebinding

Within a grant, request IDs are idempotent for identical command material and conflict on rebinding. Worker claim/start/complete transitions are one-shot.

Target-side replay protection is independent: a root-only helper atomically consumes a marker by execution job ID before process start, preventing repeated use of the same job credential on the target.

### Job-store tampering

Bootstrap job records are HMAC-SHA-256 protected with a Control-Plane-only integrity key. Unauthorized target/argv/status/approval changes fail closed. This does not defend a fully compromised Control Plane holding the key; production state will use stronger transactional isolation.

### Approval/queue crash window

A crash after `allow_once` consumption but before publication must not lose authority or create a second authorization. Jobs are staged durably before approval consumption and remain unclaimable until publication; retry recovers the matching staged job.

### Unsafe reusable approval

A full argv hash does not make arbitrary code safe for session reuse. Identical `bash /tmp/task.sh` can execute different content after the script changes. The same applies to container images, remote systems, configuration and other mutable inputs.

Therefore `ARBITRARY_CODE`, `PRIVILEGE_LAUNCHER` and `REMOTE_EXEC` support only `allow_once`. `allow_session` is rejected for those categories. Legacy persisted unsafe session approvals are ignored by matching after upgrade.

Stable semantic categories may still support narrowly scoped session approval.

### Missing shell capability

An operator approval must not silently broaden the capability itself. `exec=true` authorizes ordinary structured execution; powerful execution additionally requires `shell=true`.

Gateway rejects obviously unreachable powerful submissions early. More importantly, immediately before SSH signing the Control Plane re-authenticates the grant and refuses powerful categories without `shell=true`, so a compromised Gateway or stale queued job cannot turn operator approval into missing authority.

### Risk-policy change after queueing

An accepted job must not freeze old classifier semantics indefinitely.

Before signing, Control Plane reclassifies immutable `job.argv` using current code and requires current category + scope key to exactly equal job metadata. Denied or changed policy cancels/rejects the job before a credential is returned.

This makes both powerful-command hardening and dev.8 operational semantic hardening apply to already queued/running jobs rather than grandfathering older decisions.

### Interpreter / arbitrary-code carrier bypass

Shells, interpreters and command-carrier tools can encode behavior that top-level executable rules cannot prove safe. Sentinel treats known carriers conservatively instead of parsing their languages.

Examples include shells, Python/Perl/Ruby/Node/etc., generic launchers, container execution/start/build, `find -exec`, executable tar/cpio modes, build/compiler/linker/VCS escape surfaces and arbitrary non-system absolute binaries.

These become `ARBITRARY_CODE`, require `shell=true`, and require one-shot approval over complete argv scope.

This is containment, not proof of safety. The carrier can still execute whatever the target account and lower privilege/network layers permit.

### Privilege-launcher bypass

Tools such as `sudo`, `doas`, `su`, `pkexec`, `setpriv`, `capsh`, `chroot`, `nsenter`, `unshare`, `systemd-run` and `machinectl` can broaden identity, namespace or process authority.

They are classified `PRIVILEGE_LAUNCHER`, require `shell=true`, and are allow-once only. Actual elevated authority still depends on target-side sudo/doas/Unix policy; classifier approval alone cannot create root access.

### Remote execution / lateral pivot

SSH-family tools, Ansible/Salt, netcat/socat-style pivots, Kubernetes exec/copy/port-forward, container remote contexts, namespace/jail exec, and VM monitor/guest paths can cross the intended logical target boundary.

They are classified `REMOTE_EXEC`, require `shell=true`, and are allow-once only. Production worker/target network policy must still independently restrict possible egress.

### High-impact administrator mutation left as DEFAULT

A command can be dangerous without being an arbitrary-code carrier. Service state, routing/firewall policy, package state, storage topology, kernel controls, containers/orchestrators and hypervisors have large blast radius even when argv is structured.

`dev.8` adds semantic operational classifiers for known mutation primitives across Linux/BSD/PVE administration. Known read-only inspection forms remain ordinary `exec`, while mutation forms require approval.

Sensitive ambiguous forms fail conservatively. Firewall handling, for example, permits known inspection such as `nft list ruleset`, `iptables -nvL`, and `pfctl -vvsr`, while mixed/bundled mutation forms such as `iptables -LZ` and `pfctl -vnf ...` remain `NETWORK_CONTROL`.

This reduces dangerous `DEFAULT` gaps but does not prove that all unclassified commands are harmless.

### Overbroad operational approval

A semantic category must not become blanket authority over every operation in that category.

Stable service operations bind executable + action + concrete unit/resource. Broader administrator mutations generally bind exact full argv. Approval matching additionally includes grant, target and risk category.

Powerful workload-start/exec paths are elevated into dev.7 powerful classes rather than receiving reusable operational approval.

### Classifier incompleteness

The classifier is a risk-routing layer, not a complete proof system. Alternative binaries, complex options, plugins and yet-unknown shell escapes may exist.

Independent enforcement remains mandatory: capability target/permission scope, approval policy, immutable job binding, current-policy certificate gate, exact target identity, remote Unix permissions, narrow sudo/doas rules and network isolation.

Ordinary filesystem authority is deliberately not inferred from generic command names; actual write/root ability remains constrained by the target OS permission boundary.

### Revocation race and stale capability revival

Individual grant revocation still cancels unclaimed work and is rechecked at `start`, certificate issuance, and the active worker authority lease.

`dev.10` adds a separate global authority boundary. `REVOKE ALL` atomically advances a monotonic security epoch and disables global AI access. Every grant records the epoch at issuance. While disabled, new capability use, worker claim, start/signing paths and active authority checks fail closed. Re-enabling keeps the advanced epoch, so grants from every earlier epoch remain permanently invalid and cannot revive.

Non-running `staged`, `pending` and `claimed` jobs are canceled by revoke-all and one-shot claim material is invalidated. A job that already reached `running` is not silently rewritten as completed by the store; the worker continuously checks authoritative lease state and cancels its execution context when authority is lost.

### Kill-switch persistence failure

Emergency disable is more important than preserving a writable state file. If revoke-all updates the live in-memory authority state but persistence fails, the current Control Plane remains disabled and returns an error to the operator. It must not roll the kill switch back merely because disk persistence failed.

A restart after such a persistence failure is unsafe until the operator repairs/validates emergency-state persistence, because an unpersisted in-memory epoch cannot survive process loss.

Re-enable is stricter in the opposite direction: an enable transition that cannot be safely persisted/audited must fail closed and leave or return the system to disabled state.

### Active worker continues after revoke

Certificate expiry and firewall rule removal are not assumed to terminate an already-established SSH session. `dev.10` therefore gives the worker a dedicated internal authority-check endpoint and requires an authoritative check before executor invocation plus short-interval checks while SSH is active.

Default authority polling is approximately 250 ms and each check has a similarly bounded request timeout. Global revoke, individual grant revoke, epoch mismatch, job expiry, invalid claim, or Control Plane loss cancels the worker execution context. The SSH executor closes transport on cancellation.

This is deliberately fail-closed: temporary inability to reach the Control Plane is treated as loss of authority, not permission to keep running.

The mechanism only controls the Sentinel-owned execution/session. It cannot guarantee instantaneous removal of every daemonized/detached child process that a previously authorized target command may already have created. Target-side Unix/service policy and operation-specific controls remain necessary for that class of effect.

### Worker compromise

Worker compromise must not become policy/grant/CA compromise or arbitrary network reachability. Worker receives immutable jobs and dedicated worker credential only; it cannot broaden grants, approve requests, mutate Trust-0 or call Signer directly.

It generates per-job Ed25519 keys in memory and receives target transport only from Control Plane. `dev.9` adds an independent external worker egress boundary so a compromised worker process or guest cannot simply ignore application-level target resolution and dial arbitrary infrastructure.

The production hard boundary is outside the guest. For Proxmox VE this means VM-interface firewall enforcement owned by the operator/hypervisor. Guest-local nftables may be defense in depth but cannot be the sole boundary because guest root/RCE may rewrite it.

A fully compromised worker that also possesses its worker credential can query its own running-job authority endpoint, but that endpoint can only reduce/confirm existing job authority; it cannot mint grants, expand targets, alter epochs, or request arbitrary Signer policy.

### Worker egress confused deputy

A worker or agent must not gain a privileged mechanism for widening its own external firewall.

`sentinel-egress-policy` is intentionally render/verify-only. It accepts protected target inventory plus a literal Control Plane endpoint and produces deterministic policy; it does not apply PVE configuration and must not be exposed through the AI/MCP surface. Worker identities must have no credentials or filesystem/API path that can modify `/etc/pve`, VM NIC firewall flags or equivalent external network policy.

Normal runtime egress is limited to the literal-IP Control Plane HTTPS endpoint and global-unicast literal target SSH IP:port endpoints. DNS, generic LAN access, broad RFC1918 ranges, package mirrors and arbitrary Internet/HTTPS are not implicit runtime permissions.

### Firewall policy drift or inactive enforcement

A correct generated policy file is not evidence that traffic is actually filtered.

The operator-side verifier checks byte-for-byte policy drift, Proxmox Datacenter firewall activation and `firewall=1` on the selected worker VM NIC. The generated VM policy itself uses `enable: 1` and `policy_out: DROP` with explicit destination/port allows only.

These configuration checks are still not sufficient by themselves. Real acceptance requires packet-level tests from inside the worker VM proving that Control Plane and registered SSH endpoints succeed while unrelated LAN/Internet/DNS/unlisted ports fail.

### Stale egress after target-set change

Application inventory and external firewall are separate authority layers and can become temporarily inconsistent.

A newly added target that has reached Control Plane inventory but not external egress policy should fail closed at the network layer. Target removal should preferably narrow external egress first where practical; Control Plane removal independently blocks new normal jobs.

The generated policy includes a canonical SHA-256 over Control Plane + target destination set, and `-check` is intended for operator/Ansible reconciliation to detect drift without granting reconciliation authority to the worker.

### Established connection survives firewall shrink

Removing an allow rule is not treated as guaranteed immediate termination of an already-established stateful TCP flow.

Therefore dev.9 egress enforcement remains a containment boundary rather than a kill switch. `dev.10` independently cancels Sentinel-owned active execution through the continuous authority lease; short SSH certificate TTL, job expiry and target one-shot replay remain additional controls.

### Arbitrary SSH destination / SSRF pivot

Agent controls only a logical target in its grant. It cannot provide hostname, IP, port, Unix user or host key.

Control Plane target registry accepts global-unicast literal IPv4/IPv6 + port and rejects DNS, unspecified, multicast, loopback/link-local and malformed endpoints. This makes destination deterministic for external firewall enforcement.

### SSH host impersonation

Worker uses exact raw pinned SSH host public key. Mismatch aborts handshake before exec. TOFU, empty host callbacks or insecure host-key acceptance are outside the design.

### Stalled handshake / long-running session

TCP dial and SSH handshake are bounded. Execution context cannot outlive job expiry and closes the SSH client when deadline/cancellation fires.

Certificate expiry alone is not assumed to terminate an already-established session. Active authority loss is a separate cancellation source after `dev.10`.

### Output flooding / secret-bearing stdout

Current worker does not persist raw stdout/stderr. It performs bounded SHA-256 accounting. Limit overflow actively closes transport and records `output_limit_exceeded`.

### SSH CA compromise

Signer is a separate service boundary. CA private key is never mounted into Gateway/Worker. Current signer requires Ed25519 key and rejects group/other-readable CA key permissions. Production may later use Vault/HSM-backed storage.

### Signer confused deputy

Caller cannot request arbitrary principal, force-command, source network, extensions or TTL. Signer owns these values and limits validity by job expiry.

Control Plane proves job eligibility; Signer enforces certificate shape.

### Stolen ephemeral worker key

Per-job private key exists only in worker memory. Theft has blast radius limited by short cert validity, source-address critical option, principal, force-command, target binding and target one-shot replay state.

### Certificate replay from another machine

Certificates are source-address restricted to exact worker addresses. Network design must prevent trivial source spoofing. Even from an allowed source, second use of the same job hits target replay state.

### Certificate use on wrong target

Hosts may share the same Sentinel user CA. Therefore CA trust alone does not bind host intent.

Envelope contains logical target; each host has operator-owned local target ID. Wrapper requires equality and recomputes command binding. A `dns01` job fails closed on a host configured as `dns02`.

### Certificate privilege expansion

Current certificate extensions are empty: no PTY, agent forwarding, port forwarding or X11 forwarding. Signer-owned `force-command` points only to fixed wrapper. Target sshd/account policy independently disables escape paths.

### Remote command shell injection

Sentinel never joins agent argv into `/bin/sh -c`. Worker sends versioned base64url JSON envelope; wrapper validates it and directly executes argv. Shell-looking characters are ordinary data unless the explicitly authorized executable is itself a carrier such as a shell/interpreter.

### Target replay-state tampering

Unprivileged remote account must not own/remove replay markers. `tethys-sentinel-consume` requires effective UID 0 and verifies private real directories owned by that UID. Marker creation uses `O_EXCL`.

Privilege rule must expose only that helper, never a general root shell.

### History/memory scope leakage

History is filtered by target/session/agent scope. Notes require explicit permissions and target scope. Both remain `TRUST_2` non-authoritative data.

### Audit tampering

Audit is append-oriented and hash-chained; chain is checked on startup and history reads. External sealing remains future hardening against an attacker able to rewrite all trusted state coherently.

Certificate issuance and emergency transitions are audited. Re-enable is fail-closed around audit so an unauditable transition does not silently restore authority.

### Persistence after expiry

Agents do not receive CA keys or long-lived infrastructure keys. Worker credentials are ephemeral and short-lived; execution session is job-deadline and active-authority bounded; forwarding extensions are absent; target job can be consumed once.

## Security invariants

- AI-facing API cannot create or widen grants.
- AI-facing API cannot modify Trust-0 policy/instructions.
- AI-facing API cannot disable/delete audit.
- AI-facing API cannot claim/start/complete worker jobs or request SSH certificates.
- AI-facing API cannot choose arbitrary SSH destination/user/host key.
- `exec` and `shell` are independent capability permissions.
- Human approval cannot create missing `exec` or `shell` capability.
- `ARBITRARY_CODE`, `PRIVILEGE_LAUNCHER`, and `REMOTE_EXEC` require `shell=true` before signing.
- Those powerful classes are allow-once only; unsafe legacy session approvals never match.
- High-impact known administrator mutations require scoped approval; known inspection-only variants may remain ordinary `exec`.
- Operational approval never overrides target Unix/sudo/doas authority.
- Pre-certificate gate reclassifies immutable argv with current policy and rejects stale category/scope.
- Context/history/notes are scoped against current grant; Trust-2 cannot become authority by content.
- Agent never receives raw infrastructure SSH private keys.
- CA private key is absent from Gateway/Worker.
- Worker per-job private keys are ephemeral and not persisted.
- Plaintext capability is not stored; token hash is persisted.
- Expired/revoked grants fail closed.
- Every grant is bound to an emergency security epoch.
- Global revoke-all advances the epoch and invalidates all older grants permanently, including after re-enable.
- Global disable suppresses worker claims and blocks start/signing through grant re-authentication.
- Global revoke cancels non-running jobs and invalidates claimed one-shot material.
- Running jobs require a fail-closed active authority lease; authority loss or Control Plane loss cancels Sentinel-owned execution.
- Emergency revoke persistence failure does not re-enable the live process in memory.
- Request ID cannot be rebound to different target/argv.
- Staged jobs are unclaimable.
- Claimed jobs require authoritative start revalidation.
- SSH certificate requires running, unexpired, binding-valid, current-policy-valid job and active current-epoch grant.
- Signer caller cannot broaden principal/force-command/source/extensions/TTL.
- Certificate does not outlive job and grants no PTY/agent/port/X11 forwarding.
- Worker target is global-unicast literal IP from operator-owned inventory and host key is exactly pinned.
- Worker runtime egress is externally deny-by-default and limited to Control Plane HTTPS plus registered target SSH endpoints.
- Worker/AI identities cannot apply, widen or reconcile the external PVE egress policy.
- Generated egress policy drift and PVE Datacenter/NIC activation are operator-verifiable and fail closed on mismatch.
- Packet-level worker-VM egress behavior must be tested before treating the infrastructure boundary as accepted.
- Firewall shrink is not assumed to terminate already-established flows; active authority revocation remains independent.
- Wrapper directly executes verified argv, verifies local target identity, and consumes root-protected replay marker.
- Worker execution is bounded by job expiry, active authority and output limit.
- A functioning release is not production-deployable until tested on intended isolated infrastructure.

## Out of scope for early milestones

- fully compromised hypervisor
- malicious operator with host root
- formal verification
- proving arbitrary shell/interpreter content intrinsically safe
- instantaneous guaranteed termination of every detached/daemonized descendant process on every target OS after session loss
- production persistence before PostgreSQL migration
