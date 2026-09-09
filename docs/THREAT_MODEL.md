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

### Gateway compromise

Gateway compromise must not become grant issuance, target mutation, worker control, arbitrary SSH destination selection or CA compromise.

Gateway has no such APIs. It forwards capability hashes, not plaintext tokens, and Control Plane re-authenticates/re-enforces authoritative operations.

`dev.7` adds an early Gateway `exec`/`shell` consistency filter, but the system does **not** trust it as the hard boundary; signing rechecks current policy and grant permissions independently.

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

A full argv hash does not make arbitrary code safe for session reuse. Identical:

```text
bash /tmp/task.sh
```

can execute different content after `/tmp/task.sh` changes. The same applies to container images, remote systems, configuration and other mutable inputs.

Therefore `ARBITRARY_CODE`, `PRIVILEGE_LAUNCHER` and `REMOTE_EXEC` support only `allow_once`. `allow_session` is rejected for those categories. Legacy persisted unsafe session approvals are ignored by matching after upgrade.

Stable semantic categories may still support narrowly scoped session approval.

### Missing shell capability

An operator approval must not silently broaden the capability itself. `exec=true` authorizes ordinary structured execution; powerful execution additionally requires `shell=true`.

Gateway rejects obviously unreachable powerful submissions early. More importantly, immediately before SSH signing the Control Plane re-authenticates the grant and refuses powerful categories without `shell=true`, so a compromised Gateway or stale queued job cannot turn operator approval into missing authority.

### Risk-policy change after queueing

An accepted job must not freeze old classifier semantics indefinitely.

Before signing, Control Plane reclassifies immutable `job.argv` using current code and requires current category + scope key to exactly equal job metadata. Denied or changed policy cancels/rejects the job before a credential is returned.

This makes policy hardening apply to already queued/running jobs rather than grandfathering older decisions.

### Interpreter / arbitrary-code carrier bypass

Shells, interpreters and command-carrier tools can encode behavior that top-level executable rules cannot prove safe. `dev.7` treats known carriers conservatively instead of parsing their languages.

Examples include shells, Python/Perl/Ruby/Node/etc., generic launchers (`env`, `xargs`, `timeout`, editors/debuggers and similar tools), container run/exec, `find -exec`, tar checkpoint exec and arbitrary non-system absolute binaries.

These become `ARBITRARY_CODE`, require `shell=true`, and require one-shot approval over complete argv scope.

This is containment, not proof of safety. The carrier can still execute whatever the target account and lower privilege/network layers permit.

### Privilege-launcher bypass

Tools such as `sudo`, `doas`, `su`, `pkexec`, `setpriv`, `capsh`, `chroot`, `nsenter`, `unshare`, `systemd-run` and `machinectl` can broaden identity, namespace or process authority.

They are classified `PRIVILEGE_LAUNCHER`, require `shell=true`, and are allow-once only. Actual elevated authority still depends on target-side sudo/doas/Unix policy; classifier approval alone cannot create root access.

### Remote execution / lateral pivot

SSH-family tools, Ansible/Salt, netcat/socat-style pivots, Kubernetes exec/port-forward operations and remote `systemctl` transports can cross the intended logical target boundary.

They are classified `REMOTE_EXEC`, require `shell=true`, and are allow-once only. Production worker/target network policy must still independently restrict possible egress.

### Classifier incompleteness

The classifier is a risk-routing layer, not a complete proof system. Alternative binaries, complex options and yet-unknown shell escapes may exist.

Independent enforcement remains mandatory: capability target/permission scope, approval policy, immutable job binding, certificate constraints, exact target identity, remote Unix permissions, narrow sudo/doas rules and network isolation.

Additional semantic operational-risk coverage remains a subsequent milestone.

### Revocation race

Revocation cancels unclaimed jobs. Claimed jobs still require `start`, which revalidates the original grant. Running jobs must pass another grant/current-policy check before certificate issuance.

After an SSH certificate has already been accepted, OpenSSH cannot retroactively revoke that credential. Mitigations: short TTL, exact source binding, job-expiry cap, worker execution context capped by job expiry and target one-shot replay state. Global active-session termination remains a later emergency-control milestone.

### Worker compromise

Worker compromise must not become policy/grant/CA compromise. Worker receives immutable jobs and dedicated worker credential only; it cannot broaden grants, approve requests, mutate Trust-0 or call Signer directly.

It generates per-job Ed25519 keys in memory and receives target transport only from Control Plane. Production deployment must independently restrict worker VM egress.

### Arbitrary SSH destination / SSRF pivot

Agent controls only a logical target in its grant. It cannot provide hostname, IP, port, Unix user or host key.

Control Plane target registry accepts concrete literal IPv4/IPv6 + port and rejects DNS/unspecified/malformed endpoints. This makes destination deterministic for firewall enforcement.

### SSH host impersonation

Worker uses exact raw pinned SSH host public key. Mismatch aborts handshake before exec. TOFU, empty host callbacks or insecure host-key acceptance are outside the design.

### Stalled handshake / long-running session

TCP dial and SSH handshake are bounded. Execution context cannot outlive job expiry and closes the SSH client when deadline/cancellation fires.

Certificate expiry alone is not assumed to terminate an already-established session.

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

Certificate issuance is audited. If audit append fails after signing, certificate is withheld and job rejected/canceled.

### Persistence after expiry

Agents do not receive CA keys or long-lived infrastructure keys. Worker credentials are ephemeral and short-lived; execution session is job-deadline bounded; forwarding extensions are absent; target job can be consumed once.

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
- Pre-certificate gate reclassifies immutable argv with current policy and rejects stale category/scope.
- Context/history/notes are scoped against current grant; Trust-2 cannot become authority by content.
- Agent never receives raw infrastructure SSH private keys.
- CA private key is absent from Gateway/Worker.
- Worker per-job private keys are ephemeral and not persisted.
- Plaintext capability is not stored; token hash is persisted.
- Expired/revoked grants fail closed.
- Request ID cannot be rebound to different target/argv.
- Staged jobs are unclaimable.
- Claimed jobs require authoritative start revalidation.
- SSH certificate requires running, unexpired, binding-valid, current-policy-valid job and active grant.
- Signer caller cannot broaden principal/force-command/source/extensions/TTL.
- Certificate does not outlive job and grants no PTY/agent/port/X11 forwarding.
- Worker target is literal IP from operator-owned inventory and host key is exactly pinned.
- Wrapper directly executes verified argv, verifies local target identity, and consumes root-protected replay marker.
- Worker execution is bounded by job expiry and output limit.
- A functioning release is not production-deployable until tested on intended isolated infrastructure.

## Out of scope for early milestones

- fully compromised hypervisor
- malicious operator with host root
- formal verification
- proving arbitrary shell/interpreter content intrinsically safe
- instantaneous guaranteed termination of every descendant process on every target OS after session loss
- production persistence before PostgreSQL migration
