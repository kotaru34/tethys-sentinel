# Threat Model

## Security objective

Permit useful autonomous infrastructure operations while assuming the AI client can become confused, prompt-injected, malicious, compromised, or strategically adversarial.

The design must constrain what the client can physically cause, not merely instruct it to behave.

## Primary threats

### Prompt injection through operational data

Logs, files, tickets, web pages, historical records, agent notes or command output can contain instructions intended to redirect the model. Sentinel treats these as non-authoritative data. Only `TRUST_0` system context and explicit operator decisions can define authority.

The control plane generates the Trust-0 context bundle and filters inventory/runbooks by grant targets. The AI-facing gateway has no endpoint for changing authoritative context.

### Authoritative-context tampering

If an attacker can modify the Trust-0 source, prompt-level provenance protections are defeated even though hard capability boundaries remain. The current parser rejects unknown fields and multiple/concatenated JSON values and hashes the source/documents. Production deployment must additionally make the authoritative source operator-owned and read-only to Sentinel runtime identities, or move it into an equivalently protected control-plane store.

### Stolen capability token

Opaque capability tokens are bearer secrets by default. Mitigations: high entropy, short TTL, server-side revocation, narrow scope, token hashes at rest, TLS, and optional proof-of-possession binding in a later milestone.

### Gateway compromise

A remote-code-execution bug in the AI-facing gateway must not become grant-issuance, worker-control, or CA-key compromise. The gateway is separated from the control-plane/admin interface and signer, cannot expand capabilities, request SSH certificates or create worker jobs outside the authoritative submit flow, and sends only capability hashes to internal APIs. The control plane re-authenticates and re-enforces permissions/targets for authoritative operations and resource reads.

### Authorize/execute substitution (TOCTOU)

A separable `authorize this command` then `execute this command later` flow allows an attacker to race or substitute target/argv between the two decisions. Sentinel therefore uses atomic command submission: the Control Plane authorizes and creates one immutable job bound to grant + request ID + target + argv.

The AI never receives a mutable executable envelope or a worker claim secret.

### Execution request replay or rebinding

An agent/network retry or adversary may try to reuse a request ID for another command or replay a previously accepted operation. Per-grant request IDs are idempotent for identical command material and conflict on rebinding. Worker claim/start/complete state transitions are one-shot.

### Execution-job store tampering

An attacker with write access to the bootstrap job file may attempt to change target, argv, status, approval metadata or expiry. Records are HMAC-SHA-256 protected using a Control-Plane-only integrity key. Invalid records fail closed.

This does not protect against an attacker who has fully compromised the Control Plane and stolen the HMAC key; that is outside the guarantee of the bootstrap file store. Production persistence will move to a stronger transactional architecture.

### Approval/queue crash window

A crash after consuming `allow_once` but before making the job claimable could otherwise either lose the authorized action or invite a second approval/job on retry. Sentinel stages the immutable job before approval consumption, keeps staged jobs unclaimable, and recovers the matching staged job using the same request ID after restart/retry.

### Revocation race

A grant may be revoked after a job was queued or even after a worker claimed it. Revocation cancels unclaimed jobs, while claimed jobs still require an authoritative `start` call that revalidates the original grant immediately before executor invocation.

`0.1.0-dev.5` adds another checkpoint before SSH credential issuance: the Control Plane will not request a certificate unless the job is already `running`, the claim secret remains valid, the immutable command binding still verifies, the job is unexpired, and the original grant is still active.

A revocation after a certificate has already been issued cannot retroactively revoke an OpenSSH certificate already accepted by a target. This is mitigated by very short certificate lifetime, exact source binding and job-expiry capping. Active-session termination and stronger mid-command revocation are executor-level requirements for a later milestone.

### Worker compromise

The worker is assumed potentially compromisable independently of the Control Plane. It receives only immutable jobs and a dedicated worker credential; it cannot create/broaden grants, approve commands, mutate Trust-0 context or call the SSH Signer directly.

The worker verifies canonical command binding locally, creates a fresh Ed25519 keypair per job in process memory, sends only the public key to the Control Plane, and verifies that any returned certificate belongs to that keypair and does not outlive the job.

Future deployment must additionally isolate the worker at the VM/network level and restrict its egress to target SSH addresses plus required control-plane endpoints.

### SSH CA private-key compromise

The SSH CA is a high-value signing authority. `sentinel-signer` is a separate service boundary so compromise of the AI Gateway or ordinary worker does not directly reveal the CA private key.

The signer rejects non-Ed25519 CA keys, rejects CA key files with group/other access, and should run in a dedicated isolated VM with a narrowly scoped client CA and bearer credential. Production hardening may later move signing into Vault/HSM-backed storage, but the current private-key file must never be mounted into Gateway or Worker environments.

### Signer confused-deputy / overbroad certificate request

A compromised caller could attempt to ask the Signer for a shell-capable certificate, broad source network, different principal or long validity. The Signer request intentionally has no fields for principal, arbitrary force-command, source-address list, certificate extensions or TTL.

Signer-owned policy always supplies:

- one configured principal;
- exact worker source IPs only;
- a generated force-command using a fixed wrapper path and validated job/binding identifiers;
- empty certificate extensions;
- short validity capped by Control-Plane supplied job expiry.

The Control Plane remains responsible for proving that the job is eligible before calling the Signer; the Signer remains responsible for certificate shape.

### Stolen worker ephemeral private key

A per-job SSH private key exists only in worker process memory. Theft during the short job window could permit use of the matching certificate, but blast radius is limited by certificate validity, exact source-address constraint, principal, force-command and eventual remote account policy. The key is never persisted or returned to the AI agent.

### Certificate replay from another machine

A stolen certificate/private-key pair should not be useful from arbitrary infrastructure. The Signer emits OpenSSH `source-address` critical options restricted to configured exact worker addresses (`/32` or `/128`). A production deployment must ensure those addresses cannot be trivially spoofed across the path to SSH targets.

### Certificate privilege expansion

OpenSSH certificate extensions can implicitly grant PTY, agent forwarding, port forwarding or X11 forwarding. Sentinel currently signs with an empty extension map, so none of those privileges are granted by the certificate.

The generated `force-command` is also signer-owned and references a fixed remote wrapper path. The next milestone must implement that wrapper as root/operator-owned code and must not allow user-controlled shell interpretation of its job/binding parameters.

### SSH host impersonation

`dev.5` does not yet dial SSH. The next executor milestone must use pinned host keys or a trusted SSH host CA and must fail closed on host identity mismatch. `StrictHostKeyChecking=no` or equivalent trust-on-first-use shortcuts are outside the intended production design.

### Policy/classifier bypass

String/regex inspection can be bypassed through interpreters, shell indirection, alternate binaries or complex arguments. Command classification is therefore only one layer. Remote accounts, sudo/doas rules, SSH certificate constraints, forced-command wrapper and restricted execution paths enforce hard limits underneath it.

### Dangerous but legitimate command

A valid session may request an operation whose blast radius is disproportionate. Sensitive categories require a human approval decision unless an explicit narrow session approval already exists.

### History or memory scope leakage

A new agent session should gain useful continuity without being shown unrelated infrastructure or sessions. History is filtered by target plus current/previous-session and other-agent scope. Agent notes are filtered by target and require explicit notes permissions. History/notes responses are marked `TRUST_2` and `authoritative: false`.

### Audit tampering

A compromised component may attempt to rewrite history. Audit events are append-oriented and chained by sequence number, previous hash and SHA-256 event hash. The chain is verified on startup and re-verified for history reads, so post-startup modification is detected. External sealing remains a future hardening step against an attacker able to rewrite the complete store and restart all trusted components consistently.

SSH certificate issuance is also audited with job identity, command binding, serial and certificate/key/CA fingerprints. If that audit append fails after signing, the Control Plane cancels the job and withholds the certificate from the worker.

### Agent-note tampering

Each note has a SHA-256 content hash and the note store validates records when opened/read; note creation is also recorded in the audit chain. Notes are nevertheless non-authoritative continuity data. Stronger transactional persistence and cross-store integrity will be addressed when state moves to PostgreSQL.

### Secret leakage into history

Command output may include credentials or private data. Metadata is auditable; raw stdout/stderr storage will be configurable, encrypted when persisted, retention-limited, and subject to redaction where practical. `0.1.0-dev.5` does not persist raw execution output.

### Persistence after expiry

A compromised agent should not convert a short grant into permanent infrastructure access. Agents cannot access SSH CA keys or long-lived infrastructure keys. Worker keys are ephemeral per job, and signed credentials are short-lived and capped by job expiry. Agent forwarding and port forwarding are not granted by the current certificate profile.

## Security invariants

- AI-facing API cannot create or widen grants.
- AI-facing API cannot modify system policy or authoritative instructions.
- AI-facing API cannot disable or delete audit records.
- AI-facing API cannot directly claim, start or complete worker jobs.
- AI-facing API cannot request SSH certificates or access the SSH Signer.
- Trust-2 history/notes cannot become authority by content alone.
- Context/history/notes are filtered against the control-plane view of the current grant.
- Raw infrastructure private SSH keys are never returned to an agent.
- SSH CA private key is not present in the Gateway or Worker boundary.
- Worker per-job SSH private keys are generated ephemerally and are not persisted.
- Grant lookup stores a one-way token hash, never the plaintext capability.
- Expired/revoked grants fail closed.
- Empty/malformed execution requests fail closed.
- A request ID cannot be rebound to different target/argv within a grant.
- Staged jobs are not claimable.
- Claimed jobs are not executable until the Control Plane start gate revalidates the grant.
- SSH certificates are issued only for `running`, unexpired, binding-valid jobs whose grant still authenticates.
- Worker claim/start/complete credentials are one-shot with respect to job state.
- Signer callers cannot choose principal, arbitrary force-command, source-address restrictions, certificate extensions or signer TTL.
- Signed SSH credentials do not outlive the execution job.
- Current SSH certificates grant no PTY, agent forwarding, port forwarding or X11 forwarding extensions.
- Dangerous-action approval is scoped, not a blanket bypass.
- Signer is not directly reachable through the public AI API.
- A functioning release is not considered deployable until tested.

## Out of scope for the first milestones

- defending a fully compromised hypervisor
- protecting against a malicious operator with full host/root access
- formal verification
- arbitrary shell being made intrinsically safe by parsing alone
- guaranteeing interruption of an already-running remote command before the executor milestone implements process/session cancellation
- real SSH host-key verification and remote wrapper enforcement before the executor milestone
