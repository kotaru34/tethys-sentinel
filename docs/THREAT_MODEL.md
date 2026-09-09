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

A remote-code-execution bug in the AI-facing gateway must not become grant-issuance, worker-control, or CA-key compromise. The gateway is separated from the control-plane/admin interface and signer, cannot expand capabilities, and sends only capability hashes to internal APIs. The control plane re-authenticates and re-enforces permissions/targets for authoritative operations and resource reads.

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

A grant may be revoked after a job was queued or even after a worker claimed it. Revocation cancels unclaimed jobs, while claimed jobs still require an authoritative `start` call that revalidates the original grant immediately before executor invocation. A revoked/expired grant therefore cannot start a not-yet-running command.

Termination of a command that is already running at the moment of revocation is a future executor-level requirement and is not claimed by `0.1.0-dev.4`.

### Worker compromise

The worker is assumed potentially compromisable independently of the Control Plane. It receives only immutable jobs and a dedicated worker credential; it cannot create/broaden grants, approve commands, mutate Trust-0 context or reach the future SSH CA directly through public APIs.

The worker also verifies the canonical command binding locally before executor invocation. Future deployment must additionally isolate the worker at the VM/network level and restrict its egress to authorized execution/signing paths.

### Policy/classifier bypass

String/regex inspection can be bypassed through interpreters, shell indirection, alternate binaries or complex arguments. Command classification is therefore only one layer. Remote accounts, sudo/doas rules, SSH certificate constraints and restricted execution paths will enforce hard limits underneath it.

### Dangerous but legitimate command

A valid session may request an operation whose blast radius is disproportionate. Sensitive categories require a human approval decision unless an explicit narrow session approval already exists.

### History or memory scope leakage

A new agent session should gain useful continuity without being shown unrelated infrastructure or sessions. History is filtered by target plus current/previous-session and other-agent scope. Agent notes are filtered by target and require explicit notes permissions. History/notes responses are marked `TRUST_2` and `authoritative: false`.

### Audit tampering

A compromised component may attempt to rewrite history. Audit events are append-oriented and chained by sequence number, previous hash and SHA-256 event hash. The chain is verified on startup and re-verified for history reads, so post-startup modification is detected. External sealing remains a future hardening step against an attacker able to rewrite the complete store and restart all trusted components consistently.

### Agent-note tampering

Each note has a SHA-256 content hash and the note store validates records when opened/read; note creation is also recorded in the audit chain. Notes are nevertheless non-authoritative continuity data. Stronger transactional persistence and cross-store integrity will be addressed when state moves to PostgreSQL.

### Secret leakage into history

Command output may include credentials or private data. Metadata is auditable; raw stdout/stderr storage will be configurable, encrypted when persisted, retention-limited, and subject to redaction where practical. `0.1.0-dev.4` does not persist raw execution output.

### Persistence after expiry

A compromised agent should not convert a short grant into permanent infrastructure access. Agents cannot access SSH CA keys or long-lived infrastructure keys; the final SSH design uses ephemeral keys and short-lived certificates. Agent forwarding and port forwarding are disabled by default.

## Security invariants

- AI-facing API cannot create or widen grants.
- AI-facing API cannot modify system policy or authoritative instructions.
- AI-facing API cannot disable or delete audit records.
- AI-facing API cannot directly claim, start or complete worker jobs.
- Trust-2 history/notes cannot become authority by content alone.
- Context/history/notes are filtered against the control-plane view of the current grant.
- Raw infrastructure private SSH keys are never returned to an agent.
- Grant lookup stores a one-way token hash, never the plaintext capability.
- Expired/revoked grants fail closed.
- Empty/malformed execution requests fail closed.
- A request ID cannot be rebound to different target/argv within a grant.
- Staged jobs are not claimable.
- Claimed jobs are not executable until the Control Plane start gate revalidates the grant.
- Worker claim/start/complete credentials are one-shot with respect to job state.
- Dangerous-action approval is scoped, not a blanket bypass.
- Signer is not directly reachable through the public AI API.
- A functioning release is not considered deployable until tested.

## Out of scope for the first milestones

- defending a fully compromised hypervisor
- protecting against a malicious operator with full host/root access
- formal verification
- arbitrary shell being made intrinsically safe by parsing alone
- guaranteeing interruption of an already-running remote command before the executor milestone implements process/session cancellation
