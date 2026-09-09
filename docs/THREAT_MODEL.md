# Threat Model

## Security objective

Permit useful autonomous infrastructure operations while assuming the AI client can become confused, prompt-injected, malicious, compromised, or strategically adversarial.

The design must constrain what the client can physically cause, not merely instruct it to behave.

## Primary threats

### Prompt injection through operational data

Logs, files, tickets, web pages or command output can contain instructions intended to redirect the model. Sentinel treats discovered content as data. Only Trust-0 system context and explicit operator decisions can define authority.

### Stolen capability token

Opaque capability tokens are bearer secrets by default. Mitigations: high entropy, short TTL, server-side revocation, narrow scope, token hashes at rest, TLS, optional proof-of-possession binding in a later milestone.

### Gateway compromise

A remote-code-execution bug in the AI-facing gateway must not become grant-issuance or CA-key compromise. The gateway is separated from the control-plane/admin interface and signer, receives least-privilege storage access, and cannot expand capabilities.

### Policy/classifier bypass

String/regex inspection can be bypassed through interpreters, shell indirection, alternate binaries or complex arguments. Command classification is therefore only one layer. Remote accounts, sudo/doas rules, SSH certificate constraints and restricted execution paths enforce hard limits underneath it.

### Dangerous but legitimate command

A valid session may request an operation whose blast radius is disproportionate. Sensitive categories require a human approval decision unless an explicit narrow session approval already exists.

### Audit tampering

A compromised component may attempt to rewrite history. Audit events are append-oriented and planned to be chained using the previous event hash. Periodic external sealing can make retroactive alteration detectable.

### Secret leakage into history

Command output may include credentials or private data. Metadata is always auditable; raw stdout/stderr storage is configurable, encrypted when persisted, retention-limited, and subject to redaction where practical.

### Persistence after expiry

A compromised agent should not convert a short grant into permanent infrastructure access. Agents cannot access SSH CA keys or long-lived infrastructure keys; the final SSH design uses ephemeral keys and short-lived certificates. Agent forwarding and port forwarding are disabled by default.

## Security invariants

- AI-facing API cannot create or widen grants.
- AI-facing API cannot modify system policy or authoritative instructions.
- AI-facing API cannot disable or delete audit records.
- Raw infrastructure private SSH keys are never returned to an agent.
- Grant lookup stores a one-way token hash, never the plaintext capability.
- Expired/revoked grants fail closed.
- Empty/malformed execution requests fail closed.
- Dangerous-action approval is scoped, not a blanket bypass.
- Signer is not directly reachable through the public AI API.
- A functioning release is not considered deployable until tested.

## Out of scope for the first milestone

- defending a fully compromised hypervisor
- protecting against a malicious operator with full host/root access
- formal verification
- arbitrary shell being made intrinsically safe by parsing alone
