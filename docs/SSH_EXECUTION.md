# SSH execution boundary

This document defines the real SSH execution path introduced in `0.1.0-dev.6` and hardened through `0.1.0-dev.11`.

The execution path is intentionally split across independently enforced boundaries:

```text
AI Gateway
    |
    | logical target + argv only
    v
Control Plane
    |
    | immutable job + approval/policy decisions
    | PostgreSQL transactional authority/audit
    | operator-owned logical target resolution
    v
Execution Worker
    |
    | ephemeral Ed25519 key/job
    | short-lived OpenSSH certificate
    | exact pinned host key
    | active authority lease
    v
Target sshd
    |
    | certificate critical force-command
    v
tethys-sentinel-exec
    |
    | verify job/binding/local target
    | one-shot replay consume
    | direct exec(argv), no shell re-parse
    v
unprivileged target process
```

## Operator-owned SSH target registry

Control Plane loads execution targets from `SENTINEL_SSH_TARGETS_FILE` (default `/etc/tethys-sentinel/ssh-targets.json`).

Example:

```json
{
  "targets": [
    {
      "name": "dns01",
      "address": "10.169.0.53:22",
      "user": "sentinel-ai",
      "host_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA..."
    }
  ]
}
```

Security properties:

- `name` is the logical target referenced by grants/jobs;
- `address` is a literal global-unicast IPv4/IPv6 address plus port; DNS names are rejected;
- `user` is operator-owned, never selected by the agent;
- `host_key` is one exact raw SSH host public key; TOFU and insecure callbacks are rejected;
- unknown JSON fields are rejected;
- registry must be a regular file and not group/other writable;
- agent never supplies SSH endpoint, Unix user or host-key pin.

Control Plane resolves the target only after validating running job, claim, immutable command binding, current policy and active grant/epoch.

## Worker credential and connection flow

For every running job Worker:

1. generates a fresh Ed25519 keypair in process memory;
2. sends only the public key to Control Plane;
3. receives short-lived certificate + operator-resolved target;
4. verifies certificate matches the ephemeral key and cannot outlive the job;
5. verifies returned logical target equals immutable job target;
6. performs an authoritative execution lease check;
7. dials only the resolved literal IP/port;
8. verifies SSH host authentication with the exact configured pin;
9. opens one session without PTY/forwarding;
10. sends deterministic job-bound command envelope;
11. keeps polling Control Plane authority while the SSH execution remains active;
12. cancels/tears down transport on authority loss;
13. records terminal result metadata/output digests exactly once.

Worker receives no plaintext agent capability, PostgreSQL credentials, signer credential/CA key, target inventory file, or PVE firewall authority.

## Time and output bounds

`sentinel-worker` supports:

```text
SENTINEL_WORKER_SSH_DIAL_TIMEOUT_SECONDS   default 5
SENTINEL_WORKER_OUTPUT_LIMIT_BYTES         default 4194304
SENTINEL_WORKER_POLL_MS                    default 1000
SENTINEL_WORKER_AUTHORITY_POLL_MS          default 250
```

Execution context is capped by job/grant authority lifetime. SSH certificate expiry alone is not relied on to terminate an established session.

TCP dial and SSH handshake are deadline-bounded. Stdout/stderr are streamed through SHA-256 accounting writers and not retained as raw output by the current Worker. Crossing the configured accounting limit actively closes SSH and records a terminal error.

## Remote command envelope

Worker never reconstructs agent argv into a shell command.

It sends one protocol string:

```text
sentinel-exec-v1 <base64url(JSON)>
```

Decoded JSON contains exactly the job-bound command identity:

```json
{
  "job_id": "...",
  "grant_id": "...",
  "request_id": "...",
  "target": "dns01",
  "argv": ["systemctl", "status", "pdns"]
}
```

Target wrapper recomputes the canonical SHA-256 binding over grant ID + request ID + logical target + argv and compares it with signer-generated certificate force-command binding.

Arguments containing spaces, quotes, semicolons, substitutions, pipes or redirects remain argument bytes. Sentinel does not interpret them as shell syntax.

## Forced-command wrapper

Signer certificates contain a critical force-command structurally equivalent to:

```text
/usr/local/libexec/tethys-sentinel-exec --job <job-id> --binding <sha256>
```

`tethys-sentinel-exec`:

- reads local target ID from `/etc/tethys-sentinel/target-id`;
- requires safe regular operator-owned configuration;
- decodes `SSH_ORIGINAL_COMMAND` using the versioned envelope;
- verifies envelope job ID equals certificate job ID;
- verifies envelope target equals local target ID;
- recomputes/constant-time compares command binding;
- resolves executable only through fixed system path or clean absolute path;
- executes argv directly with `exec.Command`, never a shell reconstruction;
- uses reduced deterministic environment including fixed PATH, `PAGER=cat`, and `TERM=dumb`.

Wrapper is root/operator-owned and not writable by `sentinel-ai`.

## Target-side one-shot replay guard

A valid short-lived SSH certificate could otherwise be reused during its validity interval. Before launching requested argv, wrapper calls only:

```text
/usr/bin/sudo -n -- /usr/local/libexec/tethys-sentinel-consume --job <job-id> --binding <sha256>
```

`tethys-sentinel-consume` runs as effective UID 0 and atomically creates an `O_EXCL` replay marker below:

```text
/var/lib/tethys-sentinel/executed
```

Replay directory and parent must be real non-symlink directories, root-owned, with no group/other permission bits.

Second consume for the same job fails closed. The marker is consumed **before** requested process start, so the semantic is at-most-once, not retry-until-success.

Target sudo/doas policy may grant this narrow helper only; it must not create a generic root execution path.

## Target sshd/account requirements

Before a target enters registry it needs:

- Sentinel SSH user CA public key through `TrustedUserCAKeys`;
- dedicated `sentinel-ai` Unix account;
- authorized-principal policy accepting only configured Sentinel principal;
- password and keyboard-interactive authentication disabled;
- no ordinary `authorized_keys` bypass for the account;
- PTY, agent forwarding, TCP/stream-local forwarding, X11 forwarding, tunnels and user environment injection disabled;
- root/operator-owned `tethys-sentinel-exec` and `tethys-sentinel-consume`;
- root/operator-owned `/etc/tethys-sentinel/target-id` matching logical registry name;
- root-only replay directories;
- narrow replay-helper sudo/doas permission;
- only minimum separately approved application-specific elevated permissions.

Certificate and sshd/account restrictions are intentionally redundant.

## PostgreSQL/start/revoke interaction

`0.1.0-dev.11` moves mutable execution authority into PostgreSQL semantic transactions.

A staged job is not worker-claimable until current policy/grant/approval authorization publishes it. One-shot approval consumption, job publication and authorization audit commit together.

Worker claim stores only a hash of the one-shot claim secret. `start` revalidates current global authority and original grant under ordered database locks before `claimed -> running`, so individual/global revoke cannot slip through a stale grant snapshot.

Immediately before certificate issuance Control Plane again validates running job, claim, immutable binding, current classifier category/scope, current grant/epoch and required `shell` authority.

While execution is active Worker periodically calls the authority endpoint; revoke or inability to verify Control Plane authority cancels SSH transport. Completion then records the factual terminal result transactionally even if the original grant has become inactive.

## External Worker egress boundary

Application target resolution is not the only network boundary. The Worker VM must have external deny-by-default egress allowing only:

```text
Control Plane HTTPS literal IP:port
registered target SSH literal IP:port set
```

On PVE this is enforced outside the guest at the Worker VM interface. Worker/AI receives no privilege to widen the policy.

See `docs/WORKER_EGRESS.md`.

## Automated coverage

Automated tests cover, among other cases:

- malformed/writable target registry rejection;
- DNS/non-global-unicast target rejection;
- exact host-key success and wrong-pin rejection;
- real in-process SSH client/server path;
- deterministic binding preservation for shell-looking argument data;
- certificate/private-key matching and lifetime bounds;
- handshake/output-limit behavior;
- concurrent target replay attempts allowing exactly one consumer;
- unsafe replay-state permission rejection;
- target-ID/binding mismatch;
- powerful execution/current-policy certificate gating;
- global/individual revoke authority loss;
- PostgreSQL staged authorization/start/complete semantics and replay rejection.

## Remaining acceptance

The earlier dev.6 code limits around powerful command classes, external Worker egress, global revoke and production mutable persistence are now implemented by dev.7–dev.11.

The remaining blocker before first WIP merge is **real constrained infrastructure acceptance**, not another theoretical SSH layer. The test must prove:

- mTLS/TLS between real component VMs;
- PostgreSQL schema/runtime role and restart/failure behavior;
- external Worker PVE egress enforcement plus negative packet tests;
- real pinned-key SSH through the target forced wrapper;
- successful autonomous harmless command;
- one-shot approval execution/non-reuse;
- individual and global revoke during bounded live SSH execution;
- persistent verified audit/job state.

Use `docs/INFRASTRUCTURE_ACCEPTANCE.md`. Any failed hard-boundary check blocks the merge and becomes an implementation/configuration fix before retest.
