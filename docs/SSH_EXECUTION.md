# SSH execution boundary

This document defines the real SSH execution path introduced in `0.1.0-dev.6`.

The execution path is intentionally split across independently enforced boundaries:

```text
AI Gateway
    |
    | logical target + argv only
    v
Control Plane
    |
    | immutable job + approval/policy decisions
    | operator-owned logical target resolution
    v
Execution Worker
    |
    | ephemeral Ed25519 key/job
    | short-lived OpenSSH certificate
    | exact pinned host key
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

The Control Plane loads the execution registry from:

```text
SENTINEL_SSH_TARGETS_FILE
```

Default:

```text
/etc/tethys-sentinel/ssh-targets.json
```

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

- `name` is the logical target referenced by grants and execution jobs;
- `address` must be a concrete literal IPv4/IPv6 address plus port; DNS hostnames are rejected;
- `user` is operator-owned and cannot be selected by the agent;
- `host_key` is one raw pinned SSH host public key; certificates and TOFU are rejected;
- unknown JSON fields are rejected;
- the registry must be a regular file and must not be group/other writable;
- the agent never supplies an SSH endpoint, Unix user or host-key pin to the worker.

The Control Plane resolves the logical job target only after validating the running job, claim secret, command binding and active grant. The resolved transport specification is returned together with the short-lived certificate.

## Worker credential and connection flow

For every running job the worker:

1. generates a fresh Ed25519 keypair in process memory;
2. sends only the public key to the Control Plane;
3. receives a short-lived certificate plus the operator-resolved target specification;
4. verifies the certificate matches the ephemeral private key and does not outlive the job;
5. verifies the resolved target name still equals the immutable job target;
6. dials only the resolved literal IP/port;
7. performs SSH host authentication using `ssh.FixedHostKey` with the configured pin;
8. opens one SSH session without requesting a PTY or forwarding;
9. sends the deterministic job-bound command envelope;
10. records only result metadata/output digests and completes the job once.

There is no `StrictHostKeyChecking=no`, TOFU callback, agent-supplied hostname, or private-key file on the worker.

## Time and output bounds

`sentinel-worker` supports:

```text
SENTINEL_WORKER_SSH_DIAL_TIMEOUT_SECONDS   default 5
SENTINEL_WORKER_OUTPUT_LIMIT_BYTES         default 4194304
SENTINEL_WORKER_POLL_MS                    default 1000
```

The worker execution context is capped by `job.expires_at`. Expiry therefore closes an already-running SSH transport; certificate expiry alone is not relied upon to terminate an established session.

The TCP dial and SSH handshake are independently deadline-bounded. After handshake, the socket deadline follows the execution context/job deadline.

Stdout/stderr are streamed into SHA-256 accounting writers and are not retained as raw output by the current worker. Crossing the configured per-stream accounting limit actively closes the SSH client and records `output_limit_exceeded`; the worker does not merely discover oversized output after the remote command finishes.

## Remote command envelope

The worker does not build a shell-quoted command line from agent argv.

It sends one protocol string:

```text
sentinel-exec-v1 <base64url(JSON)>
```

The decoded JSON contains exactly:

```json
{
  "job_id": "...",
  "grant_id": "...",
  "request_id": "...",
  "target": "dns01",
  "argv": ["systemctl", "status", "pdns"]
}
```

The remote wrapper recomputes the same canonical SHA-256 binding over:

```text
grant_id + request_id + target + argv
```

and compares it with the signer-generated certificate `force-command` binding.

Arguments such as spaces, quotes, `;`, `$()`, pipes or redirects remain argument bytes. They are not interpreted as shell syntax by Sentinel.

## Target forced-command wrapper

Signer certificates contain a critical `force-command` structurally equivalent to:

```text
/usr/local/libexec/tethys-sentinel-exec --job <job-id> --binding <sha256>
```

`tethys-sentinel-exec`:

- reads the local logical target ID from `/etc/tethys-sentinel/target-id`;
- requires the file to be a regular, non-group/other-writable file;
- decodes `SSH_ORIGINAL_COMMAND` using the versioned envelope protocol;
- verifies envelope job ID equals the certificate force-command job ID;
- verifies envelope target equals the local target ID;
- recomputes and constant-time compares the canonical command binding;
- resolves the executable only through a fixed system path or a clean absolute path;
- executes `argv` directly with `exec.Command`, never `/bin/sh -c`;
- supplies a reduced deterministic environment with fixed PATH, `PAGER=cat`, `TERM=dumb`, and no inherited agent-controlled environment.

The wrapper must be root/operator-owned and not writable by the `sentinel-ai` account.

## Target-side one-shot replay guard

A short-lived SSH certificate can otherwise be reused more than once during its validity interval. Sentinel therefore consumes a local marker before launching the requested process.

The unprivileged wrapper invokes only:

```text
/usr/bin/sudo -n -- /usr/local/libexec/tethys-sentinel-consume --job <job-id> --binding <sha256>
```

`tethys-sentinel-consume` must run as effective UID 0. It creates the marker atomically with `O_EXCL` under:

```text
/var/lib/tethys-sentinel/executed
```

Both the replay directory and its parent must:

- be real directories, not symlinks;
- grant no group/other permission bits;
- be owned by the helper's effective UID.

A second consume for the same job fails closed. The marker is created before the requested process starts, so the execution semantic is deliberately **at most once**, not retry-until-success.

The target sudo/doas policy must grant only the consume helper required by this wrapper. It must not grant a general root shell or arbitrary command execution to `sentinel-ai`.

## Target sshd/account requirements

Before a host is admitted to the registry it must have all of the following:

- the Sentinel OpenSSH user CA public key installed through `TrustedUserCAKeys`;
- a dedicated `sentinel-ai` Unix account;
- an authorized-principal policy accepting only the configured Sentinel principal;
- password and keyboard-interactive authentication disabled for that account;
- no ordinary `authorized_keys` escape path for the account;
- PTY disabled;
- agent forwarding disabled;
- TCP/stream-local forwarding disabled;
- X11 forwarding disabled;
- tunnel creation disabled;
- user environment injection disabled;
- root/operator-owned `tethys-sentinel-exec` and `tethys-sentinel-consume` binaries;
- root/operator-owned `/etc/tethys-sentinel/target-id` containing the exact logical target name;
- root-owned private replay-state directories;
- the narrow consume-helper sudo/doas rule;
- only the minimum application-specific sudo/doas privileges required by separately approved infrastructure operations.

The certificate restrictions and sshd/account restrictions are intentionally redundant.

## Test coverage in dev.6

The automated suite covers, among other cases:

- target-store malformed data and writable configuration rejection;
- DNS target rejection and literal-IP enforcement;
- exact pinned-host-key success and wrong-pin handshake rejection;
- a real in-process SSH client/server execution path;
- deterministic command-envelope/binding preservation for shell-looking argument data;
- worker certificate/private-key matching;
- job expiry bounds;
- SSH handshake timeout without requiring an external context deadline;
- active output-limit termination;
- concurrent target replay attempts allowing exactly one consumer;
- unsafe replay-state permission rejection;
- target-ID and binding mismatch rejection.

## Remaining limits

`dev.6` establishes the transport and target execution boundary but is still a development milestone.

Before production trust:

- policy treatment of interpreters/shells/privilege launchers must be hardened so arbitrary-code carriers cannot silently fall through the default low-risk classifier;
- worker VM egress should be restricted independently to configured target IPs/ports and required control-plane endpoints;
- production state must move away from bootstrap file stores;
- global revoke-all semantics must prevent new signing/execution and actively terminate worker activity where possible;
- the full stack must be exercised on a deliberately disposable/constrained target before WIP merge.
