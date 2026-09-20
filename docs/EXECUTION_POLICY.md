# Execution policy and powerful-command boundary

This document defines the powerful-execution boundary introduced in `0.1.0-dev.7` and retained by `0.1.0-dev.8`.

The policy deliberately does **not** attempt to prove arbitrary shell/interpreter syntax safe. A command that can act as a general code carrier, privilege launcher, or lateral/remote execution primitive is treated as a broader execution capability even when its top-level argv looks simple.

`0.1.0-dev.8` adds a separate semantic operational-risk layer for administrator mutations such as service/network/package/storage/container/hypervisor state. See `docs/OPERATIONAL_RISK.md`. That layer routes approval decisions but does not weaken or replace the powerful-execution boundary described here.

## Capability model

Two independent permissions matter for command execution:

- `exec` — permits ordinary structured argv execution within the grant's target scope;
- `shell` — additionally permits powerful/unstructured execution classes that can carry arbitrary code, broaden privilege, or create another execution path.

`exec=true` does not imply `shell=true`.

Human approval does not grant a missing capability. A powerful command therefore requires all of:

1. active grant with `exec=true`;
2. active grant with `shell=true`;
3. matching operator approval;
4. all normal target/job/start/certificate checks.

The public Gateway rejects obviously unreachable powerful submissions early when `shell=false`, but that is only a convenience/prefilter. The authoritative hard gate is immediately before SSH certificate issuance, where the Control Plane reclassifies the immutable job using current policy and re-authenticates the grant.

## Powerful execution classes

Current classes requiring `shell=true` are:

### `ARBITRARY_CODE`

Examples include:

- shells and interpreters such as `sh`, `bash`, Python, Perl, Ruby, Node, PHP, Lua and PowerShell;
- general command carriers/launchers such as `env`, `xargs`, `timeout`, `nohup`, `nice`, `setsid`, `flock`, `watch`, build tools, editors/debuggers and similar escape-capable tools;
- container operations that execute/start/build mutable workloads;
- `find -exec`/`-execdir`, executable tar/cpio modes, compiler/linker/plugin and VCS escape surfaces;
- `go run` / `cargo run`;
- arbitrary absolute-path executables outside the fixed trusted system binary directories.

This list is conservative and is expected to grow as bypass patterns are found.

### `PRIVILEGE_LAUNCHER`

Examples include `sudo`, `doas`, `su`, `runuser`, `pkexec`, `setpriv`, `capsh`, `chroot`, `nsenter`, `unshare`, `systemd-run`, `machinectl`, and equivalent privilege/identity/namespace launchers.

The classifier does not attempt to infer that a particular invocation is harmless. These tools can alter privilege, namespace, execution identity, or process boundary and therefore require explicit broader authority.

### `REMOTE_EXEC`

Examples include SSH-family tools, Ansible/Salt remote execution, netcat/socat-style network pivots, Kubernetes exec/copy/port-forward operations, remote/machine service transports, container remote contexts, namespace/jail/VM console or guest-execution paths.

These operations can cross the logical target boundary or create another execution/network path, so they require `shell=true` in addition to operator approval.

## Approval scope

For powerful execution classes the approval scope is a canonical SHA-256 of the **complete argv**, including `argv[0]` / executable path.

This prevents delimiter collisions and prevents `/bin/bash -c ...` from sharing approval scope with `/usr/bin/bash -c ...`.

However, an identical argv still does not prove identical behavior. For example:

```text
bash /tmp/task.sh
```

can execute different content if `/tmp/task.sh` changes after approval. The same problem applies to interpreters, config-driven launchers, container images, remote destinations and other mutable inputs.

Therefore:

- `ARBITRARY_CODE` — `allow_once` only;
- `PRIVILEGE_LAUNCHER` — `allow_once` only;
- `REMOTE_EXEC` — `allow_once` only.

`allow_session` is rejected for those categories even when argv is identical. Legacy persisted `allow_session` decisions for these categories are ignored and cannot match after upgrade.

Narrow semantic operational categories may still support scoped session approval where their classifier defines a stable reusable operation/resource. See `docs/OPERATIONAL_RISK.md`.

## Policy freshness at signing time

A queued/running job does not freeze an old classifier decision forever.

Before issuing an SSH credential, the Control Plane:

1. verifies the running job and claim secret;
2. verifies immutable command binding;
3. reclassifies `job.argv` using the current risk policy;
4. requires current category and scope key to equal the stored job metadata;
5. re-authenticates the original grant;
6. requires `shell=true` for powerful classes;
7. only then resolves the protected target and calls the isolated signer.

If policy changed since job creation, certificate issuance fails closed and the job is canceled/rejected rather than grandfathered into the older policy.

## Important limit

Classification is a risk-routing layer, not a proof that commands left in lower-risk categories are intrinsically safe. Hard limits still come from capability scope, approvals, SSH credential constraints, target account permissions, forced-command/replay enforcement, sudo/doas rules and network isolation.

`dev.8` materially expands semantic coverage, but missing a future executable/option/escape must never be interpreted as permission to bypass those lower enforcement layers.
