# Sentinel target onboarding with Ansible

This automation onboards Debian/Ubuntu VMs and unprivileged Proxmox LXC containers as Tethys Sentinel SSH execution targets. It deliberately keeps target configuration, Control inventory authority, and Proxmox Worker egress authority in separate roles while exposing one normal entry point.

## Layout

```text
playbooks/onboard-sentinel-targets.yml
  -> sentinel_target
  -> sentinel_control_targets
  -> sentinel_worker_egress
```

The roles preserve the accepted security split:

- targets receive only the target wrappers, SSH user-CA **public** key, forced-account restrictions and replay state;
- Control remains the only owner of the logical target registry and authoritative context;
- the PVE host remains the only place allowed to install the external Worker egress policy;
- target hosts never receive Control admin authority, signer CA private material, PostgreSQL credentials or PVE authority.

## Controller inputs

Run Ansible from this directory so `ansible.cfg` resolves `./roles`.

Place the exact accepted/current candidate linux-amd64 artifact under:

```text
artifacts/linux-amd64/
  sentinel-egress-policy
  tethys-sentinel-exec
  tethys-sentinel-consume
  SHA256SUMS
```

Place the Signer's SSH user-CA **public** key under:

```text
secrets/ssh-user-ca.pub
```

Both directories are gitignored. Never put the SSH CA private key here.

The dev.23 CI artifact includes all three binaries above plus `sentinel-control` and `BUILDINFO.txt`. The target and egress roles run `sha256sum -c SHA256SUMS` on the controller before installing any artifact binary.

## Inventory

Copy `inventory/example.yml` to a private inventory and replace only the documentation addresses/names there.

Every target normally needs:

```yaml
sentinel_targets:
  hosts:
    app-01:
      ansible_host: 192.0.2.14
      sentinel_target_id: app-01
      sentinel_target_address: 192.0.2.14
      sentinel_target_role_description: application server
      sentinel_target_services:
        - nginx
```

`sentinel_target_address` must be a literal non-local IP. It becomes both the Control SSH endpoint and the operator-only address in authoritative context. The Agent context continues to redact addresses at runtime.

The inventory is the declarative source of truth for Sentinel-managed SSH targets. Existing context-only hosts that are not part of the current or desired SSH registry are preserved.

## Run

```sh
cd ansible
ansible-playbook -i inventory/production.yml playbooks/onboard-sentinel-targets.yml
```

The top-level playbook performs, in order:

1. **target** — installs/configures the `sentinel-ai` account, target wrappers, replay state, SSH CA trust, principal and hardened sshd policy; validates the effective sshd configuration and reads the host key locally from the target;
2. **control** — discovers those local host keys through Ansible, renders the complete canonical `ssh-targets.json`, reconciles managed hosts in `context.json`, restarts Control when required, and rolls back both files if Control does not return active;
3. **egress** — reads the actual installed Control target registry, generates the Worker policy with `sentinel-egress-policy`, writes changed policy bytes through pmxcfs, compiles it, runs the canonical `-check` activation verifier, and confirms the Proxmox firewall is enabled/running.

Useful tags:

```sh
ansible-playbook -i inventory/production.yml playbooks/onboard-sentinel-targets.yml --tags target
ansible-playbook -i inventory/production.yml playbooks/onboard-sentinel-targets.yml --tags control
ansible-playbook -i inventory/production.yml playbooks/onboard-sentinel-targets.yml --tags egress
```

The Control role discovers host keys itself, and the egress role consumes the actual Control registry, so these later stages do not depend on cached facts from an earlier role.

## Removal safety

Removing a host from `sentinel_targets` would remove execution authority from Control and then from Worker egress. That is intentionally blocked by default.

After reviewing the inventory diff, explicitly allow removal:

```sh
ansible-playbook -i inventory/production.yml \
  playbooks/onboard-sentinel-targets.yml \
  -e sentinel_allow_target_removal=true
```

This removes the target from the Control SSH registry/context and shrinks Worker egress. It does not uninstall target-side files from a machine that is no longer in inventory.

## Idempotency and acceptance

After the first successful onboarding run:

1. run the same playbook again and expect no target/Control/firewall drift;
2. confirm the Worker remains synchronized to its configured trusted NTP source;
3. issue a short-lived constrained grant for one newly onboarded logical target;
4. run a harmless structured `id` through Sentinel;
5. verify the expected unprivileged `sentinel-ai` identity;
6. revoke the test grant.

Use the disposable target first when changing this automation. Do not treat a new onboarding implementation as accepted solely because `ansible-playbook --syntax-check` passes.
