# Worker egress enforcement

`0.1.0-dev.9` introduces an operator-owned network boundary for the Execution Worker.

## Security objective

Control Plane already ensures that normal jobs resolve only to operator-owned logical targets with global-unicast literal SSH addresses. That is necessary but not sufficient against a compromised worker process or guest.

The worker network itself must independently reject connections to infrastructure that is not part of the approved worker transport set.

The hard production boundary is therefore outside the worker VM, using the Proxmox VE VM firewall (or an equivalent external firewall in another deployment environment).

Guest-local nftables may be added as defense in depth, but rules controlled by the same compromised guest cannot be the sole enforcement mechanism.

## Runtime egress set

A dedicated worker VM requires only:

1. the Control Plane internal HTTPS endpoint;
2. the SSH IP:port endpoints present in the protected Sentinel target inventory.

Both Control Plane and target destinations must use **global-unicast literal IP addresses**. This includes ordinary private RFC1918 IPv4 and ULA IPv6 deployments, but rejects DNS names, unspecified addresses, loopback, multicast and link-local endpoints.

The production runtime allowlist intentionally does not require DNS. The Control Plane URL supplied to the egress policy generator must use a literal IP. TLS identity remains independent: the worker can use `SENTINEL_INTERNAL_SERVER_NAME` for the certificate name while connecting to a literal-IP `SENTINEL_CONTROL_URL`.

Do not add broad LAN, Internet, DNS, package-mirror, or arbitrary HTTPS rules to the runtime worker policy. System maintenance should use an explicit operator maintenance path/window or a separate management plane rather than silently weakening the autonomous worker boundary.

## `sentinel-egress-policy`

The repository provides an operator-side renderer/verifier. It does **not** apply firewall rules and must not be exposed to the worker/agent as a tool.

Example values below are illustrative; use the actual worker Control Plane and target inventory in deployment.

```sh
sentinel-egress-policy \
  -targets /etc/tethys-sentinel/ssh-targets.json \
  -control https://10.169.0.10:9091 \
  -format pve \
  > 1234.fw
```

The generated file has:

```text
[OPTIONS]

enable: 1
policy_out: DROP

[RULES]

OUT ACCEPT -dest 10.169.0.10 -p tcp -dport 9091 -log nolog # sentinel-control
OUT ACCEPT -dest 10.169.0.53 -p tcp -dport 22 -log nolog # ssh:dns01
```

There is no blanket `OUT ACCEPT` fallback.

The policy carries a SHA-256 digest derived from the canonical Control Plane + target destination set. Multiple logical targets using one IP:port are deduplicated into one transport rule while preserving their names in metadata/comments.

Machine-readable policy is available with:

```sh
sentinel-egress-policy \
  -targets /etc/tethys-sentinel/ssh-targets.json \
  -control https://10.169.0.10:9091 \
  -format json
```

## Proxmox deployment

Proxmox VE stores per-VM/CT firewall configuration in `/etc/pve/firewall/<VMID>.fw` and filters traffic on the VM/CT interface outside the guest.

For a dedicated worker VM, install the generated file as the VM firewall configuration through an operator/Ansible deployment task, for example:

```sh
install -m 0640 1234.fw /etc/pve/firewall/1234.fw
```

Because `/etc/pve` is pmxcfs, use the normal Proxmox-supported configuration path and deployment account rather than granting the worker VM access to it.

Three activation conditions are mandatory:

1. Proxmox Datacenter firewall enabled;
2. worker VM firewall enabled (`enable: 1` is generated in `<VMID>.fw`);
3. firewall enabled on the worker VM virtual NIC (`firewall=1`).

The worker must never possess credentials that can modify `/etc/pve`, Proxmox firewall settings, the VM NIC firewall flag, or the generated policy source.

## Drift and activation verification

The same operator CLI can verify both the generated policy and the relevant PVE activation configuration:

```sh
sentinel-egress-policy \
  -targets /etc/tethys-sentinel/ssh-targets.json \
  -control https://10.169.0.10:9091 \
  -format pve \
  -check /etc/pve/firewall/1234.fw \
  -pve-cluster-fw /etc/pve/firewall/cluster.fw \
  -pve-vm-config /etc/pve/qemu-server/1234.conf \
  -pve-net net0
```

Verification fails when:

- installed `<VMID>.fw` differs byte-for-byte from the currently generated policy;
- Datacenter firewall does not have `enable: 1` inside `[OPTIONS]`;
- the requested `netN` is absent from the VM configuration;
- the worker NIC does not contain `firewall=1`.

The activation flags must be supplied together. Verification is read-only: the CLI does not change PVE configuration.

This check is intended for operator-side Ansible/CI/periodic reconciliation. The worker itself must not be allowed to reconcile or rewrite its external boundary.

A clean configuration audit still does **not** prove packet behavior. The real PVE acceptance test must exercise connectivity from inside the worker VM after the firewall has been activated.

## Inventory change workflow

Changing target inventory should use an ordered operator workflow:

1. update protected Sentinel target inventory;
2. regenerate external egress policy;
3. review the diff;
4. deploy/reconcile PVE firewall policy;
5. verify generated-vs-installed policy and Datacenter/NIC activation;
6. perform packet-level validation where required;
7. only then treat the new target set as infrastructure-ready.

For target removal, applying the narrower external policy first is preferable where practical; Control Plane removal still independently prevents new normal jobs for the target.

A newly added target that has not yet reached the external firewall will fail to connect rather than expanding network authority automatically.

## Acceptance test on PVE

The later real-infrastructure acceptance test must validate the boundary from **inside the worker VM**.

Expected successes:

```text
worker -> Control Plane IP:internal HTTPS port
worker -> every registered target IP:configured SSH port
```

Expected failures must include at least:

```text
worker -> 1.1.1.1:443
worker -> another LAN host:22 not in target inventory
worker -> registered target IP on an unlisted port
worker -> DNS resolver:53
```

DNS should fail under the runtime policy because Sentinel transport configuration is literal-IP based. If an operator temporarily needs DNS/package access for maintenance, that should be a separate explicit maintenance policy rather than part of autonomous runtime authority.

## Established connections and revocation

External firewall reconciliation is a containment boundary, not instantaneous active-session revocation. A stateful firewall can retain an already-established flow after a rule change.

Sentinel therefore continues to rely on short SSH certificate TTL, job expiry, worker execution deadlines and target-side one-shot execution. The separate global-revoke milestone must additionally stop new signing/execution and actively terminate worker activity/connections where feasible.

## Failure behavior

Policy generation fails closed when:

- Control Plane URL is not HTTPS;
- Control Plane host is DNS or not a global-unicast literal IP;
- target inventory is empty;
- a target endpoint is not global-unicast literal IP:port;
- target labels are unsafe for deterministic generated metadata;
- requested verification file differs from generated policy;
- requested PVE activation configuration is incomplete or disabled.

## Trust boundary

`sentinel-egress-policy` is an operator/deployment tool. It must not be included in the AI-facing MCP/tool surface, and the autonomous worker account must not receive permission to invoke an apply/reconcile path with PVE privileges.
