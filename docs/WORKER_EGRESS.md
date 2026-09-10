# Worker egress enforcement

`0.1.0-dev.9` introduced the operator-owned external network boundary for Execution Worker. The implementation remains current in `0.1.0-dev.11`; the remaining requirement is real PVE packet-level acceptance.

## Security objective

Control Plane resolves jobs only to operator-owned logical targets with literal SSH addresses, but application validation alone is not sufficient against a compromised Worker process or guest.

The Worker network must independently reject connections outside the approved transport set. On Proxmox VE the hard boundary is the **VM-interface firewall outside the guest**. Guest-local nftables may exist as defense in depth but cannot be the sole boundary.

## Runtime egress set

A dedicated Worker VM needs only:

1. Control Plane internal HTTPS endpoint;
2. SSH IP:port endpoints in protected Sentinel target inventory.

Control and target destinations must be global-unicast literal IP addresses. RFC1918 IPv4 and ULA IPv6 are valid; DNS names, unspecified, loopback, multicast and link-local endpoints are rejected.

The runtime allowlist intentionally needs no DNS. TLS identity is independent of the connection address: Worker may connect to a literal-IP `SENTINEL_CONTROL_URL` while validating a DNS certificate identity through `SENTINEL_INTERNAL_SERVER_NAME`.

Do not add broad LAN, Internet, DNS, package-mirror or generic HTTPS access to autonomous runtime policy. Maintenance requires a separate explicit operator maintenance path/window.

## `sentinel-egress-policy`

The repository provides an operator-side renderer/verifier. It does **not** apply firewall rules and must never be exposed to Worker/agent as a tool.

Example:

```sh
sentinel-egress-policy \
  -targets /etc/tethys-sentinel/ssh-targets.json \
  -control https://10.169.0.10:9091 \
  -format pve \
  > 1234.fw
```

Generated policy has `enable: 1`, `policy_out: DROP`, explicit TCP destination/port allows and no blanket `OUT ACCEPT` fallback.

Example shape:

```text
[OPTIONS]

enable: 1
policy_out: DROP

[RULES]

OUT ACCEPT -dest 10.169.0.10 -p tcp -dport 9091 -log nolog # sentinel-control
OUT ACCEPT -dest 10.169.0.53 -p tcp -dport 22 -log nolog # ssh:dns01
```

Policy carries a SHA-256 digest derived from the canonical Control + target destination set. Multiple logical targets sharing one IP:port are transport-deduplicated while preserving logical names in metadata/comments.

Machine-readable form:

```sh
sentinel-egress-policy \
  -targets /etc/tethys-sentinel/ssh-targets.json \
  -control https://10.169.0.10:9091 \
  -format json
```

## Proxmox deployment

PVE per-VM firewall configuration is `/etc/pve/firewall/<VMID>.fw` and filters traffic at the VM interface outside the guest.

Install reviewed generated policy from an operator/Ansible path, for example:

```sh
install -m 0640 1234.fw /etc/pve/firewall/1234.fw
```

Mandatory activation conditions:

1. Datacenter firewall enabled;
2. Worker VM firewall config enabled;
3. selected Worker NIC has `firewall=1`.

Worker must never possess credentials that can modify `/etc/pve`, PVE firewall state, NIC firewall flags or policy source.

## Drift and activation verification

Operator-side verification:

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

- installed policy differs byte-for-byte from current generated policy;
- Datacenter firewall lacks active `enable: 1`;
- requested VM NIC does not exist;
- selected NIC lacks `firewall=1`.

Verification is read-only. It never reconciles PVE state for the Worker.

## Inventory change workflow

Use this order:

1. update protected Sentinel target inventory;
2. regenerate external egress policy;
3. review diff;
4. deploy PVE policy through operator path;
5. verify drift + Datacenter/NIC activation;
6. run packet-level validation when required;
7. only then treat the new target set as infrastructure-ready.

For target removal, narrowing the external policy first is preferable where practical. A newly added target absent from the PVE policy fails connectivity instead of automatically expanding Worker authority.

## Packet-level acceptance

A clean policy/configuration audit does **not** prove packet behavior. Acceptance must test from inside Worker after policy activation.

Expected successes:

```text
Worker -> Control Plane internal HTTPS IP:port
Worker -> each registered target SSH IP:port
```

Expected failures include:

```text
Worker -> 1.1.1.1:443
Worker -> unrelated LAN host:22
Worker -> registered target IP on unlisted port
Worker -> DNS resolver:53
```

The concrete first-deployment procedure is in `docs/INFRASTRUCTURE_ACCEPTANCE.md`.

## Established connections and active revocation

External firewall containment and Sentinel active authority are deliberately independent.

A stateful firewall may preserve an already-established TCP flow after a rule is removed. PVE policy reconciliation is therefore **not** the emergency kill mechanism.

Since `0.1.0-dev.10`, running Worker executions use a fail-closed Control Plane authority lease. Individual grant revoke, global `REVOKE ALL`, stale epoch, expiry, Control loss or authority-check failure cancels the Worker execution context and SSH transport. Short certificate TTL, job expiry and target one-shot replay protection remain additional layers.

`0.1.0-dev.11` makes the relevant grant/emergency/job/audit transitions transactionally durable in PostgreSQL.

## Failure behavior

Policy generation/verification fails closed when:

- Control URL is not HTTPS;
- Control host is DNS or not a global-unicast literal IP;
- target inventory is empty;
- target endpoint is not global-unicast literal IP:port;
- target labels are unsafe for deterministic metadata;
- installed verification file differs from generated policy;
- requested PVE activation configuration is incomplete/disabled.

## Trust boundary

`sentinel-egress-policy` is an operator/deployment tool. It must not enter the AI-facing MCP/tool surface, and Worker/agent must never receive an apply/reconcile path with PVE privileges.

The first WIP merge remains blocked until real packet-level PVE acceptance passes alongside the SSH/revoke/PostgreSQL checks in `docs/INFRASTRUCTURE_ACCEPTANCE.md`.
