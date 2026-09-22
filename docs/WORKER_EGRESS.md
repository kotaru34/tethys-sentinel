# Worker egress enforcement

`0.1.0-dev.9` introduced the operator-owned external network boundary for Execution Worker. `0.1.0-dev.12` corrected the generated PVE policy so inbound traffic is explicitly preserved with `policy_in: ACCEPT` while outbound traffic remains deny-by-default. The `0.1.0-dev.22` candidate extends the same boundary with explicit trusted NTP sources because short-lived SSH certificates require bounded clock skew.

## Security objective

Control Plane resolves jobs only to operator-owned logical targets with literal SSH addresses, but application validation alone is not sufficient against a compromised Worker process or guest.

The Worker network must independently reject connections outside the approved transport set. On Proxmox VE the hard boundary is the **VM-interface firewall outside the guest**. Guest-local nftables may exist as defense in depth but cannot be the sole boundary.

## Runtime egress set

A dedicated Worker VM needs only:

1. Control Plane internal HTTPS endpoint;
2. SSH IP:port endpoints in protected Sentinel target inventory;
3. UDP/123 to one or more operator-chosen trusted NTP servers.

Control, target and NTP destinations must be global-unicast literal IP addresses. RFC1918 IPv4 and ULA IPv6 are valid; DNS names, unspecified, loopback, multicast and link-local endpoints are rejected.

The runtime allowlist intentionally needs no DNS. TLS identity is independent of the connection address: Worker may connect to a literal-IP `SENTINEL_CONTROL_URL` while validating a DNS certificate identity through `SENTINEL_INTERNAL_SERVER_NAME`. Time synchronization likewise uses literal NTP server IPs supplied by the operator.

Do not add broad LAN, Internet, DNS, package-mirror, generic HTTPS or unrestricted NTP access to autonomous runtime policy. Maintenance requires a separate explicit operator maintenance path/window.

## Time synchronization requirement

Worker validates each short-lived OpenSSH certificate against its local clock before opening SSH. A Worker clock outside the Signer's backdate tolerance therefore fails closed with certificate-not-currently-valid behavior even when Control, Signer and target configuration are otherwise correct.

The runtime Worker must have an active, verified time source. Configure the guest time client separately from Sentinel, for example with `systemd-timesyncd`, but keep network access constrained by the external egress policy.

A typical guest configuration using an operator-owned NTP server is:

```ini
[Time]
NTP=192.0.2.1
FallbackNTP=
```

Acceptance must verify both that the selected server is reached and that the Worker reports its system clock synchronized. Increasing SSH certificate backdate is not a substitute for a functioning time source.

## `sentinel-egress-policy`

The repository provides an operator-side renderer/verifier. It does **not** apply firewall rules and must never be exposed to Worker/agent as a tool.

At least one trusted NTP source is required. Repeat `-ntp` to allow more than one exact server:

```sh
sentinel-egress-policy \
  -targets /etc/tethys-sentinel/ssh-targets.json \
  -control https://192.0.2.10:9091 \
  -ntp 192.0.2.1 \
  -format pve \
  > 1234.fw
```

Generated policy has `enable: 1`, `policy_in: ACCEPT`, `policy_out: DROP`, exact TCP allows for Control/SSH, exact UDP/123 allows for trusted NTP, and no blanket `OUT ACCEPT` fallback. Explicit inbound accept is required because this per-VM policy is an outbound containment boundary and must not accidentally convert unspecified inbound traffic into a deny policy.

Example shape:

```text
[OPTIONS]

enable: 1
policy_in: ACCEPT
policy_out: DROP

[RULES]

OUT ACCEPT -dest 192.0.2.10 -p tcp -dport 9091 -log nolog # sentinel-control
OUT ACCEPT -dest 192.0.2.53 -p tcp -dport 22 -log nolog # ssh:target-a
OUT ACCEPT -dest 192.0.2.1 -p udp -dport 123 -log nolog # sentinel-ntp
```

Policy carries a SHA-256 digest derived from the canonical Control + target + NTP destination set. Multiple logical targets sharing one IP:port and repeated NTP addresses are transport-deduplicated deterministically.

Machine-readable form:

```sh
sentinel-egress-policy \
  -targets /etc/tethys-sentinel/ssh-targets.json \
  -control https://192.0.2.10:9091 \
  -ntp 192.0.2.1 \
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
  -control https://192.0.2.10:9091 \
  -ntp 192.0.2.1 \
  -format pve \
  -check /etc/pve/firewall/1234.fw \
  -pve-cluster-fw /etc/pve/firewall/cluster.fw \
  -pve-vm-config /etc/pve/qemu-server/1234.conf \
  -pve-net net0
```

Verification fails when:

- installed policy differs byte-for-byte from current generated policy, including NTP destinations;
- Datacenter firewall lacks active `enable: 1`;
- requested VM NIC does not exist;
- selected NIC lacks `firewall=1`.

Verification is read-only. It never reconciles PVE state for the Worker.

## Inventory and time-source change workflow

Use this order:

1. update protected Sentinel target inventory and/or trusted NTP IP set;
2. regenerate external egress policy;
3. review diff;
4. deploy PVE policy through operator path;
5. verify drift + Datacenter/NIC activation;
6. verify guest time client configuration when NTP sources changed;
7. run packet-level validation when required;
8. only then treat the new transport set as infrastructure-ready.

For target or NTP-source removal, narrowing the external policy first is preferable where practical. A newly added destination absent from the PVE policy fails connectivity instead of automatically expanding Worker authority.

## Packet-level acceptance

A clean policy/configuration audit does **not** prove packet behavior. Acceptance must test from inside Worker after policy activation.

Expected successes:

```text
Worker -> Control Plane internal HTTPS IP:port
Worker -> each registered target SSH IP:port
Worker -> each configured trusted NTP IP UDP/123
```

Also verify the guest time service reports a synchronized clock after reaching the trusted NTP server.

Expected failures include:

```text
Worker -> 1.1.1.1:443
Worker -> unrelated LAN host:22
Worker -> registered target IP on unlisted port
Worker -> DNS resolver:53
Worker -> unlisted NTP server UDP/123
```

The repeatable deployment procedure remains in `docs/INFRASTRUCTURE_ACCEPTANCE.md`.

## Established connections and active revocation

External firewall containment and Sentinel active authority are deliberately independent.

A stateful firewall may preserve an already-established TCP flow after a rule is removed. PVE policy reconciliation is therefore **not** the emergency kill mechanism.

Since `0.1.0-dev.10`, running Worker executions use a fail-closed Control Plane authority lease. Individual grant revoke, global `REVOKE ALL`, stale epoch, expiry, Control loss or authority-check failure cancels the Worker execution context and SSH transport. Short certificate TTL, job expiry and target one-shot replay protection remain additional layers.

`0.1.0-dev.11` made the relevant grant/emergency/job/audit transitions transactionally durable in PostgreSQL. Constrained acceptance proved both individual active revoke and active global revoke terminate live SSH execution, and that pre-revoke security epochs never revive after re-enable.

## Failure behavior

Policy generation/verification fails closed when:

- Control URL is not HTTPS;
- Control host is DNS or not a global-unicast literal IP;
- target inventory is empty;
- target endpoint is not global-unicast literal IP:port;
- trusted NTP source set is empty;
- an NTP source is not a global-unicast literal IP;
- target labels are unsafe for deterministic metadata;
- installed verification file differs from generated policy;
- requested PVE activation configuration is incomplete/disabled.

## Trust boundary

`sentinel-egress-policy` is an operator/deployment tool. It must not enter the AI-facing MCP/tool surface, and Worker/agent must never receive an apply/reconcile path with PVE privileges.

Any release or deployment acceptance requires the egress boundary to stay consistent with the accepted real-infrastructure evidence summarized in `HANDOFF.md` and the repeatable checks in `docs/INFRASTRUCTURE_ACCEPTANCE.md`.
