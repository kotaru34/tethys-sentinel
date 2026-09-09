# Semantic operational-risk policy

This document describes the operational mutation coverage introduced in `0.1.0-dev.8`.

`dev.7` established the hard boundary for powerful execution (`ARBITRARY_CODE`, `PRIVILEGE_LAUNCHER`, `REMOTE_EXEC`). `dev.8` extends risk routing for ordinary administrator tools whose top-level executable is not itself an arbitrary-code carrier but whose operation can materially change host, network, storage, package, container, orchestrator, or hypervisor state.

## Design rule

The classifier is intentionally **not** a generic file-write detector and is not an authorization proof.

Sentinel focuses on administrator primitives with meaningful blast radius. Ordinary `cp`, `touch`, editor-free file reads, and similar filesystem operations are not made approval-required merely because they can alter data. Their actual authority remains bounded by the target Unix account, filesystem ownership/mode/ACLs, and narrow sudo/doas policy.

The operational classifier answers a narrower question: does this argv represent a known high-impact state transition that should require explicit operator policy approval before an immutable job can execute?

## Covered classes

Current semantic categories include:

- `SERVICE_CONTROL`, `SERVICE_RESTART`, `SYSTEM_MANAGER`, `SYSTEM_CONFIG`
- `POWER`, `PROCESS_CONTROL`, `LOG_CONTROL`, `KERNEL_CONTROL`
- `NETWORK_CONTROL`
- `PACKAGE_CONTROL`
- `STORAGE_CONTROL`, `RAW_STORAGE_WRITE`, and existing destructive storage/filesystem categories
- `CONTAINER_CONTROL`, `CONTAINER_DESTRUCTIVE`
- `ORCHESTRATOR_CONTROL`, `ORCHESTRATOR_DESTRUCTIVE`
- `HYPERVISOR_CONTROL`

Examples covered across supported/administered environments include:

- systemd, classic `service`, OpenBSD `rcctl`, OpenRC `rc-service`, runit `sv`, FreeBSD `sysrc`;
- Linux `ip`/`bridge`/`tc`, BSD `ifconfig`/`route`, WireGuard, networkd, NetworkManager, resolver and NIC configuration;
- nftables, iptables/ip6tables and PF mutations while retaining explicit read-only inspection paths;
- apt/dpkg, dnf/yum/rpm, zypper, apk, pacman, XBPS, FreeBSD `pkg`, snap and flatpak mutation paths;
- mounts/swap/loop devices, partitioning, filesystem repair/resize, mdadm, LVM, ZFS, GELI/GEOM and raw-device writes;
- sysctl/module/log mutations;
- Docker/Podman/nerdctl/CRI state, Kubernetes/Helm state;
- Proxmox `qm`/`pct`/`pvesh`/HA operations, libvirt, bhyve/vm-bhyve and FreeBSD jail controls.

## Read-only versus mutation

Where command syntax has a reliably identifiable read path, inspection remains autonomous under ordinary `exec` capability.

Examples:

```text
systemctl status pdns
ip route show
nft list ruleset
iptables -nvL
pfctl -vvsr
apt list --installed
pkg info postgresql18-server
zpool status tank
zfs list tank/data
mdadm --detail /dev/md0
qm status 100
pvesh get /nodes
```

Mutation forms require approval, for example:

```text
systemctl start pdns
ip route replace default via 10.169.0.1
nft flush ruleset
iptables -A INPUT -j ACCEPT
pfctl -f /etc/pf.conf
apt-get install haproxy
zpool attach tank da0 da1
lvremove vg/data
docker stop pdns
kubectl apply -f deployment.yaml
qm start 100
```

Unknown or ambiguous forms of sensitive firewall/storage/admin tools are handled conservatively rather than assumed read-only.

Firewall option parsing specifically rejects mixed/bundled mutation forms such as `iptables -LZ` and `pfctl -vnf ...` while permitting known inspection bundles such as `iptables -nvL` and `pfctl -vvsr`.

## Workload start is code execution

Starting or building a mutable workload is not treated as a simple reusable state toggle.

Examples such as Docker/Podman `start`, `restart`, `build`, compose `up`, runtime execution, container plugins, namespace execution, VM/jail console/guest execution, and similar operations can execute behavior determined by mutable images/configuration/remote state.

Where appropriate these operations are elevated into the `dev.7` powerful classes, so they inherit:

- explicit `shell=true` capability requirement;
- complete-argv approval scope;
- `allow_once` only;
- current-policy reclassification immediately before SSH signing.

This prevents `dev.8` from accidentally creating a weaker parallel approval path for executable workloads.

## Approval reuse

Operational categories that are not powerful execution may support `allow_session`, but only against their classifier-defined scope.

Stable service operations use a semantic scope including executable + action + concrete service/resource. For example, approval of one service action does not authorize another unit.

Many broader administrative mutations deliberately use exact full-argv scope. A session approval then reuses only that exact classified operation on the same grant/target/category/scope; it is never a category-wide bypass.

Powerful classes remain `allow_once` only regardless of argv equality.

## Policy freshness

All `dev.8` categories participate in the existing immutable-job policy freshness gate.

Before SSH certificate issuance the Control Plane reclassifies `job.argv` with the currently running policy and requires current category and scope to match the stored job. A queued job created before a classifier hardening change therefore fails closed instead of retaining grandfathered authority.

## Security limit

Semantic coverage reduces dangerous `DEFAULT` gaps but cannot enumerate every program, plugin, escape path, or future option.

The classifier therefore remains a risk-routing layer. Hard containment still depends on capability scope, operator approvals, immutable job binding, current-policy certificate gating, signer constraints, exact target identity, target Unix permissions, wrapper/replay controls, narrow sudo/doas policy, and independent network isolation.
