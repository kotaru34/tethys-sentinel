package risk

func classifyRuntime(_ string, cmd string, args, argv []string) (Result, bool) {
	switch cmd {
	case "docker":
		if hasOptionPrefix(args, "-H", "--host", "--context") {
			return approval(High, "REMOTE_EXEC", exactScope(argv), "Docker operation targets another daemon/context"), true
		}
		if containsAny(args, "start", "restart", "build") || containsSequence(args, "buildx", "build") ||
			containsSequence(args, "compose", "up") || containsSequence(args, "compose", "start") ||
			containsSequence(args, "compose", "restart") || containsSequence(args, "compose", "build") ||
			containsSequence(args, "plugin", "install") || containsSequence(args, "plugin", "enable") || containsSequence(args, "plugin", "upgrade") {
			return approval(High, "ARBITRARY_CODE", exactScope(argv), "container operation can start or build mutable executable workloads"), true
		}
		if containsAny(args, "stop", "kill", "rm", "pause", "unpause", "rename", "update", "commit", "pull", "push", "tag", "load", "import") ||
			containsSequence(args, "network", "create") || containsSequence(args, "network", "rm") ||
			containsSequence(args, "network", "connect") || containsSequence(args, "network", "disconnect") ||
			containsSequence(args, "volume", "create") || containsSequence(args, "volume", "rm") ||
			containsSequence(args, "compose", "down") || containsSequence(args, "compose", "stop") ||
			containsSequence(args, "compose", "rm") {
			return approval(High, "CONTAINER_CONTROL", exactScope(argv), "container runtime state change"), true
		}
	case "podman":
		if containsAny(args, "--remote") || hasOptionPrefix(args, "--connection", "--url") {
			return approval(High, "REMOTE_EXEC", exactScope(argv), "Podman operation targets another service/context"), true
		}
		if containsAny(args, "start", "restart", "build") {
			return approval(High, "ARBITRARY_CODE", exactScope(argv), "container operation can start or build mutable executable workloads"), true
		}
		if containsAny(args, "stop", "kill", "rm", "pause", "unpause", "rename", "update", "commit", "pull", "push", "tag", "load", "import") ||
			containsSequence(args, "network", "create") || containsSequence(args, "network", "rm") ||
			containsSequence(args, "network", "connect") || containsSequence(args, "network", "disconnect") ||
			containsSequence(args, "volume", "create") || containsSequence(args, "volume", "rm") {
			return approval(High, "CONTAINER_CONTROL", exactScope(argv), "container runtime state change"), true
		}
	case "nerdctl":
		if containsAny(args, "run", "exec", "create", "start", "restart", "build") {
			return approval(High, "ARBITRARY_CODE", exactScope(argv), "container command can execute or start arbitrary code"), true
		}
		if containsAny(args, "stop", "kill", "rm", "pause", "unpause", "pull", "load") {
			return approval(High, "CONTAINER_CONTROL", exactScope(argv), "container runtime state change"), true
		}
	case "crictl":
		if containsAny(args, "exec", "run", "runp", "start") {
			return approval(High, "ARBITRARY_CODE", exactScope(argv), "CRI operation can execute or start arbitrary workloads"), true
		}
		if containsAny(args, "stop", "stopp", "rm", "rmp", "pull") {
			return approval(High, "CONTAINER_CONTROL", exactScope(argv), "CRI runtime state change"), true
		}
	case "kubectl":
		if containsAny(args, "apply", "create", "replace", "patch", "edit", "scale", "autoscale", "label", "annotate", "taint", "cordon", "uncordon", "drain") ||
			containsSequence(args, "rollout", "restart") || containsSequence(args, "rollout", "undo") ||
			containsSequence(args, "set", "image") || containsSequence(args, "set", "env") || containsSequence(args, "set", "resources") {
			return approval(High, "ORCHESTRATOR_CONTROL", exactScope(argv), "Kubernetes resource or node state change"), true
		}
		if containsAny(args, "cp") {
			return approval(High, "REMOTE_EXEC", exactScope(argv), "Kubernetes copy operation crosses the target/container boundary"), true
		}
	case "helm":
		if containsAny(args, "install", "upgrade", "uninstall", "rollback") {
			return approval(High, "ORCHESTRATOR_CONTROL", exactScope(argv), "Helm release state change"), true
		}
	case "qm":
		if containsAny(args, "terminal", "monitor", "guest") {
			return approval(High, "REMOTE_EXEC", exactScope(argv), "VM console/monitor/guest-agent operation can cross into guest execution"), true
		}
		if containsAny(args, "create", "destroy", "start", "stop", "shutdown", "reboot", "reset", "suspend", "resume", "clone", "migrate", "move_disk", "set", "resize", "snapshot", "delsnapshot", "rollback", "importdisk") {
			return approval(High, "HYPERVISOR_CONTROL", exactScope(argv), "Proxmox VM state or configuration change"), true
		}
	case "pct":
		if containsAny(args, "enter", "exec") {
			return approval(High, "REMOTE_EXEC", exactScope(argv), "container enter/exec crosses the target execution boundary"), true
		}
		if containsAny(args, "create", "destroy", "start", "stop", "shutdown", "reboot", "suspend", "resume", "clone", "migrate", "move-volume", "set", "resize", "snapshot", "delsnapshot", "rollback", "push") {
			return approval(High, "HYPERVISOR_CONTROL", exactScope(argv), "Proxmox container state or configuration change"), true
		}
	case "pvesh":
		if containsAny(args, "create", "set", "delete") {
			return approval(High, "HYPERVISOR_CONTROL", exactScope(argv), "Proxmox API state change"), true
		}
	case "ha-manager":
		if containsAny(args, "add", "remove", "set", "migrate", "relocate", "enable", "disable") {
			return approval(High, "HYPERVISOR_CONTROL", exactScope(argv), "Proxmox HA state change"), true
		}
	case "virsh":
		if containsAny(args, "console", "qemu-monitor-command", "qemu-agent-command") {
			return approval(High, "REMOTE_EXEC", exactScope(argv), "VM console/monitor/agent operation can cross into guest execution"), true
		}
		if containsAny(args, "start", "shutdown", "destroy", "reboot", "reset", "suspend", "resume", "define", "undefine", "create", "migrate", "managedsave", "snapshot-create", "snapshot-delete", "snapshot-revert", "attach-disk", "detach-disk", "attach-interface", "detach-interface", "setmem", "setvcpus") {
			return approval(High, "HYPERVISOR_CONTROL", exactScope(argv), "libvirt VM state or configuration change"), true
		}
	case "bhyvectl":
		if len(args) > 0 && !containsAny(args, "--get-stats") {
			return approval(High, "HYPERVISOR_CONTROL", exactScope(argv), "bhyve VM state change"), true
		}
	case "vm":
		if containsAny(args, "start", "stop", "restart", "poweroff", "reset", "create", "destroy", "clone", "snapshot", "rollback", "install", "configure") {
			return approval(High, "HYPERVISOR_CONTROL", exactScope(argv), "vm-bhyve state or configuration change"), true
		}
	case "jexec":
		return approval(High, "REMOTE_EXEC", exactScope(argv), "FreeBSD jail execution crosses the target process boundary"), true
	case "jail":
		if len(args) > 0 {
			return approval(High, "HYPERVISOR_CONTROL", exactScope(argv), "FreeBSD jail state change"), true
		}
	case "iocage":
		if containsAny(args, "exec", "console") {
			return approval(High, "REMOTE_EXEC", exactScope(argv), "jail exec/console crosses the target process boundary"), true
		}
		if containsAny(args, "create", "destroy", "start", "stop", "restart", "set", "rename", "clone", "snapshot", "rollback", "upgrade", "update") {
			return approval(High, "HYPERVISOR_CONTROL", exactScope(argv), "iocage jail state or configuration change"), true
		}
	}
	return Result{}, false
}
