package risk

import "strings"

// classifyOperational covers high-impact administrator primitives whose risk is
// better described by a semantic operation class than by arbitrary-code
// detection. It intentionally does not try to classify every ordinary file
// mutation; target Unix permissions and sudo/doas remain the file-authority
// boundary.
func classifyOperational(executable, cmd string, args, argv []string) (Result, bool) {
	if result, ok := classifyService(executable, cmd, args, argv); ok {
		return result, true
	}
	if result, ok := classifyNetwork(executable, cmd, args, argv); ok {
		return result, true
	}
	if result, ok := classifyPackage(cmd, args, argv); ok {
		return result, true
	}
	if result, ok := classifyStorage(cmd, args, argv); ok {
		return result, true
	}
	if result, ok := classifyKernel(cmd, args, argv); ok {
		return result, true
	}
	if result, ok := classifyContainerOrchestrator(cmd, args, argv); ok {
		return result, true
	}
	if result, ok := classifyHypervisor(cmd, args, argv); ok {
		return result, true
	}
	if result, ok := classifyProcess(cmd, argv); ok {
		return result, true
	}
	return Result{}, false
}

func classifyService(executable, cmd string, args, argv []string) (Result, bool) {
	switch cmd {
	case "systemctl":
		action, resource := actionResource(args, []string{
			"start", "stop", "restart", "try-restart", "reload", "reload-or-restart", "reload-or-try-restart",
			"enable", "disable", "reenable", "mask", "unmask", "preset", "revert", "kill", "set-property", "edit",
		})
		if action != "" {
			level := High
			category := "SERVICE_CONTROL"
			if action == "restart" || action == "try-restart" || strings.HasPrefix(action, "reload") {
				level = Medium
				category = "SERVICE_RESTART"
			}
			return approval(level, category, semanticScope(executable, "systemctl:"+action+":"+resource), "service lifecycle or configuration change"), true
		}
		if containsAny(args, "daemon-reload", "daemon-reexec", "preset-all", "isolate", "set-default", "enable-environment", "set-environment", "unset-environment", "import-environment") {
			return approval(High, "SYSTEM_MANAGER", exactScope(argv), "systemd manager state change"), true
		}
	case "service":
		if len(args) >= 2 {
			name := args[0]
			action := args[1]
			switch action {
			case "start", "stop", "enable", "disable", "onestart", "onestop", "forcestart", "forcestop":
				return approval(High, "SERVICE_CONTROL", semanticScope(executable, "service:"+action+":"+name), "service lifecycle change"), true
			case "restart", "reload", "onerestart", "forcerestart":
				return approval(Medium, "SERVICE_RESTART", semanticScope(executable, "service:"+action+":"+name), "service restart or reload"), true
			}
		}
	case "rcctl":
		action, resource := actionResource(args, []string{"start", "stop", "restart", "reload", "enable", "disable", "set"})
		if action != "" {
			level := High
			category := "SERVICE_CONTROL"
			if action == "restart" || action == "reload" {
				level = Medium
				category = "SERVICE_RESTART"
			}
			return approval(level, category, semanticScope(executable, "rcctl:"+action+":"+resource), "service lifecycle or configuration change"), true
		}
	case "rc-service":
		if len(args) >= 2 {
			name, action := args[0], args[1]
			switch action {
			case "start", "stop":
				return approval(High, "SERVICE_CONTROL", semanticScope(executable, "rc-service:"+action+":"+name), "service lifecycle change"), true
			case "restart", "reload":
				return approval(Medium, "SERVICE_RESTART", semanticScope(executable, "rc-service:"+action+":"+name), "service restart or reload"), true
			}
		}
	case "sv":
		if len(args) >= 2 {
			action, name := args[0], args[1]
			switch action {
			case "up", "down", "once", "pause", "cont", "kill", "exit":
				return approval(High, "SERVICE_CONTROL", semanticScope(executable, "sv:"+action+":"+name), "runit service lifecycle change"), true
			case "restart", "force-restart", "hup", "term", "interrupt":
				return approval(Medium, "SERVICE_RESTART", semanticScope(executable, "sv:"+action+":"+name), "runit service restart or signal"), true
			}
		}
	case "sysrc":
		if len(args) > 0 && !containsAny(args, "-a", "-A", "-n") {
			return approval(High, "SYSTEM_CONFIG", exactScope(argv), "FreeBSD rc configuration change"), true
		}
	}
	return Result{}, false
}

func classifyNetwork(executable, cmd string, args, argv []string) (Result, bool) {
	switch cmd {
	case "ip":
		if containsSequence(args, "netns", "exec") || containsSequence(args, "vrf", "exec") {
			return approval(Critical, "PRIVILEGE_LAUNCHER", exactScope(argv), "network namespace execution can cross the target process boundary"), true
		}
		objects := map[string][]string{
			"link": {"add", "delete", "del", "set"},
			"address": {"add", "change", "replace", "delete", "del", "flush"},
			"addr": {"add", "change", "replace", "delete", "del", "flush"},
			"route": {"add", "append", "change", "replace", "delete", "del", "flush"},
			"rule": {"add", "delete", "del", "flush"},
			"neigh": {"add", "change", "replace", "delete", "del", "flush"},
			"neighbor": {"add", "change", "replace", "delete", "del", "flush"},
			"tunnel": {"add", "change", "delete", "del"},
			"netns": {"add", "delete", "del", "set"},
		}
		for object, verbs := range objects {
			if containsObjectVerb(args, object, verbs) {
				return approval(High, "NETWORK_CONTROL", exactScope(argv), "network interface, address, route or namespace state change"), true
			}
		}
	case "bridge":
		if containsAny(args, "add", "del", "delete", "set", "replace", "flush") {
			return approval(High, "NETWORK_CONTROL", exactScope(argv), "bridge state change"), true
		}
	case "tc":
		if containsAny(args, "add", "change", "replace", "delete", "del") {
			return approval(High, "NETWORK_CONTROL", exactScope(argv), "traffic-control state change"), true
		}
	case "ifconfig":
		if len(args) > 1 && !(len(args) == 2 && (args[0] == "-a" || args[0] == "-l")) {
			return approval(High, "NETWORK_CONTROL", exactScope(argv), "interface configuration change"), true
		}
	case "route":
		if containsAny(args, "add", "delete", "del", "change", "replace", "flush") {
			return approval(High, "NETWORK_CONTROL", exactScope(argv), "route table change"), true
		}
	case "wg":
		if containsAny(args, "set", "setconf", "syncconf") {
			return approval(High, "NETWORK_CONTROL", exactScope(argv), "WireGuard configuration change"), true
		}
	case "wg-quick":
		if containsAny(args, "up", "down", "save") {
			return approval(High, "NETWORK_CONTROL", exactScope(argv), "WireGuard interface state change"), true
		}
	case "networkctl":
		if containsAny(args, "up", "down", "renew", "forcerenew", "reconfigure", "reload", "delete") {
			return approval(High, "NETWORK_CONTROL", exactScope(argv), "networkd state change"), true
		}
	case "resolvectl":
		if containsAny(args, "dns", "domain", "default-route", "llmnr", "mdns", "dnssec", "nta", "revert") {
			return approval(High, "NETWORK_CONTROL", exactScope(argv), "resolver link configuration change"), true
		}
	case "nmcli":
		if containsAny(args, "up", "down", "add", "delete", "modify", "clone", "import", "connect", "disconnect", "reapply") || containsSequence(args, "networking", "off") || containsSequence(args, "networking", "on") {
			return approval(High, "NETWORK_CONTROL", exactScope(argv), "NetworkManager state change"), true
		}
	case "ethtool":
		if hasOptionPrefix(args, "-s", "--change", "-K", "--offload", "-L", "--set-channels", "-G", "--set-ring", "-C", "--coalesce", "-A", "--pause", "--set-eee", "--set-priv-flags") {
			return approval(High, "NETWORK_CONTROL", exactScope(argv), "network device configuration change"), true
		}
	}
	_ = executable
	return Result{}, false
}

func classifyPackage(cmd string, args, argv []string) (Result, bool) {
	mutating := func(verbs ...string) (Result, bool) {
		if containsAny(args, verbs...) {
			return approval(Medium, "PACKAGE_CONTROL", exactScope(argv), "package or system software state change"), true
		}
		return Result{}, false
	}
	switch cmd {
	case "apt", "apt-get":
		return mutating("install", "remove", "purge", "upgrade", "full-upgrade", "dist-upgrade", "autoremove", "build-dep", "satisfy")
	case "dnf", "yum":
		return mutating("install", "remove", "erase", "upgrade", "update", "downgrade", "reinstall", "distro-sync", "autoremove", "swap")
	case "zypper":
		return mutating("install", "in", "remove", "rm", "update", "up", "dist-upgrade", "dup", "patch")
	case "apk":
		return mutating("add", "del", "upgrade", "fix")
	case "pkg":
		return mutating("install", "delete", "remove", "upgrade", "update", "autoremove", "lock", "unlock")
	case "xbps-install", "xbps-remove", "xbps-reconfigure", "xbps-pkgdb":
		return approval(Medium, "PACKAGE_CONTROL", exactScope(argv), "XBPS package state change"), true
	case "dpkg":
		if hasOptionPrefix(args, "-i", "--install", "-r", "--remove", "-P", "--purge", "--configure", "--unpack") {
			return approval(Medium, "PACKAGE_CONTROL", exactScope(argv), "dpkg package state change"), true
		}
	case "rpm":
		if hasOptionPrefix(args, "-i", "--install", "-U", "--upgrade", "-F", "--freshen", "-e", "--erase", "--rebuilddb") {
			return approval(Medium, "PACKAGE_CONTROL", exactScope(argv), "RPM package state change"), true
		}
	case "pacman":
		if hasOptionPrefix(args, "-S", "--sync", "-R", "--remove", "-U", "--upgrade") {
			return approval(Medium, "PACKAGE_CONTROL", exactScope(argv), "pacman package state change"), true
		}
	case "freebsd-update":
		return mutating("install", "upgrade", "rollback")
	case "snap":
		return mutating("install", "remove", "refresh", "revert", "enable", "disable")
	case "flatpak":
		return mutating("install", "uninstall", "update", "override", "mask", "pin")
	}
	return Result{}, false
}

func classifyStorage(cmd string, args, argv []string) (Result, bool) {
	switch cmd {
	case "dd", "blkdiscard", "sg_format":
		return approval(Critical, "RAW_STORAGE_WRITE", exactScope(argv), "raw block/storage write can destroy data"), true
	case "mount", "umount", "swapon", "swapoff", "losetup":
		return approval(High, "STORAGE_CONTROL", exactScope(argv), "mount, swap or loop-device state change"), true
	case "fdisk", "sfdisk", "cfdisk", "gdisk", "sgdisk", "parted":
		if (cmd == "fdisk" || cmd == "parted") && containsAny(args, "-l", "--list") {
			return Result{}, false
		}
		return approval(Critical, "STORAGE_CONTROL", exactScope(argv), "partition-table operation"), true
	case "fsck", "e2fsck", "xfs_repair", "resize2fs", "xfs_growfs", "tune2fs":
		return approval(High, "STORAGE_CONTROL", exactScope(argv), "filesystem repair or geometry change"), true
	case "mdadm":
		if containsAny(args, "--detail", "--examine", "--query", "--scan") && !containsAny(args, "--create", "--assemble", "--stop", "--add", "--remove", "--fail", "--grow", "--manage") {
			return Result{}, false
		}
		return approval(High, "STORAGE_CONTROL", exactScope(argv), "software RAID state change"), true
	case "pvcreate", "pvremove", "pvresize", "pvmove", "vgcreate", "vgremove", "vgextend", "vgreduce", "vgrename", "vgchange", "lvcreate", "lvremove", "lvresize", "lvextend", "lvreduce", "lvrename", "lvchange", "lvconvert":
		return approval(High, "STORAGE_CONTROL", exactScope(argv), "LVM topology or volume state change"), true
	case "zpool":
		if containsAny(args, "add", "attach", "detach", "replace", "remove", "online", "offline", "clear", "import", "export", "upgrade", "set", "trim", "checkpoint", "reguid", "split", "scrub") {
			return approval(High, "STORAGE_CONTROL", exactScope(argv), "ZFS pool state or topology change"), true
		}
	case "zfs":
		if containsAny(args, "create", "snapshot", "clone", "promote", "rename", "rollback", "set", "inherit", "hold", "release", "mount", "unmount", "share", "unshare", "receive", "recv") {
			return approval(High, "STORAGE_CONTROL", exactScope(argv), "ZFS dataset state change"), true
		}
	case "cryptsetup":
		if !containsAny(args, "status", "luksDump", "isLuks", "benchmark") {
			return approval(Critical, "STORAGE_CONTROL", exactScope(argv), "encrypted-volume state or metadata change"), true
		}
	case "geli":
		if containsAny(args, "init", "attach", "detach", "setkey", "delkey", "kill", "onetime", "configure", "resize") {
			return approval(Critical, "STORAGE_CONTROL", exactScope(argv), "GELI encrypted-volume state change"), true
		}
	case "gpart":
		if containsAny(args, "create", "add", "delete", "destroy", "modify", "resize", "recover", "set", "unset", "bootcode") {
			return approval(Critical, "STORAGE_CONTROL", exactScope(argv), "GEOM partition state change"), true
		}
	case "bectl":
		if containsAny(args, "create", "destroy", "activate", "rename", "mount", "unmount", "jail") {
			return approval(High, "STORAGE_CONTROL", exactScope(argv), "boot-environment state change"), true
		}
	}
	return Result{}, false
}

func classifyKernel(cmd string, args, argv []string) (Result, bool) {
	switch cmd {
	case "sysctl":
		if hasOptionPrefix(args, "-w", "--write") || containsAssignment(args) {
			return approval(High, "KERNEL_CONTROL", exactScope(argv), "kernel runtime parameter change"), true
		}
	case "modprobe", "insmod", "rmmod", "kldload", "kldunload":
		return approval(High, "KERNEL_CONTROL", exactScope(argv), "kernel module state change"), true
	case "kexec":
		return approval(Critical, "POWER", exactScope(argv), "kernel replacement or kexec transition"), true
	case "hostnamectl", "timedatectl", "localectl":
		if containsAny(args, "set-hostname", "set-icon-name", "set-chassis", "set-location", "set-time", "set-timezone", "set-ntp", "set-local-rtc", "set-locale", "set-keymap", "set-x11-keymap") {
			return approval(High, "SYSTEM_CONFIG", exactScope(argv), "host system configuration change"), true
		}
	}
	return Result{}, false
}

func classifyContainerOrchestrator(cmd string, args, argv []string) (Result, bool) {
	switch cmd {
	case "docker", "podman":
		if containsAny(args, "start", "stop", "restart", "kill", "rm", "pause", "unpause", "rename", "update", "commit", "pull", "push", "tag") || containsSequence(args, "network", "create") || containsSequence(args, "network", "rm") || containsSequence(args, "network", "connect") || containsSequence(args, "network", "disconnect") || containsSequence(args, "volume", "create") || containsSequence(args, "volume", "rm") || containsSequence(args, "compose", "up") || containsSequence(args, "compose", "down") {
			return approval(High, "CONTAINER_CONTROL", exactScope(argv), "container runtime state change"), true
		}
	case "kubectl":
		if containsAny(args, "apply", "create", "replace", "patch", "edit", "scale", "autoscale", "label", "annotate", "taint", "cordon", "uncordon", "drain") || containsSequence(args, "rollout", "restart") || containsSequence(args, "rollout", "undo") || containsSequence(args, "set", "image") || containsSequence(args, "set", "env") || containsSequence(args, "set", "resources") {
			return approval(High, "ORCHESTRATOR_CONTROL", exactScope(argv), "Kubernetes resource or node state change"), true
		}
		if containsAny(args, "cp") {
			return approval(High, "REMOTE_EXEC", exactScope(argv), "Kubernetes copy operation crosses the target/container boundary"), true
		}
	case "helm":
		if containsAny(args, "install", "upgrade", "uninstall", "rollback") {
			return approval(High, "ORCHESTRATOR_CONTROL", exactScope(argv), "Helm release state change"), true
		}
	case "nerdctl":
		if containsAny(args, "run", "exec", "create") {
			return approval(High, "ARBITRARY_CODE", exactScope(argv), "container command can execute arbitrary code"), true
		}
		if containsAny(args, "start", "stop", "restart", "kill", "rm", "pause", "unpause", "pull") {
			return approval(High, "CONTAINER_CONTROL", exactScope(argv), "container runtime state change"), true
		}
	}
	return Result{}, false
}

func classifyHypervisor(cmd string, args, argv []string) (Result, bool) {
	switch cmd {
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
	}
	return Result{}, false
}

func classifyProcess(cmd string, argv []string) (Result, bool) {
	switch cmd {
	case "kill", "pkill", "killall":
		return approval(High, "PROCESS_CONTROL", exactScope(argv), "process termination or signal delivery"), true
	case "renice":
		return approval(Medium, "PROCESS_CONTROL", exactScope(argv), "process scheduling priority change"), true
	}
	return Result{}, false
}

func actionResource(args, actions []string) (string, string) {
	for i, arg := range args {
		if !stringIn(arg, actions) {
			continue
		}
		resource := "*"
		for _, candidate := range args[i+1:] {
			if !strings.HasPrefix(candidate, "-") {
				resource = candidate
				break
			}
		}
		return arg, resource
	}
	return "", "*"
}

func containsSequence(args []string, values ...string) bool {
	return contains(args, values...)
}

func containsObjectVerb(args []string, object string, verbs []string) bool {
	for i, arg := range args {
		if arg != object {
			continue
		}
		for _, later := range args[i+1:] {
			if stringIn(later, verbs) {
				return true
			}
		}
	}
	return false
}

func stringIn(value string, values []string) bool {
	for _, candidate := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func containsAssignment(args []string) bool {
	for _, arg := range args {
		if strings.Contains(arg, "=") && !strings.HasPrefix(arg, "=") {
			return true
		}
	}
	return false
}
