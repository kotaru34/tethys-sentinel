package risk

func classifySystem(_ string, cmd string, args, argv []string) (Result, bool) {
	switch cmd {
	case "sysctl":
		if hasOptionPrefix(args, "-w", "--write") || containsAssignment(args) {
			return approval(High, "KERNEL_CONTROL", exactScope(argv), "kernel runtime parameter change"), true
		}
	case "modprobe", "insmod", "rmmod", "kldload", "kldunload":
		return approval(High, "KERNEL_CONTROL", exactScope(argv), "kernel module state change"), true
	case "kexec":
		return approval(Critical, "POWER", exactScope(argv), "kernel replacement or kexec transition"), true
	case "init", "telinit":
		if len(args) > 0 {
			return approval(Critical, "POWER", exactScope(argv), "init/runlevel transition can stop services or power the host"), true
		}
	case "hostnamectl", "timedatectl", "localectl":
		if containsAny(args,
			"set-hostname", "set-icon-name", "set-chassis", "set-location",
			"set-time", "set-timezone", "set-ntp", "set-local-rtc",
			"set-locale", "set-keymap", "set-x11-keymap",
		) {
			return approval(High, "SYSTEM_CONFIG", exactScope(argv), "host system configuration change"), true
		}
	case "hostname":
		if len(args) > 0 && !containsAny(args, "-f", "--fqdn", "-s", "--short", "-d", "--domain", "-i", "--ip-address", "-I", "--all-ip-addresses") {
			return approval(High, "SYSTEM_CONFIG", exactScope(argv), "host name change"), true
		}
	case "date":
		if hasOptionPrefix(args, "-s", "--set") {
			return approval(High, "SYSTEM_CONFIG", exactScope(argv), "system clock change"), true
		}
	case "hwclock":
		if containsAny(args, "--systohc", "--hctosys", "--set", "--adjust", "--predict-hc") {
			return approval(High, "SYSTEM_CONFIG", exactScope(argv), "hardware/system clock state change"), true
		}
	case "journalctl":
		if hasOptionPrefix(args, "--vacuum-size", "--vacuum-time", "--vacuum-files") || containsAny(args, "--rotate") {
			return approval(High, "LOG_CONTROL", exactScope(argv), "system journal retention or rotation change"), true
		}
	case "logrotate":
		if hasOptionPrefix(args, "-f", "--force") {
			return approval(Medium, "LOG_CONTROL", exactScope(argv), "forced log rotation"), true
		}
	case "kill", "pkill", "killall":
		return approval(High, "PROCESS_CONTROL", exactScope(argv), "process termination or signal delivery"), true
	case "renice":
		return approval(Medium, "PROCESS_CONTROL", exactScope(argv), "process scheduling priority change"), true
	}
	return Result{}, false
}
