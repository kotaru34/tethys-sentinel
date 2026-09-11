package risk

import "strings"

func classifyPackage(_ string, cmd string, args, argv []string) (Result, bool) {
	mutating := func(verbs ...string) (Result, bool) {
		if containsAny(args, verbs...) {
			return approval(Medium, "PACKAGE_CONTROL", exactScope(argv), "package or system software state change"), true
		}
		return Result{}, false
	}

	switch cmd {
	case "apt", "apt-get":
		return mutating("install", "remove", "purge", "upgrade", "full-upgrade", "dist-upgrade", "autoremove", "build-dep", "satisfy")
	case "apt-mark":
		return mutating("hold", "unhold", "manual", "auto", "minimize-manual")
	case "dnf", "yum":
		if result, ok := mutating("install", "remove", "erase", "upgrade", "update", "downgrade", "reinstall", "distro-sync", "autoremove", "swap"); ok {
			return result, true
		}
		if containsSequence(args, "module", "enable") || containsSequence(args, "module", "disable") || containsSequence(args, "module", "reset") || containsSequence(args, "module", "install") || containsSequence(args, "module", "remove") {
			return approval(Medium, "PACKAGE_CONTROL", exactScope(argv), "package module state change"), true
		}
	case "zypper":
		return mutating("install", "in", "remove", "rm", "update", "up", "dist-upgrade", "dup", "patch")
	case "apk":
		return mutating("add", "del", "upgrade", "fix")
	case "pkg":
		return mutating("bootstrap", "install", "delete", "remove", "upgrade", "update", "autoremove", "lock", "unlock", "set")
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
		if pacmanMutates(args) {
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

func pacmanMutates(args []string) bool {
	syncSeen := false
	readOnlySync := false
	for _, arg := range args {
		switch arg {
		case "-R", "--remove", "-U", "--upgrade":
			return true
		case "--sync":
			syncSeen = true
		case "--search", "--info", "--list", "--groups", "--print":
			readOnlySync = true
		}
		if strings.HasPrefix(arg, "-R") && len(arg) > 2 {
			return true
		}
		if strings.HasPrefix(arg, "-U") && len(arg) > 2 {
			return true
		}
		if strings.HasPrefix(arg, "-S") {
			syncSeen = true
			rest := strings.TrimPrefix(arg, "-S")
			if strings.ContainsAny(rest, "yu") {
				return true
			}
			if rest != "" && onlyRunes(rest, "silgpq") {
				readOnlySync = true
			}
		}
	}
	return syncSeen && !readOnlySync
}

func onlyRunes(value, allowed string) bool {
	for _, r := range value {
		if !strings.ContainsRune(allowed, r) {
			return false
		}
	}
	return true
}
