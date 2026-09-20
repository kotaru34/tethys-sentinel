package risk

func classifyEscape(_ string, cmd string, args, argv []string) (Result, bool) {
	switch cmd {
	case "git", "hg":
		return approval(High, "ARBITRARY_CODE", exactScope(argv), "VCS configuration, hooks or aliases can execute external programs"), true
	case "gcc", "g++", "cc", "c++", "clang", "clang++", "ld", "lld":
		return approval(High, "ARBITRARY_CODE", exactScope(argv), "compiler or linker plugins/wrappers can execute supplied code"), true
	case "tar":
		if hasOptionPrefix(args, "--to-command", "--use-compress-program", "-I", "--rsh-command") {
			return approval(High, "ARBITRARY_CODE", exactScope(argv), "tar option can launch an external command"), true
		}
	case "cpio":
		if hasOptionPrefix(args, "--to-command") {
			return approval(High, "ARBITRARY_CODE", exactScope(argv), "cpio option can launch an external command"), true
		}
	case "openssl":
		if hasOptionPrefix(args, "-engine", "-provider", "-provider-path") {
			return approval(High, "ARBITRARY_CODE", exactScope(argv), "OpenSSL engine/provider loading can load executable code"), true
		}
	case "man":
		if hasOptionPrefix(args, "-P", "--pager") {
			return approval(High, "ARBITRARY_CODE", exactScope(argv), "custom manual pager can execute an external command"), true
		}
	case "less", "more":
		return approval(High, "ARBITRARY_CODE", exactScope(argv), "pager command language supports shell escapes"), true
	case "sudoedit", "chpst", "setuidgid", "envuidgid", "daemon":
		return approval(Critical, "PRIVILEGE_LAUNCHER", exactScope(argv), "launcher can execute under a changed identity or privilege context"), true
	case "softlimit", "prlimit", "setarch", "linux32", "linux64", "daemonize":
		return approval(High, "ARBITRARY_CODE", exactScope(argv), "command wrapper can launch an arbitrary child executable"), true
	}
	return Result{}, false
}
