package risk

import "strings"

func classifyService(executable, cmd string, args, argv []string) (Result, bool) {
	switch cmd {
	case "systemctl":
		if containsAny(args,
			"reboot", "poweroff", "halt", "kexec", "soft-reboot",
			"suspend", "hibernate", "hybrid-sleep", "suspend-then-hibernate",
		) {
			return approval(High, "POWER", exactScope(argv), "system power-state transition"), true
		}
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
		if containsAny(args,
			"daemon-reload", "daemon-reexec", "preset-all", "isolate", "rescue", "emergency", "set-default",
			"enable-environment", "set-environment", "unset-environment", "import-environment",
		) {
			return approval(High, "SYSTEM_MANAGER", exactScope(argv), "systemd manager state change"), true
		}
	case "loginctl":
		if containsAny(args, "reboot", "poweroff", "suspend", "hibernate", "hybrid-sleep", "suspend-then-hibernate") {
			return approval(High, "POWER", exactScope(argv), "login manager power-state transition"), true
		}
		if containsAny(args, "terminate-session", "terminate-user", "terminate-seat", "kill-session", "kill-user") {
			return approval(High, "PROCESS_CONTROL", exactScope(argv), "login/session process termination"), true
		}
	case "service":
		if len(args) >= 2 {
			name, action := args[0], args[1]
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
		if containsAssignment(args) || containsAny(args, "-x") {
			return approval(High, "SYSTEM_CONFIG", exactScope(argv), "FreeBSD rc configuration change"), true
		}
	}
	return Result{}, false
}
