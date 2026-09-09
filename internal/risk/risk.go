package risk

import (
	"path/filepath"
	"strings"
)

type Level string

type Decision string

const (
	Low      Level = "low"
	Medium   Level = "medium"
	High     Level = "high"
	Critical Level = "critical"

	Allow            Decision = "allow"
	ApprovalRequired Decision = "approval_required"
	Deny             Decision = "deny"
)

type Result struct {
	Decision Decision `json:"decision"`
	Level    Level    `json:"level"`
	Category string   `json:"category"`
	ScopeKey string   `json:"scope_key"`
	Reason   string   `json:"reason"`
}

func Classify(argv []string) Result {
	if len(argv) == 0 || strings.TrimSpace(argv[0]) == "" {
		return Result{Decision: Deny, Level: Critical, Category: "INVALID", Reason: "empty command"}
	}

	cmd := filepath.Base(argv[0])
	args := argv[1:]

	switch cmd {
	case "reboot", "shutdown", "poweroff", "halt":
		return approval(High, "POWER", cmd, "host power-state change")
	case "mkfs", "mkfs.ext4", "mkfs.xfs", "wipefs", "shred":
		return approval(Critical, "FILESYSTEM_DESTRUCTIVE", exactScope(cmd, args), "destructive storage operation")
	case "zpool":
		if firstArg(args) == "destroy" {
			return approval(Critical, "STORAGE_DESTRUCTIVE", resourceScope("zpool:destroy", args[1:]), "zpool destruction")
		}
	case "zfs":
		if firstArg(args) == "destroy" {
			return approval(Critical, "STORAGE_DESTRUCTIVE", resourceScope("zfs:destroy", args[1:]), "ZFS dataset destruction")
		}
	case "rm":
		return approval(High, "FILESYSTEM_DELETE", exactScope(cmd, args), "file deletion")
	case "passwd", "useradd", "userdel", "usermod", "groupadd", "groupdel", "chpasswd":
		return approval(High, "IDENTITY", exactScope(cmd, args), "identity or authentication change")
	case "nft", "iptables", "ip6tables", "pfctl":
		return approval(High, "NETWORK_CONTROL", exactScope(cmd, args), "firewall policy change")
	case "systemctl":
		action, unit := systemctlAction(args)
		switch action {
		case "stop", "disable", "mask":
			return approval(High, "SERVICE_CONTROL", "systemctl:"+action+":"+unit, "service availability change")
		case "restart", "try-restart", "reload-or-restart":
			return approval(Medium, "SERVICE_RESTART", "systemctl:"+action+":"+unit, "service restart")
		}
	case "docker", "podman":
		if contains(args, "system", "prune") || contains(args, "volume", "prune") {
			return approval(Critical, "CONTAINER_DESTRUCTIVE", exactScope(cmd, args), "destructive container cleanup")
		}
	case "kubectl":
		if firstArg(args) == "delete" {
			return approval(High, "ORCHESTRATOR_DESTRUCTIVE", exactScope(cmd, args), "Kubernetes resource deletion")
		}
	}

	return Result{Decision: Allow, Level: Low, Category: "DEFAULT", ScopeKey: cmd, Reason: "no elevated-risk rule matched"}
}

func approval(level Level, category, scope, reason string) Result {
	return Result{Decision: ApprovalRequired, Level: level, Category: category, ScopeKey: scope, Reason: reason}
}

func firstArg(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return args[0]
}

func resourceScope(prefix string, args []string) string {
	for _, arg := range args {
		if !strings.HasPrefix(arg, "-") {
			return prefix + ":" + arg
		}
	}
	return prefix + ":*"
}

func exactScope(cmd string, args []string) string {
	return cmd + ":" + strings.Join(args, "\x1f")
}

func systemctlAction(args []string) (string, string) {
	for i, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		unit := "*"
		if i+1 < len(args) {
			unit = args[i+1]
		}
		return a, unit
	}
	return "", "*"
}

func contains(args []string, sequence ...string) bool {
	if len(sequence) == 0 || len(args) < len(sequence) {
		return false
	}
	for i := 0; i <= len(args)-len(sequence); i++ {
		ok := true
		for j := range sequence {
			if args[i+j] != sequence[j] {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}
