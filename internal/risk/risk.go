package risk

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

	executable := strings.TrimSpace(argv[0])
	cmd := filepath.Base(executable)
	args := argv[1:]

	if isPrivilegeLauncher(cmd) {
		return approval(Critical, "PRIVILEGE_LAUNCHER", exactScope(argv), "privilege or namespace launcher can broaden execution authority")
	}

	switch cmd {
	case "reboot", "shutdown", "poweroff", "halt":
		return approval(High, "POWER", exactScope(argv), "host power-state change")
	case "mkfs", "mkfs.ext4", "mkfs.xfs", "wipefs", "shred":
		return approval(Critical, "FILESYSTEM_DESTRUCTIVE", exactScope(argv), "destructive storage operation")
	case "zpool":
		if containsAny(args, "destroy") {
			return approval(Critical, "STORAGE_DESTRUCTIVE", exactScope(argv), "zpool destruction")
		}
	case "zfs":
		if containsAny(args, "destroy") {
			return approval(Critical, "STORAGE_DESTRUCTIVE", exactScope(argv), "ZFS dataset destruction")
		}
	case "rm":
		return approval(High, "FILESYSTEM_DELETE", exactScope(argv), "file deletion")
	case "passwd", "useradd", "userdel", "usermod", "groupadd", "groupdel", "chpasswd":
		return approval(High, "IDENTITY", exactScope(argv), "identity or authentication change")
	case "systemctl":
		if hasOptionPrefix(args, "--host", "-H", "--machine", "-M") {
			return approval(High, "REMOTE_EXEC", exactScope(argv), "systemctl remote/machine transport can cross the local target boundary")
		}
		action, unit := systemctlAction(args)
		switch action {
		case "stop", "disable", "mask":
			return approval(High, "SERVICE_CONTROL", semanticScope(executable, "systemctl:"+action+":"+unit), "service availability change")
		case "restart", "try-restart", "reload-or-restart":
			return approval(Medium, "SERVICE_RESTART", semanticScope(executable, "systemctl:"+action+":"+unit), "service restart")
		}
	case "docker", "podman":
		if contains(args, "system", "prune") || contains(args, "volume", "prune") {
			return approval(Critical, "CONTAINER_DESTRUCTIVE", exactScope(argv), "destructive container cleanup")
		}
		if containsAny(args, "exec", "run", "create") {
			return approval(High, "ARBITRARY_CODE", exactScope(argv), "container operation can execute arbitrary code")
		}
	case "kubectl":
		if containsAny(args, "delete") {
			return approval(High, "ORCHESTRATOR_DESTRUCTIVE", exactScope(argv), "Kubernetes resource deletion")
		}
		if containsAny(args, "exec", "run", "debug", "attach", "port-forward", "proxy") {
			return approval(High, "REMOTE_EXEC", exactScope(argv), "Kubernetes operation can execute code or expose a network path")
		}
	case "find":
		if containsAny(args, "-exec", "-execdir", "-ok", "-okdir") {
			return approval(High, "ARBITRARY_CODE", exactScope(argv), "find action can launch arbitrary commands")
		}
	case "tar":
		if tarCanExecute(args) {
			return approval(High, "ARBITRARY_CODE", exactScope(argv), "tar checkpoint action can execute arbitrary commands")
		}
	case "go":
		if containsAny(args, "run") {
			return approval(High, "ARBITRARY_CODE", exactScope(argv), "go run executes supplied code")
		}
	case "cargo":
		if containsAny(args, "run") {
			return approval(High, "ARBITRARY_CODE", exactScope(argv), "cargo run executes supplied code")
		}
	}

	if cmd == "sysrc" && sysrcReadOnly(args) {
		return Result{Decision: Allow, Level: Low, Category: "DEFAULT", ScopeKey: cmd, Reason: "read-only sysrc query"}
	}
	if result, ok := classifyOperational(executable, cmd, args, argv); ok {
		return result
	}
	if isArbitraryCodeCarrier(cmd) {
		return approval(High, "ARBITRARY_CODE", exactScope(argv), "interpreter or command carrier can execute arbitrary code")
	}
	if isRemoteExecTool(cmd) {
		return approval(High, "REMOTE_EXEC", exactScope(argv), "tool can create a remote execution or lateral network path")
	}
	if filepath.IsAbs(executable) && !trustedSystemExecutablePath(executable) {
		return approval(High, "ARBITRARY_CODE", exactScope(argv), "execution of an arbitrary absolute-path binary requires explicit approval")
	}

	return Result{Decision: Allow, Level: Low, Category: "DEFAULT", ScopeKey: cmd, Reason: "no elevated-risk rule matched"}
}

func approval(level Level, category, scope, reason string) Result {
	return Result{Decision: ApprovalRequired, Level: level, Category: category, ScopeKey: scope, Reason: reason}
}

func exactScope(argv []string) string {
	payload, _ := json.Marshal(argv)
	h := sha256.Sum256(payload)
	return "argv-sha256:" + hex.EncodeToString(h[:])
}

func semanticScope(executable, resource string) string {
	payload, _ := json.Marshal(struct {
		Executable string `json:"executable"`
		Resource   string `json:"resource"`
	}{Executable: executable, Resource: resource})
	h := sha256.Sum256(payload)
	return "semantic-sha256:" + hex.EncodeToString(h[:])
}

func systemctlAction(args []string) (string, string) {
	actions := map[string]struct{}{
		"stop": {}, "disable": {}, "mask": {},
		"restart": {}, "try-restart": {}, "reload-or-restart": {},
	}
	for i, arg := range args {
		if _, ok := actions[arg]; !ok {
			continue
		}
		unit := "*"
		for _, candidate := range args[i+1:] {
			if !strings.HasPrefix(candidate, "-") {
				unit = candidate
				break
			}
		}
		return arg, unit
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

func containsAny(args []string, values ...string) bool {
	for _, arg := range args {
		for _, value := range values {
			if arg == value {
				return true
			}
		}
	}
	return false
}

func hasOptionPrefix(args []string, values ...string) bool {
	for _, arg := range args {
		for _, value := range values {
			if arg == value || strings.HasPrefix(arg, value+"=") || (len(value) == 2 && strings.HasPrefix(arg, value) && len(arg) > len(value)) {
				return true
			}
		}
	}
	return false
}

func isPrivilegeLauncher(cmd string) bool {
	switch cmd {
	case "sudo", "doas", "su", "runuser", "pkexec", "setpriv", "capsh", "chroot", "nsenter", "unshare", "systemd-run", "machinectl":
		return true
	default:
		return false
	}
}

func isArbitraryCodeCarrier(cmd string) bool {
	switch cmd {
	case "sh", "bash", "dash", "zsh", "ksh", "mksh", "fish", "csh", "tcsh",
		"perl", "ruby", "irb", "node", "nodejs", "deno", "bun", "php",
		"lua", "luajit", "tclsh", "wish", "awk", "gawk", "mawk", "nawk",
		"java", "jshell", "dotnet", "pwsh", "powershell",
		"env", "xargs", "make", "gmake", "cmake", "ninja",
		"busybox", "toybox", "vim", "vi", "nvim", "emacs", "ed", "ex",
		"timeout", "nice", "nohup", "stdbuf", "setsid", "flock", "watch",
		"taskset", "ionice", "chrt", "fakeroot", "start-stop-daemon",
		"script", "expect", "parallel", "screen", "tmux",
		"gdb", "lldb", "strace", "ltrace", "valgrind",
		"sed", "psql", "mysql", "sqlite3", "lftp",
		"crontab", "at", "batch":
		return true
	}
	return pythonLike(cmd) || strings.HasPrefix(cmd, "pypy") || strings.HasPrefix(cmd, "ld-linux") || cmd == "ld.so"
}

func pythonLike(cmd string) bool {
	if cmd == "python" {
		return true
	}
	if !strings.HasPrefix(cmd, "python") {
		return false
	}
	rest := strings.TrimPrefix(cmd, "python")
	if rest == "" {
		return true
	}
	for _, r := range rest {
		if (r >= '0' && r <= '9') || r == '.' {
			continue
		}
		return false
	}
	return true
}

func isRemoteExecTool(cmd string) bool {
	switch cmd {
	case "ssh", "sshpass", "scp", "sftp", "rsync", "mosh",
		"nc", "ncat", "netcat", "socat", "telnet",
		"ansible", "ansible-playbook", "salt", "salt-call":
		return true
	default:
		return false
	}
}

func tarCanExecute(args []string) bool {
	for i, arg := range args {
		if strings.HasPrefix(arg, "--checkpoint-action=exec=") {
			return true
		}
		if arg == "--checkpoint-action" && i+1 < len(args) && strings.HasPrefix(args[i+1], "exec=") {
			return true
		}
	}
	return false
}

func trustedSystemExecutablePath(path string) bool {
	clean := filepath.Clean(path)
	if clean != path {
		return false
	}
	dir := filepath.Dir(clean)
	switch dir {
	case "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin":
		return true
	default:
		return false
	}
}
