package risk

import "testing"

func TestOperationalRiskRules(t *testing.T) {
	tests := []struct {
		name     string
		argv     []string
		decision Decision
		category string
	}{
		{"systemd read", []string{"systemctl", "status", "pdns"}, Allow, "DEFAULT"},
		{"systemd start", []string{"systemctl", "start", "pdns"}, ApprovalRequired, "SERVICE_CONTROL"},
		{"systemd manager", []string{"systemctl", "daemon-reload"}, ApprovalRequired, "SYSTEM_MANAGER"},
		{"systemd reboot", []string{"systemctl", "reboot"}, ApprovalRequired, "POWER"},
		{"freebsd service read", []string{"service", "sshd", "status"}, Allow, "DEFAULT"},
		{"freebsd service restart", []string{"service", "sshd", "restart"}, ApprovalRequired, "SERVICE_RESTART"},
		{"openbsd rcctl read", []string{"rcctl", "check", "unwind"}, Allow, "DEFAULT"},
		{"openbsd rcctl enable", []string{"rcctl", "enable", "unwind"}, ApprovalRequired, "SERVICE_CONTROL"},
		{"void runit read", []string{"sv", "status", "sshd"}, Allow, "DEFAULT"},
		{"void runit restart", []string{"sv", "restart", "sshd"}, ApprovalRequired, "SERVICE_RESTART"},
		{"freebsd sysrc read", []string{"sysrc", "sshd_enable"}, Allow, "DEFAULT"},
		{"freebsd sysrc write", []string{"sysrc", "sshd_enable=YES"}, ApprovalRequired, "SYSTEM_CONFIG"},
		{"freebsd sysrc delete with no-name", []string{"sysrc", "-n", "-x", "sshd_enable"}, ApprovalRequired, "SYSTEM_CONFIG"},

		{"nft read ruleset", []string{"nft", "list", "ruleset"}, Allow, "DEFAULT"},
		{"nft monitor", []string{"nft", "monitor", "trace"}, Allow, "DEFAULT"},
		{"nft flush", []string{"nft", "flush", "ruleset"}, ApprovalRequired, "NETWORK_CONTROL"},
		{"nft file", []string{"nft", "-f", "/etc/nftables.conf"}, ApprovalRequired, "NETWORK_CONTROL"},
		{"iptables list", []string{"iptables", "-L", "-n"}, Allow, "DEFAULT"},
		{"iptables check", []string{"iptables", "-C", "INPUT", "-j", "ACCEPT"}, Allow, "DEFAULT"},
		{"iptables append", []string{"iptables", "-A", "INPUT", "-j", "ACCEPT"}, ApprovalRequired, "NETWORK_CONTROL"},
		{"iptables bundled list reset", []string{"iptables", "-LZ"}, ApprovalRequired, "NETWORK_CONTROL"},
		{"ip6tables restore", []string{"ip6tables-restore", "/etc/iptables/rules.v6"}, ApprovalRequired, "NETWORK_CONTROL"},
		{"pfctl read rules", []string{"pfctl", "-sr"}, Allow, "DEFAULT"},
		{"pfctl verbose read", []string{"pfctl", "-vvsr"}, Allow, "DEFAULT"},
		{"pfctl load", []string{"pfctl", "-f", "/etc/pf.conf"}, ApprovalRequired, "NETWORK_CONTROL"},
		{"pfctl bundled verbose load", []string{"pfctl", "-vnf", "/etc/pf.conf"}, ApprovalRequired, "NETWORK_CONTROL"},

		{"ip route read", []string{"ip", "route", "show"}, Allow, "DEFAULT"},
		{"ip route replace", []string{"ip", "route", "replace", "default", "via", "10.169.0.1"}, ApprovalRequired, "NETWORK_CONTROL"},
		{"ip netns exec", []string{"ip", "netns", "exec", "blue", "id"}, ApprovalRequired, "PRIVILEGE_LAUNCHER"},
		{"freebsd ifconfig read", []string{"ifconfig", "em0"}, Allow, "DEFAULT"},
		{"freebsd ifconfig down", []string{"ifconfig", "em0", "down"}, ApprovalRequired, "NETWORK_CONTROL"},
		{"route add", []string{"route", "add", "default", "10.169.0.1"}, ApprovalRequired, "NETWORK_CONTROL"},
		{"wireguard read", []string{"wg", "show"}, Allow, "DEFAULT"},
		{"wireguard set", []string{"wg", "set", "wg0", "listen-port", "51820"}, ApprovalRequired, "NETWORK_CONTROL"},
		{"ethtool read", []string{"ethtool", "eth0"}, Allow, "DEFAULT"},
		{"ethtool mutate", []string{"ethtool", "-K", "eth0", "gro", "off"}, ApprovalRequired, "NETWORK_CONTROL"},

		{"apt read", []string{"apt", "list", "--installed"}, Allow, "DEFAULT"},
		{"apt install", []string{"apt-get", "install", "-y", "haproxy"}, ApprovalRequired, "PACKAGE_CONTROL"},
		{"xbps read", []string{"xbps-query", "-Rs", "haproxy"}, Allow, "DEFAULT"},
		{"xbps install", []string{"xbps-install", "-y", "haproxy"}, ApprovalRequired, "PACKAGE_CONTROL"},
		{"freebsd pkg read", []string{"pkg", "info", "postgresql18-server"}, Allow, "DEFAULT"},
		{"freebsd pkg upgrade", []string{"pkg", "upgrade", "-y"}, ApprovalRequired, "PACKAGE_CONTROL"},
		{"pacman search", []string{"pacman", "-Ss", "haproxy"}, Allow, "DEFAULT"},
		{"pacman upgrade", []string{"pacman", "-Syu"}, ApprovalRequired, "PACKAGE_CONTROL"},

		{"mount list", []string{"mount"}, Allow, "DEFAULT"},
		{"mount filesystem", []string{"mount", "/srv/data"}, ApprovalRequired, "STORAGE_CONTROL"},
		{"losetup list", []string{"losetup", "-a"}, Allow, "DEFAULT"},
		{"losetup attach", []string{"losetup", "/dev/loop0", "disk.img"}, ApprovalRequired, "STORAGE_CONTROL"},
		{"zpool read", []string{"zpool", "status", "tank"}, Allow, "DEFAULT"},
		{"zpool attach", []string{"zpool", "attach", "tank", "da0", "da1"}, ApprovalRequired, "STORAGE_CONTROL"},
		{"zfs read", []string{"zfs", "list", "tank/data"}, Allow, "DEFAULT"},
		{"zfs snapshot", []string{"zfs", "snapshot", "tank/data@before"}, ApprovalRequired, "STORAGE_CONTROL"},
		{"lvm read", []string{"lvs"}, Allow, "DEFAULT"},
		{"lvm remove", []string{"lvremove", "-y", "vg/data"}, ApprovalRequired, "STORAGE_CONTROL"},
		{"fdisk list", []string{"fdisk", "-l", "/dev/sda"}, Allow, "DEFAULT"},
		{"fdisk mutate", []string{"fdisk", "/dev/sda"}, ApprovalRequired, "STORAGE_CONTROL"},
		{"parted print", []string{"parted", "/dev/sda", "print"}, Allow, "DEFAULT"},
		{"parted mkpart", []string{"parted", "/dev/sda", "mkpart", "primary", "1MiB", "1GiB"}, ApprovalRequired, "STORAGE_CONTROL"},
		{"raw dd", []string{"dd", "if=/dev/zero", "of=/dev/sda", "bs=1M"}, ApprovalRequired, "RAW_STORAGE_WRITE"},
		{"mdadm detail", []string{"mdadm", "--detail", "/dev/md0"}, Allow, "DEFAULT"},
		{"mdadm create", []string{"mdadm", "--create", "/dev/md0", "--level=1", "/dev/sda", "/dev/sdb"}, ApprovalRequired, "STORAGE_CONTROL"},
		{"bectl read", []string{"bectl", "list"}, Allow, "DEFAULT"},
		{"bectl activate", []string{"bectl", "activate", "newkernel"}, ApprovalRequired, "STORAGE_CONTROL"},

		{"sysctl read", []string{"sysctl", "net.ipv4.ip_forward"}, Allow, "DEFAULT"},
		{"sysctl write", []string{"sysctl", "-w", "net.ipv4.ip_forward=1"}, ApprovalRequired, "KERNEL_CONTROL"},
		{"module load", []string{"modprobe", "wireguard"}, ApprovalRequired, "KERNEL_CONTROL"},
		{"journal read", []string{"journalctl", "-u", "sshd"}, Allow, "DEFAULT"},
		{"journal vacuum", []string{"journalctl", "--vacuum-time=7d"}, ApprovalRequired, "LOG_CONTROL"},

		{"docker read", []string{"docker", "ps"}, Allow, "DEFAULT"},
		{"docker start", []string{"docker", "start", "pdns"}, ApprovalRequired, "ARBITRARY_CODE"},
		{"docker stop", []string{"docker", "stop", "pdns"}, ApprovalRequired, "CONTAINER_CONTROL"},
		{"docker exec", []string{"docker", "exec", "pdns", "id"}, ApprovalRequired, "ARBITRARY_CODE"},
		{"docker remote context", []string{"docker", "--context", "remote", "ps"}, ApprovalRequired, "REMOTE_EXEC"},
		{"kubectl read", []string{"kubectl", "get", "pods"}, Allow, "DEFAULT"},
		{"kubectl apply", []string{"kubectl", "apply", "-f", "deployment.yaml"}, ApprovalRequired, "ORCHESTRATOR_CONTROL"},
		{"helm read", []string{"helm", "list"}, Allow, "DEFAULT"},
		{"helm upgrade", []string{"helm", "upgrade", "dns", "./chart"}, ApprovalRequired, "ORCHESTRATOR_CONTROL"},

		{"pve qm read", []string{"qm", "status", "100"}, Allow, "DEFAULT"},
		{"pve qm start", []string{"qm", "start", "100"}, ApprovalRequired, "HYPERVISOR_CONTROL"},
		{"pve qm monitor", []string{"qm", "monitor", "100"}, ApprovalRequired, "REMOTE_EXEC"},
		{"pve pct read", []string{"pct", "status", "101"}, Allow, "DEFAULT"},
		{"pve pct enter", []string{"pct", "enter", "101"}, ApprovalRequired, "REMOTE_EXEC"},
		{"pvesh read", []string{"pvesh", "get", "/nodes"}, Allow, "DEFAULT"},
		{"pvesh set", []string{"pvesh", "set", "/nodes/pve/config", "--description", "x"}, ApprovalRequired, "HYPERVISOR_CONTROL"},
		{"freebsd jail exec", []string{"jexec", "dns", "service", "unbound", "status"}, ApprovalRequired, "REMOTE_EXEC"},

		{"kill process", []string{"kill", "-TERM", "1234"}, ApprovalRequired, "PROCESS_CONTROL"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Classify(tt.argv)
			if got.Decision != tt.decision || got.Category != tt.category {
				t.Fatalf("Classify(%v) = %s/%s, want %s/%s", tt.argv, got.Decision, got.Category, tt.decision, tt.category)
			}
		})
	}
}

func TestOperationalScopesAndCapabilitySemantics(t *testing.T) {
	a := Classify([]string{"systemctl", "start", "pdns"})
	b := Classify([]string{"systemctl", "start", "pdns"})
	c := Classify([]string{"systemctl", "start", "sshd"})
	if a.ScopeKey != b.ScopeKey || a.ScopeKey == c.ScopeKey {
		t.Fatalf("service semantic scope unstable or overbroad: a=%s b=%s c=%s", a.ScopeKey, b.ScopeKey, c.ScopeKey)
	}
	if RequiresShell(a) || !SessionApprovalAllowed(a) {
		t.Fatalf("scoped service control has wrong capability/reuse semantics: %+v", a)
	}

	netns := Classify([]string{"ip", "netns", "exec", "blue", "id"})
	if !RequiresShell(netns) || SessionApprovalAllowed(netns) {
		t.Fatalf("namespace execution did not retain powerful-execution semantics: %+v", netns)
	}

	dockerStart := Classify([]string{"docker", "start", "pdns"})
	if !RequiresShell(dockerStart) || SessionApprovalAllowed(dockerStart) {
		t.Fatalf("container workload start is not treated as mutable code execution: %+v", dockerStart)
	}

	dd := Classify([]string{"dd", "if=/dev/zero", "of=/dev/sda"})
	if RequiresShell(dd) {
		t.Fatalf("raw storage write unexpectedly requires shell capability: %+v", dd)
	}
	if !SessionApprovalAllowed(dd) {
		t.Fatalf("raw storage exact operation unexpectedly lost scoped session-approval option: %+v", dd)
	}
}
