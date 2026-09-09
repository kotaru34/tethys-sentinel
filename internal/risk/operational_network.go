package risk

func classifyNetwork(_ string, cmd string, args, argv []string) (Result, bool) {
	switch cmd {
	case "ip":
		if containsSequence(args, "netns", "exec") || containsSequence(args, "vrf", "exec") {
			return approval(Critical, "PRIVILEGE_LAUNCHER", exactScope(argv), "network namespace execution can cross the target process boundary"), true
		}
		objects := []struct {
			name  string
			verbs []string
		}{
			{name: "link", verbs: []string{"add", "delete", "del", "set"}},
			{name: "address", verbs: []string{"add", "change", "replace", "delete", "del", "flush"}},
			{name: "addr", verbs: []string{"add", "change", "replace", "delete", "del", "flush"}},
			{name: "route", verbs: []string{"add", "append", "change", "replace", "delete", "del", "flush"}},
			{name: "rule", verbs: []string{"add", "delete", "del", "flush"}},
			{name: "neigh", verbs: []string{"add", "change", "replace", "delete", "del", "flush"}},
			{name: "neighbor", verbs: []string{"add", "change", "replace", "delete", "del", "flush"}},
			{name: "tunnel", verbs: []string{"add", "change", "delete", "del"}},
			{name: "netns", verbs: []string{"add", "delete", "del", "set"}},
		}
		for _, object := range objects {
			if containsObjectVerb(args, object.name, object.verbs) {
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
		if len(args) > 1 {
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
		if containsAny(args, "up", "down", "add", "delete", "modify", "clone", "import", "connect", "disconnect", "reapply") ||
			containsSequence(args, "networking", "off") || containsSequence(args, "networking", "on") {
			return approval(High, "NETWORK_CONTROL", exactScope(argv), "NetworkManager state change"), true
		}
	case "ethtool":
		if hasOptionPrefix(args,
			"-s", "--change", "-K", "--offload", "-L", "--set-channels", "-G", "--set-ring",
			"-C", "--coalesce", "-A", "--pause", "--set-eee", "--set-priv-flags",
		) {
			return approval(High, "NETWORK_CONTROL", exactScope(argv), "network device configuration change"), true
		}
	}
	return Result{}, false
}
