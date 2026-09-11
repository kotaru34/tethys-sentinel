package risk

func classifyStorage(_ string, cmd string, args, argv []string) (Result, bool) {
	switch cmd {
	case "dd", "blkdiscard", "sg_format":
		return approval(Critical, "RAW_STORAGE_WRITE", exactScope(argv), "raw block/storage write can destroy data"), true
	case "nvme":
		if containsAny(args, "format", "sanitize") {
			return approval(Critical, "RAW_STORAGE_WRITE", exactScope(argv), "NVMe destructive media operation"), true
		}
	case "hdparm":
		if hasOptionPrefix(args, "-S", "-B", "-M", "-W", "-w", "--security-set-pass", "--security-erase", "--security-erase-enhanced", "--yes-i-know-what-i-am-doing") {
			return approval(Critical, "STORAGE_CONTROL", exactScope(argv), "block-device firmware or power/security state change"), true
		}
	case "camcontrol":
		if containsAny(args, "reset", "stop", "start", "format", "sanitize", "security", "modepage") {
			return approval(Critical, "STORAGE_CONTROL", exactScope(argv), "FreeBSD CAM device state change"), true
		}
	case "mount":
		if mountReadOnlyQuery(args) {
			return Result{}, false
		}
		return approval(High, "STORAGE_CONTROL", exactScope(argv), "mount state change"), true
	case "umount":
		if helpOrVersionOnly(args) {
			return Result{}, false
		}
		return approval(High, "STORAGE_CONTROL", exactScope(argv), "unmount state change"), true
	case "swapon":
		if containsAny(args, "--show", "-s", "--summary") {
			return Result{}, false
		}
		return approval(High, "STORAGE_CONTROL", exactScope(argv), "swap state change"), true
	case "swapoff":
		return approval(High, "STORAGE_CONTROL", exactScope(argv), "swap state change"), true
	case "losetup":
		if losetupReadOnly(args) {
			return Result{}, false
		}
		return approval(High, "STORAGE_CONTROL", exactScope(argv), "loop-device state change"), true
	case "fdisk":
		if containsAny(args, "-l", "--list") || helpOrVersionOnly(args) {
			return Result{}, false
		}
		return approval(Critical, "STORAGE_CONTROL", exactScope(argv), "partition-table operation"), true
	case "sfdisk":
		if containsAny(args, "-l", "--list", "-d", "--dump") || helpOrVersionOnly(args) {
			return Result{}, false
		}
		return approval(Critical, "STORAGE_CONTROL", exactScope(argv), "partition-table operation"), true
	case "cfdisk", "gdisk":
		return approval(Critical, "STORAGE_CONTROL", exactScope(argv), "interactive partition-table operation"), true
	case "sgdisk":
		if containsAny(args, "-p", "--print", "-i", "--info") && !partitionMutationPresent(args) {
			return Result{}, false
		}
		return approval(Critical, "STORAGE_CONTROL", exactScope(argv), "GPT partition-table operation"), true
	case "parted":
		if containsAny(args, "-l", "--list", "print") && !partitionMutationPresent(args) {
			return Result{}, false
		}
		return approval(Critical, "STORAGE_CONTROL", exactScope(argv), "partition-table operation"), true
	case "fsck", "e2fsck", "xfs_repair", "resize2fs", "xfs_growfs", "tune2fs":
		return approval(High, "STORAGE_CONTROL", exactScope(argv), "filesystem repair or geometry change"), true
	case "mdadm":
		if mdadmReadOnly(args) {
			return Result{}, false
		}
		return approval(High, "STORAGE_CONTROL", exactScope(argv), "software RAID state change"), true
	case "pvcreate", "pvremove", "pvresize", "pvmove",
		"vgcreate", "vgremove", "vgextend", "vgreduce", "vgrename", "vgchange",
		"lvcreate", "lvremove", "lvresize", "lvextend", "lvreduce", "lvrename", "lvchange", "lvconvert":
		return approval(High, "STORAGE_CONTROL", exactScope(argv), "LVM topology or volume state change"), true
	case "zpool":
		if containsAny(args, "add", "attach", "detach", "replace", "remove", "online", "offline", "clear", "import", "export", "upgrade", "set", "trim", "checkpoint", "reguid", "split", "scrub") {
			return approval(High, "STORAGE_CONTROL", exactScope(argv), "ZFS pool state or topology change"), true
		}
	case "zfs":
		if containsAny(args, "create", "snapshot", "clone", "promote", "rename", "rollback", "set", "inherit", "hold", "release", "mount", "unmount", "share", "unshare", "receive", "recv") {
			if len(args) == 1 && args[0] == "mount" {
				return Result{}, false
			}
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

func mountReadOnlyQuery(args []string) bool {
	if len(args) == 0 {
		return true
	}
	for _, arg := range args {
		switch arg {
		case "-l", "--show-labels", "-h", "--help", "-V", "--version":
			continue
		default:
			return false
		}
	}
	return true
}

func helpOrVersionOnly(args []string) bool {
	if len(args) == 0 {
		return false
	}
	for _, arg := range args {
		switch arg {
		case "-h", "--help", "-V", "--version":
			continue
		default:
			return false
		}
	}
	return true
}

func losetupReadOnly(args []string) bool {
	if len(args) == 0 {
		return true
	}
	for _, arg := range args {
		switch arg {
		case "-a", "--all", "-l", "--list", "-f", "--find", "-j", "--associated", "-O", "--output", "--output-all", "--json", "--raw", "--noheadings", "-n":
			continue
		default:
			if len(arg) > 0 && arg[0] != '-' {
				return false
			}
		}
	}
	return true
}

func partitionMutationPresent(args []string) bool {
	return containsAny(args,
		"mklabel", "mktable", "mkpart", "rm", "name", "resizepart", "set", "toggle", "rescue",
		"--new", "--delete", "--change-name", "--typecode", "--attributes", "--zap", "--zap-all", "--clear",
	)
}

func mdadmReadOnly(args []string) bool {
	if !containsAny(args, "--detail", "--examine", "--query", "--scan") {
		return false
	}
	return !containsAny(args, "--create", "--assemble", "--stop", "--add", "--remove", "--fail", "--grow", "--manage", "--incremental")
}
