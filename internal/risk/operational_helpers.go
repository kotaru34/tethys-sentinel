package risk

import "strings"

func sysrcReadOnly(args []string) bool {
	if len(args) == 0 {
		return true
	}
	for _, arg := range args {
		if arg == "-x" || strings.Contains(arg, "=") {
			return false
		}
	}
	return true
}
