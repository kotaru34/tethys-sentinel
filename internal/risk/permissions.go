package risk

// RequiresShell reports whether an approved command still requires the grant's
// explicit shell/unstructured-execution capability before an SSH credential
// may be issued.
func RequiresShell(result Result) bool {
	return RequiresShellCategory(result.Category)
}

func RequiresShellCategory(category string) bool {
	switch category {
	case "ARBITRARY_CODE", "PRIVILEGE_LAUNCHER", "REMOTE_EXEC":
		return true
	default:
		return false
	}
}
