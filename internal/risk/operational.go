package risk

import "strings"

// classifyOperational covers high-impact administrator primitives whose risk is
// better described by semantic operation classes than by arbitrary-code
// detection. Ordinary file mutation is intentionally not classified here;
// target Unix permissions and sudo/doas remain the file-authority boundary.
func classifyOperational(executable, cmd string, args, argv []string) (Result, bool) {
	classifiers := []func(string, string, []string, []string) (Result, bool){
		classifyService,
		classifyNetwork,
		classifyPackage,
		classifyStorage,
		classifySystem,
		classifyRuntime,
	}
	for _, classify := range classifiers {
		if result, ok := classify(executable, cmd, args, argv); ok {
			return result, true
		}
	}
	return Result{}, false
}

func actionResource(args, actions []string) (string, string) {
	for i, arg := range args {
		if !stringIn(arg, actions) {
			continue
		}
		resource := "*"
		for _, candidate := range args[i+1:] {
			if !strings.HasPrefix(candidate, "-") {
				resource = candidate
				break
			}
		}
		return arg, resource
	}
	return "", "*"
}

func containsSequence(args []string, values ...string) bool {
	return contains(args, values...)
}

func containsObjectVerb(args []string, object string, verbs []string) bool {
	for i, arg := range args {
		if arg != object {
			continue
		}
		for _, later := range args[i+1:] {
			if stringIn(later, verbs) {
				return true
			}
		}
	}
	return false
}

func stringIn(value string, values []string) bool {
	for _, candidate := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func containsAssignment(args []string) bool {
	for _, arg := range args {
		if strings.Contains(arg, "=") && !strings.HasPrefix(arg, "=") {
			return true
		}
	}
	return false
}
