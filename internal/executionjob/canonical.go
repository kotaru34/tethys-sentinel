package executionjob

// BindingHash returns the canonical immutable command binding used by every
// execution-job persistence backend.
func BindingHash(grantID, requestID, target string, argv []string) (string, error) {
	return bindingHash(grantID, requestID, target, argv)
}

// ValidateEnqueueInput applies the common execution-job input contract.
func ValidateEnqueueInput(in EnqueueInput) error { return validateInput(in) }

// ValidateResult applies the common execution result contract.
func ValidateResult(result Result) error { return validateResult(result) }
