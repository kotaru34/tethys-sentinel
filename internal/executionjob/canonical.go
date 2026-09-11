package executionjob

// ValidateEnqueueInput applies the common execution-job input contract.
func ValidateEnqueueInput(in EnqueueInput) error { return validateInput(in) }

// ValidateResult applies the common execution result contract.
func ValidateResult(result Result) error { return validateResult(result) }
