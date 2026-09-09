package executionjob

func BindingHash(grantID, requestID, target string, argv []string) (string, error) {
	return bindingHash(grantID, requestID, target, argv)
}

func VerifyBinding(job Job) bool {
	want, err := BindingHash(job.GrantID, job.RequestID, job.Target, job.Argv)
	return err == nil && want == job.CommandSHA256
}
