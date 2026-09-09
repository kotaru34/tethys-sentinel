package executionjob

func VerifyBinding(job Job) bool {
	want, err := bindingHash(job.GrantID, job.RequestID, job.Target, job.Argv)
	return err == nil && want == job.CommandSHA256
}
