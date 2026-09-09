package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/remotewrapper"
)

func main() {
	jobID := flag.String("job", "", "execution job id")
	binding := flag.String("binding", "", "execution command binding")
	flag.Parse()
	if flag.NArg() != 0 {
		fatal(125, "unexpected wrapper arguments")
	}

	targetID, err := remotewrapper.LoadTargetID("")
	if err != nil {
		fatal(125, err.Error())
	}
	argv, err := remotewrapper.Verify(remotewrapper.Request{
		JobID: *jobID, Binding: *binding, LocalTarget: targetID,
		OriginalCommand: os.Getenv("SSH_ORIGINAL_COMMAND"),
	})
	if err != nil {
		fatal(125, err.Error())
	}
	executable, err := remotewrapper.ResolveExecutable(argv[0])
	if err != nil {
		fatal(127, err.Error())
	}
	if err := remotewrapper.ConsumeExecution("", *jobID, *binding, time.Now()); err != nil {
		fatal(125, err.Error())
	}

	cmd := exec.Command(executable, argv[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = remotewrapper.SafeEnvironment()
	if err := cmd.Start(); err != nil {
		fatal(126, "start executable: "+err.Error())
	}

	signals := make(chan os.Signal, 4)
	signal.Notify(signals, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for sig := range signals {
			if cmd.Process != nil {
				_ = cmd.Process.Signal(sig)
			}
	}()

	err = cmd.Wait()
	signal.Stop(signals)
	if err == nil {
		return
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		code := exitErr.ExitCode()
		if code < 0 {
			code = 255
		}
		os.Exit(code)
	}
	fatal(126, "wait executable: "+err.Error())
}

func fatal(code int, message string) {
	_, _ = fmt.Fprintln(os.Stderr, "tethys-sentinel-exec:", message)
	os.Exit(code)
}
