package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/kotaru34/tethys-sentinel/internal/agentclient"
	"github.com/kotaru34/tethys-sentinel/internal/buildinfo"
	"github.com/kotaru34/tethys-sentinel/internal/capability"
	"github.com/kotaru34/tethys-sentinel/internal/domain"
	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
	"github.com/kotaru34/tethys-sentinel/internal/gatewayapi"
	"github.com/kotaru34/tethys-sentinel/internal/internalapi"
)

type agentAPI interface {
	Bootstrap(context.Context) (domain.Bootstrap, error)
	Submit(context.Context, gatewayapi.CommandRequest) (internalapi.SubmitCommandResponse, error)
	Job(context.Context, string) (internalapi.AgentExecutionJob, error)
	Request(context.Context, string) (internalapi.AgentExecutionJob, error)
}

type clientFactory func(agentclient.Config) (agentAPI, error)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr, os.LookupEnv, func(cfg agentclient.Config) (agentAPI, error) {
		return agentclient.New(cfg)
	})
	os.Exit(code)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, lookupEnv func(string) (string, bool), factory clientFactory) int {
	global := flag.NewFlagSet("sentinelctl", flag.ContinueOnError)
	global.SetOutput(stderr)
	urlFlag := global.String("url", envValue(lookupEnv, "SENTINEL_URL"), "Sentinel Gateway HTTPS origin")
	caFile := global.String("ca-file", envValue(lookupEnv, "SENTINEL_CA_FILE"), "additional trusted CA PEM file")
	capFile := global.String("cap-file", envValue(lookupEnv, "SENTINEL_CAP_FILE"), "0600 file containing the capability")
	jsonOutput := global.Bool("json", false, "emit machine-readable JSON")
	version := global.Bool("version", false, "print version")
	global.Usage = func() { printUsage(stderr) }
	if err := global.Parse(args); err != nil {
		return 2
	}
	if *version {
		fmt.Fprintln(stdout, buildinfo.Version)
		return 0
	}
	rest := global.Args()
	if len(rest) == 0 {
		printUsage(stderr)
		return 2
	}
	if rest[0] == "help" {
		printUsage(stdout)
		return 0
	}
	if rest[0] == "mcp" {
		return runMCP(ctx, rest[1:], *urlFlag, *caFile, *capFile, *jsonOutput, stdout, stderr, lookupEnv)
	}

	capToken, err := loadCapability(*capFile, lookupEnv)
	if err != nil {
		fmt.Fprintf(stderr, "sentinelctl: %v\n", err)
		return 2
	}
	client, err := factory(agentclient.Config{BaseURL: *urlFlag, Capability: capToken, CAFile: *caFile})
	if err != nil {
		fmt.Fprintf(stderr, "sentinelctl: %v\n", err)
		return 2
	}

	switch rest[0] {
	case "bootstrap":
		if len(rest) != 1 {
			fmt.Fprintln(stderr, "sentinelctl: bootstrap takes no arguments")
			return 2
		}
		value, err := client.Bootstrap(ctx)
		if err != nil {
			return reportError(stderr, err)
		}
		if *jsonOutput {
			return writeJSON(stdout, stderr, value)
		}
		printBootstrap(stdout, value)
		return 0
	case "exec":
		return runExec(ctx, client, rest[1:], *jsonOutput, stdout, stderr)
	case "job":
		return runJob(ctx, client, rest[1:], *jsonOutput, stdout, stderr)
	case "request":
		return runRequest(ctx, client, rest[1:], *jsonOutput, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "sentinelctl: unknown command %q\n", rest[0])
		printUsage(stderr)
		return 2
	}
}

func runExec(ctx context.Context, client agentAPI, args []string, jsonOutput bool, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("exec", flag.ContinueOnError)
	fs.SetOutput(stderr)
	target := fs.String("target", "", "logical Sentinel target")
	requestID := fs.String("request-id", "", "idempotency key (generated when omitted)")
	reason := fs.String("reason", "", "reason for the command")
	timeout := fs.Int64("timeout", 0, "execution timeout in seconds (default 30, max 900)")
	wait := fs.Bool("wait", false, "wait through approval and terminal job state")
	poll := fs.Duration("poll", time.Second, "approval/job polling interval")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	argv := fs.Args()
	if strings.TrimSpace(*target) == "" || len(argv) == 0 {
		fmt.Fprintln(stderr, "sentinelctl: exec requires --target and a command after --")
		return 2
	}
	if *timeout < 0 || *timeout > 900 {
		fmt.Fprintln(stderr, "sentinelctl: --timeout must be 0..900 seconds")
		return 2
	}
	if err := validatePoll(*poll); err != nil {
		fmt.Fprintf(stderr, "sentinelctl: %v\n", err)
		return 2
	}
	id := strings.TrimSpace(*requestID)
	if id == "" {
		var err error
		id, err = newRequestID()
		if err != nil {
			return reportError(stderr, err)
		}
	}
	req := gatewayapi.CommandRequest{
		RequestID: id, Target: strings.TrimSpace(*target), Argv: append([]string(nil), argv...),
		AgentReason: strings.TrimSpace(*reason), TimeoutSeconds: *timeout,
	}

	var response internalapi.SubmitCommandResponse
	announcedApproval := false
	for {
		var err error
		response, err = client.Submit(ctx, req)
		if err != nil {
			return reportError(stderr, err)
		}
		switch response.Decision {
		case "accepted":
			if response.Job == nil {
				return reportError(stderr, errors.New("accepted response has no job receipt"))
			}
			if !*wait {
				if jsonOutput {
					return writeJSON(stdout, stderr, response)
				}
				printSubmission(stdout, id, response)
				return 0
			}
			job, err := waitForJob(ctx, client, response.Job.ID, *poll)
			if err != nil {
				return reportError(stderr, err)
			}
			if jsonOutput {
				value := struct {
					Submission internalapi.SubmitCommandResponse `json:"submission"`
					Job        internalapi.AgentExecutionJob     `json:"job"`
				}{response, job}
				if code := writeJSON(stdout, stderr, value); code != 0 {
					return code
				}
			} else {
				printSubmission(stdout, id, response)
				printJob(stdout, job)
			}
			return terminalExit(job)
		case "approval_required":
			if !*wait {
				if jsonOutput {
					return writeJSON(stdout, stderr, response)
				}
				printSubmission(stdout, id, response)
				return 0
			}
			if !announcedApproval && !jsonOutput {
				fmt.Fprintf(stderr, "approval required: %s; waiting with request_id=%s\n", response.ApprovalID, id)
				announcedApproval = true
			}
			if err := sleepContext(ctx, *poll); err != nil {
				return reportError(stderr, err)
			}
		case "deny":
			if jsonOutput {
				_ = writeJSON(stdout, stderr, response)
			} else {
				printSubmission(stdout, id, response)
			}
			return 1
		default:
			return reportError(stderr, fmt.Errorf("unexpected submission decision %q", response.Decision))
		}
	}
}

func runJob(ctx context.Context, client agentAPI, args []string, jsonOutput bool, stdout, stderr io.Writer) int {
	if len(args) < 2 || (args[0] != "get" && args[0] != "wait") {
		fmt.Fprintln(stderr, "usage: sentinelctl job get|wait <job-id> [--poll 1s]")
		return 2
	}
	mode, id := args[0], strings.TrimSpace(args[1])
	if id == "" {
		fmt.Fprintln(stderr, "sentinelctl: job id is required")
		return 2
	}
	poll := time.Second
	if len(args) > 2 {
		fs := flag.NewFlagSet("job "+mode, flag.ContinueOnError)
		fs.SetOutput(stderr)
		fs.DurationVar(&poll, "poll", time.Second, "job polling interval")
		if err := fs.Parse(args[2:]); err != nil || len(fs.Args()) != 0 {
			return 2
		}
	}
	if err := validatePoll(poll); err != nil {
		fmt.Fprintf(stderr, "sentinelctl: %v\n", err)
		return 2
	}
	var job internalapi.AgentExecutionJob
	var err error
	if mode == "wait" {
		job, err = waitForJob(ctx, client, id, poll)
	} else {
		job, err = client.Job(ctx, id)
	}
	if err != nil {
		return reportError(stderr, err)
	}
	if jsonOutput {
		if code := writeJSON(stdout, stderr, job); code != 0 {
			return code
		}
	} else {
		printJob(stdout, job)
	}
	if mode == "wait" {
		return terminalExit(job)
	}
	return 0
}

func runRequest(ctx context.Context, client agentAPI, args []string, jsonOutput bool, stdout, stderr io.Writer) int {
	if len(args) != 2 || args[0] != "get" || strings.TrimSpace(args[1]) == "" {
		fmt.Fprintln(stderr, "usage: sentinelctl request get <request-id>")
		return 2
	}
	job, err := client.Request(ctx, strings.TrimSpace(args[1]))
	if err != nil {
		return reportError(stderr, err)
	}
	if jsonOutput {
		return writeJSON(stdout, stderr, job)
	}
	printJob(stdout, job)
	return 0
}

func waitForJob(ctx context.Context, client agentAPI, id string, poll time.Duration) (internalapi.AgentExecutionJob, error) {
	for {
		job, err := client.Job(ctx, id)
		if err != nil {
			return internalapi.AgentExecutionJob{}, err
		}
		if terminal(job.Status) {
			return job, nil
		}
		if err := sleepContext(ctx, poll); err != nil {
			return internalapi.AgentExecutionJob{}, err
		}
	}
}

func terminal(status executionjob.Status) bool {
	switch status {
	case executionjob.Succeeded, executionjob.Failed, executionjob.Canceled, executionjob.Expired:
		return true
	default:
		return false
	}
}

func terminalExit(job internalapi.AgentExecutionJob) int {
	if job.Status == executionjob.Succeeded {
		return 0
	}
	if job.Status == executionjob.Failed && job.Result != nil && job.Result.ExitCode >= 1 && job.Result.ExitCode <= 125 {
		return job.Result.ExitCode
	}
	return 1
}

func printBootstrap(w io.Writer, value domain.Bootstrap) {
	fmt.Fprintf(w, "session: %s\nagent: %s\npurpose: %s\nexpires: %s\ntargets: %s\n",
		value.SessionID, value.Agent, value.Purpose, value.ExpiresAt.Format(time.RFC3339), strings.Join(value.Targets, ", "))
}

func printSubmission(w io.Writer, requestID string, response internalapi.SubmitCommandResponse) {
	fmt.Fprintf(w, "request: %s\ndecision: %s\n", requestID, response.Decision)
	if response.ApprovalID != "" {
		fmt.Fprintf(w, "approval: %s\n", response.ApprovalID)
	}
	if response.Job != nil {
		fmt.Fprintf(w, "job: %s\nstatus: %s\n", response.Job.ID, response.Job.Status)
	}
}

func printJob(w io.Writer, job internalapi.AgentExecutionJob) {
	fmt.Fprintf(w, "job: %s\nrequest: %s\ntarget: %s\nstatus: %s\n", job.ID, job.RequestID, job.Target, job.Status)
	if job.Result != nil {
		fmt.Fprintf(w, "success: %t\nexit: %d\n", job.Result.Success, job.Result.ExitCode)
		if job.Result.ErrorKind != "" {
			fmt.Fprintf(w, "error_kind: %s\n", job.Result.ErrorKind)
		}
		if job.Result.OutputSHA256 != "" {
			fmt.Fprintf(w, "output_sha256: %s\n", job.Result.OutputSHA256)
		}
	}
	if job.Output != nil {
		printCapturedStream(w, "stdout", job.Output.Stdout, job.Output.StdoutTruncated)
		printCapturedStream(w, "stderr", job.Output.Stderr, job.Output.StderrTruncated)
	}
}

func printCapturedStream(w io.Writer, name string, data []byte, truncated bool) {
	if len(data) == 0 && !truncated {
		return
	}
	fmt.Fprintf(w, "%s:\n", name)
	if len(data) != 0 {
		text := safeTerminalText(data)
		fmt.Fprint(w, text)
		if !strings.HasSuffix(text, "\n") {
			fmt.Fprintln(w)
		}
	}
	if truncated {
		fmt.Fprintf(w, "[%s truncated]\n", name)
	}
}

// safeTerminalText renders captured remote output without allowing terminal
// control sequences or malformed UTF-8 to execute in the operator's terminal.
// Newlines and tabs remain readable; other control/format characters are
// escaped. Use --json when byte-exact machine processing is required.
func safeTerminalText(data []byte) string {
	var b strings.Builder
	for len(data) > 0 {
		r, size := utf8.DecodeRune(data)
		if r == utf8.RuneError && size == 1 {
			fmt.Fprintf(&b, "\\x%02x", data[0])
			data = data[1:]
			continue
		}
		switch r {
		case '\n':
			b.WriteByte('\n')
		case '\t':
			b.WriteByte('\t')
		default:
			if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
				if r <= 0xff {
					fmt.Fprintf(&b, "\\x%02x", r)
				} else if r <= 0xffff {
					fmt.Fprintf(&b, "\\u%04x", r)
				} else {
					fmt.Fprintf(&b, "\\U%08x", r)
				}
			} else {
				b.WriteRune(r)
			}
		}
		data = data[size:]
	}
	return b.String()
}

func writeJSON(stdout, stderr io.Writer, value any) int {
	enc := json.NewEncoder(stdout)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		fmt.Fprintf(stderr, "sentinelctl: encode output: %v\n", err)
		return 1
	}
	return 0
}

func loadCapability(capFile string, lookupEnv func(string) (string, bool)) (string, error) {
	if path := strings.TrimSpace(capFile); path != "" {
		info, err := os.Lstat(path)
		if err != nil {
			return "", fmt.Errorf("inspect capability file: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return "", errors.New("capability file must be a regular non-symlink file")
		}
		if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
			return "", errors.New("capability file must not be group/other accessible")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read capability file: %w", err)
		}
		token := strings.TrimSpace(string(data))
		if capability.ValidateFormat(token) != nil {
			return "", errors.New("capability file does not contain a valid Sentinel capability")
		}
		return token, nil
	}
	token := strings.TrimSpace(envValue(lookupEnv, "SENTINEL_CAP"))
	if capability.ValidateFormat(token) != nil {
		return "", errors.New("set SENTINEL_CAP or provide --cap-file with a valid capability")
	}
	return token, nil
}

func newRequestID() (string, error) {
	var buf [12]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("generate request id: %w", err)
	}
	return "req-" + hex.EncodeToString(buf[:]), nil
}

func validatePoll(value time.Duration) error {
	if value < 250*time.Millisecond || value > time.Minute {
		return errors.New("poll interval must be between 250ms and 1m")
	}
	return nil
}

func sleepContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func envValue(lookupEnv func(string) (string, bool), key string) string {
	if lookupEnv == nil {
		return ""
	}
	value, _ := lookupEnv(key)
	return strings.TrimSpace(value)
}

func reportError(stderr io.Writer, err error) int {
	fmt.Fprintf(stderr, "sentinelctl: %v\n", err)
	return 1
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, `usage: sentinelctl [global options] <command>

global options:
  --url URL          Sentinel Gateway HTTPS origin (or SENTINEL_URL)
  --ca-file PATH     additional trusted CA PEM (or SENTINEL_CA_FILE)
  --cap-file PATH    capability file (or SENTINEL_CAP_FILE)
  --json             machine-readable output
  --version          print version

commands:
  bootstrap
  exec --target TARGET [--request-id ID] [--reason TEXT] [--timeout SEC] [--wait] [--poll 1s] -- COMMAND [ARG...]
  job get <JOB-ID>
  job wait <JOB-ID> [--poll 1s]
  request get <REQUEST-ID>
  mcp claim [--claim-file PATH]

Captured output is shown only when the grant has history.include_output=true.
Human output escapes terminal control sequences; --json returns byte-exact base64 fields.
Normal commands read a capability from --cap-file/SENTINEL_CAP_FILE or SENTINEL_CAP.
The mcp claim command redeems a one-time operator claim without requiring an existing capability and atomically installs the new capability.
There is intentionally no --token or --claim-code argument and no insecure TLS mode.`)
}
