package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/agentclient"
	"github.com/kotaru34/tethys-sentinel/internal/buildinfo"
	"github.com/kotaru34/tethys-sentinel/internal/capability"
	"github.com/kotaru34/tethys-sentinel/internal/githubrelay"
	"github.com/kotaru34/tethys-sentinel/internal/mcpclaim"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr, os.LookupEnv))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, lookupEnv func(string) (string, bool)) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	if args[0] == "--version" || args[0] == "version" {
		fmt.Fprintln(stdout, buildinfo.Version)
		return 0
	}
	switch args[0] {
	case "authorize":
		return runAuthorize(ctx, args[1:], stdout, stderr, lookupEnv)
	case "serve":
		return runServe(ctx, args[1:], stdout, stderr, lookupEnv)
	case "sign":
		return runSign(args[1:], stdout, stderr, lookupEnv)
	case "inspect":
		return runInspect(args[1:], stdout, stderr, lookupEnv)
	case "close":
		return runClose(args[1:], stdout, stderr, lookupEnv)
	case "help", "-h", "--help":
		usage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "sentinel-github-relay: unknown command %q\n", args[0])
		usage(stderr)
		return 2
	}
}

func runAuthorize(ctx context.Context, args []string, stdout, stderr io.Writer, lookupEnv func(string) (string, bool)) int {
	fs := flag.NewFlagSet("authorize", flag.ContinueOnError)
	fs.SetOutput(stderr)
	stateDir := fs.String("state-dir", envOr(lookupEnv, "SENTINEL_GITHUB_RELAY_STATE_DIR", "/var/lib/tethys-sentinel-github-relay"), "private relay state directory")
	baseURL := fs.String("url", envValue(lookupEnv, "SENTINEL_URL"), "Sentinel Gateway HTTPS origin")
	caFile := fs.String("ca-file", envValue(lookupEnv, "SENTINEL_CA_FILE"), "additional Sentinel CA PEM")
	capFile := fs.String("cap-file", "", "protected file containing an existing Sentinel capability")
	claimFile := fs.String("claim-file", "", "protected file containing a one-time Sentinel MCP claim")
	repository := fs.String("repository", "", "dedicated private GitHub repository in owner/name form")
	issueNumber := fs.Int("issue", 0, "existing GitHub issue number to bind")
	actorIDOverride := fs.Int64("actor-id", 0, "optional numeric GitHub request actor ID; defaults to issue author")
	target := fs.String("target", "", "single logical Sentinel target")
	ttl := fs.Duration("ttl", 15*time.Minute, "relay session lifetime, bounded by the Sentinel grant")
	maxCommands := fs.Int("max-commands", githubrelay.DefaultMaxCommands, "maximum authenticated requests in this relay session")
	exactArgvJSON := fs.String("exact-argv-json", "", "optional exact allowed argv JSON array")
	publishOutput := fs.Bool("publish-output", false, "publish bounded grant-visible stdout/stderr into the private GitHub issue")
	outputLimit := fs.Int("output-limit", githubrelay.DefaultOutputLimitBytes, "per-stream GitHub output limit when --publish-output is set")
	appID := fs.Int64("github-app-id", envInt64(lookupEnv, "SENTINEL_GITHUB_APP_ID"), "GitHub App ID")
	installationID := fs.Int64("github-installation-id", envInt64(lookupEnv, "SENTINEL_GITHUB_INSTALLATION_ID"), "GitHub App installation ID")
	appKeyFile := fs.String("github-app-key-file", envValue(lookupEnv, "SENTINEL_GITHUB_APP_PRIVATE_KEY_FILE"), "protected GitHub App RSA private key")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if len(fs.Args()) != 0 {
		fmt.Fprintln(stderr, "sentinel-github-relay: authorize takes no positional arguments")
		return 2
	}
	if (*capFile == "") == (*claimFile == "") {
		fmt.Fprintln(stderr, "sentinel-github-relay: provide exactly one of --cap-file or --claim-file")
		return 2
	}
	if strings.TrimSpace(*repository) == "" || *issueNumber <= 0 || strings.TrimSpace(*target) == "" {
		fmt.Fprintln(stderr, "sentinel-github-relay: --repository, --issue and --target are required")
		return 2
	}
	if *ttl <= 0 || *ttl > 24*time.Hour {
		fmt.Fprintln(stderr, "sentinel-github-relay: --ttl must be greater than zero and at most 24h")
		return 2
	}
	if *maxCommands < 1 || *maxCommands > githubrelay.MaxCommands {
		fmt.Fprintf(stderr, "sentinel-github-relay: --max-commands must be 1..%d\n", githubrelay.MaxCommands)
		return 2
	}
	if *publishOutput && (*outputLimit < 1 || *outputLimit > githubrelay.MaximumOutputLimitBytes) {
		fmt.Fprintf(stderr, "sentinel-github-relay: --output-limit must be 1..%d\n", githubrelay.MaximumOutputLimitBytes)
		return 2
	}

	capToken, err := obtainCapability(ctx, *baseURL, *caFile, *capFile, *claimFile)
	if err != nil {
		return report(stderr, err)
	}
	agent, err := agentclient.New(agentclient.Config{BaseURL: *baseURL, Capability: capToken, CAFile: *caFile})
	if err != nil {
		return report(stderr, err)
	}
	bootstrap, err := agent.Bootstrap(ctx)
	if err != nil {
		return report(stderr, fmt.Errorf("verify Sentinel capability: %w", err))
	}
	requestedTarget := strings.TrimSpace(*target)
	if !bootstrap.Permissions.Exec {
		return report(stderr, errors.New("underlying Sentinel grant does not include exec permission"))
	}
	if !contains(bootstrap.Targets, requestedTarget) {
		return report(stderr, errors.New("requested target is outside the underlying Sentinel grant"))
	}
	if *publishOutput && !bootstrap.History.IncludeOutput {
		return report(stderr, errors.New("--publish-output requires history.include_output in the underlying Sentinel grant"))
	}
	now := time.Now().UTC()
	if !now.Before(bootstrap.ExpiresAt) {
		return report(stderr, errors.New("underlying Sentinel grant is already expired"))
	}
	expires := now.Add(*ttl)
	if expires.After(bootstrap.ExpiresAt) {
		expires = bootstrap.ExpiresAt
	}
	if time.Until(expires) < 30*time.Second {
		return report(stderr, errors.New("underlying Sentinel grant has less than 30 seconds remaining"))
	}

	exactArgv, err := parseExactArgv(*exactArgvJSON)
	if err != nil {
		return report(stderr, err)
	}
	gh, err := githubrelay.NewGitHubClient(githubrelay.GitHubAppConfig{
		AppID: *appID, InstallationID: *installationID, PrivateKeyFile: *appKeyFile,
	})
	if err != nil {
		return report(stderr, err)
	}
	repo, err := gh.Repository(ctx, *repository)
	if err != nil {
		return report(stderr, fmt.Errorf("validate GitHub repository: %w", err))
	}
	if !repo.Private {
		return report(stderr, errors.New("relay sessions require a private GitHub repository"))
	}
	if repo.Archived {
		return report(stderr, errors.New("relay repository is archived"))
	}
	issue, err := gh.Issue(ctx, *repository, *issueNumber)
	if err != nil {
		return report(stderr, fmt.Errorf("validate GitHub issue: %w", err))
	}
	if issue.State != "open" {
		return report(stderr, errors.New("relay issue must be open"))
	}
	if issue.PullRequest != nil {
		return report(stderr, errors.New("relay channel must be a GitHub issue, not a pull request"))
	}
	if issue.User.ID <= 0 {
		return report(stderr, errors.New("relay issue has no stable numeric author identity"))
	}
	requestActorID := issue.User.ID
	requestActorLogin := issue.User.Login
	if *actorIDOverride > 0 && *actorIDOverride != issue.User.ID {
		comments, _, _, err := gh.Comments(ctx, *repository, *issueNumber, "")
		if err != nil {
			return report(stderr, fmt.Errorf("validate requested GitHub actor: %w", err))
		}
		found := false
		for _, comment := range comments {
			if comment.User.ID == *actorIDOverride {
				requestActorID = comment.User.ID
				requestActorLogin = comment.User.Login
				found = true
				break
			}
		}
		if !found {
			return report(stderr, errors.New("--actor-id was not observed on the authorized issue"))
		}
	}

	sessionID, err := githubrelay.NewSessionID()
	if err != nil {
		return report(stderr, err)
	}
	secret, err := githubrelay.NewSessionSecret()
	if err != nil {
		return report(stderr, err)
	}
	session := githubrelay.Session{
		Version: githubrelay.ProtocolVersion,
		ID:      sessionID, Secret: secret, Capability: capToken, GrantID: bootstrap.SessionID,
		Repository: repo.FullName, RepositoryID: repo.ID, IssueNumber: issue.Number, IssueID: issue.ID,
		ActorID: requestActorID, Target: requestedTarget,
		CreatedAt: now, ExpiresAt: expires,
		MaxCommands: *maxCommands, NextSequence: 1, ExactArgv: exactArgv,
		PublishOutput: *publishOutput,
	}
	if *publishOutput {
		session.OutputLimitBytes = *outputLimit
	}
	session.Normalize()
	if err := session.Validate(time.Time{}); err != nil {
		return report(stderr, err)
	}
	store, err := githubrelay.OpenStore(*stateDir)
	if err != nil {
		return report(stderr, err)
	}
	if err := store.Save(session); err != nil {
		return report(stderr, err)
	}
	authBody, err := githubrelay.BuildAuthorizationComment(secret, githubrelay.AuthorizationEnvelope{
		SessionID: session.ID, RepositoryID: session.RepositoryID, IssueNumber: session.IssueNumber,
		ActorID: session.ActorID, Target: session.Target, ExpiresAt: session.ExpiresAt.Format(time.RFC3339),
		MaxCommands: session.MaxCommands, ExactArgv: session.ExactArgv, PublishOutput: session.PublishOutput,
		OutputLimit: session.OutputLimitBytes,
	})
	if err != nil {
		return report(stderr, err)
	}
	if _, err := gh.CreateComment(ctx, session.Repository, session.IssueNumber, authBody); err != nil {
		session.Close("failed to publish relay authorization marker")
		_ = store.Save(session)
		return report(stderr, fmt.Errorf("publish authorization marker: %w", err))
	}

	fmt.Fprintf(stdout, "relay session: %s\n", session.ID)
	fmt.Fprintf(stdout, "repository: %s (id=%d)\nissue: %d (id=%d)\n", session.Repository, session.RepositoryID, session.IssueNumber, session.IssueID)
	fmt.Fprintf(stdout, "request actor: %s (id=%d)\ntarget: %s\nexpires: %s\nmax commands: %d\n", requestActorLogin, session.ActorID, session.Target, session.ExpiresAt.Format(time.RFC3339), session.MaxCommands)
	if len(session.ExactArgv) != 0 {
		data, _ := json.Marshal(session.ExactArgv)
		fmt.Fprintf(stdout, "exact argv: %s\n", data)
	}
	fmt.Fprintf(stdout, "publish output: %t\n", session.PublishOutput)
	fmt.Fprintf(stdout, "\nrelay session secret (deliver to the authorized chat OUT OF BAND; never post it to GitHub):\n%s\n", secret)
	return 0
}

func runServe(ctx context.Context, args []string, stdout, stderr io.Writer, lookupEnv func(string) (string, bool)) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	stateDir := fs.String("state-dir", envOr(lookupEnv, "SENTINEL_GITHUB_RELAY_STATE_DIR", "/var/lib/tethys-sentinel-github-relay"), "private relay state directory")
	baseURL := fs.String("url", envValue(lookupEnv, "SENTINEL_URL"), "Sentinel Gateway HTTPS origin")
	caFile := fs.String("ca-file", envValue(lookupEnv, "SENTINEL_CA_FILE"), "additional Sentinel CA PEM")
	poll := fs.Duration("poll", envDuration(lookupEnv, "SENTINEL_GITHUB_POLL_INTERVAL", 5*time.Second), "GitHub polling interval")
	once := fs.Bool("once", false, "process active sessions once and exit")
	appID := fs.Int64("github-app-id", envInt64(lookupEnv, "SENTINEL_GITHUB_APP_ID"), "GitHub App ID")
	installationID := fs.Int64("github-installation-id", envInt64(lookupEnv, "SENTINEL_GITHUB_INSTALLATION_ID"), "GitHub App installation ID")
	appKeyFile := fs.String("github-app-key-file", envValue(lookupEnv, "SENTINEL_GITHUB_APP_PRIVATE_KEY_FILE"), "protected GitHub App RSA private key")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if len(fs.Args()) != 0 || *poll < time.Second || *poll > time.Minute {
		fmt.Fprintln(stderr, "sentinel-github-relay: serve requires no positional arguments and --poll must be 1s..1m")
		return 2
	}
	store, err := githubrelay.OpenStore(*stateDir)
	if err != nil {
		return report(stderr, err)
	}
	gh, err := githubrelay.NewGitHubClient(githubrelay.GitHubAppConfig{
		AppID: *appID, InstallationID: *installationID, PrivateKeyFile: *appKeyFile,
	})
	if err != nil {
		return report(stderr, err)
	}
	runner := &githubrelay.Runner{
		Store: store, GitHub: gh, PollInterval: *poll,
		AgentFactory: func(token string) (githubrelay.Agent, error) {
			return agentclient.New(agentclient.Config{BaseURL: *baseURL, Capability: token, CAFile: *caFile})
		},
		Logf: func(format string, values ...any) {
			fmt.Fprintf(stderr, "sentinel-github-relay: "+format+"\n", values...)
		},
	}
	if *once {
		if err := runner.RunOnce(ctx); err != nil {
			return report(stderr, err)
		}
		fmt.Fprintln(stdout, "relay poll complete")
		return 0
	}
	fmt.Fprintf(stdout, "sentinel-github-relay %s polling GitHub every %s\n", buildinfo.Version, poll.String())
	if err := runner.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return report(stderr, err)
	}
	return 0
}

func runSign(args []string, stdout, stderr io.Writer, lookupEnv func(string) (string, bool)) int {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	fs.SetOutput(stderr)
	secretFile := fs.String("secret-file", "", "protected file containing relay session secret; otherwise use SENTINEL_RELAY_SESSION_SECRET or stdin")
	sessionID := fs.String("session", "", "relay session id")
	sequence := fs.Uint64("sequence", 0, "relay request sequence")
	requestID := fs.String("request-id", "", "immutable Sentinel request id")
	target := fs.String("target", "", "logical Sentinel target")
	reason := fs.String("reason", "", "agent reason")
	timeout := fs.Int64("timeout", 0, "Sentinel timeout in seconds")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	argv := fs.Args()
	if strings.TrimSpace(*sessionID) == "" || *sequence == 0 || strings.TrimSpace(*requestID) == "" || strings.TrimSpace(*target) == "" || len(argv) == 0 {
		fmt.Fprintln(stderr, "sentinel-github-relay: sign requires --session, --sequence, --request-id, --target and argv after --")
		return 2
	}
	secret, err := readRelaySecret(*secretFile, lookupEnv, os.Stdin)
	if err != nil {
		return report(stderr, err)
	}
	body, err := githubrelay.BuildRequestComment(secret, githubrelay.RequestEnvelope{
		SessionID: strings.TrimSpace(*sessionID), Sequence: *sequence, RequestID: strings.TrimSpace(*requestID),
		Target: strings.TrimSpace(*target), Argv: argv, AgentReason: *reason, TimeoutSeconds: *timeout,
	})
	if err != nil {
		return report(stderr, err)
	}
	fmt.Fprintln(stdout, body)
	return 0
}

func runInspect(args []string, stdout, stderr io.Writer, lookupEnv func(string) (string, bool)) int {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	fs.SetOutput(stderr)
	stateDir := fs.String("state-dir", envOr(lookupEnv, "SENTINEL_GITHUB_RELAY_STATE_DIR", "/var/lib/tethys-sentinel-github-relay"), "private relay state directory")
	sessionID := fs.String("session", "", "relay session id")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(*sessionID) == "" || len(fs.Args()) != 0 {
		fmt.Fprintln(stderr, "sentinel-github-relay: inspect requires --session")
		return 2
	}
	store, err := githubrelay.OpenStore(*stateDir)
	if err != nil {
		return report(stderr, err)
	}
	session, err := store.Load(*sessionID)
	if err != nil {
		return report(stderr, err)
	}
	view := struct {
		ID               string   `json:"id"`
		GrantID          string   `json:"grant_id"`
		Repository       string   `json:"repository"`
		RepositoryID     int64    `json:"repository_id"`
		IssueNumber      int      `json:"issue_number"`
		ActorID          int64    `json:"actor_id"`
		Target           string   `json:"target"`
		CreatedAt        string   `json:"created_at"`
		ExpiresAt        string   `json:"expires_at"`
		MaxCommands      int      `json:"max_commands"`
		CommandsComplete int      `json:"commands_complete"`
		NextSequence     uint64   `json:"next_sequence"`
		ExactArgv        []string `json:"exact_argv,omitempty"`
		PublishOutput    bool     `json:"publish_output"`
		Closed           bool     `json:"closed"`
		CloseReason      string   `json:"close_reason,omitempty"`
	}{
		ID: session.ID, GrantID: session.GrantID, Repository: session.Repository, RepositoryID: session.RepositoryID,
		IssueNumber: session.IssueNumber, ActorID: session.ActorID, Target: session.Target,
		CreatedAt: session.CreatedAt.Format(time.RFC3339), ExpiresAt: session.ExpiresAt.Format(time.RFC3339),
		MaxCommands: session.MaxCommands, CommandsComplete: session.CommandsComplete, NextSequence: session.NextSequence,
		ExactArgv: session.ExactArgv, PublishOutput: session.PublishOutput, Closed: session.Closed, CloseReason: session.CloseReason,
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(view); err != nil {
		return report(stderr, err)
	}
	return 0
}

func runClose(args []string, stdout, stderr io.Writer, lookupEnv func(string) (string, bool)) int {
	fs := flag.NewFlagSet("close", flag.ContinueOnError)
	fs.SetOutput(stderr)
	stateDir := fs.String("state-dir", envOr(lookupEnv, "SENTINEL_GITHUB_RELAY_STATE_DIR", "/var/lib/tethys-sentinel-github-relay"), "private relay state directory")
	sessionID := fs.String("session", "", "relay session id")
	reason := fs.String("reason", "closed by local operator", "local close reason")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(*sessionID) == "" || len(fs.Args()) != 0 {
		fmt.Fprintln(stderr, "sentinel-github-relay: close requires --session")
		return 2
	}
	store, err := githubrelay.OpenStore(*stateDir)
	if err != nil {
		return report(stderr, err)
	}
	session, err := store.Load(*sessionID)
	if err != nil {
		return report(stderr, err)
	}
	session.Close(*reason)
	if err := store.Save(session); err != nil {
		return report(stderr, err)
	}
	fmt.Fprintf(stdout, "relay session %s closed locally\n", session.ID)
	return 0
}

func obtainCapability(ctx context.Context, baseURL, caFile, capFile, claimFile string) (string, error) {
	if capFile != "" {
		data, err := readProtectedFile(capFile, 4096)
		if err != nil {
			return "", err
		}
		token := strings.TrimSpace(string(data))
		if capability.ValidateFormat(token) != nil {
			return "", errors.New("capability file does not contain a valid Sentinel capability")
		}
		return token, nil
	}
	data, err := readProtectedFile(claimFile, 4096)
	if err != nil {
		return "", err
	}
	claim, err := mcpclaim.NormalizeCode(string(data))
	if err != nil {
		return "", err
	}
	result, err := agentclient.RedeemMCPClaim(ctx, agentclient.Config{BaseURL: baseURL, CAFile: caFile}, claim)
	if err != nil {
		return "", err
	}
	if capability.ValidateFormat(result.Capability) != nil {
		return "", errors.New("claim response contained an invalid Sentinel capability")
	}
	return result.Capability, nil
}

func parseExactArgv(value string) ([]string, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	var argv []string
	dec := json.NewDecoder(strings.NewReader(value))
	if err := dec.Decode(&argv); err != nil {
		return nil, fmt.Errorf("decode --exact-argv-json: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("--exact-argv-json must contain one JSON array")
	}
	if len(argv) == 0 {
		return nil, errors.New("--exact-argv-json must not be empty")
	}
	return argv, nil
}

func readRelaySecret(path string, lookupEnv func(string) (string, bool), stdin io.Reader) (string, error) {
	if strings.TrimSpace(path) != "" {
		data, err := readProtectedFile(path, 1024)
		if err != nil {
			return "", err
		}
		secret := strings.TrimSpace(string(data))
		return secret, githubrelay.ValidateSessionSecret(secret)
	}
	if value := envValue(lookupEnv, "SENTINEL_RELAY_SESSION_SECRET"); value != "" {
		return value, githubrelay.ValidateSessionSecret(value)
	}
	reader := bufio.NewReader(io.LimitReader(stdin, 1024))
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	secret := strings.TrimSpace(line)
	return secret, githubrelay.ValidateSessionSecret(secret)
}

func readProtectedFile(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("secret input must be a regular non-symlink file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("secret input must not be group/other accessible")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("secret input exceeds size limit")
	}
	return data, nil
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func envValue(lookupEnv func(string) (string, bool), key string) string {
	if lookupEnv == nil {
		return ""
	}
	value, _ := lookupEnv(key)
	return strings.TrimSpace(value)
}

func envOr(lookupEnv func(string) (string, bool), key, fallback string) string {
	if value := envValue(lookupEnv, key); value != "" {
		return value
	}
	return fallback
}

func envInt64(lookupEnv func(string) (string, bool), key string) int64 {
	value := envValue(lookupEnv, key)
	parsed, _ := strconv.ParseInt(value, 10, 64)
	return parsed
}

func envDuration(lookupEnv func(string) (string, bool), key string, fallback time.Duration) time.Duration {
	value := envValue(lookupEnv, key)
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func report(stderr io.Writer, err error) int {
	fmt.Fprintf(stderr, "sentinel-github-relay: %v\n", err)
	return 1
}

func usage(w io.Writer) {
	fmt.Fprintln(w, `usage: sentinel-github-relay <command> [options]

commands:
  authorize   bind one private GitHub issue to one existing Sentinel grant/session
  serve       poll authorized issues and forward authenticated requests through the existing Agent API
  sign        produce an authenticated request comment (secret via protected file/env/stdin, never argv)
  inspect     show non-secret local relay session metadata
  close       locally disable a relay session
  version     print version

The relay is transport only. It does not expose a new Sentinel execution API and cannot create or widen grants.`)
}