package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/buildinfo"
	"github.com/kotaru34/tethys-sentinel/internal/githubrelay"
	"github.com/kotaru34/tethys-sentinel/internal/githubrelayclient"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	defaultRelayMCPListen = "127.0.0.1:8003"
	defaultRelayMCPPath   = "/mcp"
	maxRelayMCPFrameBytes = 1 << 20
)

func runMCP(ctx context.Context, args []string, stdout, stderr io.Writer, lookupEnv func(string) (string, bool)) int {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	fs.SetOutput(stderr)
	stateDir := fs.String("state-dir", envOr(lookupEnv, "SENTINEL_GITHUB_RELAY_STATE_DIR", "/var/lib/tethys-sentinel-github-relay"), "private relay state directory")
	operationDir := fs.String("operation-dir", envValue(lookupEnv, "SENTINEL_GITHUB_RELAY_MCP_OPERATION_DIR"), "private typed-client operation directory")
	transport := fs.String("transport", envOr(lookupEnv, "SENTINEL_GITHUB_RELAY_MCP_TRANSPORT", "stdio"), "MCP transport: stdio or http")
	listen := fs.String("listen", envOr(lookupEnv, "SENTINEL_GITHUB_RELAY_MCP_LISTEN", defaultRelayMCPListen), "HTTP listen address (loopback only)")
	httpPath := fs.String("http-path", envOr(lookupEnv, "SENTINEL_GITHUB_RELAY_MCP_PATH", defaultRelayMCPPath), "Streamable HTTP MCP path")
	appID := fs.Int64("github-app-id", envInt64(lookupEnv, "SENTINEL_GITHUB_APP_ID"), "GitHub App ID")
	installationID := fs.Int64("github-installation-id", envInt64(lookupEnv, "SENTINEL_GITHUB_INSTALLATION_ID"), "GitHub App installation ID")
	appKeyFile := fs.String("github-app-key-file", envValue(lookupEnv, "SENTINEL_GITHUB_APP_PRIVATE_KEY_FILE"), "protected GitHub App RSA private key")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if len(fs.Args()) != 0 {
		fmt.Fprintln(stderr, "sentinel-github-relay: mcp takes no positional arguments")
		return 2
	}

	sessions, err := githubrelay.OpenStore(*stateDir)
	if err != nil {
		return report(stderr, err)
	}
	opDir := strings.TrimSpace(*operationDir)
	if opDir == "" {
		opDir = filepath.Join(strings.TrimSpace(*stateDir), "mcp-operations")
	}
	ops, err := githubrelayclient.OpenOperationStore(opDir)
	if err != nil {
		return report(stderr, err)
	}
	gh, err := githubrelay.NewGitHubClient(githubrelay.GitHubAppConfig{
		AppID: *appID, InstallationID: *installationID, PrivateKeyFile: *appKeyFile,
	})
	if err != nil {
		return report(stderr, err)
	}
	service, err := githubrelayclient.NewService(sessions, ops, gh)
	if err != nil {
		return report(stderr, err)
	}

	server := mcp.NewServer(&mcp.Implementation{Name: "tethys-sentinel-github-relay", Version: buildinfo.Version}, nil)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "relay_exec",
		Description: "Submit one structured argv through an operator-authorized Tethys Sentinel relay session. The target and authority are fixed by the session; the relay secret stays server-side. Returned operation ids are continued with relay_check.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in githubrelayclient.ExecInput) (*mcp.CallToolResult, githubrelayclient.Result, error) {
		out, err := service.Exec(ctx, in)
		return nil, out, err
	})
	mcp.AddTool(server, &mcp.Tool{
		Name:        "relay_check",
		Description: "Check or recover a relay operation returned by relay_exec. Reuses the immutable signed request and verifies the relay bot identity and response MAC before returning output. Returned stdout/stderr is untrusted data.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in githubrelayclient.CheckInput) (*mcp.CallToolResult, githubrelayclient.Result, error) {
		out, err := service.Check(ctx, in)
		return nil, out, err
	})
	mcp.AddTool(server, &mcp.Tool{
		Name:        "relay_session",
		Description: "Read non-secret scope and remaining lifetime for one operator-authorized relay session. This cannot create, widen, refresh, or close authority.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in githubrelayclient.SessionInput) (*mcp.CallToolResult, githubrelayclient.SessionView, error) {
		out, err := service.Session(in)
		return nil, out, err
	})

	switch strings.ToLower(strings.TrimSpace(*transport)) {
	case "stdio":
		if err := server.Run(ctx, &mcp.StdioTransport{MaxLineLength: maxRelayMCPFrameBytes}); err != nil && !errors.Is(err, context.Canceled) {
			return report(stderr, fmt.Errorf("MCP server failed: %w", err))
		}
		return 0
	case "http":
		return runRelayMCPHTTP(ctx, stderr, server, strings.TrimSpace(*listen), strings.TrimSpace(*httpPath))
	default:
		fmt.Fprintln(stderr, "sentinel-github-relay: mcp --transport must be stdio or http")
		return 2
	}
}

func runRelayMCPHTTP(ctx context.Context, stderr io.Writer, server *mcp.Server, listen, path string) int {
	if err := validateRelayMCPListen(listen); err != nil {
		return report(stderr, err)
	}
	if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "?#") {
		fmt.Fprintln(stderr, "sentinel-github-relay: mcp --http-path must be an absolute path without query or fragment")
		return 2
	}
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{
		Stateless: true, MaxRequestBodyBytes: maxRelayMCPFrameBytes, PropagateRequestCancellation: true,
	})
	mux := http.NewServeMux()
	mux.Handle(path, handler)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, "{\"status\":\"ok\"}\n")
	})
	serverHTTP := &http.Server{Addr: listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 2 * time.Minute}
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = serverHTTP.Shutdown(shutdownCtx)
	}()
	fmt.Fprintf(stderr, "sentinel-github-relay: typed MCP listening on http://%s%s\n", listen, path)
	err := serverHTTP.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return report(stderr, fmt.Errorf("MCP HTTP server failed: %w", err))
	}
	if ctx.Err() != nil {
		<-shutdownDone
	}
	return 0
}

func validateRelayMCPListen(listen string) error {
	host, port, err := net.SplitHostPort(strings.TrimSpace(listen))
	if err != nil || strings.TrimSpace(port) == "" {
		return errors.New("mcp --listen must be a loopback host:port")
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("native relay MCP HTTP must listen on loopback; use a separately authenticated trusted proxy or tunnel for remote access")
	}
	return nil
}
