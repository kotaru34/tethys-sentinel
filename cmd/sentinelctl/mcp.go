package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/term"

	"github.com/kotaru34/tethys-sentinel/internal/agentclient"
	"github.com/kotaru34/tethys-sentinel/internal/capability"
	"github.com/kotaru34/tethys-sentinel/internal/domain"
	"github.com/kotaru34/tethys-sentinel/internal/mcpclaim"
)

type mcpClaimInstallResult struct {
	Path      string              `json:"path"`
	GrantID   string              `json:"grant_id"`
	Agent     string              `json:"agent"`
	Purpose   string              `json:"purpose"`
	Targets   []string            `json:"targets"`
	ExpiresAt string              `json:"expires_at"`
	Shell     bool                `json:"shell"`
	History   domain.HistoryScope `json:"history"`
}

func runMCP(ctx context.Context, args []string, baseURL, caFile, capFile string, jsonOutput bool, stdout, stderr io.Writer, lookupEnv func(string) (string, bool)) int {
	if len(args) == 0 || args[0] != "claim" {
		fmt.Fprintln(stderr, "usage: sentinelctl mcp claim [--claim-file PATH]")
		return 2
	}
	if len(args) > 1 && args[1] == "help" {
		fmt.Fprintln(stdout, "usage: sentinelctl mcp claim [--claim-file PATH]")
		return 0
	}
	fs := flag.NewFlagSet("mcp claim", flag.ContinueOnError)
	fs.SetOutput(stderr)
	claimFile := fs.String("claim-file", "", "read one-time MCP claim code from a protected file instead of prompting/stdin")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if len(fs.Args()) != 0 {
		fmt.Fprintln(stderr, "sentinelctl: MCP claim code is not accepted as an argv value; use the prompt/stdin or --claim-file")
		return 2
	}
	code, err := readMCPClaimCode(strings.TrimSpace(*claimFile), lookupEnv, stderr)
	if err != nil {
		return reportError(stderr, err)
	}
	result, err := agentclient.RedeemMCPClaim(ctx, agentclient.Config{BaseURL: baseURL, CAFile: caFile}, code)
	if err != nil {
		return reportError(stderr, err)
	}
	if capability.ValidateFormat(result.Capability) != nil {
		return reportError(stderr, errors.New("claim response contained an invalid capability"))
	}
	path := strings.TrimSpace(capFile)
	if path == "" {
		path, err = defaultCapabilityPath()
		if err != nil {
			return reportError(stderr, err)
		}
	}
	if err := installCapabilityAtomically(path, result.Capability); err != nil {
		return reportError(stderr, fmt.Errorf("install capability: %w", err))
	}

	// Verify the installed capability immediately. A verification failure does
	// not delete it: the one-time claim has already been consumed, and retaining
	// the securely written capability lets the operator recover from a transient
	// network failure without losing authority material.
	client, err := agentclient.New(agentclient.Config{BaseURL: baseURL, Capability: result.Capability, CAFile: caFile})
	if err != nil {
		return reportError(stderr, fmt.Errorf("capability installed but client setup failed: %w", err))
	}
	bootstrap, err := client.Bootstrap(ctx)
	if err != nil {
		return reportError(stderr, fmt.Errorf("capability installed at %s but bootstrap verification failed: %w", path, err))
	}

	view := mcpClaimInstallResult{
		Path: path, GrantID: bootstrap.SessionID, Agent: bootstrap.Agent, Purpose: bootstrap.Purpose,
		Targets: bootstrap.Targets, ExpiresAt: bootstrap.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"),
		Shell: bootstrap.Permissions.Shell, History: bootstrap.History,
	}
	if jsonOutput {
		return writeJSON(stdout, stderr, view)
	}
	fmt.Fprintf(stdout, "MCP capability installed: %s\n", path)
	fmt.Fprintf(stdout, "session: %s\nagent: %s\npurpose: %s\nexpires: %s\nshell: %t\ntargets: %s\n",
		view.GrantID, view.Agent, view.Purpose, view.ExpiresAt, view.Shell, strings.Join(view.Targets, ", "))
	return 0
}

func readMCPClaimCode(claimFile string, lookupEnv func(string) (string, bool), stderr io.Writer) (string, error) {
	if claimFile != "" {
		info, err := os.Lstat(claimFile)
		if err != nil {
			return "", fmt.Errorf("inspect claim file: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return "", errors.New("claim file must be a regular non-symlink file")
		}
		if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
			return "", errors.New("claim file must not be group/other accessible")
		}
		data, err := os.ReadFile(claimFile)
		if err != nil {
			return "", err
		}
		return mcpclaim.NormalizeCode(string(data))
	}
	if value := envValue(lookupEnv, "SENTINEL_MCP_CLAIM"); value != "" {
		return mcpclaim.NormalizeCode(value)
	}
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(stderr, "One-time Sentinel MCP claim: ")
		data, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(stderr)
		if err != nil {
			return "", err
		}
		return mcpclaim.NormalizeCode(string(data))
	}
	reader := bufio.NewReader(io.LimitReader(os.Stdin, 1024))
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return mcpclaim.NormalizeCode(line)
}

func defaultCapabilityPath() (string, error) {
	if config := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME")); config != "" {
		return filepath.Join(config, "tethys-sentinel", "cap"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return "", errors.New("could not determine capability path; set --cap-file or SENTINEL_CAP_FILE")
	}
	return filepath.Join(home, ".config", "tethys-sentinel", "cap"), nil
}

func installCapabilityAtomically(path, token string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return errors.New("capability path is empty")
	}
	if capability.ValidateFormat(strings.TrimSpace(token)) != nil {
		return errors.New("invalid capability")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	dirInfo, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if dirInfo.Mode()&os.ModeSymlink != 0 || !dirInfo.IsDir() {
		return errors.New("capability directory must be a non-symlink directory")
	}
	if runtime.GOOS != "windows" && dirInfo.Mode().Perm()&0o077 != 0 {
		return errors.New("capability directory must not be group/other accessible")
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("existing capability path must be a regular non-symlink file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	tmp, err := os.CreateTemp(dir, ".cap-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := io.WriteString(tmp, strings.TrimSpace(token)+"\n"); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	if directory, err := os.Open(dir); err == nil {
		_ = directory.Sync()
		_ = directory.Close()
	}
	return nil
}
