package sshexec

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
	"github.com/kotaru34/tethys-sentinel/internal/remotecommand"
	"github.com/kotaru34/tethys-sentinel/internal/sshtarget"
	"github.com/kotaru34/tethys-sentinel/internal/workeridentity"
)

const (
	defaultDialTimeout = 5 * time.Second
	defaultOutputLimit = 4 << 20
)

type Executor struct {
	DialTimeout      time.Duration
	OutputLimitBytes int64
}

func (e Executor) Execute(ctx context.Context, job executionjob.Job, credential workeridentity.Credential, target sshtarget.Spec) (executionjob.Result, error) {
	if job.Status != executionjob.Running || !executionjob.VerifyBinding(job) {
		return executionjob.Result{Success: false, ExitCode: -1, ErrorKind: "invalid_running_job"}, errors.New("SSH executor requires a valid running job")
	}
	if credential.Signer == nil || credential.Certificate == nil {
		return executionjob.Result{Success: false, ExitCode: -1, ErrorKind: "invalid_ssh_credential"}, errors.New("SSH executor requires a bound certificate credential")
	}
	if target.Name != job.Target {
		return executionjob.Result{Success: false, ExitCode: -1, ErrorKind: "ssh_target_mismatch"}, errors.New("resolved SSH target does not match execution job")
	}
	pinnedKey, err := parsePinnedHostKey(target.HostKey)
	if err != nil {
		return executionjob.Result{Success: false, ExitCode: -1, ErrorKind: "invalid_host_key_pin"}, err
	}
	command, err := remotecommand.Encode(job)
	if err != nil {
		return executionjob.Result{Success: false, ExitCode: -1, ErrorKind: "remote_command_encoding_failed"}, err
	}

	dialTimeout := e.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = defaultDialTimeout
	}
	limit := e.OutputLimitBytes
	if limit <= 0 {
		limit = defaultOutputLimit
	}
	stdout := newDigestWriter(limit)
	stderr := newDigestWriter(limit)

	config := &ssh.ClientConfig{
		User:            target.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(credential.Signer)},
		HostKeyCallback: ssh.FixedHostKey(pinnedKey),
		Timeout:         dialTimeout,
	}
	dialer := net.Dialer{Timeout: dialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", target.Address)
	if err != nil {
		return resultWithOutput(false, -1, "ssh_dial_failed", stdout, stderr), fmt.Errorf("SSH dial: %w", err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	clientConn, chans, reqs, err := ssh.NewClientConn(conn, target.Address, config)
	if err != nil {
		return resultWithOutput(false, -1, "ssh_handshake_failed", stdout, stderr), fmt.Errorf("SSH handshake: %w", err)
	}
	client := ssh.NewClient(clientConn, chans, reqs)
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return resultWithOutput(false, -1, "ssh_session_open_failed", stdout, stderr), fmt.Errorf("open SSH session: %w", err)
	}
	defer session.Close()
	session.Stdout = stdout
	session.Stderr = stderr
	session.Stdin = strings.NewReader("")

	errCh := make(chan error, 1)
	go func() { errCh <- session.Run(command) }()
	select {
	case <-ctx.Done():
		_ = client.Close()
		<-errCh
		kind := "ssh_execution_canceled"
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			kind = "ssh_execution_timeout"
		}
		return resultWithOutput(false, -1, kind, stdout, stderr), ctx.Err()
	case runErr := <-errCh:
		if runErr == nil {
			result := resultWithOutput(true, 0, "", stdout, stderr)
			if stdout.Truncated() || stderr.Truncated() {
				result.Success = false
				result.ErrorKind = "output_limit_exceeded"
				return result, errors.New("SSH command output exceeded configured accounting limit")
			}
			return result, nil
		}
		var exitErr *ssh.ExitError
		if errors.As(runErr, &exitErr) {
			result := resultWithOutput(false, exitErr.ExitStatus(), "remote_exit_nonzero", stdout, stderr)
			if stdout.Truncated() || stderr.Truncated() {
				result.ErrorKind = "output_limit_exceeded"
			}
			return result, runErr
		}
		return resultWithOutput(false, -1, "ssh_session_error", stdout, stderr), runErr
	}
}

func parsePinnedHostKey(value string) (ssh.PublicKey, error) {
	key, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(value) + "\n"))
	if err != nil {
		return nil, fmt.Errorf("parse pinned SSH host key: %w", err)
	}
	if len(options) != 0 || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("pinned SSH host key must be one bare public key")
	}
	if _, isCert := key.(*ssh.Certificate); isCert {
		return nil, errors.New("pinned SSH host key must not be a certificate")
	}
	return key, nil
}

type digestWriter struct {
	mu        sync.Mutex
	h         hash.Hash
	limit     int64
	accounted int64
	total     int64
	truncated bool
}

func newDigestWriter(limit int64) *digestWriter {
	return &digestWriter{h: sha256.New(), limit: limit}
}

func (w *digestWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.total += int64(len(p))
	remaining := w.limit - w.accounted
	if remaining > 0 {
		n := int64(len(p))
		if n > remaining {
			n = remaining
		}
		_, _ = w.h.Write(p[:int(n)])
		w.accounted += n
	}
	if w.total > w.limit {
		w.truncated = true
	}
	return len(p), nil
}

func (w *digestWriter) snapshot() (string, int64, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return hex.EncodeToString(w.h.Sum(nil)), w.total, w.truncated
}

func (w *digestWriter) Truncated() bool {
	_, _, truncated := w.snapshot()
	return truncated
}

func resultWithOutput(success bool, exitCode int, errorKind string, stdout, stderr *digestWriter) executionjob.Result {
	stdoutHash, stdoutBytes, stdoutTruncated := stdout.snapshot()
	stderrHash, stderrBytes, stderrTruncated := stderr.snapshot()
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "stdout:%s:%d:%t\nstderr:%s:%d:%t\n", stdoutHash, stdoutBytes, stdoutTruncated, stderrHash, stderrBytes, stderrTruncated)
	return executionjob.Result{
		Success: success, ExitCode: exitCode, ErrorKind: errorKind,
		OutputSHA256: hex.EncodeToString(h.Sum(nil)),
	}
}
