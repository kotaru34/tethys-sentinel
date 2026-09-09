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
	overflow := newOutputLimiter()
	stdout := newDigestWriterWithLimiter(limit, overflow)
	stderr := newDigestWriterWithLimiter(limit, overflow)

	config := &ssh.ClientConfig{
		User:            target.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(credential.Signer)},
		HostKeyCallback: ssh.FixedHostKey(pinnedKey),
	}
	dialer := net.Dialer{Timeout: dialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", target.Address)
	if err != nil {
		return resultWithOutput(false, -1, "ssh_dial_failed", stdout, stderr), fmt.Errorf("SSH dial: %w", err)
	}
	defer conn.Close()

	handshakeDeadline := time.Now().Add(dialTimeout)
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(handshakeDeadline) {
		handshakeDeadline = deadline
	}
	if err := conn.SetDeadline(handshakeDeadline); err != nil {
		return resultWithOutput(false, -1, "ssh_deadline_failed", stdout, stderr), fmt.Errorf("set SSH handshake deadline: %w", err)
	}
	clientConn, chans, reqs, err := ssh.NewClientConn(conn, target.Address, config)
	if err != nil {
		return resultWithOutput(false, -1, "ssh_handshake_failed", stdout, stderr), fmt.Errorf("SSH handshake: %w", err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			_ = clientConn.Close()
			return resultWithOutput(false, -1, "ssh_deadline_failed", stdout, stderr), fmt.Errorf("set SSH execution deadline: %w", err)
		}
	} else if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = clientConn.Close()
		return resultWithOutput(false, -1, "ssh_deadline_failed", stdout, stderr), fmt.Errorf("clear SSH handshake deadline: %w", err)
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
	case <-overflow.ch:
		_ = client.Close()
		<-errCh
		return resultWithOutput(false, -1, "output_limit_exceeded", stdout, stderr), errors.New("SSH command output exceeded configured accounting limit")
	case runErr := <-errCh:
		if stdout.Truncated() || stderr.Truncated() {
			return resultWithOutput(false, -1, "output_limit_exceeded", stdout, stderr), errors.New("SSH command output exceeded configured accounting limit")
		}
		if runErr == nil {
			return resultWithOutput(true, 0, "", stdout, stderr), nil
		}
		var exitErr *ssh.ExitError
		if errors.As(runErr, &exitErr) {
			return resultWithOutput(false, exitErr.ExitStatus(), "remote_exit_nonzero", stdout, stderr), runErr
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

type outputLimiter struct {
	once sync.Once
	ch   chan struct{}
}

func newOutputLimiter() *outputLimiter {
	return &outputLimiter{ch: make(chan struct{})}
}

func (l *outputLimiter) trigger() {
	if l == nil {
		return
	}
	l.once.Do(func() { close(l.ch) })
}

type digestWriter struct {
	mu        sync.Mutex
	h         hash.Hash
	limit     int64
	accounted int64
	total     int64
	truncated bool
	overflow  *outputLimiter
}

func newDigestWriter(limit int64) *digestWriter {
	return newDigestWriterWithLimiter(limit, nil)
}

func newDigestWriterWithLimiter(limit int64, overflow *outputLimiter) *digestWriter {
	return &digestWriter{h: sha256.New(), limit: limit, overflow: overflow}
}

func (w *digestWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
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
	exceeded := w.truncated
	w.mu.Unlock()
	if exceeded {
		w.overflow.trigger()
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
