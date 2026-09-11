package sshexec

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
	"github.com/kotaru34/tethys-sentinel/internal/remotecommand"
	"github.com/kotaru34/tethys-sentinel/internal/sshsigner"
	"github.com/kotaru34/tethys-sentinel/internal/sshtarget"
	"github.com/kotaru34/tethys-sentinel/internal/workeridentity"
)

func TestExecutorUsesPinnedHostKeyAndBoundEnvelope(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	hostSigner := newSigner(t)
	server := startTestSSHServer(t, hostSigner)
	defer server.Close()

	job, credential := testCredential(t, now)
	target := sshtarget.Spec{
		Name: job.Target, Address: server.Address(), User: "sentinel-ai",
		HostKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(hostSigner.PublicKey()))),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := (Executor{DialTimeout: time.Second, OutputLimitBytes: 4096}).Execute(ctx, job, credential, target)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Success || result.ExitCode != 0 || len(result.OutputSHA256) != 64 {
		t.Fatalf("unexpected result: %+v", result)
	}

	select {
	case command := <-server.commands:
		envelope, binding, err := remotecommand.Decode(command)
		if err != nil {
			t.Fatal(err)
		}
		if envelope.JobID != job.ID || envelope.Target != job.Target || binding != job.CommandSHA256 {
			t.Fatalf("remote envelope mismatch: %+v binding=%s", envelope, binding)
		}
		if len(envelope.Argv) != len(job.Argv) || envelope.Argv[2] != job.Argv[2] {
			t.Fatalf("remote argv mismatch: %#v", envelope.Argv)
		}
	case <-ctx.Done():
		t.Fatal("SSH server did not receive exec request")
	}
}

func TestExecutorNegotiatesPinnedHostKeyAlgorithmWithMultipleServerKeys(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	pinnedHostSigner := newSigner(t)
	alternateHostSigner := newECDSASigner(t)
	server := startTestSSHServerWithHostKeys(t, []ssh.Signer{alternateHostSigner, pinnedHostSigner}, []byte("ok\n"))
	defer server.Close()

	job, credential := testCredential(t, now)
	target := sshtarget.Spec{
		Name: job.Target, Address: server.Address(), User: "sentinel-ai",
		HostKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pinnedHostSigner.PublicKey()))),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := (Executor{DialTimeout: time.Second, OutputLimitBytes: 4096}).Execute(ctx, job, credential, target)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Success || result.ExitCode != 0 {
		t.Fatalf("unexpected result: %+v", result)
	}
	select {
	case <-server.commands:
	case <-ctx.Done():
		t.Fatal("SSH server did not receive exec request")
	}
}

func TestExecutorRejectsWrongPinnedHostKeyBeforeExec(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	server := startTestSSHServer(t, newSigner(t))
	defer server.Close()
	job, credential := testCredential(t, now)
	wrongHostSigner := newSigner(t)
	target := sshtarget.Spec{
		Name: job.Target, Address: server.Address(), User: "sentinel-ai",
		HostKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(wrongHostSigner.PublicKey()))),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := (Executor{DialTimeout: time.Second}).Execute(ctx, job, credential, target)
	if err == nil || result.ErrorKind != "ssh_handshake_failed" {
		t.Fatalf("wrong host pin result=%+v err=%v", result, err)
	}
	select {
	case command := <-server.commands:
		t.Fatalf("exec reached wrong-pinned server: %q", command)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestExecutorStopsWhenOutputLimitIsExceeded(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	hostSigner := newSigner(t)
	server := startTestSSHServerWithOutput(t, hostSigner, bytes.Repeat([]byte("x"), 8192))
	defer server.Close()
	job, credential := testCredential(t, now)
	target := sshtarget.Spec{
		Name: job.Target, Address: server.Address(), User: "sentinel-ai",
		HostKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(hostSigner.PublicKey()))),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := (Executor{DialTimeout: time.Second, OutputLimitBytes: 64}).Execute(ctx, job, credential, target)
	if err == nil || result.Success || result.ErrorKind != "output_limit_exceeded" {
		t.Fatalf("overflow result=%+v err=%v", result, err)
	}
	if len(result.OutputSHA256) != 64 {
		t.Fatalf("overflow result missing digest: %+v", result)
	}
}

func TestExecutorBoundsHandshakeWithoutContextDeadline(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	release := make(chan struct{})
	defer close(release)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		<-release
	}()

	now := time.Now().UTC().Truncate(time.Second)
	job, credential := testCredential(t, now)
	target := sshtarget.Spec{
		Name: job.Target, Address: listener.Addr().String(), User: "sentinel-ai",
		HostKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(newSigner(t).PublicKey()))),
	}
	started := time.Now()
	result, err := (Executor{DialTimeout: 100 * time.Millisecond}).Execute(context.Background(), job, credential, target)
	elapsed := time.Since(started)
	if err == nil || result.ErrorKind != "ssh_handshake_failed" {
		t.Fatalf("stalled handshake result=%+v err=%v", result, err)
	}
	if elapsed > time.Second {
		t.Fatalf("stalled handshake exceeded bound: %s", elapsed)
	}
}

func TestDigestWriterAccountsWithoutRetainingRawOutput(t *testing.T) {
	writer := newDigestWriter(4)
	payload := []byte("super-secret-output")
	if n, err := writer.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("write n=%d err=%v", n, err)
	}
	digest, total, truncated := writer.snapshot()
	if len(digest) != 64 || total != int64(len(payload)) || !truncated {
		t.Fatalf("digest=%q total=%d truncated=%v", digest, total, truncated)
	}
	if bytes.Contains([]byte(digest), payload) {
		t.Fatal("raw output appeared in digest state")
	}
}

func testCredential(t *testing.T, now time.Time) (executionjob.Job, workeridentity.Credential) {
	t.Helper()
	job := executionjob.Job{
		ID: "job-ssh-test-01", GrantID: "grant-ssh-test-01", RequestID: "request-ssh-test-01",
		Target: "dns01", Argv: []string{"printf", "%s", "$(id); still-data"},
		ExpiresAt: now.Add(30 * time.Second), Status: executionjob.Running,
	}
	binding, err := executionjob.BindingHash(job.GrantID, job.RequestID, job.Target, job.Argv)
	if err != nil {
		t.Fatal(err)
	}
	job.CommandSHA256 = binding

	identity, err := workeridentity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	ca := newSigner(t)
	signer, err := sshsigner.NewWithClock(ca, sshsigner.Policy{
		Principal: "sentinel-ai", WrapperPath: "/usr/local/libexec/tethys-sentinel-exec",
		SourceAddresses: []string{"127.0.0.1"}, CertificateTTL: 20 * time.Second, Backdate: time.Second,
	}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := signer.Sign(sshsigner.Request{
		JobID: job.ID, GrantID: job.GrantID, Target: job.Target, CommandSHA256: job.CommandSHA256,
		PublicKey: identity.PublicKey(), NotAfter: job.ExpiresAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := identity.Bind(job, certificate, now)
	if err != nil {
		t.Fatal(err)
	}
	return job, credential
}

func newSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func newECDSASigner(t *testing.T) ssh.Signer {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

type testSSHServer struct {
	listener net.Listener
	commands chan string
	done     chan struct{}
}

func startTestSSHServer(t *testing.T, hostSigner ssh.Signer) *testSSHServer {
	t.Helper()
	return startTestSSHServerWithOutput(t, hostSigner, []byte("ok\n"))
}

func startTestSSHServerWithOutput(t *testing.T, hostSigner ssh.Signer, output []byte) *testSSHServer {
	t.Helper()
	return startTestSSHServerWithHostKeys(t, []ssh.Signer{hostSigner}, output)
}

func startTestSSHServerWithHostKeys(t *testing.T, hostSigners []ssh.Signer, output []byte) *testSSHServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &testSSHServer{listener: listener, commands: make(chan string, 4), done: make(chan struct{})}
	config := &ssh.ServerConfig{
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return nil, nil
		},
	}
	for _, hostSigner := range hostSigners {
		config.AddHostKey(hostSigner)
	}
	go func() {
		defer close(server.done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go handleTestSSHConn(conn, config, server.commands, output)
		}
	}()
	return server
}

func (s *testSSHServer) Address() string { return s.listener.Addr().String() }

func (s *testSSHServer) Close() {
	_ = s.listener.Close()
	<-s.done
}

func handleTestSSHConn(conn net.Conn, config *ssh.ServerConfig, commands chan<- string, output []byte) {
	defer conn.Close()
	_, channels, requests, err := ssh.NewServerConn(conn, config)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(requests)
	for newChannel := range channels {
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(ssh.UnknownChannelType, "session only")
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer channel.Close()
			for req := range requests {
				if req.Type != "exec" {
					_ = req.Reply(false, nil)
					continue
				}
				var message struct{ Command string }
				if err := ssh.Unmarshal(req.Payload, &message); err != nil {
					_ = req.Reply(false, nil)
					return
				}
				commands <- message.Command
				_ = req.Reply(true, nil)
				_, _ = channel.Write(output)
				_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
				return
			}
		}()
	}
}
