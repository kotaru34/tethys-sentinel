package githubrelay

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func testSecret() string {
	return relaySecretPrefix + base64.RawURLEncoding.EncodeToString(make([]byte, secretBytes))
}

func TestRequestCommentRoundTripAndMAC(t *testing.T) {
	secret := testSecret()
	req := RequestEnvelope{
		SessionID: "sgr_abcdefghijklmnop", Sequence: 1, RequestID: "request-0001",
		Target: "target-test", Argv: []string{"id"}, AgentReason: "acceptance", TimeoutSeconds: 60,
	}
	body, err := BuildRequestComment(secret, req)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseRequestComment(body)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRequestMAC(secret, got); err != nil {
		t.Fatalf("valid MAC rejected: %v", err)
	}
	got.Argv = []string{"uname", "-a"}
	if err := VerifyRequestMAC(secret, got); err == nil {
		t.Fatal("mutated request retained a valid MAC")
	}
}

func TestCanonicalMACSupportsUnicodeWithoutHTMLEscaping(t *testing.T) {
	secret := testSecret()
	req := RequestEnvelope{
		Version: ProtocolVersion, SessionID: "sgr_abcdefghijklmnop", Sequence: 7, RequestID: "request-0007",
		Target: "target-test", Argv: []string{"printf", "<тест>&"}, AgentReason: "перевірка",
	}
	mac, err := RequestMAC(secret, req)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(mac, macPrefix) {
		t.Fatalf("unexpected MAC %q", mac)
	}
	req.MAC = mac
	if err := VerifyRequestMAC(secret, req); err != nil {
		t.Fatal(err)
	}
}

func TestSessionExactArgvAndExpiry(t *testing.T) {
	now := time.Date(2026, 9, 23, 4, 0, 0, 0, time.UTC)
	s := Session{
		Version: ProtocolVersion, ID: "sgr_abcdefghijklmnop", Secret: testSecret(), Capability: "cap", GrantID: "grant",
		Repository: "example/relay", RepositoryID: 1, IssueNumber: 2, IssueID: 3, ActorID: 4, Target: "target-test",
		CreatedAt: now, ExpiresAt: now.Add(time.Minute), MaxCommands: 1, NextSequence: 1, ExactArgv: []string{"id"},
	}
	s.Normalize()
	req := RequestEnvelope{Version: ProtocolVersion, SessionID: s.ID, Sequence: 1, RequestID: "request-0001", Target: s.Target, Argv: []string{"id"}}
	mac, err := RequestMAC(s.Secret, req)
	if err != nil {
		t.Fatal(err)
	}
	req.MAC = mac
	if err := s.ValidateRequest(req, now); err != nil {
		t.Fatalf("expected request to pass: %v", err)
	}
	req.Argv = []string{"whoami"}
	req.MAC, _ = RequestMAC(s.Secret, req)
	if err := s.ValidateRequest(req, now); err == nil {
		t.Fatal("exact argv scope did not reject another command")
	}
	if s.Active(now.Add(2 * time.Minute)) {
		t.Fatal("expired session reported active")
	}
}

func TestRequestMACKnownVectorMatchesPluginSigner(t *testing.T) {
	secret := "tsr_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	req := RequestEnvelope{
		Version: ProtocolVersion, SessionID: "sgr_abcdefghijklmnop", Sequence: 1, RequestID: "request-0001",
		Target: "target-test", Argv: []string{"id"}, AgentReason: "acceptance", TimeoutSeconds: 60,
	}
	got, err := RequestMAC(secret, req)
	if err != nil {
		t.Fatal(err)
	}
	const want = "h1_JUZ5EQ6w9eDMKOSSZuT3u_7iymcCTI37Pmx6ZRtyyE8"
	if got != want {
		t.Fatalf("MAC = %q, want %q", got, want)
	}
}