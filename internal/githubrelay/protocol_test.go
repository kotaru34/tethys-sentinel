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

func TestSessionRejectsSequenceTargetAndExactArgvViolations(t *testing.T) {
	now := time.Date(2026, 9, 23, 4, 0, 0, 0, time.UTC)
	s := Session{
		Version: ProtocolVersion, ID: "sgr_abcdefghijklmnop", Secret: testSecret(), Capability: "cap", GrantID: "grant",
		Repository: "example/relay", RepositoryID: 1, IssueNumber: 2, IssueID: 3, ActorID: 4, Target: "target-test",
		CreatedAt: now, ExpiresAt: now.Add(time.Minute), MaxCommands: 2, NextSequence: 2, ExactArgv: []string{"id"},
	}
	s.Normalize()

	tests := []struct {
		name   string
		mutate func(*RequestEnvelope)
	}{
		{name: "sequence skip or reorder", mutate: func(req *RequestEnvelope) { req.Sequence = 3 }},
		{name: "wrong target", mutate: func(req *RequestEnvelope) { req.Target = "other-target" }},
		{name: "wrong exact argv", mutate: func(req *RequestEnvelope) { req.Argv = []string{"whoami"} }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := RequestEnvelope{Version: ProtocolVersion, SessionID: s.ID, Sequence: 2, RequestID: "request-0002", Target: s.Target, Argv: []string{"id"}}
			tc.mutate(&req)
			req.MAC, _ = RequestMAC(s.Secret, req)
			if err := s.ValidateRequest(req, now); err == nil {
				t.Fatal("policy violation was accepted")
			}
		})
	}
}

func TestActorRequestRoundTripHasNoAuthorityMaterial(t *testing.T) {
	req := ActorRequestEnvelope{
		SessionID:      "sgr_abcdefghijklmnop",
		Argv:           []string{"id"},
		AgentReason:    "inspect identity",
		TimeoutSeconds: 30,
	}
	body, err := BuildActorRequestComment(req)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(body, "mac") || strings.Contains(body, "target") || strings.Contains(body, "request_id") || strings.Contains(body, "sequence") {
		t.Fatalf("actor request exposed derived or secret-bearing fields: %s", body)
	}
	got, err := ParseActorRequestComment(body)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != ProtocolVersion || got.SessionID != req.SessionID || len(got.Argv) != 1 || got.Argv[0] != "id" {
		t.Fatalf("unexpected actor request: %+v", got)
	}
}

func TestActorAuthorizationAndResponseRoundTrip(t *testing.T) {
	authBody, err := BuildActorAuthorizationComment(ActorAuthorizationEnvelope{
		SessionID: "sgr_abcdefghijklmnop", RepositoryID: 1, IssueNumber: 2,
		ActorID: 42, ActorType: "User", Target: "target-test",
		ExpiresAt: "2026-09-25T20:00:00Z", MaxCommands: 8,
		PublishOutput: true, OutputLimit: 8192,
	})
	if err != nil {
		t.Fatal(err)
	}
	auth, err := ParseActorAuthorizationComment(authBody)
	if err != nil {
		t.Fatal(err)
	}
	if auth.ActorID != 42 || auth.ActorType != "User" || auth.Target != "target-test" {
		t.Fatalf("unexpected actor authorization: %+v", auth)
	}

	success := true
	exit := 0
	responseBody, err := BuildActorResponseComment(ResponseEnvelope{
		RequestCommentID: 123, SessionID: auth.SessionID, Sequence: 1,
		Status: "completed", Success: &success, ExitCode: &exit,
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(responseBody, "mac") {
		t.Fatalf("actor response unexpectedly contains a MAC: %s", responseBody)
	}
	response, err := ParseActorResponseComment(responseBody)
	if err != nil {
		t.Fatal(err)
	}
	if response.RequestCommentID != 123 || response.Success == nil || !*response.Success || response.ExitCode == nil || *response.ExitCode != 0 {
		t.Fatalf("unexpected actor response: %+v", response)
	}
}

func TestActorSessionBoundsAndRequestValidation(t *testing.T) {
	now := time.Date(2026, 9, 25, 19, 0, 0, 0, time.UTC)
	s := Session{
		Version: ProtocolVersion, ID: "sgr_abcdefghijklmnop", Secret: testSecret(), Capability: "cap", GrantID: "grant",
		Repository: "example/relay", RepositoryID: 1, IssueNumber: 2, IssueID: 3,
		ActorID: 42, ActorType: "User", TransportMode: TransportModeActor, Target: "target-test",
		CreatedAt: now, ExpiresAt: now.Add(20 * time.Minute), MaxCommands: ActorMaxCommands, NextSequence: 1,
	}
	s.Normalize()
	if err := s.Validate(time.Time{}); err != nil {
		t.Fatal(err)
	}
	req := RequestEnvelope{
		Version: ProtocolVersion, SessionID: s.ID, Sequence: 1, RequestID: "ghc-12345678",
		Target: s.Target, Argv: []string{"id"},
	}
	if err := s.ValidateActorRequest(req, now); err != nil {
		t.Fatalf("valid actor request rejected: %v", err)
	}
	if err := s.ValidateRequest(req, now); err == nil {
		t.Fatal("actor session accepted the HMAC request path")
	}

	tooLong := s
	tooLong.ExpiresAt = now.Add(ActorMaxLifetime + time.Second)
	if err := tooLong.Validate(time.Time{}); err == nil {
		t.Fatal("actor session lifetime bound was not enforced")
	}
	tooMany := s
	tooMany.MaxCommands = ActorMaxCommands + 1
	if err := tooMany.Validate(time.Time{}); err == nil {
		t.Fatal("actor session command bound was not enforced")
	}
	wrongType := s
	wrongType.ActorType = "Bot"
	if err := wrongType.Validate(time.Time{}); err == nil {
		t.Fatal("actor session accepted a non-User request actor")
	}
}
