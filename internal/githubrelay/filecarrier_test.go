package githubrelay

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestGitHubFileCarrierUsesScopedContentsTokenAndPinnedCommitActor(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "app.pem")
	data := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(keyPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	sessionID := "sgr_abcdefghijklmnop"
	requestPath, err := FileRequestPath(sessionID, 1)
	if err != nil {
		t.Fatal(err)
	}
	req := RequestEnvelope{SessionID: sessionID, Sequence: 1, RequestID: "request-file-0001", Target: "target-test", Argv: []string{"id"}}
	body, err := BuildRequestComment(testSecret(), req)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(body))

	var tokenRequests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/app/installations/7/access_tokens":
			tokenRequests.Add(1)
			var request struct {
				Permissions map[string]string `json:"permissions"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatalf("decode installation token request: %v", err)
			}
			if request.Permissions["contents"] != "read" || request.Permissions["issues"] != "write" || request.Permissions["metadata"] != "read" {
				t.Fatalf("unexpected contents token permissions: %#v", request.Permissions)
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"token":"ghs_contents","expires_at":%q}`, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/contents/"+FileRequestRoot+"/"+sessionID) && strings.HasSuffix(r.URL.Path, sessionID):
			if r.Header.Get("Authorization") != "Bearer ghs_contents" {
				t.Fatalf("directory authorization = %q", r.Header.Get("Authorization"))
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `[{"type":"file","name":"00000000000000000001.req","path":%q,"sha":"blob-1","size":%d}]`, requestPath, len(body))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/contents/"+requestPath):
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"type":"file","name":"00000000000000000001.req","path":%q,"sha":"blob-1","size":%d,"encoding":"base64","content":%q}`, requestPath, len(body), encoded)

		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/commits"):
			if r.URL.Query().Get("path") != requestPath {
				t.Fatalf("commit path query = %q", r.URL.Query().Get("path"))
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `[{"sha":"commit-1","author":{"id":42,"login":"operator","type":"User"}}]`)

		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewGitHubClient(GitHubAppConfig{
		AppID: 5, InstallationID: 7, PrivateKeyFile: keyPath, APIBase: server.URL, HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	files, err := client.RequestFiles(context.Background(), "example/relay", sessionID)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].Path != requestPath || files[0].SHA != "blob-1" {
		t.Fatalf("unexpected request files: %+v", files)
	}
	file, err := client.RequestFile(context.Background(), "example/relay", requestPath)
	if err != nil {
		t.Fatal(err)
	}
	if file.Body != body || file.CommitSHA != "commit-1" || file.Actor.ID != 42 {
		t.Fatalf("unexpected request file: %+v", file)
	}
	if got := tokenRequests.Load(); got != 1 {
		t.Fatalf("contents token requests = %d, want 1", got)
	}
}

func TestFileRequestPathIsCanonical(t *testing.T) {
	got, err := FileRequestPath("sgr_abcdefghijklmnop", 17)
	if err != nil {
		t.Fatal(err)
	}
	want := FileRequestRoot + "/sgr_abcdefghijklmnop/00000000000000000017.req"
	if got != want {
		t.Fatalf("path = %q, want %q", got, want)
	}
	if err := validateFileRequestPath(got); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{
		FileRequestRoot + "/sgr_abcdefghijklmnop/17.req",
		FileRequestRoot + "/other/00000000000000000017.req",
		FileRequestRoot + "/sgr_abcdefghijklmnop/00000000000000000000.req",
	} {
		if err := validateFileRequestPath(value); err == nil {
			t.Fatalf("invalid fallback path accepted: %q", value)
		}
	}
}

func TestRequestFilesTreatsMissingSessionDirectoryAsEmpty(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "app.pem")
	data := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(keyPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/app/installations/7/access_tokens":
			fmt.Fprintf(w, `{"token":"ghs_contents","expires_at":%q}`, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client, err := NewGitHubClient(GitHubAppConfig{AppID: 5, InstallationID: 7, PrivateKeyFile: keyPath, APIBase: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	files, err := client.RequestFiles(context.Background(), "example/relay", "sgr_abcdefghijklmnop")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 0 {
		t.Fatalf("missing session directory returned files: %+v", files)
	}
}
