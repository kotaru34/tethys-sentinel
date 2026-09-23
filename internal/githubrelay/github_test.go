package githubrelay

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
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

func TestGitHubAppMintsAndCachesInstallationToken(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "app.pem")
	data := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(keyPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	var tokenRequests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app/installations/7/access_tokens":
			tokenRequests.Add(1)
			bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if len(strings.Split(bearer, ".")) != 3 {
				t.Fatalf("installation token request did not use an App JWT")
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"token":"ghs_test","expires_at":%q}`, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
		case "/repos/example/relay":
			if r.Header.Get("Authorization") != "Bearer ghs_test" {
				t.Fatalf("repository request authorization = %q", r.Header.Get("Authorization"))
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"id":123,"full_name":"example/relay","private":true,"archived":false}`)
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
	for range 2 {
		repo, err := client.Repository(context.Background(), "example/relay")
		if err != nil {
			t.Fatal(err)
		}
		if repo.ID != 123 || !repo.Private {
			t.Fatalf("unexpected repository: %+v", repo)
		}
	}
	if got := tokenRequests.Load(); got != 1 {
		t.Fatalf("installation token requests = %d, want 1", got)
	}
}

func TestCommentsConditionalRequest(t *testing.T) {
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
			fmt.Fprintf(w, `{"token":"ghs_test","expires_at":%q}`, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
		case strings.HasSuffix(r.URL.Path, "/comments"):
			if r.Header.Get("If-None-Match") == `"abc"` {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", `"abc"`)
			fmt.Fprint(w, `[]`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client, err := NewGitHubClient(GitHubAppConfig{AppID: 5, InstallationID: 7, PrivateKeyFile: keyPath, APIBase: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	_, etag, notModified, err := client.Comments(context.Background(), "example/relay", 17, "")
	if err != nil || notModified || etag != `"abc"` {
		t.Fatalf("first comments request: etag=%q notModified=%t err=%v", etag, notModified, err)
	}
	_, _, notModified, err = client.Comments(context.Background(), "example/relay", 17, etag)
	if err != nil || !notModified {
		t.Fatalf("conditional comments request: notModified=%t err=%v", notModified, err)
	}
}
