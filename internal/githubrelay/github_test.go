package githubrelay

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
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
			var request struct {
				Permissions map[string]string `json:"permissions"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatalf("decode installation token request: %v", err)
			}
			if len(request.Permissions) != 2 || request.Permissions["metadata"] != "read" || request.Permissions["issues"] != "write" {
				t.Fatalf("installation token permissions = %#v", request.Permissions)
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

func TestInstallationTokenRetriesTransientEOF(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "app.pem")
	data := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(keyPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	var attempts atomic.Int32
	client, err := NewGitHubClient(GitHubAppConfig{
		AppID: 5, InstallationID: 7, PrivateKeyFile: keyPath,
		HTTPClient: &http.Client{
			Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path != "/app/installations/7/access_tokens" {
					t.Fatalf("unexpected path %q", r.URL.Path)
				}
				if attempts.Add(1) < 3 {
					return nil, io.EOF
				}
				body := fmt.Sprintf(`{"token":"ghs_retry","expires_at":%q}`, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
				return &http.Response{
					StatusCode: http.StatusCreated,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(body)),
					Request:    r,
				}, nil
			}),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	token, err := client.installationToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if token != "ghs_retry" {
		t.Fatalf("token = %q, want ghs_retry", token)
	}
	if got := attempts.Load(); got != 3 {
		t.Fatalf("attempts = %d, want 3", got)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestDefaultGitHubTransportUsesHTTP1Only(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "app.pem")
	data := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(keyPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	client, err := NewGitHubClient(GitHubAppConfig{
		AppID: 5, InstallationID: 7, PrivateKeyFile: keyPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := client.http.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("default transport type = %T, want *http.Transport", client.http.Transport)
	}
	if transport.Proxy != nil {
		t.Fatal("default GitHub transport unexpectedly honors proxy environment")
	}
	if transport.ForceAttemptHTTP2 {
		t.Fatal("default GitHub transport unexpectedly forces HTTP/2")
	}
	if transport.Protocols != nil {
		t.Fatal("default GitHub transport unexpectedly uses Protocols plumbing")
	}
	if transport.TLSNextProto == nil {
		t.Fatal("default GitHub transport does not explicitly disable alternate TLS protocols")
	}
	if _, ok := transport.TLSNextProto["h2"]; ok {
		t.Fatal("default GitHub transport unexpectedly enables h2")
	}
	if transport.TLSClientConfig == nil || len(transport.TLSClientConfig.NextProtos) != 1 || transport.TLSClientConfig.NextProtos[0] != "http/1.1" {
		t.Fatalf("default GitHub ALPN = %#v, want only http/1.1", transport.TLSClientConfig)
	}
	if !transport.DisableKeepAlives {
		t.Fatal("default GitHub transport unexpectedly reuses connections")
	}
	if transport.TLSHandshakeTimeout <= 0 || transport.ResponseHeaderTimeout <= 0 {
		t.Fatal("default GitHub transport lost transport timeouts")
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
