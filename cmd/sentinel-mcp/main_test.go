package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/agentclient"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestStableToolSurfaceDoesNotDependOnCapability(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	server := mcp.NewServer(&mcp.Implementation{Name: "tethys-sentinel-test", Version: "test"}, nil)
	registerTools(server, &serviceProvider{})
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "test"}, nil)
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}

	result, err := clientSession.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(result.Tools))
	for _, tool := range result.Tools {
		got = append(got, tool.Name)
	}
	sort.Strings(got)
	want := []string{
		"sentinel_check",
		"sentinel_code",
		"sentinel_exec",
		"sentinel_exec_batch",
		"sentinel_output",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("tool surface=%v, want %v", got, want)
	}

	if err := clientSession.Close(); err != nil {
		t.Fatal(err)
	}
	if err := serverSession.Wait(); err != nil && ctx.Err() == nil {
		t.Fatal(err)
	}
}

func TestCapabilityErrorsAreActionableForModels(t *testing.T) {
	missing := capabilityLoadError(fmt.Errorf("inspect capability file: %w", os.ErrNotExist))
	if !strings.HasPrefix(missing.Error(), "CAPABILITY_MISSING:") || !strings.Contains(missing.Error(), "instead of retrying") {
		t.Fatalf("missing capability error is not actionable: %q", missing)
	}

	invalid := capabilityBootstrapError(&agentclient.HTTPError{
		StatusCode: http.StatusUnauthorized,
		Message:    "valid capability required",
	})
	if !strings.HasPrefix(invalid.Error(), "CAPABILITY_INVALID:") || !strings.Contains(invalid.Error(), "instead of retrying") {
		t.Fatalf("invalid capability error is not actionable: %q", invalid)
	}

	unavailable := capabilityBootstrapError(errors.New("dial failed"))
	if !strings.HasPrefix(unavailable.Error(), "SENTINEL_UNAVAILABLE:") {
		t.Fatalf("transport error misclassified: %q", unavailable)
	}
}

func TestHTTPTransportStartsWithoutCapability(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stderr bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, []string{
			"--transport", "http",
			"--listen", addr,
			"--url", "https://127.0.0.1:1",
			"--journal", filepath.Join(t.TempDir(), "journal.json"),
		}, &stderr, func(string) (string, bool) { return "", false })
	}()

	client := &http.Client{Timeout: 250 * time.Millisecond}
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, requestErr := client.Get(fmt.Sprintf("http://%s/healthz", addr))
		if requestErr == nil {
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("health status=%d", resp.StatusCode)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("native HTTP MCP did not start without a capability: %v; stderr=%s", requestErr, stderr.String())
		}
		time.Sleep(25 * time.Millisecond)
	}

	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("HTTP MCP exit=%d stderr=%s", code, stderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("HTTP MCP did not shut down after context cancellation")
	}
}

func TestValidateHTTPListenRequiresLoopback(t *testing.T) {
	for _, good := range []string{"127.0.0.1:8002", "[::1]:8002", "localhost:8002"} {
		if err := validateHTTPListen(good); err != nil {
			t.Fatalf("validateHTTPListen(%q): %v", good, err)
		}
	}
	for _, bad := range []string{"0.0.0.0:8002", "192.0.2.5:8002", ":8002", "localhost"} {
		if err := validateHTTPListen(bad); err == nil {
			t.Fatalf("validateHTTPListen(%q) unexpectedly succeeded", bad)
		}
	}
}
