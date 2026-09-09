package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/approval"
	"github.com/kotaru34/tethys-sentinel/internal/audit"
	"github.com/kotaru34/tethys-sentinel/internal/buildinfo"
	"github.com/kotaru34/tethys-sentinel/internal/capability"
	"github.com/kotaru34/tethys-sentinel/internal/contextstore"
	"github.com/kotaru34/tethys-sentinel/internal/controlapi"
	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
	"github.com/kotaru34/tethys-sentinel/internal/notes"
	"github.com/kotaru34/tethys-sentinel/internal/resourceapi"
	"github.com/kotaru34/tethys-sentinel/internal/store"
	"github.com/kotaru34/tethys-sentinel/internal/tlsutil"
)

func main() {
	adminToken := os.Getenv("SENTINEL_ADMIN_TOKEN")
	if len(adminToken) < 32 {
		log.Fatal("SENTINEL_ADMIN_TOKEN must be at least 32 characters")
	}
	workerToken := os.Getenv("SENTINEL_WORKER_TOKEN")
	if len(workerToken) < 32 {
		log.Fatal("SENTINEL_WORKER_TOKEN must be at least 32 characters")
	}
	jobAuthKey, err := readSecretFile(env("SENTINEL_JOB_AUTH_KEY_FILE", "/etc/tethys-sentinel/job-auth.key"))
	if err != nil {
		log.Fatalf("read execution job auth key: %v", err)
	}
	if len(jobAuthKey) < 32 {
		log.Fatal("execution job auth key must be at least 32 bytes")
	}

	statePath := env("SENTINEL_GRANT_STORE", "/var/lib/tethys-sentinel/grants.json")
	grantStore, err := store.NewFileGrantStore(statePath)
	if err != nil {
		log.Fatalf("open grant store: %v", err)
	}
	approvalStore, err := approval.Open(env("SENTINEL_APPROVAL_STORE", "/var/lib/tethys-sentinel/approvals.json"))
	if err != nil {
		log.Fatalf("open approval store: %v", err)
	}
	auditLog, err := audit.Open(env("SENTINEL_AUDIT_LOG", "/var/lib/tethys-sentinel/audit.jsonl"))
	if err != nil {
		log.Fatalf("open/verify audit log: %v", err)
	}
	jobStore, err := executionjob.Open(env("SENTINEL_JOB_STORE", "/var/lib/tethys-sentinel/execution-jobs.json"), jobAuthKey)
	if err != nil {
		log.Fatalf("open/verify execution job store: %v", err)
	}
	contextStore, err := contextstore.New(env("SENTINEL_CONTEXT_FILE", "/etc/tethys-sentinel/context.json"))
	if err != nil {
		log.Fatalf("open authoritative context: %v", err)
	}
	noteStore, err := notes.Open(env("SENTINEL_NOTES_STORE", "/var/lib/tethys-sentinel/notes.jsonl"))
	if err != nil {
		log.Fatalf("open notes store: %v", err)
	}

	caps := capability.NewService(grantStore)
	api := controlapi.New(caps, approvalStore, auditLog, jobStore, adminToken, workerToken)
	resources := resourceapi.New(caps, contextStore, auditLog, noteStore).Handler()
	credentials, err := credentialHandlerFromEnv(caps, jobStore, auditLog, workerToken)
	if err != nil {
		log.Fatalf("configure SSH signer client: %v", err)
	}

	internalMux := http.NewServeMux()
	internalMux.Handle("/internal/v1/context", resources)
	internalMux.Handle("/internal/v1/history", resources)
	internalMux.Handle("/internal/v1/notes/", resources)
	internalMux.Handle("POST /internal/v1/execution/jobs/{id}/ssh-certificate", credentials)
	internalMux.Handle("/", api.InternalHandler())

	adminAddr := env("SENTINEL_ADMIN_LISTEN", "127.0.0.1:8081")
	if !loopbackAddr(adminAddr) {
		log.Fatal("admin API must bind a loopback address in this development milestone")
	}
	adminServer := hardenedServer(adminAddr, api.AdminHandler())

	internalAddr := env("SENTINEL_INTERNAL_LISTEN", "127.0.0.1:9091")
	internalServer := hardenedServer(internalAddr, internalMux)
	devInsecure := os.Getenv("SENTINEL_DEV_INSECURE_INTERNAL") == "1"

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	errCh := make(chan error, 2)

	go func() {
		log.Printf("tethys-sentinel control %s admin=%s", buildinfo.Version, adminAddr)
		errCh <- adminServer.ListenAndServe()
	}()

	go func() {
		if devInsecure {
			if !loopbackAddr(internalAddr) {
				errCh <- errors.New("insecure internal API may only bind loopback")
				return
			}
			log.Printf("WARNING: development-only plaintext internal API on %s", internalAddr)
			errCh <- internalServer.ListenAndServe()
			return
		}
		tlsCfg, err := tlsutil.ServerMTLS(
			os.Getenv("SENTINEL_INTERNAL_TLS_CERT"),
			os.Getenv("SENTINEL_INTERNAL_TLS_KEY"),
			os.Getenv("SENTINEL_INTERNAL_CLIENT_CA"),
		)
		if err != nil {
			errCh <- err
			return
		}
		ln, err := net.Listen("tcp", internalAddr)
		if err != nil {
			errCh <- err
			return
		}
		log.Printf("mTLS internal API on %s", internalAddr)
		errCh <- internalServer.Serve(tls.NewListener(ln, tlsCfg))
	}()

	select {
	case <-ctx.Done():
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Printf("server stopped: %v", err)
		}
		stop()
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = adminServer.Shutdown(shutdownCtx)
	_ = internalServer.Shutdown(shutdownCtx)
}

func hardenedServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
}

func loopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

func readSecretFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return []byte(strings.TrimSpace(string(data))), nil
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
