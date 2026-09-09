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

	"github.com/kotaru34/tethys-sentinel/internal/buildinfo"
	"github.com/kotaru34/tethys-sentinel/internal/contextstore"
	"github.com/kotaru34/tethys-sentinel/internal/controlapi"
	"github.com/kotaru34/tethys-sentinel/internal/emergencyapi"
	"github.com/kotaru34/tethys-sentinel/internal/resourceapi"
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

	startupCtx, startupCancel := context.WithTimeout(context.Background(), 10*time.Second)
	persistence, err := openPersistence(startupCtx)
	startupCancel()
	if err != nil {
		log.Fatalf("open persistence backend: %v", err)
	}
	defer persistence.close()

	contextStore, err := contextstore.New(env("SENTINEL_CONTEXT_FILE", "/etc/tethys-sentinel/context.json"))
	if err != nil {
		log.Fatalf("open authoritative context: %v", err)
	}

	caps := persistence.caps
	api := controlapi.New(caps, persistence.approvals, persistence.audit, persistence.jobs, adminToken, workerToken)
	emergencyAPI := emergencyapi.NewWithController(persistence.emergency, caps, adminToken, workerToken)
	resources := resourceapi.New(caps, contextStore, persistence.audit, persistence.notes).Handler()
	credentials, err := credentialHandlerFromEnv(caps, persistence.jobs, persistence.audit, workerToken)
	if err != nil {
		log.Fatalf("configure SSH signer client: %v", err)
	}
	controlInternal := api.InternalHandler()

	internalMux := http.NewServeMux()
	internalMux.Handle("/internal/v1/context", resources)
	internalMux.Handle("/internal/v1/history", resources)
	internalMux.Handle("/internal/v1/notes/", resources)
	internalMux.Handle("POST /internal/v1/execution/jobs/{id}/ssh-certificate", credentials)
	internalMux.Handle("POST /internal/v1/execution/jobs/{id}/authority", emergencyAPI.InternalHandler())
	internalMux.Handle("POST /internal/v1/execution/jobs/claim", emergencyAPI.GuardWorkerEnabled(controlInternal))
	internalMux.Handle("/", controlInternal)

	adminAddr := env("SENTINEL_ADMIN_LISTEN", "127.0.0.1:8081")
	if !loopbackAddr(adminAddr) {
		log.Fatal("admin API must bind a loopback address in this development milestone")
	}
	adminMux := http.NewServeMux()
	adminMux.Handle("/admin/v1/emergency/", emergencyAPI.AdminHandler())
	adminMux.Handle("/", api.AdminHandler())
	adminServer := hardenedServer(adminAddr, adminMux)

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
