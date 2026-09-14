package main

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
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
	"github.com/kotaru34/tethys-sentinel/internal/credentialapi"
	"github.com/kotaru34/tethys-sentinel/internal/emergencyapi"
	"github.com/kotaru34/tethys-sentinel/internal/resourceapi"
	"github.com/kotaru34/tethys-sentinel/internal/risk"
	"github.com/kotaru34/tethys-sentinel/internal/tlsutil"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	persistence, err := openPersistence(ctx)
	cancel()
	if err != nil {
		log.Fatal("open persistence backend: ", err)
	}
	defer persistence.close()

	contextStore := contextstore.New(env("SENTINEL_CONTEXT_FILE", "/etc/tethys-sentinel/context.json"))
	adminToken := os.Getenv("SENTINEL_ADMIN_TOKEN")
	if len(adminToken) < 32 {
		log.Fatal("SENTINEL_ADMIN_TOKEN must be at least 32 characters")
	}
	workerToken := os.Getenv("SENTINEL_WORKER_TOKEN")
	if len(workerToken) < 32 {
		log.Fatal("SENTINEL_WORKER_TOKEN must be at least 32 characters")
	}

	api := controlapi.New(persistence.caps, persistence.approvals, persistence.audit, persistence.jobs, adminToken, workerToken)
	resourceAPI := resourceapi.New(persistence.caps, persistence.audit, persistence.notes)
	emergencyAPI := emergencyapi.New(persistence.emergency, adminToken, workerToken)
	credentialHandler, err := credentialHandlerFromEnv(persistence.caps, persistence.jobs, workerToken)
	if err != nil {
		log.Fatal("configure credential handler: ", err)
	}

	internalMux := http.NewServeMux()
	internalMux.Handle("/internal/v1/", api.InternalHandler())
	internalMux.Handle("/internal/v1/resources/", resourceAPI.Handler())
	internalMux.Handle("/internal/v1/execution/", emergencyAPI.InternalHandler())
	internalMux.Handle("/internal/v1/execution/jobs/", credentialHandler)
	internalMux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": buildinfo.Version})
	})

	adminAddr := env("SENTINEL_ADMIN_LISTEN", "127.0.0.1:8081")
	if !loopbackAddr(adminAddr) {
		log.Fatal("admin API must bind a loopback address in this development milestone")
	}
	grantAdmin := api.GrantHandler(persistence.grants)
	approvalAdmin := api.ApprovalHandler(persistence.approvalOps)
	operatorRead := api.OperatorReadHandler(persistence.operator)
	adminMux := http.NewServeMux()
	adminMux.Handle("GET /admin/v1/overview", operatorRead)
	adminMux.Handle("GET /admin/v1/grants", operatorRead)
	adminMux.Handle("GET /admin/v1/grants/{id}", operatorRead)
	adminMux.Handle("GET /admin/v1/approvals", operatorRead)
	adminMux.Handle("GET /admin/v1/jobs", operatorRead)
	adminMux.Handle("GET /admin/v1/jobs/{id}", operatorRead)
	adminMux.Handle("GET /admin/v1/audit", operatorRead)
	adminMux.Handle("/admin/v1/emergency/", emergencyAPI.AdminHandler())
	adminMux.Handle("/admin/v1/grants", grantAdmin)
	adminMux.Handle("/admin/v1/grants/", grantAdmin)
	adminMux.Handle("/admin/v1/approvals/", approvalAdmin)
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

func authenticateBearer(r *http.Request, expected string) bool {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		return false
	}
	got := strings.TrimSpace(strings.TrimPrefix(auth, prefix))
	if len(got) != len(expected) || subtle.ConstantTimeCompare([]byte(got), []byte(expected)) != 1 {
		return false
	}
	return true
}

func formatServerName(url string) string {
	host := strings.TrimSpace(url)
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")
	if i := strings.IndexByte(host, '/'); i >= 0 {
		host = host[:i]
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

func validateRiskPolicy() error {
	for _, item := range risk.KnownCategories() {
		if item == "" {
			return fmt.Errorf("risk policy contains empty category")
		}
	}
	return nil
}
