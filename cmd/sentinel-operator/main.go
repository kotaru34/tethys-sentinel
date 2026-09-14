package main

import (
	"context"
	"crypto/tls"
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
	"github.com/kotaru34/tethys-sentinel/internal/operatorproxy"
	"github.com/kotaru34/tethys-sentinel/internal/tlsutil"
)

const maxAdminTokenFileSize = 4096

func main() {
	publicOrigin := strings.TrimSpace(os.Getenv("SENTINEL_OPERATOR_PUBLIC_ORIGIN"))
	if publicOrigin == "" {
		log.Fatal("SENTINEL_OPERATOR_PUBLIC_ORIGIN is required")
	}

	adminTokenPath := env("SENTINEL_OPERATOR_ADMIN_TOKEN_FILE", "/etc/tethys-sentinel/operator-admin.token")
	adminToken, err := readAdminToken(adminTokenPath)
	if err != nil {
		log.Fatalf("read operator admin token: %v", err)
	}

	proxy, err := operatorproxy.New(operatorproxy.Config{
		ControlBaseURL: env("SENTINEL_OPERATOR_CONTROL_URL", "http://127.0.0.1:8081"),
		AdminToken:     adminToken,
		PublicOrigin:   publicOrigin,
	})
	if err != nil {
		log.Fatalf("configure operator proxy: %v", err)
	}

	addr := env("SENTINEL_OPERATOR_LISTEN", ":8444")
	server := &http.Server{
		Addr:              addr,
		Handler:           proxy.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}

	tlsCfg, err := tlsutil.ServerMTLS(
		env("SENTINEL_OPERATOR_TLS_CERT", "/etc/tethys-sentinel/operator-server.crt"),
		env("SENTINEL_OPERATOR_TLS_KEY", "/etc/tethys-sentinel/operator-server.key"),
		env("SENTINEL_OPERATOR_CLIENT_CA", "/etc/tethys-sentinel/operator-client-ca.crt"),
	)
	if err != nil {
		log.Fatalf("configure operator mTLS: %v", err)
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("listen operator interface: %v", err)
	}
	defer ln.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	errCh := make(chan error, 1)

	go func() {
		log.Printf("mTLS operator interface %s version=%s", addr, buildinfo.Version)
		errCh <- server.Serve(tls.NewListener(ln, tlsCfg))
	}()

	select {
	case <-ctx.Done():
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Printf("operator server stopped: %v", err)
		}
		stop()
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdownCtx)
}

func readAdminToken(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", errors.New("operator admin token path is empty")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("operator admin token must be a regular file, not a symlink or device")
	}
	perm := info.Mode().Perm()
	if perm&0o077 != 0 {
		return "", fmt.Errorf("operator admin token file permissions %04o expose it to group/other", perm)
	}
	if perm&0o400 == 0 {
		return "", errors.New("operator admin token file must be owner-readable")
	}
	if info.Size() < 1 || info.Size() > maxAdminTokenFileSize {
		return "", errors.New("operator admin token file has invalid size")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(data))
	if len(token) < 32 {
		return "", errors.New("operator admin token must be at least 32 characters")
	}
	if strings.IndexAny(token, " \t\r\n") >= 0 {
		return "", errors.New("operator admin token must be one whitespace-free value")
	}
	return token, nil
}

func env(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}
