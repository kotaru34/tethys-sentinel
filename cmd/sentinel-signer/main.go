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
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/kotaru34/tethys-sentinel/internal/buildinfo"
	"github.com/kotaru34/tethys-sentinel/internal/signerapi"
	"github.com/kotaru34/tethys-sentinel/internal/sshsigner"
	"github.com/kotaru34/tethys-sentinel/internal/tlsutil"
)

func main() {
	apiToken := os.Getenv("SENTINEL_SIGNER_API_TOKEN")
	if len(apiToken) < 32 {
		log.Fatal("SENTINEL_SIGNER_API_TOKEN must be at least 32 characters")
	}
	ca, err := sshsigner.LoadCA(os.Getenv("SENTINEL_SIGNER_CA_KEY"))
	if err != nil {
		log.Fatalf("load SSH CA: %v", err)
	}
	certTTL, err := secondsEnv("SENTINEL_SIGNER_CERT_TTL_SECONDS", 45)
	if err != nil {
		log.Fatal(err)
	}
	backdate, err := secondsEnv("SENTINEL_SIGNER_BACKDATE_SECONDS", 5)
	if err != nil {
		log.Fatal(err)
	}
	service, err := sshsigner.New(ca, sshsigner.Policy{
		Principal:       env("SENTINEL_SIGNER_PRINCIPAL", "sentinel-ai"),
		WrapperPath:     env("SENTINEL_SIGNER_WRAPPER", "/usr/local/libexec/tethys-sentinel-exec"),
		SourceAddresses: splitList(os.Getenv("SENTINEL_SIGNER_SOURCE_ADDRESSES")),
		CertificateTTL:  certTTL,
		Backdate:        backdate,
	})
	if err != nil {
		log.Fatalf("configure SSH signer: %v", err)
	}
	api, err := signerapi.New(service, apiToken)
	if err != nil {
		log.Fatal(err)
	}

	addr := env("SENTINEL_SIGNER_LISTEN", "127.0.0.1:9443")
	server := &http.Server{
		Addr:              addr,
		Handler:           api.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	devInsecure := os.Getenv("SENTINEL_DEV_INSECURE_SIGNER") == "1"
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	errCh := make(chan error, 1)

	go func() {
		if devInsecure {
			if !loopbackAddr(addr) {
				errCh <- errors.New("insecure signer may only bind loopback")
				return
			}
			log.Printf("WARNING: development-only plaintext signer %s version=%s ca=%s", addr, buildinfo.Version, ssh.FingerprintSHA256(ca.PublicKey()))
			errCh <- server.ListenAndServe()
			return
		}
		tlsCfg, err := tlsutil.ServerMTLS(
			os.Getenv("SENTINEL_SIGNER_TLS_CERT"),
			os.Getenv("SENTINEL_SIGNER_TLS_KEY"),
			os.Getenv("SENTINEL_SIGNER_CLIENT_CA"),
		)
		if err != nil {
			errCh <- err
			return
		}
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			errCh <- err
			return
		}
		log.Printf("mTLS signer %s version=%s ca=%s", addr, buildinfo.Version, ssh.FingerprintSHA256(ca.PublicKey()))
		errCh <- server.Serve(tls.NewListener(ln, tlsCfg))
	}()

	select {
	case <-ctx.Done():
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Printf("signer stopped: %v", err)
		}
		stop()
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdownCtx)
}

func secondsEnv(key string, fallback int64) (time.Duration, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return time.Duration(fallback) * time.Second, nil
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value < 0 {
		return 0, errors.New(key + " must be a non-negative integer number of seconds")
	}
	return time.Duration(value) * time.Second, nil
}

func splitList(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
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

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
