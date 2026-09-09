package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/buildinfo"
	"github.com/kotaru34/tethys-sentinel/internal/controlclient"
	"github.com/kotaru34/tethys-sentinel/internal/gatewayapi"
	"github.com/kotaru34/tethys-sentinel/internal/tlsutil"
)

func main() {
	controlURL := env("SENTINEL_CONTROL_URL", "https://127.0.0.1:9091")
	controlHTTP, err := controlHTTPClient(controlURL)
	if err != nil {
		log.Fatal(err)
	}
	api := gatewayapi.New(controlclient.New(controlURL, controlHTTP))

	addr := env("SENTINEL_GATEWAY_LISTEN", ":8443")
	server := &http.Server{
		Addr:              addr,
		Handler:           api.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}

	devInsecure := os.Getenv("SENTINEL_DEV_INSECURE_PUBLIC") == "1"
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	errCh := make(chan error, 1)

	go func() {
		if devInsecure {
			if !loopbackAddr(addr) {
				errCh <- errors.New("insecure public gateway may only bind loopback")
				return
			}
			log.Printf("WARNING: development-only plaintext gateway %s version=%s", addr, buildinfo.Version)
			errCh <- server.ListenAndServe()
			return
		}
		tlsCfg, err := tlsutil.ServerTLS(os.Getenv("SENTINEL_GATEWAY_TLS_CERT"), os.Getenv("SENTINEL_GATEWAY_TLS_KEY"))
		if err != nil {
			errCh <- err
			return
		}
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			errCh <- err
			return
		}
		log.Printf("TLS gateway %s version=%s", addr, buildinfo.Version)
		errCh <- server.Serve(tls.NewListener(ln, tlsCfg))
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
	_ = server.Shutdown(shutdownCtx)
}

func controlHTTPClient(rawURL string) (*http.Client, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{ForceAttemptHTTP2: true}
	if u.Scheme == "http" {
		if os.Getenv("SENTINEL_DEV_INSECURE_INTERNAL") != "1" || !loopbackHost(u.Hostname()) {
			return nil, errors.New("plaintext control-plane connection requires SENTINEL_DEV_INSECURE_INTERNAL=1 and a loopback host")
		}
	} else if u.Scheme == "https" {
		tlsCfg, err := tlsutil.ClientMTLS(
			os.Getenv("SENTINEL_INTERNAL_TLS_CERT"),
			os.Getenv("SENTINEL_INTERNAL_TLS_KEY"),
			os.Getenv("SENTINEL_INTERNAL_SERVER_CA"),
			env("SENTINEL_INTERNAL_SERVER_NAME", u.Hostname()),
		)
		if err != nil {
			return nil, err
		}
		transport.TLSClientConfig = tlsCfg
	} else {
		return nil, errors.New("control URL must use https, or http in explicit loopback dev mode")
	}
	return &http.Client{Transport: transport, Timeout: 10 * time.Second}, nil
}

func loopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	return loopbackHost(strings.Trim(host, "[]"))
}

func loopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
