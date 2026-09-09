package main

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/buildinfo"
	"github.com/kotaru34/tethys-sentinel/internal/sshexec"
	"github.com/kotaru34/tethys-sentinel/internal/tlsutil"
	"github.com/kotaru34/tethys-sentinel/internal/worker"
	"github.com/kotaru34/tethys-sentinel/internal/workerclient"
)

func main() {
	workerID := strings.TrimSpace(os.Getenv("SENTINEL_WORKER_ID"))
	if workerID == "" || len(workerID) > 128 {
		log.Fatal("SENTINEL_WORKER_ID is required and must be at most 128 characters")
	}
	workerToken := os.Getenv("SENTINEL_WORKER_TOKEN")
	if len(workerToken) < 32 {
		log.Fatal("SENTINEL_WORKER_TOKEN must be at least 32 characters")
	}
	controlURL := env("SENTINEL_CONTROL_URL", "https://127.0.0.1:9091")
	httpClient, err := controlHTTPClient(controlURL)
	if err != nil {
		log.Fatal(err)
	}
	pollInterval, err := durationMillisEnv("SENTINEL_WORKER_POLL_MS", 1000)
	if err != nil {
		log.Fatal(err)
	}
	dialTimeout, err := durationSecondsEnv("SENTINEL_WORKER_SSH_DIAL_TIMEOUT_SECONDS", 5)
	if err != nil {
		log.Fatal(err)
	}
	outputLimit, err := int64Env("SENTINEL_WORKER_OUTPUT_LIMIT_BYTES", 4<<20)
	if err != nil {
		log.Fatal(err)
	}

	client := workerclient.New(controlURL, httpClient, workerToken)
	runner := worker.Runner{
		Control:  client,
		Executor: sshexec.Executor{DialTimeout: dialTimeout, OutputLimitBytes: outputLimit},
		WorkerID: workerID,
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log.Printf("tethys-sentinel worker %s id=%s control=%s", buildinfo.Version, workerID, controlURL)

	for ctx.Err() == nil {
		didWork, err := runner.RunOnce(ctx)
		if err != nil && !errors.Is(err, workerclient.ErrNoJob) && !errors.Is(err, context.Canceled) {
			log.Printf("worker iteration failed: %v", err)
		}
		if didWork {
			continue
		}
		timer := time.NewTimer(pollInterval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
		case <-timer.C:
		}
	}
}

func controlHTTPClient(rawURL string) (*http.Client, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return nil, errors.New("SENTINEL_CONTROL_URL must be a valid URL with a host")
	}
	transport := &http.Transport{ForceAttemptHTTP2: true}
	switch u.Scheme {
	case "http":
		if os.Getenv("SENTINEL_DEV_INSECURE_INTERNAL") != "1" || !loopbackHost(u.Hostname()) {
			return nil, errors.New("plaintext worker control connection requires SENTINEL_DEV_INSECURE_INTERNAL=1 and a loopback host")
		}
	case "https":
		tlsCfg, err := tlsutil.ClientMTLS(
			os.Getenv("SENTINEL_WORKER_TLS_CERT"),
			os.Getenv("SENTINEL_WORKER_TLS_KEY"),
			os.Getenv("SENTINEL_INTERNAL_SERVER_CA"),
			env("SENTINEL_INTERNAL_SERVER_NAME", u.Hostname()),
		)
		if err != nil {
			return nil, err
		}
		transport.TLSClientConfig = tlsCfg
	default:
		return nil, errors.New("SENTINEL_CONTROL_URL must use https, or http in explicit loopback development mode")
	}
	return &http.Client{Transport: transport, Timeout: 15 * time.Second}, nil
}

func loopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func durationMillisEnv(key string, fallback int64) (time.Duration, error) {
	value, err := int64Env(key, fallback)
	if err != nil {
		return 0, err
	}
	if value < 100 {
		return 0, errors.New(key + " must be at least 100 milliseconds")
	}
	return time.Duration(value) * time.Millisecond, nil
}

func durationSecondsEnv(key string, fallback int64) (time.Duration, error) {
	value, err := int64Env(key, fallback)
	if err != nil {
		return 0, err
	}
	if value < 1 || value > 60 {
		return 0, errors.New(key + " must be between 1 and 60 seconds")
	}
	return time.Duration(value) * time.Second, nil
}

func int64Env(key string, fallback int64) (int64, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value <= 0 {
		return 0, errors.New(key + " must be a positive integer")
	}
	return value, nil
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
