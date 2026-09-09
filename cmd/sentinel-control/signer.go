package main

import (
	"errors"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/audit"
	"github.com/kotaru34/tethys-sentinel/internal/capability"
	"github.com/kotaru34/tethys-sentinel/internal/credentialapi"
	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
	"github.com/kotaru34/tethys-sentinel/internal/signerclient"
	"github.com/kotaru34/tethys-sentinel/internal/tlsutil"
)

func credentialHandlerFromEnv(caps *capability.Service, jobs *executionjob.Store, auditLog *audit.Log, workerToken string) (http.Handler, error) {
	rawURL := env("SENTINEL_SIGNER_URL", "https://127.0.0.1:9443")
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if u.Host == "" {
		return nil, errors.New("SENTINEL_SIGNER_URL must include a host")
	}

	transport := &http.Transport{ForceAttemptHTTP2: true}
	switch u.Scheme {
	case "http":
		if os.Getenv("SENTINEL_DEV_INSECURE_SIGNER") != "1" || !loopbackHost(u.Hostname()) {
			return nil, errors.New("plaintext signer connection requires SENTINEL_DEV_INSECURE_SIGNER=1 and a loopback host")
		}
	case "https":
		tlsCfg, err := tlsutil.ClientMTLS(
			os.Getenv("SENTINEL_SIGNER_CLIENT_TLS_CERT"),
			os.Getenv("SENTINEL_SIGNER_CLIENT_TLS_KEY"),
			os.Getenv("SENTINEL_SIGNER_SERVER_CA"),
			env("SENTINEL_SIGNER_SERVER_NAME", u.Hostname()),
		)
		if err != nil {
			return nil, err
		}
		transport.TLSClientConfig = tlsCfg
	default:
		return nil, errors.New("SENTINEL_SIGNER_URL must use https, or http in explicit loopback development mode")
	}

	httpClient := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	client, err := signerclient.New(rawURL, httpClient, os.Getenv("SENTINEL_SIGNER_API_TOKEN"))
	if err != nil {
		return nil, err
	}
	api, err := credentialapi.New(caps, jobs, auditLog, client, workerToken)
	if err != nil {
		return nil, err
	}
	return api.Handler(), nil
}

func loopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	return netParseIPLoopback(host)
}
