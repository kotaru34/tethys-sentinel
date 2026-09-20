package agentclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/domain"
	"github.com/kotaru34/tethys-sentinel/internal/gatewayapi"
	"github.com/kotaru34/tethys-sentinel/internal/internalapi"
)

const maxResponseBytes = 8 << 20

type Client struct {
	baseURL    string
	capability string
	http       *http.Client
}

type HTTPError struct {
	StatusCode int
	Message    string
}

func (e *HTTPError) Error() string {
	if strings.TrimSpace(e.Message) != "" {
		return fmt.Sprintf("sentinel HTTP %d: %s", e.StatusCode, e.Message)
	}
	return fmt.Sprintf("sentinel HTTP %d", e.StatusCode)
}

type Config struct {
	BaseURL    string
	Capability string
	CAFile     string
	Timeout    time.Duration
}

func New(cfg Config) (*Client, error) {
	baseURL, err := validateBaseURL(cfg.BaseURL)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.Capability) == "" {
		return nil, errors.New("capability is required")
	}
	tlsConfig, err := clientTLSConfig(strings.TrimSpace(cfg.CAFile))
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		Proxy:             nil,
		ForceAttemptHTTP2: true,
		TLSClientConfig:   tlsConfig,
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &Client{
		baseURL: baseURL, capability: cfg.Capability,
		http: &http.Client{
			Transport: transport,
			Timeout:   timeout,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func (c *Client) Bootstrap(ctx context.Context) (domain.Bootstrap, error) {
	var response domain.Bootstrap
	err := c.doJSON(ctx, http.MethodGet, "/v1/bootstrap", nil, &response)
	return response, err
}

func (c *Client) Submit(ctx context.Context, req gatewayapi.CommandRequest) (internalapi.SubmitCommandResponse, error) {
	var response internalapi.SubmitCommandResponse
	err := c.doJSON(ctx, http.MethodPost, "/v1/commands/submit", req, &response)
	return response, err
}

func (c *Client) Job(ctx context.Context, id string) (internalapi.AgentExecutionJob, error) {
	var response struct {
		Job internalapi.AgentExecutionJob `json:"job"`
	}
	err := c.doJSON(ctx, http.MethodGet, "/v1/jobs/"+url.PathEscape(id), nil, &response)
	return response.Job, err
}

func (c *Client) Request(ctx context.Context, requestID string) (internalapi.AgentExecutionJob, error) {
	var response struct {
		Job internalapi.AgentExecutionJob `json:"job"`
	}
	err := c.doJSON(ctx, http.MethodGet, "/v1/requests/"+url.PathEscape(requestID), nil, &response)
	return response.Job, err
}

func (c *Client) doJSON(ctx context.Context, method, path string, bodyValue, responseValue any) error {
	var body io.Reader
	if bodyValue != nil {
		encoded, err := json.Marshal(bodyValue)
		if err != nil {
			return err
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.capability)
	req.Header.Set("Accept", "application/json")
	if bodyValue != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("sentinel request: %w", err)
	}
	defer resp.Body.Close()
	limited := io.LimitReader(resp.Body, maxResponseBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("read sentinel response: %w", err)
	}
	if len(data) > maxResponseBytes {
		return errors.New("sentinel response exceeds client limit")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var apiErr struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(data, &apiErr) == nil && strings.TrimSpace(apiErr.Error) != "" {
			return &HTTPError{StatusCode: resp.StatusCode, Message: apiErr.Error}
		}
		return &HTTPError{StatusCode: resp.StatusCode}
	}
	if responseValue == nil || len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, responseValue); err != nil {
		return fmt.Errorf("decode sentinel response: %w", err)
	}
	return nil
}

func validateBaseURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("Sentinel URL is required")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", errors.New("Sentinel URL must be a valid HTTPS origin")
	}
	if u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", errors.New("Sentinel URL must be an HTTPS origin without credentials, path, query, or fragment")
	}
	return strings.TrimRight(u.String(), "/"), nil
}

func clientTLSConfig(caFile string) (*tls.Config, error) {
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file: %w", err)
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, errors.New("CA file contains no usable certificates")
		}
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, nil
}
