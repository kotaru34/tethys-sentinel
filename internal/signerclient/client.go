package signerclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/kotaru34/tethys-sentinel/internal/sshsigner"
)

type Client struct {
	baseURL string
	http    *http.Client
	token   string
}

func New(baseURL string, httpClient *http.Client, token string) (*Client, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		return nil, errors.New("signer base URL is required")
	}
	if httpClient == nil {
		return nil, errors.New("signer HTTP client is required")
	}
	if len(token) < 32 {
		return nil, errors.New("signer API token must be at least 32 characters")
	}
	return &Client{baseURL: baseURL, http: httpClient, token: token}, nil
}

func (c *Client) Sign(ctx context.Context, reqValue sshsigner.Request) (sshsigner.Response, error) {
	body, err := json.Marshal(reqValue)
	if err != nil {
		return sshsigner.Response{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/internal/v1/sign", bytes.NewReader(body))
	if err != nil {
		return sshsigner.Response{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return sshsigner.Response{}, fmt.Errorf("SSH signer request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return sshsigner.Response{}, fmt.Errorf("SSH signer rejected request with status %d", resp.StatusCode)
	}
	var out sshsigner.Response
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&out); err != nil {
		return sshsigner.Response{}, fmt.Errorf("decode SSH signer response: %w", err)
	}
	return out, nil
}
