package controlclient

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/kotaru34/tethys-sentinel/internal/domain"
	"github.com/kotaru34/tethys-sentinel/internal/internalapi"
)

type Client struct {
	baseURL string
	http    *http.Client
}

func New(baseURL string, httpClient *http.Client) *Client {
	return &Client{baseURL: strings.TrimRight(baseURL, "/"), http: httpClient}
}

func (c *Client) Introspect(ctx context.Context, hash [32]byte) (domain.Grant, error) {
	var response internalapi.IntrospectResponse
	if err := c.post(ctx, "/internal/v1/introspect", internalapi.IntrospectRequest{TokenHash: hex.EncodeToString(hash[:])}, &response); err != nil {
		return domain.Grant{}, err
	}
	return response.Grant, nil
}

func (c *Client) AuthorizeCommand(ctx context.Context, hash [32]byte, target string, argv []string, agentReason string) (internalapi.AuthorizeCommandResponse, error) {
	var response internalapi.AuthorizeCommandResponse
	err := c.post(ctx, "/internal/v1/commands/authorize", internalapi.AuthorizeCommandRequest{
		TokenHash: hex.EncodeToString(hash[:]), Target: target, Argv: argv, AgentReason: agentReason,
	}, &response)
	return response, err
}

func (c *Client) post(ctx context.Context, path string, bodyValue, responseValue any) error {
	body, err := json.Marshal(bodyValue)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("control-plane request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New("request rejected by control plane")
	}
	return json.NewDecoder(resp.Body).Decode(responseValue)
}
