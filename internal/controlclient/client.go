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
	body, err := json.Marshal(internalapi.IntrospectRequest{TokenHash: hex.EncodeToString(hash[:])})
	if err != nil {
		return domain.Grant{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/internal/v1/introspect", bytes.NewReader(body))
	if err != nil {
		return domain.Grant{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return domain.Grant{}, fmt.Errorf("control-plane introspection: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return domain.Grant{}, errors.New("capability rejected by control plane")
	}
	var decoded internalapi.IntrospectResponse
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return domain.Grant{}, err
	}
	return decoded.Grant, nil
}
