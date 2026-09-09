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
	if err := c.post(ctx, "/internal/v1/introspect", internalapi.IntrospectRequest{TokenHash: encodeHash(hash)}, &response); err != nil {
		return domain.Grant{}, err
	}
	return response.Grant, nil
}

func (c *Client) AuthorizeCommand(ctx context.Context, hash [32]byte, target string, argv []string, agentReason string) (internalapi.AuthorizeCommandResponse, error) {
	var response internalapi.AuthorizeCommandResponse
	err := c.post(ctx, "/internal/v1/commands/authorize", internalapi.AuthorizeCommandRequest{
		TokenHash: encodeHash(hash), Target: target, Argv: argv, AgentReason: agentReason,
	}, &response)
	return response, err
}

func (c *Client) Context(ctx context.Context, hash [32]byte) (domain.ContextBundle, error) {
	var response internalapi.ContextResponse
	err := c.post(ctx, "/internal/v1/context", internalapi.ContextRequest{TokenHash: encodeHash(hash)}, &response)
	return response.Bundle, err
}

func (c *Client) History(ctx context.Context, hash [32]byte, limit int) (internalapi.HistoryResponse, error) {
	var response internalapi.HistoryResponse
	err := c.post(ctx, "/internal/v1/history", internalapi.HistoryRequest{TokenHash: encodeHash(hash), Limit: limit}, &response)
	return response, err
}

func (c *Client) ListNotes(ctx context.Context, hash [32]byte, limit int) (internalapi.NotesListResponse, error) {
	var response internalapi.NotesListResponse
	err := c.post(ctx, "/internal/v1/notes/list", internalapi.NotesListRequest{TokenHash: encodeHash(hash), Limit: limit}, &response)
	return response, err
}

func (c *Client) WriteNote(ctx context.Context, hash [32]byte, target, content string) (internalapi.NoteWriteResponse, error) {
	var response internalapi.NoteWriteResponse
	err := c.post(ctx, "/internal/v1/notes/write", internalapi.NoteWriteRequest{
		TokenHash: encodeHash(hash), Target: target, Content: content,
	}, &response)
	return response, err
}

func encodeHash(hash [32]byte) string { return hex.EncodeToString(hash[:]) }

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
