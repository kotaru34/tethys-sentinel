package agentclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/gatewayapi"
	"github.com/kotaru34/tethys-sentinel/internal/mcpclaim"
)

// RedeemMCPClaim exchanges a short-lived one-time MCP claim for a normal
// capability. The claim is the credential for this single endpoint; no existing
// Sentinel capability is sent or required.
func RedeemMCPClaim(ctx context.Context, cfg Config, claimCode string) (mcpclaim.RedeemResult, error) {
	baseURL, err := validateBaseURL(cfg.BaseURL)
	if err != nil {
		return mcpclaim.RedeemResult{}, err
	}
	claimCode, err = mcpclaim.NormalizeCode(claimCode)
	if err != nil {
		return mcpclaim.RedeemResult{}, err
	}
	tlsConfig, err := clientTLSConfig(strings.TrimSpace(cfg.CAFile))
	if err != nil {
		return mcpclaim.RedeemResult{}, err
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	client := &http.Client{
		Transport: &http.Transport{Proxy: nil, ForceAttemptHTTP2: true, TLSClientConfig: tlsConfig},
		Timeout:   timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	body, err := json.Marshal(gatewayapi.RedeemMCPClaimRequest{ClaimCode: claimCode})
	if err != nil {
		return mcpclaim.RedeemResult{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/v1/mcp/claims/redeem", bytes.NewReader(body))
	if err != nil {
		return mcpclaim.RedeemResult{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return mcpclaim.RedeemResult{}, fmt.Errorf("sentinel claim request: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return mcpclaim.RedeemResult{}, fmt.Errorf("read sentinel claim response: %w", err)
	}
	if len(data) > maxResponseBytes {
		return mcpclaim.RedeemResult{}, errors.New("sentinel claim response exceeds client limit")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return mcpclaim.RedeemResult{}, errors.New("MCP claim was rejected, expired, stale, or already used")
	}
	var result mcpclaim.RedeemResult
	if err := json.Unmarshal(data, &result); err != nil {
		return mcpclaim.RedeemResult{}, fmt.Errorf("decode sentinel claim response: %w", err)
	}
	if result.Capability == "" {
		return mcpclaim.RedeemResult{}, errors.New("sentinel claim response did not contain a capability")
	}
	return result, nil
}
