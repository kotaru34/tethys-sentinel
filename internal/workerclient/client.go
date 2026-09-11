package workerclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
	"github.com/kotaru34/tethys-sentinel/internal/internalapi"
	"github.com/kotaru34/tethys-sentinel/internal/sshsigner"
	"github.com/kotaru34/tethys-sentinel/internal/sshtarget"
)

var (
	ErrNoJob           = errors.New("no execution job available")
	ErrAuthorityDenied = errors.New("execution authority denied")
)

type Client struct {
	baseURL string
	http    *http.Client
	token   string
}

func New(baseURL string, httpClient *http.Client, token string) *Client {
	return &Client{baseURL: strings.TrimRight(baseURL, "/"), http: httpClient, token: token}
}

func (c *Client) Claim(ctx context.Context, workerID string) (executionjob.Claim, error) {
	body, err := json.Marshal(internalapi.ClaimExecutionJobRequest{WorkerID: workerID})
	if err != nil {
		return executionjob.Claim{}, err
	}
	resp, err := c.post(ctx, "/internal/v1/execution/jobs/claim", body)
	if err != nil {
		return executionjob.Claim{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return executionjob.Claim{}, ErrNoJob
	}
	if resp.StatusCode != http.StatusOK {
		return executionjob.Claim{}, fmt.Errorf("execution job claim rejected with status %d", resp.StatusCode)
	}
	var out internalapi.ClaimExecutionJobResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return executionjob.Claim{}, err
	}
	return executionjob.Claim{Job: out.Job, ClaimToken: out.ClaimToken}, nil
}

func (c *Client) Start(ctx context.Context, workerID string, claim executionjob.Claim) (executionjob.Job, error) {
	body, err := json.Marshal(internalapi.StartExecutionJobRequest{WorkerID: workerID, ClaimToken: claim.ClaimToken})
	if err != nil {
		return executionjob.Job{}, err
	}
	resp, err := c.post(ctx, "/internal/v1/execution/jobs/"+claim.Job.ID+"/start", body)
	if err != nil {
		return executionjob.Job{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return executionjob.Job{}, fmt.Errorf("execution job start rejected with status %d", resp.StatusCode)
	}
	var out internalapi.StartExecutionJobResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return executionjob.Job{}, err
	}
	return out.Job, nil
}

func (c *Client) IssueSSHAccess(ctx context.Context, workerID string, claim executionjob.Claim, publicKey string) (sshsigner.Response, sshtarget.Spec, error) {
	body, err := json.Marshal(internalapi.IssueSSHCertificateRequest{
		WorkerID: workerID, ClaimToken: claim.ClaimToken, PublicKey: publicKey,
	})
	if err != nil {
		return sshsigner.Response{}, sshtarget.Spec{}, err
	}
	resp, err := c.post(ctx, "/internal/v1/execution/jobs/"+claim.Job.ID+"/ssh-certificate", body)
	if err != nil {
		return sshsigner.Response{}, sshtarget.Spec{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return sshsigner.Response{}, sshtarget.Spec{}, fmt.Errorf("SSH certificate request rejected with status %d", resp.StatusCode)
	}
	var out internalapi.IssueSSHCertificateResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return sshsigner.Response{}, sshtarget.Spec{}, err
	}
	if out.Job.ID != claim.Job.ID || out.Target.Name != claim.Job.Target {
		return sshsigner.Response{}, sshtarget.Spec{}, errors.New("control plane returned SSH access for a different job or target")
	}
	return out.Certificate, out.Target, nil
}

func (c *Client) IssueSSHCertificate(ctx context.Context, workerID string, claim executionjob.Claim, publicKey string) (sshsigner.Response, error) {
	certificate, _, err := c.IssueSSHAccess(ctx, workerID, claim, publicKey)
	return certificate, err
}

func (c *Client) CheckAuthority(ctx context.Context, workerID string, claim executionjob.Claim) error {
	body, err := json.Marshal(internalapi.CheckExecutionAuthorityRequest{WorkerID: workerID, ClaimToken: claim.ClaimToken})
	if err != nil {
		return err
	}
	resp, err := c.post(ctx, "/internal/v1/execution/jobs/"+claim.Job.ID+"/authority", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("execution authority check rejected with status %d", resp.StatusCode)
	}
	var out internalapi.CheckExecutionAuthorityResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return err
	}
	if !out.Allowed {
		reason := strings.TrimSpace(out.Reason)
		if reason == "" {
			reason = "unspecified"
		}
		return fmt.Errorf("%w: %s", ErrAuthorityDenied, reason)
	}
	return nil
}

func (c *Client) Complete(ctx context.Context, workerID string, claim executionjob.Claim, result executionjob.Result) (executionjob.Job, error) {
	body, err := json.Marshal(internalapi.CompleteExecutionJobRequest{
		WorkerID: workerID, ClaimToken: claim.ClaimToken, Result: result,
	})
	if err != nil {
		return executionjob.Job{}, err
	}
	resp, err := c.post(ctx, "/internal/v1/execution/jobs/"+claim.Job.ID+"/complete", body)
	if err != nil {
		return executionjob.Job{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return executionjob.Job{}, fmt.Errorf("execution job completion rejected with status %d", resp.StatusCode)
	}
	var out internalapi.CompleteExecutionJobResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return executionjob.Job{}, err
	}
	return out.Job, nil
}

func (c *Client) post(ctx context.Context, path string, body []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("worker control-plane request: %w", err)
	}
	return resp, nil
}
