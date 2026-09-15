package internalapi

import (
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/domain"
	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
	"github.com/kotaru34/tethys-sentinel/internal/risk"
)

type IntrospectRequest struct {
	TokenHash string `json:"token_hash"`
}

type IntrospectResponse struct {
	Grant domain.Grant `json:"grant"`
}

type SubmitCommandRequest struct {
	TokenHash      string   `json:"token_hash"`
	RequestID      string   `json:"request_id"`
	Target         string   `json:"target"`
	Argv           []string `json:"argv"`
	AgentReason    string   `json:"agent_reason,omitempty"`
	TimeoutSeconds int64    `json:"timeout_seconds,omitempty"`
}

type ExecutionJobReceipt struct {
	ID            string              `json:"id"`
	RequestID     string              `json:"request_id"`
	Status        executionjob.Status `json:"status"`
	CommandSHA256 string              `json:"command_sha256"`
	ExpiresAt     time.Time           `json:"expires_at"`
}

type SubmitCommandResponse struct {
	Accepted   bool                 `json:"accepted"`
	Decision   string               `json:"decision"`
	ApprovalID string               `json:"approval_id,omitempty"`
	Risk       risk.Result          `json:"risk"`
	Job        *ExecutionJobReceipt `json:"job,omitempty"`
}

type AgentExecutionJob struct {
	ID            string               `json:"id"`
	RequestID     string               `json:"request_id"`
	Target        string               `json:"target"`
	Argv          []string             `json:"argv"`
	CommandSHA256 string               `json:"command_sha256"`
	ApprovalID    string               `json:"approval_id,omitempty"`
	RiskCategory  string               `json:"risk_category,omitempty"`
	CreatedAt     time.Time            `json:"created_at"`
	ExpiresAt     time.Time            `json:"expires_at"`
	Status        executionjob.Status  `json:"status"`
	ClaimedAt     *time.Time           `json:"claimed_at,omitempty"`
	StartedAt     *time.Time           `json:"started_at,omitempty"`
	CompletedAt   *time.Time           `json:"completed_at,omitempty"`
	Result        *executionjob.Result `json:"result,omitempty"`
}

func AgentJob(job executionjob.Job) AgentExecutionJob {
	out := AgentExecutionJob{
		ID: job.ID, RequestID: job.RequestID, Target: job.Target,
		Argv: append([]string(nil), job.Argv...), CommandSHA256: job.CommandSHA256,
		ApprovalID: job.ApprovalID, RiskCategory: job.RiskCategory,
		CreatedAt: job.CreatedAt, ExpiresAt: job.ExpiresAt, Status: job.Status,
		ClaimedAt: job.ClaimedAt, StartedAt: job.StartedAt, CompletedAt: job.CompletedAt,
	}
	if job.Result != nil {
		result := *job.Result
		out.Result = &result
	}
	return out
}

type GetExecutionJobRequest struct {
	TokenHash string `json:"token_hash"`
	JobID     string `json:"job_id"`
}

type GetExecutionJobByRequestRequest struct {
	TokenHash string `json:"token_hash"`
	RequestID string `json:"request_id"`
}

type GetExecutionJobResponse struct {
	Job AgentExecutionJob `json:"job"`
}

type ClaimExecutionJobRequest struct {
	WorkerID string `json:"worker_id"`
}

type ClaimExecutionJobResponse struct {
	Job        executionjob.Job `json:"job"`
	ClaimToken string           `json:"claim_token"`
}

type StartExecutionJobRequest struct {
	WorkerID   string `json:"worker_id"`
	ClaimToken string `json:"claim_token"`
}

type StartExecutionJobResponse struct {
	Job executionjob.Job `json:"job"`
}

type CheckExecutionAuthorityRequest struct {
	WorkerID   string `json:"worker_id"`
	ClaimToken string `json:"claim_token"`
}

type CheckExecutionAuthorityResponse struct {
	Allowed   bool      `json:"allowed"`
	Epoch     uint64    `json:"epoch"`
	Reason    string    `json:"reason,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

type CompleteExecutionJobRequest struct {
	WorkerID   string              `json:"worker_id"`
	ClaimToken string              `json:"claim_token"`
	Result     executionjob.Result `json:"result"`
}

type CompleteExecutionJobResponse struct {
	Job executionjob.Job `json:"job"`
}
