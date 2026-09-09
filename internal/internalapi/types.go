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
	TokenHash   string   `json:"token_hash"`
	RequestID   string   `json:"request_id"`
	Target      string   `json:"target"`
	Argv        []string `json:"argv"`
	AgentReason string   `json:"agent_reason,omitempty"`
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

type ClaimExecutionJobRequest struct {
	WorkerID string `json:"worker_id"`
}

type ClaimExecutionJobResponse struct {
	Job        executionjob.Job `json:"job"`
	ClaimToken string           `json:"claim_token"`
}

type CompleteExecutionJobRequest struct {
	WorkerID   string              `json:"worker_id"`
	ClaimToken string              `json:"claim_token"`
	Result     executionjob.Result `json:"result"`
}

type CompleteExecutionJobResponse struct {
	Job executionjob.Job `json:"job"`
}
