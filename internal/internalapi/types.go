package internalapi

import (
	"github.com/kotaru34/tethys-sentinel/internal/domain"
	"github.com/kotaru34/tethys-sentinel/internal/risk"
)

type IntrospectRequest struct {
	TokenHash string `json:"token_hash"`
}

type IntrospectResponse struct {
	Grant domain.Grant `json:"grant"`
}

type AuthorizeCommandRequest struct {
	TokenHash   string   `json:"token_hash"`
	Target      string   `json:"target"`
	Argv        []string `json:"argv"`
	AgentReason string   `json:"agent_reason,omitempty"`
}

type AuthorizeCommandResponse struct {
	Authorized bool        `json:"authorized"`
	Decision   string      `json:"decision"`
	ApprovalID string      `json:"approval_id,omitempty"`
	Risk       risk.Result `json:"risk"`
}
