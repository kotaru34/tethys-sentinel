package internalapi

import (
	"github.com/kotaru34/tethys-sentinel/internal/audit"
	"github.com/kotaru34/tethys-sentinel/internal/domain"
)

type ContextRequest struct {
	TokenHash string `json:"token_hash"`
}

type ContextResponse struct {
	Bundle domain.ContextBundle `json:"bundle"`
}

type HistoryRequest struct {
	TokenHash string `json:"token_hash"`
	Limit     int    `json:"limit,omitempty"`
}

type HistoryResponse struct {
	TrustLevel    string        `json:"trust_level"`
	Authoritative bool          `json:"authoritative"`
	Events        []audit.Event `json:"events"`
}

type NotesListRequest struct {
	TokenHash string `json:"token_hash"`
	Limit     int    `json:"limit,omitempty"`
}

type NotesListResponse struct {
	TrustLevel    string             `json:"trust_level"`
	Authoritative bool               `json:"authoritative"`
	Notes         []domain.AgentNote `json:"notes"`
}

type NoteWriteRequest struct {
	TokenHash string `json:"token_hash"`
	Target    string `json:"target,omitempty"`
	Content   string `json:"content"`
}

type NoteWriteResponse struct {
	Note domain.AgentNote `json:"note"`
}
