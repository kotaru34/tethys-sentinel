package domain

import "time"

const (
	Trust0 = "TRUST_0"
	Trust2 = "TRUST_2"
)

type ContextDocument struct {
	Path       string `json:"path"`
	MediaType  string `json:"media_type"`
	TrustLevel string `json:"trust_level"`
	ReadOnly   bool   `json:"read_only"`
	SHA256     string `json:"sha256"`
	Content    string `json:"content"`
}

type ContextBundle struct {
	Version    string            `json:"version"`
	TrustLevel string            `json:"trust_level"`
	Documents  []ContextDocument `json:"documents"`
}

type AgentNote struct {
	ID         string    `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	GrantID    string    `json:"grant_id"`
	Agent      string    `json:"agent"`
	Target     string    `json:"target,omitempty"`
	TrustLevel string    `json:"trust_level"`
	Content    string    `json:"content"`
	SHA256     string    `json:"sha256"`
}

type ResourceLinks struct {
	Context string `json:"context"`
	History string `json:"history,omitempty"`
	Notes   string `json:"notes,omitempty"`
}
