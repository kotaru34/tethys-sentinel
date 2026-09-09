package domain

import "time"

type Permissions struct {
	Exec        bool `json:"exec"`
	Shell       bool `json:"shell"`
	Upload      bool `json:"upload"`
	Download    bool `json:"download"`
	HistoryRead bool `json:"history_read"`
	NotesRead   bool `json:"notes_read"`
	NotesWrite  bool `json:"notes_write"`
}

type HistoryScope struct {
	CurrentSession bool `json:"current_session"`
	Previous       bool `json:"previous_sessions"`
	OtherAgents    bool `json:"other_agents"`
	IncludeOutput  bool `json:"include_output"`
}

type Grant struct {
	ID          string       `json:"id"`
	TokenHash   [32]byte     `json:"-"`
	Purpose     string       `json:"purpose"`
	Agent       string       `json:"agent"`
	Targets     []string     `json:"targets"`
	Permissions Permissions  `json:"permissions"`
	History     HistoryScope `json:"history"`
	IssuedAt    time.Time    `json:"issued_at"`
	ExpiresAt   time.Time    `json:"expires_at"`
	RevokedAt   *time.Time   `json:"revoked_at,omitempty"`
}

type AuthoritativeContext struct {
	TrustLevel string `json:"trust_level"`
	Statement  string `json:"statement"`
}

type Bootstrap struct {
	SessionID     string               `json:"session_id"`
	Purpose       string               `json:"purpose"`
	Agent         string               `json:"agent"`
	Targets       []string             `json:"targets"`
	Permissions   Permissions          `json:"permissions"`
	History       HistoryScope         `json:"history"`
	IssuedAt      time.Time            `json:"issued_at"`
	ExpiresAt     time.Time            `json:"expires_at"`
	Authoritative AuthoritativeContext `json:"authoritative"`
}
