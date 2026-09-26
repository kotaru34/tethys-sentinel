package mcpclaim

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/domain"
)

const (
	codePrefix       = "MCP1-"
	claimIDPrefix    = "mcpclaim-"
	claimRandomBytes = 20
	claimIDBytes     = 16
	MinClaimTTL      = 30 * time.Second
	MaxClaimTTL      = 5 * time.Minute
	MinGrantTTL      = 30 * time.Second
	MaxGrantTTL      = 8 * time.Hour
)

var (
	ErrNotFound = errors.New("MCP claim not found")
	ErrExpired  = errors.New("MCP claim expired")
	ErrUsed     = errors.New("MCP claim already used")
	ErrStale    = errors.New("MCP claim belongs to a stale security epoch")
)

type IssueInput struct {
	Agent           string              `json:"agent"`
	Purpose         string              `json:"purpose"`
	Targets         []string            `json:"targets"`
	Permissions     domain.Permissions  `json:"permissions"`
	History         domain.HistoryScope `json:"history"`
	GrantTTLSeconds int64               `json:"grant_ttl_seconds"`
	ClaimTTLSeconds int64               `json:"claim_ttl_seconds"`
}

type Claim struct {
	ID              string              `json:"id"`
	CodeHash        [32]byte            `json:"-"`
	Agent           string              `json:"agent"`
	Purpose         string              `json:"purpose"`
	Targets         []string            `json:"targets"`
	Permissions     domain.Permissions  `json:"permissions"`
	History         domain.HistoryScope `json:"history"`
	GrantTTLSeconds int64               `json:"grant_ttl_seconds"`
	SecurityEpoch   uint64              `json:"security_epoch"`
	IssuedAt        time.Time           `json:"issued_at"`
	ExpiresAt       time.Time           `json:"expires_at"`
	UsedAt          *time.Time          `json:"used_at,omitempty"`
}

type IssueResult struct {
	Claim Claim  `json:"claim"`
	Code  string `json:"claim_code"`
}

type RedeemResult struct {
	Grant      domain.Grant `json:"grant"`
	Capability string       `json:"capability"`
}

type Lifecycle interface {
	Issue(context.Context, IssueInput) (IssueResult, error)
	Redeem(context.Context, [32]byte) (RedeemResult, error)
}

func ValidateIssueInput(input IssueInput) (IssueInput, error) {
	input.Agent = strings.TrimSpace(input.Agent)
	input.Purpose = strings.TrimSpace(input.Purpose)
	if input.Agent == "" || len(input.Agent) > 128 {
		return IssueInput{}, errors.New("agent must be 1..128 characters")
	}
	if input.Purpose == "" || len(input.Purpose) > 2048 {
		return IssueInput{}, errors.New("purpose must be 1..2048 characters")
	}
	input.Targets = uniqueTargets(input.Targets)
	if len(input.Targets) == 0 {
		return IssueInput{}, errors.New("at least one target is required")
	}
	for _, target := range input.Targets {
		if len(target) > 128 {
			return IssueInput{}, errors.New("target must be 1..128 characters")
		}
	}
	claimTTL := time.Duration(input.ClaimTTLSeconds) * time.Second
	if claimTTL < MinClaimTTL || claimTTL > MaxClaimTTL {
		return IssueInput{}, fmt.Errorf("claim_ttl_seconds must be between %d and %d", int64(MinClaimTTL/time.Second), int64(MaxClaimTTL/time.Second))
	}
	grantTTL := time.Duration(input.GrantTTLSeconds) * time.Second
	if grantTTL < MinGrantTTL || grantTTL > MaxGrantTTL {
		return IssueInput{}, fmt.Errorf("grant_ttl_seconds must be between %d and %d", int64(MinGrantTTL/time.Second), int64(MaxGrantTTL/time.Second))
	}
	if !input.Permissions.Exec {
		return IssueInput{}, errors.New("MCP claim must grant exec permission")
	}
	if input.Permissions.UnrestrictedShell && !input.Permissions.Shell {
		return IssueInput{}, errors.New("unrestricted_shell requires shell permission")
	}
	return input, nil
}

func Generate(random io.Reader) (id, code string, hash [32]byte, err error) {
	if random == nil {
		random = rand.Reader
	}
	idBytes := make([]byte, claimIDBytes)
	if _, err = io.ReadFull(random, idBytes); err != nil {
		return "", "", [32]byte{}, err
	}
	codeBytes := make([]byte, claimRandomBytes)
	if _, err = io.ReadFull(random, codeBytes); err != nil {
		return "", "", [32]byte{}, err
	}
	id = claimIDPrefix + hex.EncodeToString(idBytes)
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(codeBytes)
	groups := make([]string, 0, len(encoded)/4)
	for len(encoded) > 0 {
		n := 4
		if len(encoded) < n {
			n = len(encoded)
		}
		groups = append(groups, encoded[:n])
		encoded = encoded[n:]
	}
	code = codePrefix + strings.Join(groups, "-")
	hash = sha256.Sum256([]byte(code))
	return id, code, hash, nil
}

func HashCode(raw string) ([32]byte, error) {
	code, err := NormalizeCode(raw)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256([]byte(code)), nil
}

func NormalizeCode(raw string) (string, error) {
	code := strings.ToUpper(strings.TrimSpace(raw))
	if !strings.HasPrefix(code, codePrefix) {
		return "", errors.New("invalid MCP claim code")
	}
	payload := strings.TrimPrefix(code, codePrefix)
	parts := strings.Split(payload, "-")
	if len(parts) != 8 {
		return "", errors.New("invalid MCP claim code")
	}
	compact := strings.Join(parts, "")
	if len(compact) != 32 {
		return "", errors.New("invalid MCP claim code")
	}
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(compact)
	if err != nil || len(decoded) != claimRandomBytes {
		return "", errors.New("invalid MCP claim code")
	}
	for _, part := range parts {
		if len(part) != 4 {
			return "", errors.New("invalid MCP claim code")
		}
	}
	return codePrefix + strings.Join(parts, "-"), nil
}

func uniqueTargets(raw []string) []string {
	seen := make(map[string]struct{}, len(raw))
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		target := strings.TrimSpace(item)
		if target == "" {
			continue
		}
		if _, ok := seen[target]; ok {
			continue
		}
		seen[target] = struct{}{}
		out = append(out, target)
	}
	return out
}
