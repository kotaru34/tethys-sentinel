package operatorview

import (
	"testing"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/domain"
	"github.com/kotaru34/tethys-sentinel/internal/emergency"
)

func TestListOptionsNormalized(t *testing.T) {
	tests := []struct {
		name string
		in   ListOptions
		want ListOptions
	}{
		{
			name: "defaults and trims",
			in:   ListOptions{Cursor: "  next  ", Status: " pending "},
			want: ListOptions{Limit: DefaultLimit, Cursor: "next", Status: "pending"},
		},
		{
			name: "caps limit",
			in:   ListOptions{Limit: MaxLimit + 99},
			want: ListOptions{Limit: MaxLimit},
		},
		{
			name: "keeps supported limit",
			in:   ListOptions{Limit: 25},
			want: ListOptions{Limit: 25},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.in.Normalized()
			if got != tt.want {
				t.Fatalf("Normalized() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestDeriveGrantState(t *testing.T) {
	now := time.Date(2026, 9, 14, 19, 30, 0, 0, time.UTC)
	future := now.Add(time.Hour)
	past := now.Add(-time.Minute)

	tests := []struct {
		name      string
		grant     domain.Grant
		authority emergency.State
		want      GrantState
	}{
		{
			name:      "active",
			grant:     domain.Grant{SecurityEpoch: 3, ExpiresAt: future},
			authority: emergency.State{Epoch: 3},
			want:      GrantActive,
		},
		{
			name:      "globally disabled",
			grant:     domain.Grant{SecurityEpoch: 3, ExpiresAt: future},
			authority: emergency.State{Epoch: 3, Disabled: true},
			want:      GrantDisabled,
		},
		{
			name:      "stale epoch precedes disabled",
			grant:     domain.Grant{SecurityEpoch: 2, ExpiresAt: future},
			authority: emergency.State{Epoch: 3, Disabled: true},
			want:      GrantStaleEpoch,
		},
		{
			name:      "expired",
			grant:     domain.Grant{SecurityEpoch: 3, ExpiresAt: past},
			authority: emergency.State{Epoch: 3, Disabled: true},
			want:      GrantExpired,
		},
		{
			name: "revoked wins",
			grant: domain.Grant{
				SecurityEpoch: 2,
				ExpiresAt:     past,
				RevokedAt:     &past,
			},
			authority: emergency.State{Epoch: 3, Disabled: true},
			want:      GrantRevoked,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DeriveGrantState(tt.grant, tt.authority, now); got != tt.want {
				t.Fatalf("DeriveGrantState() = %q, want %q", got, tt.want)
			}
		})
	}
}
