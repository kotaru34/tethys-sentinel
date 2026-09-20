package operatoridentity

import (
	"context"
	"testing"
)

func TestForwardedActor(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		{name: "default", raw: "", want: DefaultActor},
		{name: "certificate fingerprint", raw: " cert-sha256:abcDEF0123 ", want: "operator:cert-sha256:abcDEF0123"},
		{name: "reject whitespace", raw: "cert sha256:abc", wantErr: true},
		{name: "reject control", raw: "cert-sha256:abc\nspoof", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ForwardedActor(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ForwardedActor(%q) unexpectedly succeeded: %q", tt.raw, got)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("ForwardedActor(%q) = %q, %v; want %q", tt.raw, got, err, tt.want)
			}
		})
	}
}

func TestActorContextDefaultsAndOverrides(t *testing.T) {
	if got := Actor(context.Background()); got != DefaultActor {
		t.Fatalf("default actor=%q", got)
	}
	ctx := WithActor(context.Background(), "operator:cert-sha256:abc")
	if got := Actor(ctx); got != "operator:cert-sha256:abc" {
		t.Fatalf("context actor=%q", got)
	}
}
