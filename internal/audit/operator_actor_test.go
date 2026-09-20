package audit

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/kotaru34/tethys-sentinel/internal/operatoridentity"
)

func TestFileAuditResolvesOnlyLegacyOperatorActor(t *testing.T) {
	log, err := Open(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := operatoridentity.WithActor(context.Background(), "operator:cert-sha256:file-test")

	operatorEvent, err := log.Append(ctx, Input{Kind: "operator.test", Actor: "operator"})
	if err != nil {
		t.Fatal(err)
	}
	if operatorEvent.Actor != "operator:cert-sha256:file-test" {
		t.Fatalf("operator actor=%q", operatorEvent.Actor)
	}

	agentEvent, err := log.Append(ctx, Input{Kind: "agent.test", Actor: "agent-a"})
	if err != nil {
		t.Fatal(err)
	}
	if agentEvent.Actor != "agent-a" {
		t.Fatalf("non-operator actor changed to %q", agentEvent.Actor)
	}
}
