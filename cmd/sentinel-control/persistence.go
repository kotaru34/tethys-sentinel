package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/kotaru34/tethys-sentinel/internal/approval"
	"github.com/kotaru34/tethys-sentinel/internal/audit"
	"github.com/kotaru34/tethys-sentinel/internal/capability"
	"github.com/kotaru34/tethys-sentinel/internal/controlapi"
	"github.com/kotaru34/tethys-sentinel/internal/controlops"
	"github.com/kotaru34/tethys-sentinel/internal/credentialapi"
	"github.com/kotaru34/tethys-sentinel/internal/emergency"
	"github.com/kotaru34/tethys-sentinel/internal/emergencyapi"
	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
	"github.com/kotaru34/tethys-sentinel/internal/notes"
	"github.com/kotaru34/tethys-sentinel/internal/postgresrepo"
	"github.com/kotaru34/tethys-sentinel/internal/resourceapi"
	"github.com/kotaru34/tethys-sentinel/internal/store"
)

type jobPersistence interface {
	controlapi.JobStore
	credentialapi.JobStore
}

type persistenceBundle struct {
	caps      *capability.Service
	grants    controlops.GrantLifecycle
	approvals controlapi.ApprovalStore
	audit     resourceapi.AuditStore
	jobs      jobPersistence
	notes     resourceapi.NoteStore
	emergency emergencyapi.Controller
	close     func()
}

func openPersistence(ctx context.Context) (*persistenceBundle, error) {
	switch strings.TrimSpace(os.Getenv("SENTINEL_PERSISTENCE_BACKEND")) {
	case "file":
		return openFilePersistence()
	case "postgres":
		return openPostgresPersistence(ctx)
	case "":
		return nil, errors.New("SENTINEL_PERSISTENCE_BACKEND must be explicitly set to file or postgres")
	default:
		return nil, errors.New("SENTINEL_PERSISTENCE_BACKEND must be file or postgres")
	}
}

func openFilePersistence() (*persistenceBundle, error) {
	jobAuthKey, err := readSecretFile(env("SENTINEL_JOB_AUTH_KEY_FILE", "/etc/tethys-sentinel/job-auth.key"))
	if err != nil {
		return nil, fmt.Errorf("read execution job auth key: %w", err)
	}
	if len(jobAuthKey) < 32 {
		return nil, errors.New("execution job auth key must be at least 32 bytes")
	}

	grantStore, err := store.NewFileGrantStore(env("SENTINEL_GRANT_STORE", "/var/lib/tethys-sentinel/grants.json"))
	if err != nil {
		return nil, fmt.Errorf("open grant store: %w", err)
	}
	approvalStore, err := approval.Open(env("SENTINEL_APPROVAL_STORE", "/var/lib/tethys-sentinel/approvals.json"))
	if err != nil {
		return nil, fmt.Errorf("open approval store: %w", err)
	}
	auditLog, err := audit.Open(env("SENTINEL_AUDIT_LOG", "/var/lib/tethys-sentinel/audit.jsonl"))
	if err != nil {
		return nil, fmt.Errorf("open/verify audit log: %w", err)
	}
	jobStore, err := executionjob.Open(env("SENTINEL_JOB_STORE", "/var/lib/tethys-sentinel/execution-jobs.json"), jobAuthKey)
	if err != nil {
		return nil, fmt.Errorf("open/verify execution job store: %w", err)
	}
	emergencyStore, err := emergency.Open(env("SENTINEL_EMERGENCY_STATE", "/var/lib/tethys-sentinel/emergency.json"))
	if err != nil {
		return nil, fmt.Errorf("open emergency authority state: %w", err)
	}
	noteStore, err := notes.Open(env("SENTINEL_NOTES_STORE", "/var/lib/tethys-sentinel/notes.jsonl"))
	if err != nil {
		return nil, fmt.Errorf("open notes store: %w", err)
	}
	caps := capability.NewServiceWithEmergency(grantStore, emergencyStore)
	return &persistenceBundle{
		caps: caps,
		grants: controlops.NewLegacyGrantLifecycle(caps, jobStore, auditLog),
		approvals: approvalStore,
		audit: auditLog,
		jobs: jobStore,
		notes: noteStore,
		emergency: emergencyapi.NewLegacyController(emergencyStore, jobStore, auditLog),
		close: func() {},
	}, nil
}

func openPostgresPersistence(ctx context.Context) (*persistenceBundle, error) {
	dsn := strings.TrimSpace(os.Getenv("SENTINEL_POSTGRES_DSN"))
	if dsn == "" {
		return nil, errors.New("SENTINEL_POSTGRES_DSN is required for postgres persistence")
	}
	repo, err := postgresrepo.Open(ctx, postgresrepo.Config{
		DSN:                    dsn,
		AllowInsecureTransport: os.Getenv("SENTINEL_DEV_INSECURE_POSTGRES") == "1",
	})
	if err != nil {
		return nil, err
	}
	caps := capability.NewServiceWithBackend(repo.Capabilities())
	return &persistenceBundle{
		caps: caps,
		grants: repo.Grants(),
		approvals: repo.Approvals(),
		audit: repo.Audit(),
		jobs: repo.Jobs(),
		notes: repo.Notes(),
		emergency: repo.Emergency(),
		close: repo.Close,
	}, nil
}
