package postgresrepo

import (
	"github.com/kotaru34/tethys-sentinel/internal/capability"
	"github.com/kotaru34/tethys-sentinel/internal/controlapi"
	"github.com/kotaru34/tethys-sentinel/internal/controlops"
	"github.com/kotaru34/tethys-sentinel/internal/credentialapi"
	"github.com/kotaru34/tethys-sentinel/internal/emergencyapi"
	"github.com/kotaru34/tethys-sentinel/internal/resourceapi"
)

var (
	_ capability.Backend       = (*CapabilityBackend)(nil)
	_ controlapi.ApprovalStore = (*ApprovalStore)(nil)
	_ controlapi.AuditStore    = (*AuditStore)(nil)
	_ controlapi.JobStore      = (*JobStore)(nil)
	_ controlops.GrantLifecycle = (*GrantLifecycle)(nil)
	_ credentialapi.JobStore   = (*JobStore)(nil)
	_ credentialapi.AuditStore = (*AuditStore)(nil)
	_ emergencyapi.Controller  = (*EmergencyController)(nil)
	_ resourceapi.AuditStore   = (*AuditStore)(nil)
	_ resourceapi.NoteStore    = (*NoteStore)(nil)
)
