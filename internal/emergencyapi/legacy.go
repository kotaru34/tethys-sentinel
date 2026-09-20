package emergencyapi

import (
	"github.com/kotaru34/tethys-sentinel/internal/audit"
	"github.com/kotaru34/tethys-sentinel/internal/emergency"
	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
)

func NewLegacyController(state *emergency.Store, jobs *executionjob.Store, auditLog *audit.Log) Controller {
	return &legacyController{state: state, jobs: jobs, audit: auditLog}
}
