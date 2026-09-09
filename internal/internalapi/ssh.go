package internalapi

import (
	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
	"github.com/kotaru34/tethys-sentinel/internal/sshsigner"
)

type IssueSSHCertificateRequest struct {
	WorkerID   string `json:"worker_id"`
	ClaimToken string `json:"claim_token"`
	PublicKey  string `json:"public_key"`
}

type IssueSSHCertificateResponse struct {
	Job         executionjob.Job   `json:"job"`
	Certificate sshsigner.Response `json:"certificate"`
}
