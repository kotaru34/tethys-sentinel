package credentialapi

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/audit"
	"github.com/kotaru34/tethys-sentinel/internal/capability"
	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
	"github.com/kotaru34/tethys-sentinel/internal/internalapi"
	"github.com/kotaru34/tethys-sentinel/internal/risk"
	"github.com/kotaru34/tethys-sentinel/internal/sshsigner"
	"github.com/kotaru34/tethys-sentinel/internal/sshtarget"
)

type Signer interface {
	Sign(context.Context, sshsigner.Request) (sshsigner.Response, error)
}

type API struct {
	caps           *capability.Service
	jobs           *executionjob.Store
	audit          *audit.Log
	signer         Signer
	targets        sshtarget.Resolver
	workerTokenSHA [32]byte
	now            func() time.Time
}

func New(caps *capability.Service, jobs *executionjob.Store, auditLog *audit.Log, signer Signer, targets sshtarget.Resolver, workerToken string) (*API, error) {
	if caps == nil || jobs == nil || auditLog == nil || signer == nil || targets == nil {
		return nil, errors.New("capability, job, audit, signer and SSH target dependencies are required")
	}
	if len(workerToken) < 32 {
		return nil, errors.New("worker token must be at least 32 characters")
	}
	return &API{
		caps: caps, jobs: jobs, audit: auditLog, signer: signer, targets: targets,
		workerTokenSHA: sha256.Sum256([]byte(workerToken)),
		now:            func() time.Time { return time.Now().UTC() },
	}, nil
}

func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("POST /internal/v1/execution/jobs/{id}/ssh-certificate", a.requireWorker(http.HandlerFunc(a.issueCertificate)))
	return mux
}

func (a *API) issueCertificate(w http.ResponseWriter, r *http.Request) {
	var req internalapi.IssueSSHCertificateRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.WorkerID = strings.TrimSpace(req.WorkerID)
	req.ClaimToken = strings.TrimSpace(req.ClaimToken)
	req.PublicKey = strings.TrimSpace(req.PublicKey)
	if req.WorkerID == "" || len(req.WorkerID) > 128 || req.ClaimToken == "" || req.PublicKey == "" {
		writeError(w, http.StatusBadRequest, "worker_id, claim_token and public_key are required")
		return
	}
	if len(req.PublicKey) > 16<<10 {
		writeError(w, http.StatusBadRequest, "public_key is too large")
		return
	}

	job, err := a.jobs.ValidateRunningClaim(r.Context(), r.PathValue("id"), req.ClaimToken)
	if err != nil {
		if errors.Is(err, executionjob.ErrExpired) {
			_, _ = a.jobs.RejectClaim(r.Context(), r.PathValue("id"), req.ClaimToken, "job_expired_before_ssh_certificate")
		}
		writeError(w, http.StatusConflict, "SSH certificate issuance rejected")
		return
	}
	if !executionjob.VerifyBinding(job) {
		_, _ = a.jobs.RejectClaim(r.Context(), job.ID, req.ClaimToken, "command_binding_invalid_before_ssh_certificate")
		writeError(w, http.StatusConflict, "SSH certificate issuance rejected")
		return
	}

	currentRisk := risk.Classify(job.Argv)
	if currentRisk.Decision == risk.Deny || currentRisk.Category != job.RiskCategory || currentRisk.ScopeKey != job.ScopeKey {
		_, _ = a.jobs.RejectClaim(r.Context(), job.ID, req.ClaimToken, "risk_policy_changed_before_ssh_certificate")
		a.auditRejection(r.Context(), req.WorkerID, job, "current risk policy no longer matches the immutable execution job")
		writeError(w, http.StatusConflict, "SSH certificate issuance rejected because execution policy changed")
		return
	}

	grant, err := a.caps.AuthenticateID(r.Context(), job.GrantID, a.now())
	if err != nil {
		_, _ = a.jobs.RejectClaim(r.Context(), job.ID, req.ClaimToken, "grant_inactive_before_ssh_certificate")
		a.auditRejection(r.Context(), req.WorkerID, job, "grant inactive before SSH certificate issuance")
		writeError(w, http.StatusConflict, "SSH certificate issuance rejected")
		return
	}
	if risk.RequiresShell(currentRisk) && !grant.Permissions.Shell {
		_, _ = a.jobs.RejectClaim(r.Context(), job.ID, req.ClaimToken, "shell_permission_required_before_ssh_certificate")
		a.auditRejection(r.Context(), req.WorkerID, job, "powerful execution class requires explicit shell capability")
		writeError(w, http.StatusConflict, "SSH certificate issuance rejected because shell capability is not granted")
		return
	}

	target, err := a.targets.Resolve(job.Target)
	if err != nil {
		_, _ = a.jobs.RejectClaim(r.Context(), job.ID, req.ClaimToken, "ssh_target_resolution_failed")
		a.auditRejection(r.Context(), req.WorkerID, job, "operator-owned SSH target resolution failed")
		writeError(w, http.StatusServiceUnavailable, "SSH target is not configured for execution")
		return
	}
	if target.Name != job.Target {
		_, _ = a.jobs.RejectClaim(r.Context(), job.ID, req.ClaimToken, "ssh_target_identity_mismatch")
		a.auditRejection(r.Context(), req.WorkerID, job, "resolved SSH target identity does not match job target")
		writeError(w, http.StatusServiceUnavailable, "SSH target configuration is inconsistent")
		return
	}

	certificate, err := a.signer.Sign(r.Context(), sshsigner.Request{
		JobID: job.ID, GrantID: job.GrantID, Target: job.Target, CommandSHA256: job.CommandSHA256,
		PublicKey: req.PublicKey, NotAfter: job.ExpiresAt,
	})
	if err != nil {
		_, _ = a.jobs.RejectClaim(r.Context(), job.ID, req.ClaimToken, "ssh_signer_rejected_request")
		a.auditRejection(r.Context(), req.WorkerID, job, "SSH signer rejected certificate request")
		writeError(w, http.StatusBadGateway, "SSH certificate signer rejected request")
		return
	}

	if _, err := a.audit.Append(r.Context(), audit.Input{
		Kind: "ssh.certificate_issued", Actor: req.WorkerID, GrantID: job.GrantID, Target: job.Target, Argv: job.Argv,
		Decision: "allow", Category: job.RiskCategory, ScopeKey: job.ScopeKey, ApprovalID: job.ApprovalID,
		Metadata: map[string]string{
			"job_id":                  job.ID,
			"request_id":              job.RequestID,
			"command_sha256":          job.CommandSHA256,
			"serial":                  strconv.FormatUint(certificate.Serial, 10),
			"ca_fingerprint":          certificate.CAFingerprint,
			"certificate_fingerprint": certificate.CertificateFingerprint,
			"public_key_fingerprint":  certificate.PublicKeyFingerprint,
			"valid_before":            certificate.ValidBefore.Format(time.RFC3339Nano),
			"ssh_address":             target.Address,
			"ssh_user":                target.User,
		},
	}); err != nil {
		_, _ = a.jobs.RejectClaim(r.Context(), job.ID, req.ClaimToken, "audit_failure_after_ssh_certificate")
		writeError(w, http.StatusInternalServerError, "SSH certificate withheld because audit append failed")
		return
	}

	writeJSON(w, http.StatusOK, internalapi.IssueSSHCertificateResponse{Job: job, Certificate: certificate, Target: target})
}

func (a *API) auditRejection(ctx context.Context, workerID string, job executionjob.Job, reason string) {
	_, _ = a.audit.Append(ctx, audit.Input{
		Kind: "ssh.certificate_rejected", Actor: workerID, GrantID: job.GrantID, Target: job.Target, Argv: job.Argv,
		Decision: "deny", Category: job.RiskCategory, ScopeKey: job.ScopeKey, ApprovalID: job.ApprovalID,
		Reason: reason, Metadata: map[string]string{"job_id": job.ID, "request_id": job.RequestID},
	})
}

func (a *API) requireWorker(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearer(r.Header.Get("Authorization"))
		if !ok {
			writeError(w, http.StatusUnauthorized, "worker authentication required")
			return
		}
		got := sha256.Sum256([]byte(token))
		if subtle.ConstantTimeCompare(got[:], a.workerTokenSHA[:]) != 1 {
			writeError(w, http.StatusUnauthorized, "worker authentication required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func bearer(header string) (string, bool) {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return "", false
	}
	token := strings.TrimSpace(strings.TrimPrefix(header, prefix))
	return token, token != ""
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
