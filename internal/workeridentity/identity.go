package workeridentity

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
	"github.com/kotaru34/tethys-sentinel/internal/sshsigner"
)

type Ephemeral struct {
	private ssh.Signer
	public  string
}

type Credential struct {
	Signer      ssh.Signer
	Certificate *ssh.Certificate
	Metadata    sshsigner.Response
}

func Generate() (*Ephemeral, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return nil, err
	}
	public := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	return &Ephemeral{private: signer, public: public}, nil
}

func (e *Ephemeral) PublicKey() string {
	if e == nil {
		return ""
	}
	return e.public
}

func (e *Ephemeral) Bind(job executionjob.Job, response sshsigner.Response, now time.Time) (Credential, error) {
	if e == nil || e.private == nil {
		return Credential{}, errors.New("ephemeral identity is not initialized")
	}
	if job.Status != executionjob.Running || !executionjob.VerifyBinding(job) {
		return Credential{}, errors.New("SSH credential requires a valid running job")
	}
	parsed, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(response.Certificate) + "\n"))
	if err != nil {
		return Credential{}, errors.New("parse issued SSH certificate: " + err.Error())
	}
	if len(options) != 0 || len(strings.TrimSpace(string(rest))) != 0 {
		return Credential{}, errors.New("issued SSH certificate contains unexpected options or trailing data")
	}
	cert, ok := parsed.(*ssh.Certificate)
	if !ok || cert.CertType != ssh.UserCert {
		return Credential{}, errors.New("issued SSH credential is not a user certificate")
	}
	if string(cert.Key.Marshal()) != string(e.private.PublicKey().Marshal()) {
		return Credential{}, errors.New("issued SSH certificate does not match ephemeral private key")
	}
	if cert.ValidBefore == ssh.CertTimeInfinity || cert.ValidBefore > uint64(job.ExpiresAt.Unix()) {
		return Credential{}, errors.New("issued SSH certificate outlives execution job")
	}
	nowUnix := uint64(now.UTC().Unix())
	if nowUnix < cert.ValidAfter || nowUnix >= cert.ValidBefore {
		return Credential{}, errors.New("issued SSH certificate is not currently valid")
	}
	if response.CertificateFingerprint != "" && response.CertificateFingerprint != ssh.FingerprintSHA256(cert) {
		return Credential{}, errors.New("SSH certificate fingerprint metadata mismatch")
	}
	if response.PublicKeyFingerprint != "" && response.PublicKeyFingerprint != ssh.FingerprintSHA256(e.private.PublicKey()) {
		return Credential{}, errors.New("SSH public key fingerprint metadata mismatch")
	}
	certSigner, err := ssh.NewCertSigner(cert, e.private)
	if err != nil {
		return Credential{}, errors.New("bind SSH certificate to ephemeral key: " + err.Error())
	}
	return Credential{Signer: certSigner, Certificate: cert, Metadata: response}, nil
}
