package sshsigner

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	minCertificateTTL = 10 * time.Second
	maxCertificateTTL = 2 * time.Minute
	maxBackdate       = 15 * time.Second
)

var safeToken = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

type Policy struct {
	Principal       string
	WrapperPath     string
	SourceAddresses []string
	CertificateTTL  time.Duration
	Backdate        time.Duration
}

type Request struct {
	JobID         string    `json:"job_id"`
	GrantID       string    `json:"grant_id"`
	Target        string    `json:"target"`
	CommandSHA256 string    `json:"command_sha256"`
	PublicKey     string    `json:"public_key"`
	NotAfter      time.Time `json:"not_after"`
}

type Response struct {
	Certificate            string    `json:"certificate"`
	Serial                 uint64    `json:"serial"`
	KeyID                  string    `json:"key_id"`
	Principal              string    `json:"principal"`
	ForceCommand           string    `json:"force_command"`
	SourceAddresses        []string  `json:"source_addresses"`
	ValidAfter             time.Time `json:"valid_after"`
	ValidBefore            time.Time `json:"valid_before"`
	CAFingerprint          string    `json:"ca_fingerprint"`
	CertificateFingerprint string    `json:"certificate_fingerprint"`
	PublicKeyFingerprint   string    `json:"public_key_fingerprint"`
}

type Service struct {
	ca              ssh.Signer
	principal       string
	wrapperPath     string
	sourceAddresses []string
	ttl             time.Duration
	backdate        time.Duration
	now             func() time.Time
}

func New(ca ssh.Signer, policy Policy) (*Service, error) {
	if ca == nil {
		return nil, errors.New("SSH CA signer is required")
	}
	if ca.PublicKey().Type() != ssh.KeyAlgoED25519 {
		return nil, errors.New("SSH CA must use Ed25519")
	}
	principal := strings.TrimSpace(policy.Principal)
	if !safeToken.MatchString(principal) {
		return nil, errors.New("principal contains unsupported characters")
	}
	wrapper, err := validateWrapperPath(policy.WrapperPath)
	if err != nil {
		return nil, err
	}
	if policy.CertificateTTL < minCertificateTTL || policy.CertificateTTL > maxCertificateTTL {
		return nil, fmt.Errorf("certificate TTL must be between %s and %s", minCertificateTTL, maxCertificateTTL)
	}
	if policy.Backdate < 0 || policy.Backdate > maxBackdate {
		return nil, fmt.Errorf("certificate backdate must be between 0 and %s", maxBackdate)
	}
	sources, err := canonicalSourceAddresses(policy.SourceAddresses)
	if err != nil {
		return nil, err
	}
	return &Service{
		ca:              ca,
		principal:       principal,
		wrapperPath:     wrapper,
		sourceAddresses: sources,
		ttl:             policy.CertificateTTL,
		backdate:        policy.Backdate,
		now:             func() time.Time { return time.Now().UTC() },
	}, nil
}

func LoadCA(path string) (ssh.Signer, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("SSH CA key path is required")
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat SSH CA key: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("SSH CA key must be a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("SSH CA key permissions must not grant group/other access")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read SSH CA key: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("parse SSH CA key: %w", err)
	}
	if signer.PublicKey().Type() != ssh.KeyAlgoED25519 {
		return nil, errors.New("SSH CA must use Ed25519")
	}
	return signer, nil
}

func (s *Service) Sign(req Request) (Response, error) {
	jobID := strings.TrimSpace(req.JobID)
	grantID := strings.TrimSpace(req.GrantID)
	target := strings.TrimSpace(req.Target)
	binding := strings.ToLower(strings.TrimSpace(req.CommandSHA256))
	if !safeToken.MatchString(jobID) || !safeToken.MatchString(grantID) || !safeToken.MatchString(target) {
		return Response{}, errors.New("job_id, grant_id and target must use safe identifier characters")
	}
	if err := validateSHA256(binding); err != nil {
		return Response{}, fmt.Errorf("command_sha256: %w", err)
	}
	publicKey, err := parseEphemeralPublicKey(req.PublicKey)
	if err != nil {
		return Response{}, err
	}

	now := s.now().UTC()
	if req.NotAfter.IsZero() {
		return Response{}, errors.New("not_after is required")
	}
	requestLimit := req.NotAfter.UTC()
	if !now.Before(requestLimit) {
		return Response{}, errors.New("not_after must be in the future")
	}
	validBefore := now.Add(s.ttl)
	if requestLimit.Before(validBefore) {
		validBefore = requestLimit
	}
	if validBefore.Unix() <= now.Unix() {
		return Response{}, errors.New("certificate validity window is too short")
	}

	serial, err := randomSerial()
	if err != nil {
		return Response{}, err
	}
	validAfter := now.Add(-s.backdate)
	forceCommand := fmt.Sprintf("%s --job %s --binding %s", s.wrapperPath, jobID, binding)
	keyID := fmt.Sprintf("tethys-sentinel:job:%s:grant:%s:target:%s", jobID, grantID, target)

	cert := &ssh.Certificate{
		Key:             publicKey,
		Serial:          serial,
		CertType:        ssh.UserCert,
		KeyId:           keyID,
		ValidPrincipals: []string{s.principal},
		ValidAfter:      uint64(validAfter.Unix()),
		ValidBefore:     uint64(validBefore.Unix()),
		Permissions: ssh.Permissions{
			CriticalOptions: map[string]string{
				"force-command":  forceCommand,
				"source-address": strings.Join(s.sourceAddresses, ","),
			},
			Extensions: map[string]string{},
		},
	}
	if err := cert.SignCert(rand.Reader, s.ca); err != nil {
		return Response{}, fmt.Errorf("sign SSH certificate: %w", err)
	}
	certificate := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert)))
	return Response{
		Certificate:            certificate,
		Serial:                 serial,
		KeyID:                  keyID,
		Principal:              s.principal,
		ForceCommand:           forceCommand,
		SourceAddresses:        append([]string(nil), s.sourceAddresses...),
		ValidAfter:             validAfter,
		ValidBefore:            validBefore,
		CAFingerprint:          ssh.FingerprintSHA256(s.ca.PublicKey()),
		CertificateFingerprint: ssh.FingerprintSHA256(cert),
		PublicKeyFingerprint:   ssh.FingerprintSHA256(publicKey),
	}, nil
}

func parseEphemeralPublicKey(value string) (ssh.PublicKey, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, errors.New("ephemeral public key is required")
	}
	key, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(value + "\n"))
	if err != nil {
		return nil, fmt.Errorf("parse ephemeral public key: %w", err)
	}
	if len(options) != 0 || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("ephemeral public key must not contain authorized_keys options or additional records")
	}
	if _, isCert := key.(*ssh.Certificate); isCert {
		return nil, errors.New("ephemeral public key must not already be a certificate")
	}
	if key.Type() != ssh.KeyAlgoED25519 {
		return nil, errors.New("ephemeral public key must use Ed25519")
	}
	return key, nil
}

func canonicalSourceAddresses(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, errors.New("at least one exact worker source address is required")
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, raw := range values {
		addr, err := netip.ParseAddr(strings.TrimSpace(raw))
		if err != nil {
			return nil, fmt.Errorf("invalid worker source address %q", raw)
		}
		addr = addr.Unmap()
		bits := 128
		if addr.Is4() {
			bits = 32
		}
		prefix := netip.PrefixFrom(addr, bits).String()
		if _, exists := seen[prefix]; exists {
			continue
		}
		seen[prefix] = struct{}{}
		out = append(out, prefix)
	}
	if len(out) > 16 {
		return nil, errors.New("too many worker source addresses")
	}
	return out, nil
}

func validateWrapperPath(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || !filepath.IsAbs(value) || filepath.Clean(value) != value {
		return "", errors.New("wrapper path must be a clean absolute path")
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("/._-", r) {
			continue
		}
		return "", errors.New("wrapper path contains shell-unsafe characters")
	}
	return value, nil
}

func validateSHA256(value string) error {
	if len(value) != 64 {
		return errors.New("must be a 64-character SHA-256 hex digest")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		return errors.New("must be a 64-character SHA-256 hex digest")
	}
	return nil
}

func randomSerial() (uint64, error) {
	for {
		var raw [8]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return 0, fmt.Errorf("generate certificate serial: %w", err)
		}
		serial := binary.BigEndian.Uint64(raw[:])
		if serial != 0 {
			return serial, nil
		}
	}
}
