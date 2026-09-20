package operatorview

import (
	"context"
	"errors"
	"sort"

	"golang.org/x/crypto/ssh"

	"github.com/kotaru34/tethys-sentinel/internal/contextstore"
	"github.com/kotaru34/tethys-sentinel/internal/domain"
	"github.com/kotaru34/tethys-sentinel/internal/sshtarget"
)

type FullReader interface {
	Reader
	Targets(context.Context) ([]TargetView, error)
	Context(context.Context) (ContextView, error)
}

type TargetView struct {
	Name               string `json:"name"`
	Address            string `json:"address"`
	User               string `json:"user"`
	HostKeyAlgorithm   string `json:"host_key_algorithm"`
	HostKeyFingerprint string `json:"host_key_fingerprint"`
	HostKey            string `json:"host_key"`
}

type ContextView struct {
	Version      string                 `json:"version"`
	TrustLevel   string                 `json:"trust_level"`
	Policy       string                 `json:"policy"`
	Instructions string                 `json:"instructions"`
	Hosts        []contextstore.Host    `json:"hosts"`
	Runbooks     []contextstore.Runbook `json:"runbooks"`
}

type Service struct {
	Reader
	contexts *contextstore.Store
	targets  *sshtarget.Store
}

func NewService(reader Reader, contexts *contextstore.Store, targets *sshtarget.Store) (*Service, error) {
	if reader == nil || contexts == nil || targets == nil {
		return nil, errors.New("operator read service requires state, context and target readers")
	}
	return &Service{Reader: reader, contexts: contexts, targets: targets}, nil
}

func (s *Service) Targets(ctx context.Context) ([]TargetView, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	specs := s.targets.List()
	out := make([]TargetView, 0, len(specs))
	for _, spec := range specs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(spec.HostKey + "\n"))
		if err != nil {
			return nil, errors.New("operator target contains invalid pinned host key")
		}
		out = append(out, TargetView{
			Name:               spec.Name,
			Address:            spec.Address,
			User:               spec.User,
			HostKeyAlgorithm:   key.Type(),
			HostKeyFingerprint: ssh.FingerprintSHA256(key),
			HostKey:            spec.HostKey,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *Service) Context(ctx context.Context) (ContextView, error) {
	if err := ctx.Err(); err != nil {
		return ContextView{}, err
	}
	cfg, version, err := s.contexts.Snapshot()
	if err != nil {
		return ContextView{}, err
	}
	return ContextView{
		Version:      version,
		TrustLevel:   domain.Trust0,
		Policy:       cfg.Policy,
		Instructions: cfg.Instructions,
		Hosts:        cfg.Hosts,
		Runbooks:     cfg.Runbooks,
	}, nil
}
