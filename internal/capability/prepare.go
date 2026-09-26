package capability

import (
	"errors"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/domain"
)

// PrepareGrant performs capability-secret generation and immutable grant
// preparation without persisting authority. Transactional persistence backends
// use it immediately before their own atomic grant+audit transaction.
func PrepareGrant(grant domain.Grant) (domain.Grant, string, error) {
	if err := validateGrantPermissions(grant.Permissions); err != nil {
		return domain.Grant{}, "", err
	}
	if grant.ID == "" {
		id, err := randomID()
		if err != nil {
			return domain.Grant{}, "", err
		}
		grant.ID = id
	}
	if grant.IssuedAt.IsZero() {
		grant.IssuedAt = time.Now().UTC()
	}
	if !grant.ExpiresAt.After(grant.IssuedAt) {
		return domain.Grant{}, "", errors.New("expiry must be after issue time")
	}
	token, hash, err := Generate()
	if err != nil {
		return domain.Grant{}, "", err
	}
	grant.TokenHash = hash
	return grant, token, nil
}

func validateGrantPermissions(permissions domain.Permissions) error {
	if permissions.UnrestrictedShell && (!permissions.Exec || !permissions.Shell) {
		return errors.New("unrestricted_shell requires both exec and shell permissions")
	}
	return nil
}
