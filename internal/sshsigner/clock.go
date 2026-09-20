package sshsigner

import (
	"errors"
	"time"

	"golang.org/x/crypto/ssh"
)

func NewWithClock(ca ssh.Signer, policy Policy, now func() time.Time) (*Service, error) {
	if now == nil {
		return nil, errors.New("SSH signer clock is required")
	}
	service, err := New(ca, policy)
	if err != nil {
		return nil, err
	}
	service.now = func() time.Time { return now().UTC() }
	return service, nil
}
