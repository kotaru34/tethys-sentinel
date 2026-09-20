package capability

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
)

const (
	prefix     = "tsc_"
	randomSize = 32
)

var ErrMalformedToken = errors.New("malformed capability token")

func Generate() (string, [32]byte, error) {
	buf := make([]byte, randomSize)
	if _, err := rand.Read(buf); err != nil {
		return "", [32]byte{}, err
	}

	token := prefix + base64.RawURLEncoding.EncodeToString(buf)
	return token, Hash(token), nil
}

func Hash(token string) [32]byte {
	return sha256.Sum256([]byte(token))
}

func ValidateFormat(token string) error {
	if !strings.HasPrefix(token, prefix) {
		return ErrMalformedToken
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(token, prefix))
	if err != nil || len(raw) != randomSize {
		return ErrMalformedToken
	}
	return nil
}
