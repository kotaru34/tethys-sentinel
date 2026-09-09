package internalapi

import "github.com/kotaru34/tethys-sentinel/internal/domain"

type IntrospectRequest struct {
	TokenHash string `json:"token_hash"`
}

type IntrospectResponse struct {
	Grant domain.Grant `json:"grant"`
}
