package controlapi

import (
	"net/http"

	"github.com/kotaru34/tethys-sentinel/internal/operatoridentity"
)

// withOperatorIdentity attaches accountability metadata forwarded by the
// trusted operator BFF. It must always be placed behind requireAdmin: the
// forwarded identity is not authentication or authorization on its own.
func withOperatorIdentity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		actor, err := operatoridentity.ForwardedActor(r.Header.Get(operatoridentity.ForwardedHeader))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid operator identity")
			return
		}
		next.ServeHTTP(w, r.WithContext(operatoridentity.WithActor(r.Context(), actor)))
	})
}
