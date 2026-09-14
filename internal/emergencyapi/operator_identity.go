package emergencyapi

import (
	"net/http"

	"github.com/kotaru34/tethys-sentinel/internal/operatoridentity"
)

// withOperatorIdentity is only used behind the authenticated admin bearer
// boundary. Worker/internal requests never pass through this middleware.
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
