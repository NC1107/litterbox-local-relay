package api

import (
	"errors"
	"log"
	"net/http"

	"github.com/nc1107/litterbox-local-relay/internal/keys"
)

type registerResp struct {
	Key string `json:"key"`
}

// handleRegister mints a scoped key for a self-hosting server. It is self-serve: a server
// calls this once on first boot and stores the returned key. Registration is limited per
// address and again across all addresses, so neither one host nor a spread of them can
// mass-mint. The request body is never read, because the relay has no use for anything a
// server could tell it about itself, and so it neither stores nor logs it.
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if !s.registerLim.Allow(s.clientIP(r)) || !s.registerGlobalLim.Allow("all") {
		writeErr(w, http.StatusTooManyRequests, "too many registrations, try again later")
		return
	}
	key, err := s.keys.Issue(r.Context(), "", int64(s.cfg.MaxRegistrations))
	if err != nil {
		if errors.Is(err, keys.ErrRegistrationCeiling) {
			writeErr(w, http.StatusForbidden, "relay has reached its maximum number of registrations")
			return
		}
		log.Printf("relay: issue key: %v", err)
		writeErr(w, http.StatusInternalServerError, "could not issue key")
		return
	}
	log.Print("relay: issued key")
	writeJSON(w, http.StatusOK, registerResp{Key: key})
}
