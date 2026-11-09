// Package api wires the relay's HTTP endpoints: self-serve key registration, the
// authenticated send fan-out, a health check, and a token-gated admin surface.
package api

import (
	"net/http"

	"github.com/nc1107/litterbox-local-relay/internal/config"
	"github.com/nc1107/litterbox-local-relay/internal/keys"
	"github.com/nc1107/litterbox-local-relay/internal/push"
	"github.com/nc1107/litterbox-local-relay/internal/ratelimit"
)

// Server holds dependencies shared by all handlers.
type Server struct {
	cfg     config.Config
	ios     push.Sender // APNs, nil when not configured
	android push.Sender // FCM, nil when not configured
	keys    *keys.Store
	health  *health

	registerLim       *ratelimit.Limiter // per client address
	registerGlobalLim *ratelimit.Limiter // all addresses together
	// sendIPLim is checked before the key is looked up, so an unauthenticated flood never
	// reaches the single-connection key store. sendLim is the per-key budget, counted in
	// messages. tokenLim and providerLim bound one device and one delivery network.
	sendIPLim    *ratelimit.Limiter
	sendLim      *ratelimit.Limiter
	tokenLim     *ratelimit.Limiter
	providerLim  *ratelimit.Limiter
	adminFailLim *ratelimit.Limiter
}

// New constructs a Server.
func New(cfg config.Config, ios, android push.Sender, store *keys.Store) *Server {
	return &Server{
		cfg:               cfg,
		ios:               ios,
		android:           android,
		keys:              store,
		health:            newHealth(),
		registerLim:       ratelimit.New(float64(cfg.RegisterPerHour)/60.0, cfg.RegisterBurst),
		registerGlobalLim: ratelimit.New(float64(cfg.RegisterGlobalPerHour)/60.0, cfg.RegisterGlobalBurst),
		sendIPLim:         ratelimit.New(float64(cfg.SendIPPerMinute), cfg.SendIPBurst),
		sendLim:           ratelimit.New(float64(cfg.SendPerMinute), cfg.SendBurst),
		tokenLim:          ratelimit.New(float64(cfg.TokenPerMinute), cfg.TokenBurst),
		providerLim:       ratelimit.New(float64(cfg.APNsPerMinute), cfg.APNsBurst),
		adminFailLim:      ratelimit.New(float64(cfg.AdminFailPerMinute), cfg.AdminFailPerMinute),
	}
}

// Router builds the HTTP handler. Routing uses net/http's method+path patterns (Go 1.22+),
// keeping the relay free of a router dependency.
func (s *Server) Router() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("POST /v1/register", s.handleRegister)
	mux.HandleFunc("POST /v1/send", s.handleSend)

	// Admin is only mounted when a token is configured, and every request must carry it.
	// The proxy rule keeps it off the public hostname as well.
	if s.cfg.AdminToken != "" {
		mux.HandleFunc("GET /admin/keys", s.requireAdmin(s.handleAdminListKeys))
		mux.HandleFunc("POST /admin/keys/{id}/revoke", s.requireAdmin(s.handleAdminRevokeKey))
	}
	return recoverer(mux)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
