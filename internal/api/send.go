package api

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/nc1107/litterbox-local-relay/internal/keys"
	"github.com/nc1107/litterbox-local-relay/internal/push"
)

// dispatchTimeout bounds one request's time at the providers, however slow they are.
const dispatchTimeout = 25 * time.Second

type sendReq struct {
	Messages []sendMessage `json:"messages"`
}

type sendMessage struct {
	Platform string            `json:"platform"`
	Token    string            `json:"token"`
	Title    string            `json:"title"`
	Body     string            `json:"body"`
	Data     map[string]string `json:"data"`

	// CollapseID is optional: a server sets it so a repeat of one alert replaces the earlier
	// notification on the device instead of stacking.
	CollapseID string `json:"collapseId"`
}

type sendResp struct {
	Results []push.Result `json:"results"`
}

// handleSend delivers a batch of notifications on behalf of a registered server. The caller
// is limited by address first, then authenticates with its registration key and is limited
// per message. It gets back one result per token so it can prune the dead ones. The relay
// never logs tokens or notification text, only counts and the key id.
func (s *Server) handleSend(w http.ResponseWriter, r *http.Request) {
	if !s.sendIPLim.Allow(s.clientIP(r)) {
		writeErr(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}
	plain := bearerToken(r)
	if plain == "" {
		writeErr(w, http.StatusUnauthorized, "missing bearer key")
		return
	}
	k, err := s.keys.Verify(r.Context(), plain)
	if err != nil {
		if err == keys.ErrNotFound {
			writeErr(w, http.StatusUnauthorized, "invalid or revoked key")
			return
		}
		log.Printf("relay: verify key: %v", err)
		writeErr(w, http.StatusInternalServerError, "server error")
		return
	}

	var req sendReq
	if err := decodeJSON(w, r, &req, 1<<20); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if len(req.Messages) > s.cfg.MaxMessages {
		writeErr(w, http.StatusBadRequest, "too many messages in one request")
		return
	}
	// Counted in messages, so one request carrying a hundred tokens costs a hundred.
	if !s.sendLim.AllowN(strconv.FormatInt(k.ID, 10), len(req.Messages)) {
		writeErr(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}

	results := make([]push.Result, 0, len(req.Messages))
	var ios, android pending
	retention := time.Duration(s.cfg.TokenRetentionDays) * 24 * time.Hour
	for _, m := range req.Messages {
		if m.Token == "" {
			continue
		}
		platform := push.Platform(m.Platform)
		if !validToken(platform, m.Token) || !validContent(m) {
			results = append(results, push.Result{Token: m.Token, Status: push.StatusError})
			continue
		}
		if s.senderFor(platform) == nil {
			// Checked before binding so a platform nobody can serve never takes a slot.
			results = append(results, push.Result{Token: m.Token, Status: push.StatusUnsupported})
			continue
		}
		if !s.tokenLim.Allow(m.Token) || !s.providerLim.Allow(string(platform)) {
			results = append(results, push.Result{Token: m.Token, Status: push.StatusRateLimited})
			continue
		}
		if err := s.keys.BindToken(r.Context(), k.ID, m.Token, retention, s.cfg.MaxTokensPerKey); err != nil {
			if !errors.Is(err, keys.ErrTokenLimit) {
				log.Printf("relay: bind token: %v", err)
			}
			results = append(results, push.Result{Token: m.Token, Status: push.StatusError})
			continue
		}
		batch := &ios
		if platform == push.PlatformAndroid {
			batch = &android
		}
		batch.slots = append(batch.slots, len(results))
		results = append(results, push.Result{})
		batch.msgs = append(batch.msgs, push.Message{
			Platform:   platform,
			Token:      m.Token,
			Title:      m.Title,
			Body:       m.Body,
			Data:       m.Data,
			CollapseID: m.CollapseID,
		})
	}
	ctx, cancel := context.WithTimeout(r.Context(), dispatchTimeout)
	defer cancel()
	revoke := s.dispatch(ctx, k.ID, s.ios, ios, results)
	revoke = s.dispatch(ctx, k.ID, s.android, android, results) || revoke
	if revoke {
		s.revokeForAbuse(r.Context(), k.ID)
	}

	delivered, unregistered, forbidden, failed := tally(results)
	log.Printf("relay: send key=%d n=%d delivered=%d unregistered=%d forbidden=%d error=%d",
		k.ID, len(results), delivered, unregistered, forbidden, failed)
	writeJSON(w, http.StatusOK, sendResp{Results: results})
}

// pending is one provider's share of a request: the messages to send and where each
// outcome belongs in the response, so skipped entries keep their place.
type pending struct {
	msgs  []push.Message
	slots []int
}

func (s *Server) senderFor(p push.Platform) push.Sender {
	switch p {
	case push.PlatformIOS:
		return s.ios
	case push.PlatformAndroid:
		return s.android
	}
	return nil
}

// dispatch sends a provider's batch and releases the bindings of any token it reports dead,
// so the slots free up and a re-registered device can be claimed again. It reports whether
// the key's recent results have become bad enough to revoke it.
func (s *Server) dispatch(ctx context.Context, keyID int64, sender push.Sender, batch pending, results []push.Result) bool {
	if len(batch.msgs) == 0 {
		return false
	}
	revoke := false
	for i, res := range sender.Send(ctx, batch.msgs) {
		results[batch.slots[i]] = res
		switch res.Status {
		case push.StatusUnregistered:
			s.keys.ReleaseToken(ctx, res.Token)
			revoke = s.health.record(keyID, true) || revoke
		case push.StatusDelivered:
			s.health.record(keyID, false)
		}
	}
	return revoke
}

// revokeForAbuse cuts off a key whose sends are mostly to dead tokens.
func (s *Server) revokeForAbuse(ctx context.Context, keyID int64) {
	if err := s.keys.Revoke(ctx, keyID); err != nil && !errors.Is(err, keys.ErrNotFound) {
		log.Printf("relay: auto-revoke key=%d: %v", keyID, err)
		return
	}
	s.health.forget(keyID)
	log.Printf("relay: auto-revoked key=%d, most of its recent sends were to dead tokens", keyID)
}
