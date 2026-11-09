package api

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/nc1107/litterbox-local-relay/internal/push"
)

// writeJSON renders v as a JSON response with the given status.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeErr renders a JSON {"error": msg} with the given status.
func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// decodeJSON reads a JSON body up to maxBytes into v, rejecting unknown fields.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any, maxBytes int64) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBytes))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// bearerToken extracts the token from an "Authorization: Bearer <token>" header.
func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
		return strings.TrimSpace(h[len(prefix):])
	}
	return ""
}

// recoverer turns a handler panic into a 500 instead of crashing the process.
func recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("relay: recovered from panic: %v", rec)
				writeErr(w, http.StatusInternalServerError, "server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

const (
	// maxTokenLen is generous for FCM registration tokens, which run to a few hundred bytes.
	maxTokenLen = 1024
	// APNs device tokens are 32 bytes today and Apple allows them to grow, so hex of 64
	// characters or more up to a safe ceiling is accepted.
	minAPNsTokenLen = 64
	maxAPNsTokenLen = 200

	// APNs rejects a payload over 4 KB. These caps leave room for the envelope and for the
	// data entries, so no accepted message can be refused for size.
	maxTitleBytes     = 256
	maxBodyBytes      = 1024
	maxDataEntries    = 10
	maxDataKeyBytes   = 32
	maxDataValueBytes = 256
)

// validToken keeps junk out of the binding table and junk away from APNs. An iOS token must
// be hex of a plausible length, so a caller cannot spend the relay's APNs standing on
// strings Apple will only reject.
func validToken(platform push.Platform, token string) bool {
	if platform == push.PlatformIOS {
		if len(token) < minAPNsTokenLen || len(token) > maxAPNsTokenLen {
			return false
		}
		for i := 0; i < len(token); i++ {
			c := token[i]
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
				return false
			}
		}
		return true
	}
	if platform != push.PlatformAndroid || len(token) == 0 || len(token) > maxTokenLen {
		return false
	}
	for i := 0; i < len(token); i++ {
		if token[i] <= ' ' || token[i] >= 0x7f {
			return false
		}
	}
	return true
}

// validContent rejects a message that would not fit APNs' payload, or that tries to set the
// reserved "aps" key and so rewrite the notification itself.
func validContent(m sendMessage) bool {
	if len(m.Title) > maxTitleBytes || len(m.Body) > maxBodyBytes || len(m.Data) > maxDataEntries {
		return false
	}
	for k, v := range m.Data {
		if k == "aps" || len(k) == 0 || len(k) > maxDataKeyBytes || len(v) > maxDataValueBytes {
			return false
		}
	}
	return true
}

// tally counts delivery outcomes for logging, without touching tokens or content.
func tally(results []push.Result) (delivered, unregistered, forbidden, failed int) {
	for _, r := range results {
		switch r.Status {
		case push.StatusDelivered:
			delivered++
		case push.StatusUnregistered:
			unregistered++
		case push.StatusForbidden:
			forbidden++
		default:
			failed++
		}
	}
	return
}
