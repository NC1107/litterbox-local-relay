// Package push holds the types every delivery provider shares, so the API can route a
// message by platform without knowing which provider sits behind it.
package push

import "context"

// Platform names the delivery network a device token belongs to.
type Platform string

const (
	PlatformIOS     Platform = "ios"
	PlatformAndroid Platform = "android"
)

// Message is a single visible notification bound for one device token.
type Message struct {
	Platform Platform
	Token    string
	Title    string
	Body     string
	Data     map[string]string

	// CollapseID folds repeat deliveries of one event into a single entry on the device.
	// Empty means no collapsing.
	CollapseID string
}

// Status is the delivery outcome for one token.
type Status string

const (
	// StatusDelivered means the provider accepted the message.
	StatusDelivered Status = "delivered"
	// StatusUnregistered means the provider rejected the token as dead; the caller should
	// delete it from its own store.
	StatusUnregistered Status = "unregistered"
	// StatusForbidden is set by the relay, never by a provider: the token is bound to a
	// different registered server, so nothing was sent.
	StatusForbidden Status = "forbidden"
	// StatusUnsupported means this relay has no provider configured for the token's
	// platform. Unlike an error it will not succeed on retry, and unlike unregistered the
	// token is not dead, so the caller should keep it.
	StatusUnsupported Status = "unsupported"
	// StatusRateLimited means a per-token or relay-wide budget was spent. It is worth
	// retrying later and says nothing about the token itself.
	StatusRateLimited Status = "rate_limited"
	// StatusError means the send failed for some other reason and may be worth a retry.
	StatusError Status = "error"
)

// Result pairs an input token with its delivery outcome.
type Result struct {
	Token  string `json:"token"`
	Status Status `json:"status"`
}

// Sender delivers messages and returns one Result per input, in the same order. It must
// never log tokens or message content.
type Sender interface {
	Send(ctx context.Context, msgs []Message) []Result
}
