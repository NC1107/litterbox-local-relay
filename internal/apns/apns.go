// Package apns delivers visible notifications to iOS devices straight through Apple Push
// Notification service, using a token-based (.p8) key via the apns2 client.
package apns

import (
	"context"
	"fmt"
	"log"
	"sync"

	"github.com/sideshow/apns2"
	"github.com/sideshow/apns2/payload"
	"github.com/sideshow/apns2/token"

	"github.com/nc1107/litterbox-local-relay/internal/push"
)

// collapseIDMax is APNs' hard limit on the apns-collapse-id header. A longer value makes
// APNs reject the notification outright, so an over-long id is dropped instead.
const collapseIDMax = 64

// client is the slice of *apns2.Client this package uses, named as an interface so tests
// can substitute a fake gateway.
type client interface {
	PushWithContext(ctx apns2.Context, n *apns2.Notification) (*apns2.Response, error)
}

// Config is the token-based credential set required to reach APNs.
type Config struct {
	// KeyPath is the .p8 private key downloaded from the Apple Developer portal.
	KeyPath string
	// KeyID is the 10-character identifier of that key.
	KeyID string
	// TeamID is the 10-character Apple Developer Team ID.
	TeamID string
	// BundleID is the app's bundle identifier, used as the APNs topic.
	BundleID string
	// Production selects the production gateway. Debug builds register against the sandbox.
	Production bool
	// Concurrency bounds simultaneous requests to APNs. Zero means 8.
	Concurrency int
}

// Sender holds the APNs client and posts notifications to the gateway.
type Sender struct {
	client   client
	bundleID string
	// slots bounds simultaneous requests to APNs across every caller, so a large batch
	// cannot open an unbounded number of connections.
	slots chan struct{}
}

func newSender(c client, bundleID string, concurrency int) *Sender {
	if concurrency < 1 {
		concurrency = 1
	}
	return &Sender{client: c, bundleID: bundleID, slots: make(chan struct{}, concurrency)}
}

// New builds a Sender from a .p8 key. A key that is present but unusable is a real
// misconfiguration and is returned as an error.
func New(cfg Config) (*Sender, error) {
	authKey, err := token.AuthKeyFromFile(cfg.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("apns: read .p8 key: %w", err)
	}
	c := apns2.NewTokenClient(&token.Token{AuthKey: authKey, KeyID: cfg.KeyID, TeamID: cfg.TeamID})
	if cfg.Production {
		c = c.Production()
	} else {
		c = c.Development()
	}
	if cfg.Concurrency == 0 {
		cfg.Concurrency = 8
	}
	return newSender(c, cfg.BundleID, cfg.Concurrency), nil
}

// Send posts every message, a bounded number at a time, and returns one Result per input in
// the same order. A message still waiting for a slot when ctx ends comes back as an error.
func (s *Sender) Send(ctx context.Context, msgs []push.Message) []push.Result {
	results := make([]push.Result, len(msgs))
	var wg sync.WaitGroup
	for i, m := range msgs {
		results[i] = push.Result{Token: m.Token, Status: push.StatusError}
		// select picks at random when both cases are ready, so a spent context is checked first.
		if ctx.Err() != nil {
			continue
		}
		select {
		case s.slots <- struct{}{}:
		case <-ctx.Done():
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-s.slots }()
			results[i].Status = s.sendOne(ctx, m)
		}()
	}
	wg.Wait()
	return results
}

func (s *Sender) sendOne(ctx context.Context, m push.Message) push.Status {
	p := payload.NewPayload().AlertTitle(m.Title).AlertBody(m.Body).Sound("default")
	for k, v := range m.Data {
		p.Custom(k, v)
	}
	n := &apns2.Notification{
		DeviceToken: m.Token,
		Topic:       s.bundleID,
		PushType:    apns2.PushTypeAlert,
		Priority:    apns2.PriorityHigh,
		Payload:     p,
	}
	if m.CollapseID != "" && len(m.CollapseID) <= collapseIDMax {
		n.CollapseID = m.CollapseID
	}
	resp, err := s.client.PushWithContext(ctx, n)
	if err != nil {
		return push.StatusError
	}
	if resp.Sent() {
		return push.StatusDelivered
	}
	switch resp.Reason {
	case apns2.ReasonUnregistered, apns2.ReasonBadDeviceToken, apns2.ReasonExpiredToken:
		return push.StatusUnregistered
	case apns2.ReasonExpiredProviderToken, apns2.ReasonInvalidProviderToken,
		apns2.ReasonMissingProviderToken, apns2.ReasonForbidden:
		// Credential trouble fails every send until the operator fixes the key, so it must
		// not look like a stale device token, which is silent.
		log.Printf("relay: apns rejected the provider credential (reason=%s); every ios send will fail until the key is fixed", resp.Reason)
		return push.StatusError
	default:
		return push.StatusError
	}
}
