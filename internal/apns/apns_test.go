package apns

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sideshow/apns2"

	"github.com/nc1107/litterbox-local-relay/internal/push"
)

type fakeClient struct {
	resp *apns2.Response
	err  error
	got  []*apns2.Notification
}

func (f *fakeClient) PushWithContext(_ apns2.Context, n *apns2.Notification) (*apns2.Response, error) {
	f.got = append(f.got, n)
	return f.resp, f.err
}

func TestSendMapsResponseToStatus(t *testing.T) {
	tests := []struct {
		name string
		resp *apns2.Response
		err  error
		want push.Status
	}{
		{"delivered", &apns2.Response{StatusCode: 200}, nil, push.StatusDelivered},
		{"unregistered token", &apns2.Response{StatusCode: 410, Reason: apns2.ReasonUnregistered}, nil, push.StatusUnregistered},
		{"bad device token", &apns2.Response{StatusCode: 400, Reason: apns2.ReasonBadDeviceToken}, nil, push.StatusUnregistered},
		{"expired token", &apns2.Response{StatusCode: 410, Reason: apns2.ReasonExpiredToken}, nil, push.StatusUnregistered},
		{"credential rejected", &apns2.Response{StatusCode: 403, Reason: apns2.ReasonInvalidProviderToken}, nil, push.StatusError},
		{"other rejection", &apns2.Response{StatusCode: 400, Reason: apns2.ReasonPayloadTooLarge}, nil, push.StatusError},
		{"transport error", nil, errors.New("boom"), push.StatusError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newSender(&fakeClient{resp: tt.resp, err: tt.err}, "com.example.app", 4)
			results := s.Send(context.Background(), []push.Message{{Token: "tok", Title: "t", Body: "b"}})
			if len(results) != 1 || results[0].Status != tt.want {
				t.Fatalf("results = %+v, want status %v", results, tt.want)
			}
		})
	}
}

func TestSendBuildsAVisibleAlert(t *testing.T) {
	fc := &fakeClient{resp: &apns2.Response{StatusCode: 200}}
	s := newSender(fc, "com.example.app", 4)
	s.Send(context.Background(), []push.Message{{
		Token: "tok", Title: "Litter robot", Body: "Drawer full.",
		Data: map[string]string{"kind": "drawer_full"}, CollapseID: "drawer_full",
	}})

	n := fc.got[0]
	if n.Topic != "com.example.app" || n.PushType != apns2.PushTypeAlert || n.CollapseID != "drawer_full" {
		t.Fatalf("notification = %+v", n)
	}
	raw, _ := json.Marshal(n.Payload)
	for _, want := range []string{`"title":"Litter robot"`, `"body":"Drawer full."`, `"kind":"drawer_full"`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("payload %s lacks %s", raw, want)
		}
	}
}

func TestSendDropsAnOverlongCollapseID(t *testing.T) {
	fc := &fakeClient{resp: &apns2.Response{StatusCode: 200}}
	s := newSender(fc, "com.example.app", 4)
	s.Send(context.Background(), []push.Message{{Token: "tok", CollapseID: strings.Repeat("x", 65)}})
	if fc.got[0].CollapseID != "" {
		t.Fatalf("collapse id %q should have been dropped", fc.got[0].CollapseID)
	}
}

type slowClient struct {
	mu       sync.Mutex
	inflight int
	peak     int
}

func (c *slowClient) PushWithContext(_ apns2.Context, _ *apns2.Notification) (*apns2.Response, error) {
	c.mu.Lock()
	c.inflight++
	if c.inflight > c.peak {
		c.peak = c.inflight
	}
	c.mu.Unlock()
	time.Sleep(5 * time.Millisecond)
	c.mu.Lock()
	c.inflight--
	c.mu.Unlock()
	return &apns2.Response{StatusCode: 200}, nil
}

func TestSendNeverExceedsTheConcurrencyBound(t *testing.T) {
	c := &slowClient{}
	s := newSender(c, "com.example.app", 3)
	msgs := make([]push.Message, 40)
	for i := range msgs {
		msgs[i] = push.Message{Token: "tok"}
	}
	results := s.Send(context.Background(), msgs)
	for i, r := range results {
		if r.Status != push.StatusDelivered {
			t.Fatalf("result %d = %q, want delivered", i, r.Status)
		}
	}
	if c.peak > 3 {
		t.Fatalf("peak concurrency %d exceeds the bound of 3", c.peak)
	}
}

func TestSendGivesUpOnAMessageWhenTheContextEnds(t *testing.T) {
	s := newSender(&slowClient{}, "com.example.app", 1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	results := s.Send(ctx, []push.Message{{Token: "a"}, {Token: "b"}})
	for _, r := range results {
		if r.Status == push.StatusDelivered {
			t.Fatal("a message was sent after its context ended")
		}
	}
}
