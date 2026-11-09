package fcm

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

// testSender points a Sender at a fake FCM so Send can be exercised without credentials.
func testSender(endpoint string) *Sender {
	return &Sender{
		tokens:    oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test"}),
		projectID: "example-project",
		http:      &http.Client{Timeout: 5 * time.Second},
		endpoint:  endpoint,
	}
}

func TestErrorCode(t *testing.T) {
	tests := []struct{ name, body, want string }{
		{"unregistered", `{"error":{"code":404,"status":"NOT_FOUND","details":[
			{"errorCode":"UNREGISTERED"}]}}`, "UNREGISTERED"},
		{"falls back to status", `{"error":{"code":401,"status":"UNAUTHENTICATED"}}`, "UNAUTHENTICATED"},
		{"not json", `<html>502</html>`, ""},
		{"empty", ``, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := errorCode([]byte(tt.body)); got != tt.want {
				t.Errorf("errorCode() = %q, want %q", got, tt.want)
			}
		})
	}
}

// Send must map each FCM response to the right per-token status, in input order, so the
// caller can prune exactly the dead tokens.
func TestSendMapsPerTokenStatus(t *testing.T) {
	fcm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch {
		case strings.Contains(string(body), "dead"):
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":{"status":"NOT_FOUND","details":[{"errorCode":"UNREGISTERED"}]}}`))
		case strings.Contains(string(body), "boom"):
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":{"status":"INTERNAL"}}`))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer fcm.Close()

	s := testSender(fcm.URL)
	results := s.Send(context.Background(), []Message{
		{Token: "good"}, {Token: "dead"}, {Token: "boom"},
	})

	want := []Result{
		{Token: "good", Status: StatusDelivered},
		{Token: "dead", Status: StatusUnregistered},
		{Token: "boom", Status: StatusError},
	}
	if len(results) != len(want) {
		t.Fatalf("got %d results, want %d", len(results), len(want))
	}
	for i := range want {
		if results[i] != want[i] {
			t.Errorf("result %d = %+v, want %+v", i, results[i], want[i])
		}
	}
}

// captureBody runs one Send against a fake FCM and returns the message object it posted.
func captureBody(t *testing.T, m Message) map[string]any {
	t.Helper()
	var payload map[string]any
	fcm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode request: %v", err)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer fcm.Close()

	testSender(fcm.URL).Send(context.Background(), []Message{m})
	message, ok := payload["message"].(map[string]any)
	if !ok {
		t.Fatalf("no message object in payload: %v", payload)
	}
	return message
}

// A collapse id has to reach both platforms, since the point is one device entry per event
// whichever OS the member is on.
func TestSendAppliesCollapseIDToBothPlatforms(t *testing.T) {
	message := captureBody(t, Message{Token: "tok", Title: "hi", CollapseID: "xpost-42"})

	apns, _ := message["apns"].(map[string]any)
	headers, _ := apns["headers"].(map[string]any)
	if got := headers["apns-collapse-id"]; got != "xpost-42" {
		t.Errorf("apns-collapse-id = %v, want xpost-42 (message %v)", got, message)
	}
	android, _ := message["android"].(map[string]any)
	notification, _ := android["notification"].(map[string]any)
	if got := notification["tag"]; got != "xpost-42" {
		t.Errorf("android tag = %v, want xpost-42 (message %v)", got, message)
	}
}

// Back-compat pin: a message with no collapse id must produce the payload servers were
// already getting, with no platform blocks that could change how FCM renders it.
func TestSendWithoutCollapseIDKeepsThePayloadUnchanged(t *testing.T) {
	message := captureBody(t, Message{Token: "tok", Title: "hi", Body: "there",
		Data: map[string]string{"type": "post"}})

	want := map[string]any{
		"token":        "tok",
		"notification": map[string]any{"title": "hi", "body": "there"},
		"data":         map[string]any{"type": "post"},
	}
	if !reflect.DeepEqual(message, want) {
		t.Errorf("payload changed:\n got %v\nwant %v", message, want)
	}
}

// APNs rejects a collapse id over 64 bytes, which would lose the notification entirely, so
// an over-long id is trimmed to a valid one instead.
func TestSendTrimsAnOverlongCollapseID(t *testing.T) {
	message := captureBody(t, Message{Token: "tok", CollapseID: strings.Repeat("x", 100)})

	apns, _ := message["apns"].(map[string]any)
	headers, _ := apns["headers"].(map[string]any)
	got, _ := headers["apns-collapse-id"].(string)
	if len(got) != collapseIDMax {
		t.Errorf("collapse id is %d bytes, want it trimmed to %d", len(got), collapseIDMax)
	}
}

// A notification's title and body must never reach the logs, whatever FCM answers.
func TestSendNeverLogsContent(t *testing.T) {
	fcm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":{"status":"INTERNAL"}}`))
	}))
	defer fcm.Close()

	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(nil) })

	s := testSender(fcm.URL)
	s.Send(context.Background(), []Message{{Token: "tok", Title: "Alice checked in", Body: "at the gym"}})

	for _, secret := range []string{"Alice", "gym", "tok"} {
		if strings.Contains(buf.String(), secret) {
			t.Errorf("log leaked %q:\n%s", secret, buf.String())
		}
	}
}
