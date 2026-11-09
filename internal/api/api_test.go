package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/nc1107/litterbox-local-relay/internal/config"
	"github.com/nc1107/litterbox-local-relay/internal/keys"
	"github.com/nc1107/litterbox-local-relay/internal/push"
)

// fakeProvider records what it was asked to send and reports every token delivered.
type fakeProvider struct {
	got []push.Message
}

func (f *fakeProvider) Send(_ context.Context, msgs []push.Message) []push.Result {
	f.got = append(f.got, msgs...)
	out := make([]push.Result, len(msgs))
	for i, m := range msgs {
		out[i] = push.Result{Token: m.Token, Status: push.StatusDelivered}
	}
	return out
}

// deadProvider reports every token as retired.
type deadProvider struct{}

func (deadProvider) Send(_ context.Context, msgs []push.Message) []push.Result {
	out := make([]push.Result, len(msgs))
	for i, m := range msgs {
		out[i] = push.Result{Token: m.Token, Status: push.StatusUnregistered}
	}
	return out
}

func newTestServer(t *testing.T, cfg config.Config) (*Server, *fakeProvider, *keys.Store) {
	t.Helper()
	store, err := keys.Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	fake := &fakeProvider{}
	return New(cfg, fake, nil, store), fake, store
}

// defaultCfg sets limits high enough not to interfere with tests that aren't about limits.
func defaultCfg() config.Config {
	return config.Config{
		MaxMessages:           100,
		RegisterPerHour:       100000,
		RegisterBurst:         100000,
		RegisterGlobalPerHour: 100000,
		RegisterGlobalBurst:   100000,
		SendPerMinute:         100000,
		SendBurst:             100000,
		SendIPPerMinute:       100000,
		SendIPBurst:           100000,
		TokenPerMinute:        100000,
		TokenBurst:            100000,
		APNsPerMinute:         100000,
		APNsBurst:             100000,
		AdminFailPerMinute:    5,
	}
}

func do(h http.Handler, method, target, body, bearer string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// tok is a valid iOS device token: 64 hex characters, distinct per n.
func tok(n int) string { return fmt.Sprintf("%064x", n+1) }

func msg(n int) string {
	return fmt.Sprintf(`{"platform":"ios","token":%q,"title":"t","body":"b"}`, tok(n))
}

func batch(msgs ...string) string { return `{"messages":[` + strings.Join(msgs, ",") + `]}` }

func send(t *testing.T, h http.Handler, key, body string) sendResp {
	t.Helper()
	rr := do(h, http.MethodPost, "/v1/send", body, key)
	if rr.Code != http.StatusOK {
		t.Fatalf("send = %d, want 200 (body %s)", rr.Code, rr.Body)
	}
	var resp sendResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return resp
}

func issue(t *testing.T, store *keys.Store) (string, int64) {
	t.Helper()
	plain, err := store.Issue(context.Background(), "", 0)
	if err != nil {
		t.Fatal(err)
	}
	k, err := store.Verify(context.Background(), plain)
	if err != nil {
		t.Fatal(err)
	}
	return plain, k.ID
}

// Registration

func TestRegisterIssuesAKeyAndIgnoresAnyBody(t *testing.T) {
	srv, _, store := newTestServer(t, defaultCfg())
	rr := do(srv.Router(), http.MethodPost, "/v1/register", `{"publicUrl":"https://alpha.example.com"}`, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("register = %d, want 200 (body %s)", rr.Code, rr.Body)
	}
	var resp registerResp
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if !strings.HasPrefix(resp.Key, "llr_") {
		t.Fatalf("key %q lacks llr_ prefix", resp.Key)
	}
	k, err := store.Verify(context.Background(), resp.Key)
	if err != nil {
		t.Fatalf("issued key does not verify: %v", err)
	}
	if k.Label != "" {
		t.Errorf("the relay has no use for the public URL, but stored label %q", k.Label)
	}
}

func TestRegisterRateLimitedPerAddress(t *testing.T) {
	cfg := defaultCfg()
	cfg.RegisterBurst = 1
	cfg.RegisterPerHour = 1
	srv, _, _ := newTestServer(t, cfg)
	h := srv.Router()
	if rr := do(h, http.MethodPost, "/v1/register", "", ""); rr.Code != http.StatusOK {
		t.Fatalf("first register = %d, want 200", rr.Code)
	}
	if rr := do(h, http.MethodPost, "/v1/register", "", ""); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("second register = %d, want 429", rr.Code)
	}
}

func TestRegisterHasAGlobalLimitAcrossAddresses(t *testing.T) {
	cfg := defaultCfg()
	cfg.RegisterGlobalBurst = 2
	cfg.RegisterGlobalPerHour = 1
	srv, _, _ := newTestServer(t, cfg)
	h := srv.Router()
	var codes []int
	for i := range 3 {
		req := httptest.NewRequest(http.MethodPost, "/v1/register", nil)
		req.RemoteAddr = fmt.Sprintf("198.51.100.%d:5000", i+1)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		codes = append(codes, rr.Code)
	}
	if codes[0] != 200 || codes[1] != 200 || codes[2] != http.StatusTooManyRequests {
		t.Fatalf("codes = %v, want [200 200 429] from three different addresses", codes)
	}
}

func TestRegisterCeilingIsFreedByRevoking(t *testing.T) {
	cfg := defaultCfg()
	cfg.MaxRegistrations = 1
	cfg.AdminToken = strings.Repeat("a", 32)
	srv, _, store := newTestServer(t, cfg)
	h := srv.Router()
	rr := do(h, http.MethodPost, "/v1/register", "", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("first register = %d, want 200", rr.Code)
	}
	if rr := do(h, http.MethodPost, "/v1/register", "", ""); rr.Code != http.StatusForbidden {
		t.Fatalf("register past the ceiling = %d, want 403", rr.Code)
	}
	var resp registerResp
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	k, _ := store.Verify(context.Background(), resp.Key)
	revoke := "/admin/keys/" + strconv.FormatInt(k.ID, 10) + "/revoke"
	if rr := do(h, http.MethodPost, revoke, "", cfg.AdminToken); rr.Code != http.StatusNoContent {
		t.Fatalf("revoke = %d, want 204", rr.Code)
	}
	if rr := do(h, http.MethodPost, "/v1/register", "", ""); rr.Code != http.StatusOK {
		t.Fatalf("register after a revoke = %d, want 200", rr.Code)
	}
}

// Client address

func ipFor(t *testing.T, trust bool, remote string, headers ...string) string {
	t.Helper()
	cfg := defaultCfg()
	cfg.TrustProxy = trust
	prefixes, err := config.ParsePrefixes(config.DefaultTrustedProxies)
	if err != nil {
		t.Fatal(err)
	}
	cfg.TrustedProxies = prefixes
	srv, _, _ := newTestServer(t, cfg)
	req := httptest.NewRequest(http.MethodPost, "/v1/register", nil)
	req.RemoteAddr = remote
	for _, h := range headers {
		req.Header.Add("X-Forwarded-For", h)
	}
	return srv.clientIP(req)
}

func TestClientIPIgnoresForwardedForUnlessTrusted(t *testing.T) {
	if got := ipFor(t, false, "203.0.113.9:1", "198.51.100.1"); got != "203.0.113.9" {
		t.Errorf("proxy trust off: %q, want the socket address", got)
	}
	if got := ipFor(t, true, "203.0.113.9:1", "198.51.100.1"); got != "203.0.113.9" {
		t.Errorf("untrusted peer: %q, want its own address, since it may have forged the header", got)
	}
}

func TestClientIPWalksPastCloudflareAndTraefik(t *testing.T) {
	// client -> Cloudflare edge -> Traefik container -> relay
	got := ipFor(t, true, "172.18.0.5:1", "198.51.100.7, 104.16.9.9")
	if got != "198.51.100.7" {
		t.Errorf("got %q, want the visitor behind the Cloudflare edge", got)
	}
}

func TestClientIPCannotBeForgedByALeadingEntry(t *testing.T) {
	got := ipFor(t, true, "172.18.0.5:1", "6.6.6.6, 198.51.100.7, 104.16.9.9")
	if got != "198.51.100.7" {
		t.Errorf("got %q, want the entry Cloudflare appended, not the forged one", got)
	}
}

func TestClientIPReadsEveryHeaderLine(t *testing.T) {
	// A second header line is how a client hides a forged value from Header.Get.
	got := ipFor(t, true, "172.18.0.5:1", "6.6.6.6", "198.51.100.7, 104.16.9.9")
	if got != "198.51.100.7" {
		t.Errorf("got %q, want the address from the last header line", got)
	}
}

func TestClientIPFallsBackWhenTheChainIsGarbled(t *testing.T) {
	if got := ipFor(t, true, "172.18.0.5:1", "not-an-ip"); got != "172.18.0.5" {
		t.Errorf("got %q, want the proxy's address", got)
	}
}

func TestClientIPMasksIPv6ToItsSlash64(t *testing.T) {
	a := ipFor(t, true, "172.18.0.5:1", "2001:db8:1:2:aaaa::1, 104.16.9.9")
	b := ipFor(t, true, "172.18.0.5:1", "2001:db8:1:2:bbbb::9, 104.16.9.9")
	if a != b || a != "2001:db8:1:2::/64" {
		t.Errorf("got %q and %q, want both to be 2001:db8:1:2::/64", a, b)
	}
	if netip.MustParsePrefix(a).Bits() != 64 {
		t.Errorf("not a /64: %q", a)
	}
}

// Sending: admission and limits

func TestSendRequiresBearer(t *testing.T) {
	srv, _, _ := newTestServer(t, defaultCfg())
	if rr := do(srv.Router(), http.MethodPost, "/v1/send", batch(), ""); rr.Code != http.StatusUnauthorized {
		t.Fatalf("send without bearer = %d, want 401", rr.Code)
	}
}

func TestSendRejectsUnknownKey(t *testing.T) {
	srv, _, _ := newTestServer(t, defaultCfg())
	if rr := do(srv.Router(), http.MethodPost, "/v1/send", batch(msg(1)), "llr_nope"); rr.Code != http.StatusUnauthorized {
		t.Fatalf("send with unknown key = %d, want 401", rr.Code)
	}
}

func TestSendIsLimitedByAddressBeforeTheKeyIsLookedUp(t *testing.T) {
	cfg := defaultCfg()
	cfg.SendIPBurst = 1
	cfg.SendIPPerMinute = 1
	srv, _, _ := newTestServer(t, cfg)
	h := srv.Router()
	if rr := do(h, http.MethodPost, "/v1/send", batch(), "llr_wrong"); rr.Code != http.StatusUnauthorized {
		t.Fatalf("first bad-key send = %d, want 401", rr.Code)
	}
	if rr := do(h, http.MethodPost, "/v1/send", batch(), "llr_wrong"); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("second bad-key send = %d, want 429 from the address limiter", rr.Code)
	}
}

func TestSendLimiterCountsMessagesNotRequests(t *testing.T) {
	cfg := defaultCfg()
	cfg.SendBurst = 3
	cfg.SendPerMinute = 1
	srv, _, store := newTestServer(t, cfg)
	key, _ := issue(t, store)
	h := srv.Router()

	if rr := do(h, http.MethodPost, "/v1/send", batch(msg(1), msg(2), msg(3), msg(4)), key); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("4 messages against a budget of 3 = %d, want 429", rr.Code)
	}
	if rr := do(h, http.MethodPost, "/v1/send", batch(msg(1), msg(2), msg(3)), key); rr.Code != http.StatusOK {
		t.Fatalf("3 messages = %d, want 200 (the refused request must not spend the budget)", rr.Code)
	}
	if rr := do(h, http.MethodPost, "/v1/send", batch(msg(1)), key); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("a 4th message = %d, want 429", rr.Code)
	}
}

func TestSendRejectsOversizedBatch(t *testing.T) {
	cfg := defaultCfg()
	cfg.MaxMessages = 2
	srv, _, store := newTestServer(t, cfg)
	key, _ := issue(t, store)
	if rr := do(srv.Router(), http.MethodPost, "/v1/send", batch(msg(1), msg(2), msg(3)), key); rr.Code != http.StatusBadRequest {
		t.Fatalf("oversized batch = %d, want 400", rr.Code)
	}
}

func TestOneTokenIsRateLimited(t *testing.T) {
	cfg := defaultCfg()
	cfg.TokenBurst = 2
	cfg.TokenPerMinute = 1
	srv, fake, store := newTestServer(t, cfg)
	key, _ := issue(t, store)
	resp := send(t, srv.Router(), key, batch(msg(1), msg(1), msg(1), msg(2)))
	want := []push.Status{push.StatusDelivered, push.StatusDelivered, push.StatusRateLimited, push.StatusDelivered}
	for i, w := range want {
		if resp.Results[i].Status != w {
			t.Errorf("result %d = %q, want %q", i, resp.Results[i].Status, w)
		}
	}
	if len(fake.got) != 3 {
		t.Errorf("provider saw %d messages, want 3", len(fake.got))
	}
}

func TestTheProviderBudgetIsRelayWide(t *testing.T) {
	cfg := defaultCfg()
	cfg.APNsBurst = 2
	cfg.APNsPerMinute = 1
	srv, fake, store := newTestServer(t, cfg)
	alpha, _ := issue(t, store)
	beta, _ := issue(t, store)
	h := srv.Router()
	send(t, h, alpha, batch(msg(1), msg(2)))
	resp := send(t, h, beta, batch(msg(3)))
	if resp.Results[0].Status != push.StatusRateLimited {
		t.Fatalf("a different key = %q, want rate_limited once the shared budget is spent", resp.Results[0].Status)
	}
	if len(fake.got) != 2 {
		t.Errorf("provider saw %d messages, want 2", len(fake.got))
	}
}

// Sending: validation

func TestIOSTokensMustBeLongHex(t *testing.T) {
	srv, fake, store := newTestServer(t, defaultCfg())
	key, _ := issue(t, store)
	bad := []string{
		strings.Repeat("a", 63),
		strings.Repeat("a", 201),
		strings.Repeat("g", 64),
		strings.Repeat("a", 63) + " ",
		"a",
	}
	var msgs []string
	for _, b := range bad {
		msgs = append(msgs, fmt.Sprintf(`{"platform":"ios","token":%q}`, b))
	}
	resp := send(t, srv.Router(), key, batch(msgs...))
	for i, r := range resp.Results {
		if r.Status != push.StatusError {
			t.Errorf("token %d = %q, want error", i, r.Status)
		}
	}
	if len(fake.got) != 0 {
		t.Fatalf("APNs saw %d malformed tokens, want 0", len(fake.got))
	}
	ok := send(t, srv.Router(), key, batch(fmt.Sprintf(`{"platform":"ios","token":%q}`, strings.Repeat("aB", 32))))
	if ok.Results[0].Status != push.StatusDelivered {
		t.Fatalf("a 64 character hex token = %q, want delivered", ok.Results[0].Status)
	}
}

func TestContentIsCappedToWhatFitsAPNs(t *testing.T) {
	srv, fake, store := newTestServer(t, defaultCfg())
	key, _ := issue(t, store)
	one := func(n int, extra string) string {
		return fmt.Sprintf(`{"platform":"ios","token":%q,%s}`, tok(n), extra)
	}
	data := func(entries int) string {
		var parts []string
		for i := range entries {
			parts = append(parts, fmt.Sprintf(`"k%d":"v"`, i))
		}
		return `"data":{` + strings.Join(parts, ",") + `}`
	}
	cases := map[string]string{
		"title":        one(1, `"title":"`+strings.Repeat("x", 257)+`"`),
		"body":         one(2, `"body":"`+strings.Repeat("x", 1025)+`"`),
		"entries":      one(3, data(11)),
		"value":        one(4, `"data":{"k":"`+strings.Repeat("x", 257)+`"}`),
		"key":          one(5, `"data":{"`+strings.Repeat("k", 33)+`":"v"}`),
		"reserved aps": one(6, `"data":{"aps":"{}"}`),
	}
	for name, m := range cases {
		resp := send(t, srv.Router(), key, batch(m))
		if resp.Results[0].Status != push.StatusError {
			t.Errorf("%s: %q, want error", name, resp.Results[0].Status)
		}
	}
	if len(fake.got) != 0 {
		t.Fatalf("APNs saw %d oversized or reserved messages, want 0", len(fake.got))
	}
	fits := one(7, `"title":"`+strings.Repeat("x", 256)+`","body":"`+strings.Repeat("y", 1024)+`","data":{"kind":"drawer_full"}`)
	if resp := send(t, srv.Router(), key, batch(fits)); resp.Results[0].Status != push.StatusDelivered {
		t.Fatalf("a message at the caps = %q, want delivered", resp.Results[0].Status)
	}
}

func TestSendForwardsCollapseID(t *testing.T) {
	srv, fake, store := newTestServer(t, defaultCfg())
	key, _ := issue(t, store)
	send(t, srv.Router(), key, batch(fmt.Sprintf(`{"platform":"ios","token":%q,"collapseId":"drawer_full"}`, tok(1))))
	if len(fake.got) != 1 || fake.got[0].CollapseID != "drawer_full" {
		t.Fatalf("collapse id not forwarded: %+v", fake.got)
	}
}

// Sending: routing and ownership

func TestAndroidIsUnsupportedWithoutAProviderAndTakesNoSlot(t *testing.T) {
	cfg := defaultCfg()
	cfg.MaxTokensPerKey = 1
	srv, fake, store := newTestServer(t, cfg)
	key, _ := issue(t, store)
	h := srv.Router()

	resp := send(t, h, key, batch(`{"platform":"android","token":"droid"}`))
	if resp.Results[0].Status != push.StatusUnsupported {
		t.Fatalf("android = %q, want unsupported", resp.Results[0].Status)
	}
	if len(fake.got) != 0 {
		t.Fatal("an unsupported message reached a provider")
	}
	if resp := send(t, h, key, batch(msg(1))); resp.Results[0].Status != push.StatusDelivered {
		t.Fatalf("ios after android = %q, want delivered", resp.Results[0].Status)
	}
}

func TestSendRoutesByPlatform(t *testing.T) {
	srv, ios, store := newTestServer(t, defaultCfg())
	android := &fakeProvider{}
	srv.android = android
	key, _ := issue(t, store)
	send(t, srv.Router(), key, batch(msg(1), `{"platform":"android","token":"b"}`))
	if len(ios.got) != 1 || len(android.got) != 1 || android.got[0].Token != "b" {
		t.Fatalf("routing wrong: ios=%+v android=%+v", ios.got, android.got)
	}
}

func TestSendRejectsAMissingOrUnknownPlatform(t *testing.T) {
	srv, fake, store := newTestServer(t, defaultCfg())
	key, _ := issue(t, store)
	resp := send(t, srv.Router(), key, batch(fmt.Sprintf(`{"token":%q}`, tok(1)), fmt.Sprintf(`{"platform":"web","token":%q}`, tok(2))))
	for _, r := range resp.Results {
		if r.Status != push.StatusError {
			t.Errorf("status = %q, want error", r.Status)
		}
	}
	if len(fake.got) != 0 {
		t.Fatal("a message with no usable platform reached a provider")
	}
}

// One server must not be able to lock a phone out of another, so up to three servers can
// hold a token and a newcomer pushes out the one that sent least recently.
func TestSeveralServersCanReachTheSamePhone(t *testing.T) {
	srv, _, store := newTestServer(t, defaultCfg())
	h := srv.Router()
	var ids []int64
	for range 4 {
		key, id := issue(t, store)
		ids = append(ids, id)
		resp := send(t, h, key, batch(msg(1)))
		if resp.Results[0].Status != push.StatusDelivered {
			t.Fatalf("server %d = %q, want delivered", id, resp.Results[0].Status)
		}
	}
	n, _ := store.OwnerCount(context.Background(), tok(1))
	if n != keys.MaxOwnersPerToken {
		t.Fatalf("owners = %d, want %d", n, keys.MaxOwnersPerToken)
	}
	if held, _ := store.Holds(context.Background(), ids[3], tok(1)); !held {
		t.Error("the newest server should hold the token")
	}
}

// A dead token must release its bindings, or the device could never register with another
// server and the owners would keep slots for it.
func TestDeadTokenReleasesItsBindings(t *testing.T) {
	srv, _, store := newTestServer(t, defaultCfg())
	srv.ios = deadProvider{}
	key, _ := issue(t, store)
	send(t, srv.Router(), key, batch(msg(1)))
	if n, _ := store.OwnerCount(context.Background(), tok(1)); n != 0 {
		t.Fatalf("owners of a dead token = %d, want 0", n)
	}
}

func TestAKeySendingMostlyToDeadTokensIsRevoked(t *testing.T) {
	srv, _, store := newTestServer(t, defaultCfg())
	srv.ios = deadProvider{}
	key, id := issue(t, store)
	h := srv.Router()
	var msgs []string
	for i := range healthMinSample {
		msgs = append(msgs, msg(i))
	}
	send(t, h, key, batch(msgs...))
	if rr := do(h, http.MethodPost, "/v1/send", batch(msg(99)), key); rr.Code != http.StatusUnauthorized {
		t.Fatalf("send after auto-revoke = %d, want 401", rr.Code)
	}
	if _, err := store.Verify(context.Background(), key); err != keys.ErrNotFound {
		t.Fatalf("key still verifies after auto-revoke: %v", err)
	}
	if held, _ := store.Holds(context.Background(), id, tok(99)); held {
		t.Error("an auto-revoked key still holds tokens")
	}
}

func TestAHealthyKeyIsNotRevokedByAFewDeadTokens(t *testing.T) {
	h := newHealth()
	for i := range 40 {
		if h.record(1, i%5 == 0) {
			t.Fatalf("a key with 20%% dead tokens was marked for revocation at result %d", i)
		}
	}
}

func TestHealthNeedsASampleBeforeJudging(t *testing.T) {
	h := newHealth()
	for i := range healthMinSample - 1 {
		if h.record(1, true) {
			t.Fatalf("revoked on only %d results", i+1)
		}
	}
	if !h.record(1, true) {
		t.Fatal("a full sample of dead tokens must trip the check")
	}
}

// Admin

func adminServer(t *testing.T) (*Server, string) {
	t.Helper()
	cfg := defaultCfg()
	cfg.AdminToken = strings.Repeat("s", 32)
	srv, _, _ := newTestServer(t, cfg)
	return srv, cfg.AdminToken
}

func TestAdminNeedsTheToken(t *testing.T) {
	srv, token := adminServer(t)
	h := srv.Router()
	if rr := do(h, http.MethodGet, "/admin/keys", "", ""); rr.Code != http.StatusUnauthorized {
		t.Fatalf("admin without token = %d, want 401", rr.Code)
	}
	if rr := do(h, http.MethodGet, "/admin/keys", "", token); rr.Code != http.StatusOK {
		t.Fatalf("admin with token = %d, want 200", rr.Code)
	}
}

func TestAdminIsOffWithoutAToken(t *testing.T) {
	srv, _, _ := newTestServer(t, defaultCfg())
	if rr := do(srv.Router(), http.MethodGet, "/admin/keys", "", ""); rr.Code != http.StatusNotFound {
		t.Fatalf("admin with no token configured = %d, want 404", rr.Code)
	}
}

func TestFailedAdminAttemptsAreRateLimited(t *testing.T) {
	srv, token := adminServer(t)
	h := srv.Router()
	for i := range 5 {
		if rr := do(h, http.MethodGet, "/admin/keys", "", "wrong"); rr.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d = %d, want 401", i, rr.Code)
		}
	}
	if rr := do(h, http.MethodGet, "/admin/keys", "", "wrong"); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("failure past the limit = %d, want 429", rr.Code)
	}
	if rr := do(h, http.MethodGet, "/admin/keys", "", token); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("even the right token = %d, want 429 while the address is locked out", rr.Code)
	}
}

func TestRevokingAKeyStopsDelivery(t *testing.T) {
	cfg := defaultCfg()
	cfg.AdminToken = strings.Repeat("s", 32)
	srv, _, store := newTestServer(t, cfg)
	key, id := issue(t, store)
	h := srv.Router()
	send(t, h, key, batch(msg(1)))
	revoke := "/admin/keys/" + strconv.FormatInt(id, 10) + "/revoke"
	if rr := do(h, http.MethodPost, revoke, "", cfg.AdminToken); rr.Code != http.StatusNoContent {
		t.Fatalf("revoke = %d, want 204", rr.Code)
	}
	if rr := do(h, http.MethodPost, "/v1/send", batch(msg(1)), key); rr.Code != http.StatusUnauthorized {
		t.Fatalf("post-revoke send = %d, want 401", rr.Code)
	}
	if held, _ := store.Holds(context.Background(), id, tok(1)); held {
		t.Error("revoking left the key's bindings behind")
	}
}
