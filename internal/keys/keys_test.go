package keys

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func openTemp(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestIssueThenVerify(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()

	plain, err := s.Issue(ctx, "https://alpha.example.com", 0)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if !strings.HasPrefix(plain, keyPrefix) {
		t.Errorf("issued key %q lacks the %q prefix", plain, keyPrefix)
	}
	k, err := s.Verify(ctx, plain)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if k.Label != "https://alpha.example.com" {
		t.Errorf("got label=%q", k.Label)
	}
	if k.LastUsedAt == nil {
		t.Error("verify should stamp last-used")
	}
}

func TestVerifyUnknownKey(t *testing.T) {
	s := openTemp(t)
	if _, err := s.Verify(context.Background(), "llr_not-a-real-key"); err != ErrNotFound {
		t.Errorf("want ErrNotFound, got %v", err)
	}
}

func TestRevokeBlocksVerify(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()

	plain, _ := s.Issue(ctx, "", 0)
	k, err := s.Verify(ctx, plain)
	if err != nil {
		t.Fatalf("verify before revoke: %v", err)
	}
	if err := s.Revoke(ctx, k.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := s.Verify(ctx, plain); err != ErrNotFound {
		t.Errorf("a revoked key should verify as ErrNotFound, got %v", err)
	}
}

func TestRevokeUnknownKey(t *testing.T) {
	s := openTemp(t)
	if err := s.Revoke(context.Background(), 9999); err != ErrNotFound {
		t.Errorf("want ErrNotFound revoking a missing key, got %v", err)
	}
}

func TestListNewestFirst(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	_, _ = s.Issue(ctx, "first", 0)
	_, _ = s.Issue(ctx, "second", 0)

	list, err := s.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("want 2 keys, got %d", len(list))
	}
	if list[0].Label != "second" {
		t.Errorf("want newest (second) first, got %q", list[0].Label)
	}
}

func TestDistinctKeysHashDistinctly(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	a, _ := s.Issue(ctx, "", 0)
	b, _ := s.Issue(ctx, "", 0)
	if a == b {
		t.Fatal("two issued keys must differ")
	}
	ka, _ := s.Verify(ctx, a)
	kb, _ := s.Verify(ctx, b)
	if ka.ID == kb.ID {
		t.Error("distinct keys must map to distinct rows")
	}
}

func TestIssueCeilingCountsOnlyUnrevokedKeys(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	var first string
	for i := range 2 {
		plain, err := s.Issue(ctx, "", 2)
		if err != nil {
			t.Fatalf("issue under the ceiling: %v", err)
		}
		if i == 0 {
			first = plain
		}
	}
	if _, err := s.Issue(ctx, "", 2); err != ErrRegistrationCeiling {
		t.Fatalf("issue past the ceiling = %v, want ErrRegistrationCeiling", err)
	}
	k, _ := s.Verify(ctx, first)
	if err := s.Revoke(ctx, k.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Issue(ctx, "", 2); err != nil {
		t.Fatalf("revoking a key must free its slot: %v", err)
	}
}

func TestVerifyWritesLastUsedAtMostOncePerMinute(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	plain, _ := s.Issue(ctx, "", 0)
	k, _ := s.Verify(ctx, plain)

	if _, err := s.db.Exec(`UPDATE keys SET last_used_at = last_used_at - 30 WHERE id = ?`, k.ID); err != nil {
		t.Fatal(err)
	}
	var before int64
	_ = s.db.QueryRow(`SELECT last_used_at FROM keys WHERE id = ?`, k.ID).Scan(&before)
	_, _ = s.Verify(ctx, plain)
	var after int64
	_ = s.db.QueryRow(`SELECT last_used_at FROM keys WHERE id = ?`, k.ID).Scan(&after)
	if after != before {
		t.Fatalf("last_used_at was rewritten within a minute: %d -> %d", before, after)
	}

	if _, err := s.db.Exec(`UPDATE keys SET last_used_at = last_used_at - 120 WHERE id = ?`, k.ID); err != nil {
		t.Fatal(err)
	}
	_, _ = s.Verify(ctx, plain)
	_ = s.db.QueryRow(`SELECT last_used_at FROM keys WHERE id = ?`, k.ID).Scan(&after)
	if after <= before-120 {
		t.Fatalf("last_used_at was not refreshed after a minute: %d", after)
	}
}

func bind(t *testing.T, s *Store, key int64, token string) {
	t.Helper()
	if err := s.BindToken(context.Background(), key, token, 0, 0); err != nil {
		t.Fatalf("bind key %d: %v", key, err)
	}
}

func age(t *testing.T, s *Store, key int64, token string, seconds int) {
	t.Helper()
	if _, err := s.db.Exec(`UPDATE token_owners SET last_seen_at = last_seen_at - ? WHERE token = ? AND key_id = ?`, seconds, token, key); err != nil {
		t.Fatal(err)
	}
}

func TestATokenHasUpToThreeOwners(t *testing.T) {
	s := openTemp(t)
	for key := int64(1); key <= 3; key++ {
		bind(t, s, key, "tok")
	}
	if n, _ := s.OwnerCount(context.Background(), "tok"); n != 3 {
		t.Fatalf("owners = %d, want 3", n)
	}
}

func TestAFourthOwnerEvictsTheLeastRecentlyUsed(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	for key := int64(1); key <= 3; key++ {
		bind(t, s, key, "tok")
	}
	age(t, s, 1, "tok", 300)
	age(t, s, 2, "tok", 100)
	age(t, s, 3, "tok", 200)

	bind(t, s, 4, "tok")

	if held, _ := s.Holds(ctx, 1, "tok"); held {
		t.Error("the owner unused for longest should have been evicted")
	}
	for _, key := range []int64{2, 3, 4} {
		if held, _ := s.Holds(ctx, key, "tok"); !held {
			t.Errorf("key %d should still hold the token", key)
		}
	}
}

func TestSendingRefreshesAnOwnerSoItIsNotTheOneEvicted(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	for key := int64(1); key <= 3; key++ {
		bind(t, s, key, "tok")
		age(t, s, key, "tok", 1000)
	}
	bind(t, s, 1, "tok")
	bind(t, s, 4, "tok")
	if held, _ := s.Holds(ctx, 1, "tok"); !held {
		t.Error("a key that just sent must outlast one that did not")
	}
}

func TestBindTokenHonoursThePerKeyCap(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	for _, tok := range []string{"a", "b"} {
		if err := s.BindToken(ctx, 1, tok, 0, 2); err != nil {
			t.Fatalf("bind %s: %v", tok, err)
		}
	}
	if err := s.BindToken(ctx, 1, "c", 0, 2); err != ErrTokenLimit {
		t.Fatalf("bind past the cap = %v, want ErrTokenLimit", err)
	}
	if err := s.BindToken(ctx, 1, "a", 0, 2); err != nil {
		t.Fatalf("an owned token must still bind at the cap: %v", err)
	}
}

func TestReleaseTokenDropsEveryOwner(t *testing.T) {
	s := openTemp(t)
	bind(t, s, 1, "tok")
	bind(t, s, 2, "tok")
	s.ReleaseToken(context.Background(), "tok")
	if n, _ := s.OwnerCount(context.Background(), "tok"); n != 0 {
		t.Fatalf("owners after release = %d, want 0", n)
	}
}

func TestRevokingAKeyReleasesItsBindings(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	plain, _ := s.Issue(ctx, "", 0)
	k, _ := s.Verify(ctx, plain)
	bind(t, s, k.ID, "tok")
	bind(t, s, 99, "tok")
	if err := s.Revoke(ctx, k.ID); err != nil {
		t.Fatal(err)
	}
	if held, _ := s.Holds(ctx, k.ID, "tok"); held {
		t.Error("a revoked key still holds a token")
	}
	if held, _ := s.Holds(ctx, 99, "tok"); !held {
		t.Error("revoking one key must not touch another key's binding")
	}
}
