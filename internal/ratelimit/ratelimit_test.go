package ratelimit

import (
	"testing"
	"time"
)

func TestAllowsUpToBurstThenDenies(t *testing.T) {
	// No refill worth mentioning within the test's runtime, so the burst is the whole budget.
	l := New(0, 3)
	for i := 0; i < 3; i++ {
		if !l.Allow("k") {
			t.Fatalf("call %d should have been allowed within the burst of 3", i+1)
		}
	}
	if l.Allow("k") {
		t.Fatal("a 4th call should be denied once the burst is spent")
	}
}

func TestKeysAreIndependent(t *testing.T) {
	l := New(0, 1)
	if !l.Allow("a") {
		t.Fatal("first key should be allowed")
	}
	if !l.Allow("b") {
		t.Fatal("a different key has its own bucket and should be allowed")
	}
	if l.Allow("a") {
		t.Fatal("the first key's bucket is spent")
	}
}

func TestRefillsOverTime(t *testing.T) {
	// 60/min = 1/sec. Spend the single-token burst, then hand the bucket a second of
	// elapsed time by moving its last-seen back, and it should allow again.
	l := New(60, 1)
	if !l.Allow("k") {
		t.Fatal("first call should be allowed")
	}
	if l.Allow("k") {
		t.Fatal("second immediate call should be denied")
	}
	l.mu.Lock()
	l.buckets["k"].last = l.buckets["k"].last.Add(-2 * time.Second)
	l.mu.Unlock()
	if !l.Allow("k") {
		t.Fatal("after ~2s of refill the call should be allowed again")
	}
}

func TestAllowNConsumesAllOrNothing(t *testing.T) {
	l := New(0, 10)
	if !l.AllowN("k", 6) {
		t.Fatal("6 of 10 should fit")
	}
	if l.AllowN("k", 6) {
		t.Fatal("6 more must not fit in the 4 that are left")
	}
	if !l.AllowN("k", 4) {
		t.Fatal("a refused request must not have spent the remaining 4")
	}
}

func TestAllowNRefusesMoreThanTheBurstEvenWhenIdle(t *testing.T) {
	l := New(60, 5)
	if l.AllowN("k", 6) {
		t.Fatal("a request larger than the burst can never be granted")
	}
}

func TestPeekDoesNotConsume(t *testing.T) {
	l := New(0, 1)
	for range 3 {
		if !l.Peek("k") {
			t.Fatal("peeking must not use up the token")
		}
	}
	if !l.Allow("k") {
		t.Fatal("the token should still be there")
	}
	if l.Peek("k") {
		t.Fatal("peek should report an empty bucket")
	}
}
