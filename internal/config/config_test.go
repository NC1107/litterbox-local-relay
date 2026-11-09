package config

import (
	"net/netip"
	"strings"
	"testing"
)

func TestValidateRefusesAShortAdminToken(t *testing.T) {
	if err := (Config{AdminToken: strings.Repeat("x", 31)}).Validate(); err == nil {
		t.Fatal("a 31 byte admin token was accepted")
	}
	if err := (Config{AdminToken: strings.Repeat("x", 32)}).Validate(); err != nil {
		t.Fatalf("a 32 byte admin token was refused: %v", err)
	}
	if err := (Config{}).Validate(); err != nil {
		t.Fatalf("no admin token must be allowed, it just disables admin: %v", err)
	}
}

func TestValidateRefusesHalfAnAPNsSetup(t *testing.T) {
	if err := (Config{APNsKeyID: "ABC"}).Validate(); err == nil {
		t.Fatal("a partial APNs setup was accepted")
	}
}

func TestDefaultTrustedProxiesCoverCloudflareAndPrivateRanges(t *testing.T) {
	prefixes, err := ParsePrefixes(DefaultTrustedProxies)
	if err != nil {
		t.Fatal(err)
	}
	has := func(addr string) bool {
		a := netip.MustParseAddr(addr)
		for _, p := range prefixes {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}
	for _, addr := range []string{"104.16.1.1", "172.67.5.5", "2606:4700::1", "10.1.2.3", "172.18.0.2", "127.0.0.1"} {
		if !has(addr) {
			t.Errorf("%s should be trusted by default", addr)
		}
	}
	for _, addr := range []string{"8.8.8.8", "203.0.113.9", "2001:db8::1"} {
		if has(addr) {
			t.Errorf("%s should not be trusted by default", addr)
		}
	}
}
