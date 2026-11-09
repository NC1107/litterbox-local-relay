// Package config loads the relay's runtime settings from the environment, so the service
// stays a single self-contained binary that is easy to run under Docker.
package config

import (
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// Config holds all runtime configuration for the relay.
type Config struct {
	// HTTPAddr is the address the relay listens on, e.g. ":8090".
	HTTPAddr string
	// FCMCredentialsFile points to the Firebase service-account JSON for Android sends.
	// Optional: without it Android tokens are answered "unsupported".
	FCMCredentialsFile string
	// APNs* are the token-based (.p8) credentials for iOS sends. All four of the key path,
	// key id, team id and bundle id are needed together.
	APNsKeyPath    string
	APNsKeyID      string
	APNsTeamID     string
	APNsBundleID   string
	APNsProduction bool
	// TrustProxy makes the relay read X-Forwarded-For at all. Off by default because without
	// a proxy that sets the header, any caller could pick its own rate-limit identity.
	TrustProxy bool
	// TrustedProxies are the networks whose forwarding headers are believed. The client is
	// the first address, walking from the right, that is not in one of them. The default is
	// Cloudflare's published ranges plus private ranges, because Traefik sits behind
	// Cloudflare and so the nearest hop is a Cloudflare edge address.
	TrustedProxies []netip.Prefix
	// RegisterGlobalPerHour and RegisterGlobalBurst bound registrations from everywhere
	// together, on top of the per-IP limit.
	RegisterGlobalPerHour int
	RegisterGlobalBurst   int
	// SendIPPerMinute and SendIPBurst bound requests per client address, ahead of key
	// verification, so unauthenticated floods cannot reach the database.
	SendIPPerMinute int
	SendIPBurst     int
	// TokenPerMinute and TokenBurst bound messages to one device token.
	TokenPerMinute int
	TokenBurst     int
	// APNsPerMinute and APNsBurst are the relay-wide budget for APNs messages.
	APNsPerMinute int
	APNsBurst     int
	// APNsConcurrency bounds simultaneous requests to APNs.
	APNsConcurrency int
	// AdminFailPerMinute bounds failed admin attempts per client address.
	AdminFailPerMinute int
	// DBPath is the SQLite file that stores hashed registration keys.
	DBPath string
	// AdminToken guards the /admin endpoints (list and revoke keys). Empty disables them.
	AdminToken string
	// RegisterPerHour and RegisterBurst bound how often one IP may mint new keys.
	RegisterPerHour int
	RegisterBurst   int
	// SendPerMinute and SendBurst bound how often one key may fan out notifications.
	SendPerMinute int
	SendBurst     int
	// MaxRegistrations is the total number of keys the relay will ever mint.
	MaxRegistrations int
	// TokenRetentionDays is how long a device-token binding may go unused before it is pruned.
	TokenRetentionDays int
	// MaxTokensPerKey caps how many device tokens one registered server may hold.
	MaxTokensPerKey int
	// MaxMessages caps how many device tokens a single /v1/send request may carry.
	MaxMessages int
}

// Load reads configuration from the environment, applying defaults that suit a single
// maintainer-run relay.
func Load() Config {
	return Config{
		HTTPAddr:              getenv("RELAY_HTTP_ADDR", ":8090"),
		FCMCredentialsFile:    getenv("RELAY_FCM_CREDENTIALS_FILE", ""),
		APNsKeyPath:           getenv("RELAY_APNS_KEY_PATH", ""),
		APNsKeyID:             getenv("RELAY_APNS_KEY_ID", ""),
		APNsTeamID:            getenv("RELAY_APNS_TEAM_ID", ""),
		APNsBundleID:          getenv("RELAY_APNS_BUNDLE_ID", ""),
		APNsProduction:        getbool("RELAY_APNS_PRODUCTION", true),
		TrustProxy:            getbool("RELAY_TRUST_PROXY", false),
		DBPath:                getenv("RELAY_DB_PATH", "/data/relay.db"),
		AdminToken:            getenv("RELAY_ADMIN_TOKEN", ""),
		RegisterPerHour:       getint("RELAY_REGISTER_PER_HOUR", 5),
		RegisterBurst:         getint("RELAY_REGISTER_BURST", 3),
		SendPerMinute:         getint("RELAY_SEND_PER_MINUTE", 120),
		SendBurst:             getint("RELAY_SEND_BURST", 200),
		TrustedProxies:        getprefixes("RELAY_TRUSTED_PROXIES", DefaultTrustedProxies),
		RegisterGlobalPerHour: getint("RELAY_REGISTER_GLOBAL_PER_HOUR", 60),
		RegisterGlobalBurst:   getint("RELAY_REGISTER_GLOBAL_BURST", 20),
		SendIPPerMinute:       getint("RELAY_SEND_IP_PER_MINUTE", 120),
		SendIPBurst:           getint("RELAY_SEND_IP_BURST", 60),
		TokenPerMinute:        getint("RELAY_TOKEN_PER_MINUTE", 6),
		TokenBurst:            getint("RELAY_TOKEN_BURST", 10),
		APNsPerMinute:         getint("RELAY_APNS_PER_MINUTE", 600),
		APNsBurst:             getint("RELAY_APNS_BURST", 200),
		APNsConcurrency:       getint("RELAY_APNS_CONCURRENCY", 8),
		AdminFailPerMinute:    getint("RELAY_ADMIN_FAIL_PER_MINUTE", 5),
		MaxRegistrations:      getint("RELAY_MAX_REGISTRATIONS", 10000),
		TokenRetentionDays:    getint("RELAY_TOKEN_RETENTION_DAYS", 90),
		MaxTokensPerKey:       getint("RELAY_MAX_TOKENS_PER_KEY", 50),
		MaxMessages:           getint("RELAY_MAX_MESSAGES", 100),
	}
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getint(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func getbool(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}

// APNsConfigured reports whether every APNs credential is set.
func (c Config) APNsConfigured() bool {
	return c.APNsKeyPath != "" && c.APNsKeyID != "" && c.APNsTeamID != "" && c.APNsBundleID != ""
}

// APNsPartial reports a half-filled APNs setup, which is always a mistake.
func (c Config) APNsPartial() bool {
	any := c.APNsKeyPath != "" || c.APNsKeyID != "" || c.APNsTeamID != "" || c.APNsBundleID != ""
	return any && !c.APNsConfigured()
}

// DefaultTrustedProxies is Cloudflare's published edge ranges plus loopback and private
// ranges, which covers a Traefik container on a Docker network behind Cloudflare.
const DefaultTrustedProxies = "173.245.48.0/20,103.21.244.0/22,103.22.200.0/22,103.31.4.0/22," +
	"141.101.64.0/18,108.162.192.0/18,190.93.240.0/20,188.114.96.0/20,197.234.240.0/22," +
	"198.41.128.0/17,162.158.0.0/15,104.16.0.0/13,104.24.0.0/14,172.64.0.0/13,131.0.72.0/22," +
	"2400:cb00::/32,2606:4700::/32,2803:f800::/32,2405:b500::/32,2405:8100::/32," +
	"2a06:98c0::/29,2c0f:f248::/32," +
	"127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,::1/128,fc00::/7,fe80::/10"

// ParsePrefixes reads a comma-separated list of CIDR ranges.
func ParsePrefixes(list string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, part := range strings.Split(list, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		p, err := netip.ParsePrefix(part)
		if err != nil {
			return nil, err
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

func getprefixes(key, def string) []netip.Prefix {
	list := getenv(key, def)
	out, err := ParsePrefixes(list)
	if err != nil {
		// A typo here would silently change who is trusted, so it must not be ignored.
		log.Fatalf("%s: %v", key, err)
	}
	return out
}

// MinAdminTokenBytes is the shortest admin token the relay accepts.
const MinAdminTokenBytes = 32

// Validate refuses settings the relay must not run with.
func (c Config) Validate() error {
	if c.AdminToken != "" && len(c.AdminToken) < MinAdminTokenBytes {
		return fmt.Errorf("RELAY_ADMIN_TOKEN must be at least %d bytes; generate one with: openssl rand -base64 32", MinAdminTokenBytes)
	}
	if c.APNsPartial() {
		return errors.New("RELAY_APNS_KEY_PATH, RELAY_APNS_KEY_ID, RELAY_APNS_TEAM_ID and RELAY_APNS_BUNDLE_ID must be set together")
	}
	return nil
}
