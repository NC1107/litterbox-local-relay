package api

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// clientIP is the caller's address, used as the identity for rate limits.
//
// Forwarding headers are believed only when the operator opted in with RELAY_TRUST_PROXY and
// the connection itself came from a trusted proxy. Then every X-Forwarded-For line is read
// (a client may send several), and the chain is walked from the right, skipping trusted
// proxies, to the first address that is not one. That is the last hop a trusted proxy
// vouches for. Taking the rightmost entry alone would name the Cloudflare edge in front of
// Traefik, and taking the leftmost would accept whatever the caller wrote.
func (s *Server) clientIP(r *http.Request) string {
	remote, ok := remoteAddr(r)
	if !ok {
		return r.RemoteAddr
	}
	if !s.cfg.TrustProxy || !s.trusted(remote) {
		return identity(remote)
	}
	var chain []string
	for _, line := range r.Header.Values("X-Forwarded-For") {
		for _, part := range strings.Split(line, ",") {
			chain = append(chain, strings.TrimSpace(part))
		}
	}
	for i := len(chain) - 1; i >= 0; i-- {
		hop, err := netip.ParseAddr(chain[i])
		if err != nil {
			// A garbled entry vouches for nothing, so stop at the proxy that sent it.
			return identity(remote)
		}
		hop = hop.Unmap().WithZone("")
		if !s.trusted(hop) {
			return identity(hop)
		}
	}
	return identity(remote)
}

func remoteAddr(r *http.Request) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap().WithZone(""), true
}

func (s *Server) trusted(addr netip.Addr) bool {
	for _, p := range s.cfg.TrustedProxies {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// identity is what a limiter keys on. An IPv6 customer usually holds a whole /64, so
// limiting single addresses would let one household mint an address per request.
func identity(addr netip.Addr) string {
	if addr.Is6() {
		prefix, err := addr.Prefix(64)
		if err == nil {
			return prefix.String()
		}
	}
	return addr.String()
}
