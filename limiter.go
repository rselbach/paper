package main

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// fixedWindowLimiter rate-limits each client key independently so one source
// cannot exhaust the budget for everyone else. Every key shares one aligned
// window and the table is capped, so per-request work stays constant and a
// client cannot grow it without bound.
type fixedWindowLimiter struct {
	mu          sync.Mutex
	limit       int
	window      time.Duration
	maxClients  int
	windowStart time.Time
	clients     map[string]int
	overflow    int
}

func (l *fixedWindowLimiter) Allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.windowStart.IsZero() || now.Before(l.windowStart) || now.Sub(l.windowStart) >= l.window {
		l.windowStart = now
		l.clients = make(map[string]int, len(l.clients))
		l.overflow = 0
	}

	maxClients := l.maxClients
	if maxClients <= 0 {
		maxClients = maxRateLimitClients
	}

	count, tracked := l.clients[key]
	// Once the table is full, untracked keys share a single budget so their
	// number cannot grow the table or the cost of this call.
	if !tracked && len(l.clients) >= maxClients {
		if l.overflow >= l.limit {
			return false
		}
		l.overflow++
		return true
	}
	if count >= l.limit {
		return false
	}
	l.clients[key] = count + 1
	return true
}

// clientKey identifies the rate-limit bucket for a request. Forwarding headers
// are honored only for loopback peers, because the service listens on
// localhost behind a local reverse proxy and any other peer is talking to us
// directly and can forge them.
func clientKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}

	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return clientKeyPrefix(host)
	}
	if forwarded := lastForwardedFor(r.Header.Values("X-Forwarded-For")); forwarded != "" {
		return clientKeyPrefix(forwarded)
	}
	if real := strings.TrimSpace(r.Header.Get("X-Real-IP")); real != "" {
		return clientKeyPrefix(real)
	}
	return clientKeyPrefix(host)
}

// lastForwardedFor returns the rightmost X-Forwarded-For entry. Proxies append
// the address they observed, so every entry to its left was supplied by the
// client and cannot be trusted.
func lastForwardedFor(values []string) string {
	if len(values) == 0 {
		return ""
	}
	parts := strings.Split(values[len(values)-1], ",")
	return strings.TrimSpace(parts[len(parts)-1])
}

// clientKeyPrefix groups IPv6 addresses by /64 so a single allocation cannot
// supply an unbounded number of buckets.
func clientKeyPrefix(host string) string {
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() != nil {
		return host
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}
