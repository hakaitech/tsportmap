// Package relay copies bytes between an accepted connection and an onward dial.
//
// It is deliberately transport-agnostic and knows nothing about Tailscale: the
// same code serves egress (local listener, tsnet dial) and ingress (tsnet
// listener, local dial). Which side is which is the caller's business.
package relay

import (
	"context"
	"net"
	"net/netip"
	"time"
)

// DialFunc opens the onward leg of a session.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// Options configures a relay. The zero value is usable for TCP.
type Options struct {
	// Name labels this relay in logs and metrics.
	Name string

	// Target is the onward address passed to DialFunc.
	Target string

	// DialTimeout bounds a single onward dial. Zero means no timeout.
	DialTimeout time.Duration

	// Idle closes a session that has moved no bytes in either direction for
	// this long. Zero disables idle reaping.
	Idle time.Duration

	// Allow, when non-empty, restricts which source addresses may connect.
	Allow []netip.Prefix

	// Metrics receives per-session accounting. Never nil in production; a nil
	// Metrics is tolerated and means "do not record".
	Metrics Recorder
}

// Recorder accounts relay activity. Implementations must be safe for
// concurrent use.
type Recorder interface {
	// SessionOpened is called once per accepted session.
	SessionOpened(name string)
	// SessionClosed reports a finished session and the bytes moved in each
	// direction: up is client->target, down is target->client.
	SessionClosed(name string, up, down int64, d time.Duration)
	// DialFailed reports an onward dial that did not succeed.
	DialFailed(name, reason string)
	// Rejected reports a session refused before any dial, e.g. by Allow.
	Rejected(name, reason string)
}

// Allowed reports whether addr is permitted by prefixes. An empty prefix list
// permits everything, which is the documented default: the bind address and the
// operator's network are the access control.
func Allowed(prefixes []netip.Prefix, addr net.Addr) bool {
	if len(prefixes) == 0 {
		return true
	}
	ap, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		return false
	}
	ip := ap.Addr().Unmap()
	for _, p := range prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}
