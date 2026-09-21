// Package relay copies bytes between an accepted connection and an onward dial.
//
// It is deliberately transport-agnostic and knows nothing about Tailscale: the
// same code serves egress (local listener, tsnet dial) and ingress (tsnet
// listener, local dial). Which side is which is the caller's business.
package relay

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"syscall"
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
//
// A nil addr is refused, and is refused ahead of the empty-list fast path: an
// empty list means "any identifiable source", not "any source at all", so a
// peer nothing can name must not be waved through merely because no allow list
// was configured. Nothing is lost by refusing it. An address only goes missing
// once the connection behind it is already dead, and one rule — an
// unidentifiable source is never admitted — is far easier to reason about than
// a rule whose answer flips with the presence of an allow list.
//
// Ingress conns come from tsnet's gVisor stack, and *gonet.TCPConn.RemoteAddr
// returns a nil net.Addr once its endpoint has reached an error or closed
// state; a peer that connects and immediately resets reaches one before the
// relay ever looks. Allowed must therefore never dereference addr blindly: it
// runs on the per-session goroutine, so a panic here would take down every
// mapping in the process, not just this session.
func Allowed(prefixes []netip.Prefix, addr net.Addr) bool {
	if addr == nil {
		return false
	}
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

// Reasons are the closed set of values a Recorder ever receives for a dial
// failure or a rejection.
//
// The set lives here, in the package that produces the values, rather than in
// the package that exposes them. A relay is free to phrase a log line for a
// human however it likes, but the string handed to a Recorder is one of these
// constants, so a metrics backend can treat "reason" as a bounded label without
// a translation table that silently rots when a phrase is reworded.
const (
	// ReasonAllowList is a source address outside a mapping's allow list.
	ReasonAllowList = "allow_list"
	// ReasonCanceled is a dial abandoned because its context was cancelled,
	// which normally means the process is shutting down rather than that
	// anything failed.
	ReasonCanceled = "canceled"
	// ReasonDNS is a name that could not be resolved.
	ReasonDNS = "dns"
	// ReasonDialTimeout is an onward dial that ran out of time.
	ReasonDialTimeout = "dial_timeout"
	// ReasonNoRoute is a destination outside every AllowedIPs on the WireGuard
	// interface a mapping uses, so the dial was refused rather than handed to a
	// tunnel with no peer to carry it. It is distinct from ReasonNotTailnet
	// because the two name different networks and different fixes: one is a
	// missing peer or subnet route on the tailnet, the other a missing
	// AllowedIPs entry in a wg configuration.
	ReasonNoRoute = "no_route"
	// ReasonNotTailnet is a destination that could not be confirmed as a
	// tailnet peer or an eligible route, so the dial was refused rather than
	// allowed to fall through to the host network.
	ReasonNotTailnet = "not_tailnet"
	// ReasonOther is every reason not named here.
	ReasonOther = "other"
	// ReasonQueueFull is a datagram dropped because the session's egress queue
	// was already full — the target has stopped draining writes. It is distinct
	// from ReasonSessionCap, which is a whole session refused because the table
	// was full: one says an admitted client is losing traffic, the other says a
	// new client was never admitted, and an operator alerts on them differently.
	ReasonQueueFull = "queue_full"
	// ReasonRefused is an onward dial actively refused by the target.
	ReasonRefused = "refused"
	// ReasonSessionCap is a session refused because the session table was
	// already at its limit.
	ReasonSessionCap = "session_cap"
)

// ReasonForError classifies a dial error into the closed reason set.
//
// This is the only classifier in the codebase. The error text itself is never
// used as a label: it embeds addresses and ports, and an unbounded label mints
// a new time series per connection.
func ReasonForError(err error) string {
	if err == nil {
		return ReasonOther
	}
	var dnsErr *net.DNSError
	var netErr net.Error
	switch {
	case errors.Is(err, context.Canceled):
		return ReasonCanceled
	case errors.As(err, &dnsErr):
		return ReasonDNS
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded):
		return ReasonDialTimeout
	case errors.Is(err, syscall.ECONNREFUSED):
		return ReasonRefused
	case errors.As(err, &netErr) && netErr.Timeout():
		return ReasonDialTimeout
	default:
		return ReasonOther
	}
}
