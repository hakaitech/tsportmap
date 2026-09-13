// Package tsnode owns the embedded Tailscale node: its lifecycle, the prefs
// that tsnet does not persist, and the destination guard that keeps a dial from
// silently escaping onto the host network.
package tsnode

import (
	"context"
	"crypto/tls"
	"net"
)

// Dialer is the subset of a node used to open outbound tailnet connections.
type Dialer interface {
	// DialContext opens a connection to address over the tailnet. It returns
	// ErrNotTailnet if the destination is not verifiably a tailnet peer or an
	// eligible route and the guard is enabled.
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Listener is the subset of a node used to accept inbound tailnet connections.
type Listener interface {
	// Listen accepts plaintext connections from the tailnet.
	Listen(network, addr string) (net.Listener, error)
	// ListenTLS accepts TLS connections terminated with the node's
	// Tailscale-issued certificate. It requires MagicDNS and HTTPS
	// certificates to be enabled on the tailnet.
	ListenTLS(network, addr string) (net.Listener, error)
	// ListenPacket accepts datagrams from the tailnet. addr must name a
	// concrete tailnet address: tsnet rejects wildcard binds for packets.
	ListenPacket(network, addr string) (net.PacketConn, error)
	// TLSConfig returns a config using the node's certificate, for callers
	// that need to wrap a listener themselves.
	TLSConfig() *tls.Config
}

// Guard decides whether a destination may be dialled over the tailnet.
//
// This exists because tsnet's dialer does not fail closed. When a destination
// is neither a known peer nor covered by an accepted route, the dial falls
// through to a plain host-network dial, so a typo or a missing subnet-route
// approval connects to whatever happens to answer on the container's own
// network rather than reporting an error.
type Guard interface {
	// Check reports whether host — a MagicDNS name, an FQDN, or an IP — is a
	// tailnet peer or covered by an eligible accepted route.
	//
	// approved is the host in the exact spelling the verdict was reached on.
	// Check matches a normalised host (unbracketed, lower case, no root dot,
	// IPv4-mapped IPv6 unmapped), and several of those rewrites change how a
	// dialer resolves the address, so a caller that dials its own spelling
	// instead of approved can reach a destination that was never authorised.
	// It is only meaningful when ok is true.
	//
	// why explains the decision and is safe to log.
	Check(ctx context.Context, host string) (ok bool, approved string, why string, err error)
}
