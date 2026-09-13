// Package config defines tsportmap's configuration model and its parsers.
package config

import (
	"net/netip"
	"time"
)

// Direction is which way a mapping moves bytes across the tailnet boundary.
type Direction string

const (
	// Out is egress: a listener on a local/private network accepts a connection
	// and it is dialled onward to a tailnet peer via the tsnet node.
	Out Direction = "out"
	// In is ingress: a listener on the tailnet accepts a connection from a peer
	// and it is dialled onward to a target reachable from this container.
	In Direction = "in"
)

// Proto is the transport a mapping relays.
type Proto string

const (
	TCP Proto = "tcp"
	UDP Proto = "udp"
)

// Mapping is one declared port relay. Every mapping is bound to exactly one
// target; tsportmap deliberately offers no ad-hoc destination selection
// (no SOCKS5, no HTTP CONNECT), so a caller can only ever reach what an
// operator wrote down.
type Mapping struct {
	// Name is the operator-supplied label. It is what appears in logs, metrics
	// and errors, so it is required and must be unique.
	Name string

	Dir   Direction
	Proto Proto

	// Listen is the bind address, "host:port".
	//
	// For Out mappings this is an address on the container's own network stack
	// and the host part is REQUIRED — there is deliberately no default. Render
	// is IPv4-only and wants 0.0.0.0; Fly's 6PN is IPv6-only and wants ::; a
	// laptop wants 127.0.0.1. No portable default exists and a wrong one is an
	// open relay.
	//
	// For In mappings this is an address on the tailnet side. An empty host
	// means "this node's own tailnet addresses", which tsnet handles natively
	// for TCP. For UDP an empty host is resolved to a concrete tailnet IP at
	// bind time, because tsnet's ListenPacket rejects wildcard binds
	// (tailscale/tailscale#18995).
	Listen string

	// Target is the far side, "host:port". For Out mappings a MagicDNS short
	// name is preferred over an FQDN: short names survive a tailnet rename.
	Target string

	// TLS terminates TLS on an In mapping using the node's Tailscale-issued
	// certificate. Requires MagicDNS and HTTPS certificates to be enabled on
	// the tailnet. Invalid on Out mappings and on UDP.
	TLS bool

	// Allow optionally restricts which source addresses may use this mapping.
	// Empty means any source that can reach Listen. It is the operator's job to
	// understand that a non-loopback bind with no allow-list means anything on
	// that network can use the mapping.
	Allow []netip.Prefix

	// Idle is how long a session may go with no bytes in either direction
	// before it is closed. Zero means never for TCP; UDP falls back to
	// DefaultUDPIdle because a UDP session has no close handshake to wait for.
	Idle time.Duration
}

// DefaultUDPIdle bounds the lifetime of an idle UDP session. UDP has no FIN, so
// without this the session table grows without limit.
const DefaultUDPIdle = 60 * time.Second

// Config is the fully-resolved runtime configuration.
type Config struct {
	// Hostname is the tsnet node name as it appears in the tailnet.
	Hostname string

	// AuthKey is a Tailscale auth key or OAuth client secret. A "file:" prefix
	// reads the value from that path instead, keeping the credential out of
	// /proc/<pid>/environ and platform dashboards. Never logged.
	AuthKey string

	// Tags are the ACL tags to advertise. Required when AuthKey is an OAuth
	// client secret. Tagged nodes also have key expiry disabled by default,
	// which is what a long-lived proxy wants.
	Tags []string

	// StateDir holds the tsnet node identity. Always set explicitly: tsnet
	// unconditionally MkdirAlls this path for its log buffer, and when it is
	// empty it falls back to os.UserConfigDir(), which errors in a distroless
	// container with no $HOME (tailscale/tailscale#16556).
	StateDir string

	// Ephemeral registers a node that control removes when it disconnects.
	// Appropriate on platforms with no durable volume; costs a new node
	// identity, and therefore a new certificate, on every restart.
	Ephemeral bool

	// ControlURL overrides the coordination server, e.g. for Headscale.
	ControlURL string

	// AcceptRoutes enables use of subnet routes advertised by other nodes.
	// Off by default because it materially widens what the proxy can reach.
	// Must be re-applied after every Start: tsnet passes freshly-built prefs as
	// UpdatePrefs, which clones wholesale and preserves only Persist, so this
	// silently reverts on every restart.
	AcceptRoutes bool

	// RequireTailnetDest refuses to dial an Out target that does not resolve to
	// a tailnet peer or an eligible accepted route.
	//
	// This defaults ON and is a correctness control, not hardening. tsnet's
	// dialer does not error on a non-tailnet destination — it falls through to
	// a plain host-network dial. Render's private network is RFC1918 10.x, so
	// without this guard a mistyped target silently connects to a Render
	// sibling service instead of the intended tailnet host: wrong backend, no
	// error, no log line.
	RequireTailnetDest bool

	Maps []Mapping

	// MetricsAddr serves /healthz, /readyz and /metrics. Defaults to loopback;
	// these endpoints are unauthenticated.
	MetricsAddr string

	// DialTimeout bounds a single onward dial.
	DialTimeout time.Duration

	// UpTimeout bounds waiting for the node to reach Running. tsnet's Up()
	// deliberately does not error on NeedsLogin or NeedsMachineAuth — it loops
	// until running or the context expires — so an unbounded wait turns a bad
	// auth key into a hang instead of a message.
	UpTimeout time.Duration

	// ShutdownGrace bounds draining on SIGTERM.
	ShutdownGrace time.Duration

	LogLevel string
}
