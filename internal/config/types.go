// Package config defines tsportmap's configuration model and its parsers.
package config

import (
	"net/netip"
	"time"
)

// Direction is which way a mapping moves bytes across the boundary between the
// container's own network and the mapping's network — its tailnet, a WireGuard
// interface, or, for a plain forwarder, the container's network on both sides.
type Direction string

const (
	// Out is egress: a listener on the container's own network accepts a
	// connection and it is dialled onward over the mapping's network.
	Out Direction = "out"
	// In is ingress: a listener on the mapping's network accepts a connection
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
	// For In mappings this is an address on the mapping's network. An empty
	// host means "every address this node holds on that network". On the
	// tailnet that is native for TCP, while for UDP it is resolved to a
	// concrete tailnet IP at bind time because tsnet's ListenPacket rejects
	// wildcard binds (tailscale/tailscale#18995); a WireGuard interface accepts
	// a wildcard for both.
	Listen string

	// Target is the far side, "host:port".
	//
	// On the tailnet a MagicDNS short name is preferred over an FQDN: short
	// names survive a tailnet rename. Over a WireGuard interface the host must
	// be a literal IP — a WireGuard tunnel carries no resolver of its own, and
	// resolving a tunnel-side name on the container's resolver is the same
	// silent-wrong-destination failure the tailnet guard exists to prevent.
	Target string

	// Via is the network this mapping uses: which plane an Out mapping dials
	// over, and which plane an In mapping listens on. It defaults to the
	// tailnet, so a mapping written without via= keeps its original meaning.
	Via Network

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

	// WG are the userspace WireGuard interfaces declared by TSPM_WG_<NAME>.
	// Each is brought up in-process with no TUN device and no NET_ADMIN, the
	// same way the tailnet node is, so holding several costs nothing but
	// memory and one UDP socket apiece.
	WG []WGInterface

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

// NetworkKind names a transport plane a mapping can use. tsportmap holds more
// than one at a time: the embedded Tailscale node, any number of userspace
// WireGuard interfaces, and the container's own stack. A mapping names exactly
// one, which is what makes "what can this reach" answerable by reading the
// configuration.
type NetworkKind string

const (
	// NetTailnet is the embedded Tailscale node. It is the default, so a
	// configuration written before WireGuard existed keeps its meaning.
	NetTailnet NetworkKind = "ts"
	// NetWireGuard is a userspace WireGuard interface declared by TSPM_WG_<NAME>.
	NetWireGuard NetworkKind = "wg"
	// NetLocal is the container's own network stack: no tunnel at all. It turns
	// a mapping into a plain port forwarder, which is what makes this usable as
	// one proxy in front of tunnelled and untunnelled destinations alike.
	NetLocal NetworkKind = "local"
)

// Network is a resolved via= value: which plane, and for WireGuard which
// interface on it.
type Network struct {
	Kind NetworkKind
	// Name is the WireGuard interface name, lowercased for lookup. It is empty
	// for every other kind.
	Name string
}

// String renders a Network in the same spelling via= accepts, so a log line, an
// error and the configuration an operator wrote all agree.
func (n Network) String() string {
	if n.Kind == NetWireGuard {
		return string(NetWireGuard) + ":" + n.Name
	}
	if n.Kind == "" {
		return string(NetTailnet)
	}
	return string(n.Kind)
}

// IsTailnet reports whether this network is the embedded Tailscale node.
//
// The zero Network counts as the tailnet. The parser always sets the kind, so
// a zero value only arises from a Mapping built in code rather than parsed —
// and the alternative, a zero value that belongs to no network at all, would
// make such a mapping bind nowhere while String still called it "ts".
func (n Network) IsTailnet() bool { return n.Kind == NetTailnet || n.Kind == "" }

// WGPeer is one peer of a userspace WireGuard interface, as parsed from a
// [Peer] section.
type WGPeer struct {
	// PublicKey is the peer's public key, base64 as WireGuard writes it. It is
	// public by construction, so it is safe in logs and is what labels the
	// peer's metrics — the same identifier `wg show` prints.
	PublicKey string

	// PresharedKey is the optional symmetric key mixed into the handshake.
	// Secret: never logged, never rendered by --validate.
	PresharedKey string

	// AllowedIPs is the set of destinations routed to this peer, and on the
	// inbound side the set of source addresses accepted from it. Required:
	// WireGuard has no route to a peer without it.
	AllowedIPs []netip.Prefix

	// Endpoint is the peer's address on the container's own network,
	// "host:port". It may be empty for a peer that always initiates, and it may
	// be a DNS name, which is resolved on the host's resolver — correctly so,
	// since the endpoint is reached outside the tunnel.
	Endpoint string

	// Keepalive sends a keepalive every interval, which is what holds a NAT
	// binding open for a peer behind one. Zero disables it.
	Keepalive time.Duration
}

// WGInterface is one userspace WireGuard interface, declared by TSPM_WG_<NAME>
// and configured in the wg-quick INI format that every WireGuard deployment
// already produces.
type WGInterface struct {
	// Name is the operator-supplied label from the variable's suffix. It labels
	// logs and metrics and is what a mapping's via=wg:<name> refers to.
	Name string

	// PrivateKey is the interface's own private key, base64. Secret: never
	// logged, never rendered by --validate.
	PrivateKey string

	// Addresses are the interface's own addresses inside the tunnel, with the
	// prefix length from the config. At least one is required: a stack with no
	// address has nothing to send from.
	Addresses []netip.Prefix

	// ListenPort is the UDP port on the container's own network that carries
	// the encrypted tunnel. Zero lets the kernel choose, which is right for an
	// interface that only ever initiates and wrong for one a peer must reach.
	ListenPort int

	// MTU is the tunnel's MTU. DefaultWGMTU when the config omits it.
	MTU int

	Peers []WGPeer
}

// DefaultWGMTU is wg-quick's own default: 1420 leaves room for the WireGuard
// header inside a 1500-byte path.
const DefaultWGMTU = 1420

// MinWGMTU is the smallest MTU that can carry an IPv6 packet, which is the
// floor gVisor's stack will work at.
const MinWGMTU = 1280

// MaxWGMTU bounds the MTU at the largest jumbo frame, so a typo of 14200 is a
// startup error rather than an interface that silently black-holes.
const MaxWGMTU = 9000
