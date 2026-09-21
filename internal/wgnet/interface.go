// Package wgnet owns tsportmap's userspace WireGuard interfaces: their
// lifecycle, the configuration handed to wireguard-go, the socket API over the
// tunnel, and the route check that turns an unroutable destination into an
// error that says so.
//
// Like the embedded Tailscale node, an interface here runs entirely in process:
// wireguard-go moves packets across an in-memory gVisor stack instead of a
// kernel TUN device, so a container needs no /dev/net/tun, no NET_ADMIN and no
// network namespace of its own to hold one. That is what lets one unprivileged
// process carry tailnet mappings and conventional WireGuard mappings at once.
package wgnet

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hakaitech/tsportmap/internal/config"

	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/device"
)

// ErrNoRoute reports a destination that no peer's AllowedIPs covers.
//
// It is a distinct sentinel for the same reason tsnode.ErrNotTailnet is: it is
// an operator configuration error — a target outside what the tunnel was told
// to carry — and not a transient network failure, so a caller must not retry
// it. Without this check the same mistake presents as a connection that hangs
// until the dial timeout, because wireguard-go drops a packet it has no peer
// for and nothing sends back an error.
var ErrNoRoute = errors.New("destination is not covered by any peer's AllowedIPs")

// Interface is one userspace WireGuard interface: its device, its network
// stack, and the routing table its dials are checked against.
type Interface struct {
	cfg config.WGInterface
	log *slog.Logger

	tun   *netTUN
	stack *Stack
	dev   *device.Device

	// routes is the union of every peer's AllowedIPs, longest prefix first, so
	// a destination check can stop at the first match and report the specific
	// route that covered it rather than a wider one that also would have.
	routes []route

	mu      sync.Mutex
	started bool

	closeOnce sync.Once
	closeErr  error
}

// route is one AllowedIPs entry and the peer it belongs to.
type route struct {
	prefix netip.Prefix
	peer   string
}

// New builds an interface from its configuration. It performs no network I/O:
// nothing here sends a packet or opens the tunnel's UDP socket.
func New(cfg config.WGInterface, logger *slog.Logger) (*Interface, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.Name == "" {
		return nil, errors.New("wgnet: the interface has no name")
	}
	if cfg.PrivateKey == "" {
		return nil, fmt.Errorf("wgnet: interface %s has no private key", cfg.Name)
	}
	if len(cfg.Peers) == 0 {
		return nil, fmt.Errorf("wgnet: interface %s has no peers, so it can reach nothing", cfg.Name)
	}
	mtu := cfg.MTU
	if mtu == 0 {
		mtu = config.DefaultWGMTU
	}

	tun, err := newNetTUN(cfg.Addresses, mtu)
	if err != nil {
		return nil, fmt.Errorf("wgnet: interface %s: %w", cfg.Name, err)
	}

	i := &Interface{
		cfg:    cfg,
		log:    logger.With("wg", cfg.Name),
		tun:    tun,
		stack:  &Stack{tun: tun},
		routes: buildRoutes(cfg.Peers),
	}
	i.dev = device.NewDevice(tun, conn.NewDefaultBind(), newDeviceLogger(i.log))
	return i, nil
}

// buildRoutes flattens the peers' AllowedIPs into one table ordered by
// decreasing prefix length, which is the order a longest-prefix match needs and
// the order WireGuard itself resolves a destination in.
func buildRoutes(peers []config.WGPeer) []route {
	var rs []route
	for _, p := range peers {
		for _, a := range p.AllowedIPs {
			rs = append(rs, route{prefix: a, peer: p.PublicKey})
		}
	}
	sort.SliceStable(rs, func(a, b int) bool { return rs[a].prefix.Bits() > rs[b].prefix.Bits() })
	return rs
}

// Name is the operator's label for this interface.
func (i *Interface) Name() string { return i.cfg.Name }

// Addrs are the interface's own addresses inside the tunnel.
func (i *Interface) Addrs() []netip.Prefix { return i.cfg.Addresses }

// Start configures the device and brings it up.
//
// Bringing a WireGuard interface up sends nothing and proves nothing: the
// protocol has no connect step, and a handshake happens only when there is a
// packet to carry or a keepalive falls due. A peer whose key is wrong, whose
// endpoint is unreachable, or whose firewall drops the traffic looks exactly
// like a peer that is simply idle, right up until the first dial. That is why
// readiness deliberately does not wait for a handshake, and why the per-peer
// handshake metric exists instead.
func (i *Interface) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	uapi, err := uapiConfig(i.cfg)
	if err != nil {
		return fmt.Errorf("wgnet: interface %s: %w", i.cfg.Name, err)
	}
	if err := i.dev.IpcSet(uapi); err != nil {
		return fmt.Errorf("wgnet: interface %s: configuring the device: %w", i.cfg.Name, redactUAPIError(err))
	}
	if err := i.dev.Up(); err != nil {
		return fmt.Errorf("wgnet: interface %s: bringing the device up: %w", i.cfg.Name, err)
	}

	i.mu.Lock()
	i.started = true
	i.mu.Unlock()

	i.log.Info("wireguard interface up",
		"addrs", prefixList(i.cfg.Addresses),
		"listen_port", i.listenPort(),
		"mtu", i.tun.mtu,
		"peers", len(i.cfg.Peers),
		"routes", routeList(i.routes),
	)
	for _, p := range i.cfg.Peers {
		i.log.Debug("wireguard peer configured",
			"peer", p.PublicKey,
			"endpoint", p.Endpoint,
			"allowed_ips", prefixList(p.AllowedIPs),
			"keepalive", p.Keepalive,
			"preshared_key", p.PresharedKey != "",
		)
	}
	return nil
}

// listenPort reports the UDP port the tunnel is actually bound to, which is not
// the configured one when the configuration asked for 0.
func (i *Interface) listenPort() int {
	// The device reports the bound port through the same UAPI surface as the
	// rest of its state, which is the only place a kernel-chosen port shows up:
	// a configuration asking for 0 gets a real port here and nowhere else.
	if v, ok := i.ipcState()["listen_port"]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return i.cfg.ListenPort
}

// Close tears the interface down. It is safe whether or not Start succeeded and
// safe to call more than once.
func (i *Interface) Close() error {
	i.closeOnce.Do(func() {
		// Cleared first so that a readiness probe or a metrics scrape arriving
		// during shutdown reports an interface that is going away, rather than
		// querying a device that is being torn down underneath it.
		i.mu.Lock()
		i.started = false
		i.mu.Unlock()

		// Device.Close closes the TUN it was given, so the stack goes with it.
		// Closing the TUN as well is harmless — netTUN.Close is idempotent —
		// and is what tears the stack down when Start never ran.
		i.dev.Close()
		i.closeErr = i.tun.Close()
	})
	return i.closeErr
}

// Running reports nil while the interface is usable. It does not consult a peer:
// a WireGuard interface with no traffic has no handshake and no liveness signal
// of any kind, so anything stronger than this would report an idle tunnel as
// broken. See Start.
func (i *Interface) Running(context.Context) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if !i.started {
		return fmt.Errorf("wgnet: interface %s has not started", i.cfg.Name)
	}
	return nil
}

// DialContext opens a connection over the tunnel, refusing a destination that
// no peer's AllowedIPs covers.
func (i *Interface) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("wgnet: dial %q: address must be host:port: %w", address, err)
	}
	ip, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return nil, fmt.Errorf("wgnet: dial %q: %q is not an IP address. A WireGuard tunnel carries no resolver, "+
			"so a destination reached over one is written as a literal address; resolving it on the container's own resolver "+
			"would answer with whatever that network calls the name, which is not the host inside the tunnel", address, host)
	}
	ip = ip.Unmap()
	r, ok := i.routeFor(ip)
	if !ok {
		i.log.Error("refusing dial: destination is not routed by this WireGuard interface",
			"address", address, "routes", routeList(i.routes))
		return nil, fmt.Errorf("%w: %s: no peer of interface %s lists it in AllowedIPs (routed here: %s). "+
			"Without this check the packet would be dropped by the tunnel with nothing to report it, so the dial would hang until it timed out",
			ErrNoRoute, address, i.cfg.Name, routeList(i.routes))
	}
	i.log.Debug("destination routed", "address", address, "route", r.prefix.String(), "peer", r.peer)
	return i.stack.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
}

// routeFor finds the most specific AllowedIPs entry covering ip.
func (i *Interface) routeFor(ip netip.Addr) (route, bool) {
	for _, r := range i.routes {
		if r.prefix.Contains(ip) {
			return r, true
		}
	}
	return route{}, false
}

// Listen accepts connections arriving over the tunnel.
func (i *Interface) Listen(network, addr string) (net.Listener, error) {
	return i.stack.Listen(network, addr)
}

// ListenPacket accepts datagrams arriving over the tunnel.
func (i *Interface) ListenPacket(network, addr string) (net.PacketConn, error) {
	return i.stack.ListenPacket(network, addr)
}

// PeerStat is one peer's state as the device reports it.
type PeerStat struct {
	Interface string
	Peer      string
	// LastHandshake is the zero time when the peer has never completed one,
	// which is the normal state of an idle tunnel and not by itself a fault.
	LastHandshake time.Time
	RxBytes       int64
	TxBytes       int64
}

// Stats reports every peer's counters, for the metrics exposition.
//
// The handshake age is the one number that distinguishes a tunnel that is
// working from one that is misconfigured, and nothing else in the process can
// see it: a dial over a broken tunnel fails the same way a dial to a stopped
// service does.
func (i *Interface) Stats() []PeerStat {
	i.mu.Lock()
	started := i.started
	i.mu.Unlock()
	if !started {
		return nil
	}

	var (
		out  []PeerStat
		cur  *PeerStat
		push = func() {
			if cur != nil {
				out = append(out, *cur)
				cur = nil
			}
		}
	)
	for k, v := range i.ipcPairs() {
		switch k {
		case "public_key":
			push()
			key, err := hex.DecodeString(v)
			if err != nil {
				continue
			}
			cur = &PeerStat{Interface: i.cfg.Name, Peer: base64.StdEncoding.EncodeToString(key)}
		case "last_handshake_time_sec":
			if cur == nil {
				continue
			}
			if secs, err := strconv.ParseInt(v, 10, 64); err == nil && secs > 0 {
				cur.LastHandshake = time.Unix(secs, 0)
			}
		case "rx_bytes":
			if cur != nil {
				cur.RxBytes, _ = strconv.ParseInt(v, 10, 64)
			}
		case "tx_bytes":
			if cur != nil {
				cur.TxBytes, _ = strconv.ParseInt(v, 10, 64)
			}
		}
	}
	push()
	return out
}

// ipcState reads the device's own settings — everything before the first peer.
func (i *Interface) ipcState() map[string]string {
	out := map[string]string{}
	for k, v := range i.ipcPairs() {
		if k == "public_key" {
			// The peer list starts here; nothing after it describes the device.
			break
		}
		out[k] = v
	}
	return out
}

// ipcPairs yields the device's UAPI state as key/value pairs in wire order.
// Order carries meaning: a peer's counters follow the public_key line that
// opens its record.
func (i *Interface) ipcPairs() func(func(string, string) bool) {
	return func(yield func(string, string) bool) {
		state, err := i.dev.IpcGet()
		if err != nil {
			i.log.Debug("reading wireguard device state", "error", err)
			return
		}
		for _, line := range strings.Split(state, "\n") {
			k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
			if !ok {
				continue
			}
			if !yield(k, v) {
				return
			}
		}
	}
}

func prefixList(ps []netip.Prefix) string {
	parts := make([]string, len(ps))
	for i, p := range ps {
		parts[i] = p.String()
	}
	return strings.Join(parts, ",")
}

func routeList(rs []route) string {
	parts := make([]string, len(rs))
	for i, r := range rs {
		parts[i] = r.prefix.String()
	}
	return strings.Join(parts, ",")
}

// newDeviceLogger adapts wireguard-go's printf logging to slog.
//
// Both levels go to Debug. wireguard-go's "error" level carries per-packet
// events an operator cannot act on — a handshake from an unknown peer, a
// replayed packet — and anything that actually stops the interface is returned
// as an error from IpcSet or Up instead, where it becomes a startup failure.
func newDeviceLogger(l *slog.Logger) *device.Logger {
	line := func(format string, args ...any) {
		if !l.Enabled(context.Background(), slog.LevelDebug) {
			return
		}
		l.Debug(strings.TrimRight(fmt.Sprintf(format, args...), "\n"), "src", "wireguard-go")
	}
	return &device.Logger{Verbosef: line, Errorf: line}
}

// redactUAPIError strips the configuration out of an error raised while parsing
// it. wireguard-go quotes the offending line, and the lines it parses include
// the private key and any preshared key.
func redactUAPIError(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	for _, secret := range []string{"private_key", "preshared_key"} {
		if idx := strings.Index(msg, secret); idx >= 0 {
			return fmt.Errorf("%s: the device rejected a key in the configuration (the message is withheld because it quotes the key)", secret)
		}
	}
	return err
}
