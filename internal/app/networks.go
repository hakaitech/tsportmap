package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"

	"github.com/hakaitech/tsportmap/internal/config"
	"github.com/hakaitech/tsportmap/internal/obs"
	"github.com/hakaitech/tsportmap/internal/relay"
	"github.com/hakaitech/tsportmap/internal/wgnet"
)

// wgInterface is the slice of a userspace WireGuard interface this package
// uses. It is an interface for the same reason node is: the wiring — which
// mapping binds where, what starts before what, what is torn down in which
// order — is the part with interesting failure modes, and it should be testable
// without standing up a tunnel. *wgnet.Interface implements it.
type wgInterface interface {
	Name() string
	Start(ctx context.Context) error
	Close() error
	Running(ctx context.Context) error
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
	Listen(network, addr string) (net.Listener, error)
	ListenPacket(network, addr string) (net.PacketConn, error)
	Stats() []wgnet.PeerStat
}

// wgFactory builds a WireGuard interface. Injected so tests can supply a stub.
type wgFactory func(config.WGInterface, *slog.Logger) (wgInterface, error)

func newWireGuardInterface(cfg config.WGInterface, log *slog.Logger) (wgInterface, error) {
	return wgnet.New(cfg, log)
}

// networks is every transport plane this process holds, keyed the way a
// mapping's via= names it.
//
// It exists so that the rest of the wiring asks one question — "which network
// does this mapping use?" — instead of branching on direction and kind at every
// bind and every dial. A mapping that names a network which is not here is a
// configuration error the parser already refused; the lookups below still report
// it rather than dereferencing nil, because a bug in that refusal must not
// become a crash in a process that is already serving other mappings.
type networks struct {
	// node is nil when no mapping uses the tailnet. That is the whole point of
	// making it optional: a node configured only with WireGuard and local
	// mappings should not need a tailnet credential, should not register a
	// device, and should not fail to start because control is unreachable.
	node node

	wg map[string]wgInterface

	// localDialer is the dialer for anything that goes out on the container's
	// own network: every ingress mapping's onward leg, and every egress mapping
	// with via=local.
	localDialer *net.Dialer
}

// needsTailnet reports whether any mapping uses the tailnet, which is what
// decides whether a Tailscale node is built and started at all.
func needsTailnet(cfg *config.Config) bool {
	for _, m := range cfg.Maps {
		if m.Via.IsTailnet() {
			return true
		}
	}
	return false
}

// build constructs every network the configuration names. Nothing here touches
// the network; Start does that.
func buildNetworks(cfg *config.Config, log *slog.Logger, newNode nodeFactory, newWG wgFactory) (*networks, error) {
	ns := &networks{wg: make(map[string]wgInterface, len(cfg.WG)), localDialer: &net.Dialer{}}

	for _, w := range cfg.WG {
		iface, err := newWG(w, log)
		if err != nil {
			ns.Close(log)
			return nil, fmt.Errorf("wireguard interface %s (%s%s): %w", w.Name, config.EnvPrefixWG, w.Name, err)
		}
		ns.wg[normaliseNetworkName(w.Name)] = iface
	}

	if needsTailnet(cfg) {
		n, err := newNode(cfg, log)
		if err != nil {
			ns.Close(log)
			return nil, err
		}
		ns.node = n
	} else {
		log.Info("no mapping uses the tailnet, so no Tailscale node is started",
			"networks", len(ns.wg))
	}
	return ns, nil
}

// Start brings every network up.
//
// The WireGuard interfaces go first because they are cheap and local: bringing
// one up opens a UDP socket and configures an in-process device, with no remote
// party involved and nothing that can hang. The tailnet node goes last because
// it is the one that talks to a coordination server and the one whose failure
// takes the longest to report, and a configuration error in a wg interface
// should not cost an operator a ninety-second wait to discover.
func (ns *networks) Start(ctx context.Context) error {
	for _, name := range ns.wgNames() {
		if err := ns.wg[name].Start(ctx); err != nil {
			return err
		}
	}
	if ns.node != nil {
		return ns.node.Start(ctx)
	}
	return nil
}

// Close tears every network down. It is safe whether or not Start succeeded and
// reports nothing upward: it runs during shutdown, after the error that matters
// has already been chosen.
func (ns *networks) Close(log *slog.Logger) {
	for _, name := range ns.wgNames() {
		if err := ns.wg[name].Close(); err != nil {
			log.Warn("closing wireguard interface", "wg", name, "error", err)
		}
	}
	if ns.node != nil {
		if err := ns.node.Close(); err != nil {
			log.Warn("closing tailnet node", "error", err)
		}
	}
}

// Running reports nil while every network is usable. It is the remote half of
// readiness.
func (ns *networks) Running(ctx context.Context) error {
	for _, name := range ns.wgNames() {
		if err := ns.wg[name].Running(ctx); err != nil {
			return err
		}
	}
	if ns.node != nil {
		return ns.node.Running(ctx)
	}
	return nil
}

// wgNames lists the WireGuard interfaces in a stable order, so that startup
// order, shutdown order and log order are the same from one run to the next.
func (ns *networks) wgNames() []string {
	names := make([]string, 0, len(ns.wg))
	for n := range ns.wg {
		names = append(names, n)
	}
	slices.Sort(names)
	return names
}

// wireGuardStats adapts every interface's peer state to the metrics registry.
// It returns nil when there are no interfaces, which is what keeps the
// WireGuard metric families off a tailnet-only node entirely.
func (ns *networks) wireGuardStats() obs.WireGuardSource {
	if len(ns.wg) == 0 {
		return nil
	}
	return func() []obs.WireGuardPeer {
		var out []obs.WireGuardPeer
		for _, name := range ns.wgNames() {
			for _, s := range ns.wg[name].Stats() {
				out = append(out, obs.WireGuardPeer{
					Interface:     s.Interface,
					Peer:          s.Peer,
					LastHandshake: s.LastHandshake,
					RxBytes:       s.RxBytes,
					TxBytes:       s.TxBytes,
				})
			}
		}
		return out
	}
}

// tailnet returns the node, or an error naming what is missing.
func (ns *networks) tailnet() (node, error) {
	if ns.node == nil {
		return nil, errors.New("this mapping uses the tailnet, but no Tailscale node was started")
	}
	return ns.node, nil
}

// wireGuard returns the interface a mapping names.
func (ns *networks) wireGuard(n config.Network) (wgInterface, error) {
	iface, ok := ns.wg[normaliseNetworkName(n.Name)]
	if !ok {
		return nil, fmt.Errorf("no WireGuard interface named %q is configured (%s%s)", n.Name, config.EnvPrefixWG, n.Name)
	}
	return iface, nil
}

// listen opens a mapping's listener on the network it listens on.
//
// An egress mapping listens on the container's own network whatever it dials
// over, so only an ingress mapping consults the network at all. That asymmetry
// is the shape of the whole tool: an egress mapping is a door into a network,
// an ingress mapping is a door out of one.
func (ns *networks) listen(m config.Mapping, addr string) (net.Listener, error) {
	if m.Dir == config.Out {
		return net.Listen("tcp", addr)
	}
	switch m.Via.Kind {
	case config.NetTailnet, "":
		n, err := ns.tailnet()
		if err != nil {
			return nil, err
		}
		if m.TLS {
			return n.ListenTLS("tcp", addr)
		}
		return n.Listen("tcp", addr)
	case config.NetWireGuard:
		iface, err := ns.wireGuard(m.Via)
		if err != nil {
			return nil, err
		}
		return iface.Listen("tcp", addr)
	default:
		return nil, fmt.Errorf("no listener for an %q mapping on network %s", m.Dir, m.Via)
	}
}

func (ns *networks) listenPacket(m config.Mapping, addr string) (net.PacketConn, error) {
	if m.Dir == config.Out {
		return net.ListenPacket("udp", addr)
	}
	switch m.Via.Kind {
	case config.NetTailnet, "":
		n, err := ns.tailnet()
		if err != nil {
			return nil, err
		}
		return n.ListenPacket("udp", addr)
	case config.NetWireGuard:
		iface, err := ns.wireGuard(m.Via)
		if err != nil {
			return nil, err
		}
		return iface.ListenPacket("udp", addr)
	default:
		return nil, fmt.Errorf("no packet listener for an %q mapping on network %s", m.Dir, m.Via)
	}
}

// dialer builds the onward leg for a mapping.
//
// An ingress mapping always dials the container's own network: it has just
// accepted something from a tunnel and is delivering it to a local target, and
// sending that dial back down a tunnel would be a loop. An egress mapping dials
// over the network it names, which is where the destination guards live — the
// tailnet's, which refuses a target it cannot place in the netmap, and
// WireGuard's, which refuses a target no peer's AllowedIPs covers.
func (ns *networks) dialer(m config.Mapping) (relay.DialFunc, error) {
	if m.Dir == config.In {
		return ns.localDialer.DialContext, nil
	}
	switch m.Via.Kind {
	case config.NetTailnet, "":
		n, err := ns.tailnet()
		if err != nil {
			return nil, err
		}
		return n.DialContext, nil
	case config.NetWireGuard:
		iface, err := ns.wireGuard(m.Via)
		if err != nil {
			return nil, err
		}
		return iface.DialContext, nil
	case config.NetLocal:
		return ns.localDialer.DialContext, nil
	default:
		return nil, fmt.Errorf("no dialer for network %s", m.Via)
	}
}

// tailnetIPs reports the node's own tailnet addresses, or the zero values when
// there is no node. Only an ingress UDP mapping on the tailnet needs them, and
// such a mapping cannot exist without a node.
func (ns *networks) tailnetIPs() (ip4, ip6 netip.Addr) {
	if ns.node == nil {
		return netip.Addr{}, netip.Addr{}
	}
	return ns.node.TailnetIPs()
}

// normaliseNetworkName folds a WireGuard interface name to the form via= is
// matched in. The parser lowercases a via= name and compares interface names
// case-insensitively, so the registry has to key on the same form, or a mapping
// written via=wg:home would miss an interface declared TSPM_WG_HOME.
func normaliseNetworkName(s string) string {
	return strings.ToLower(s)
}
