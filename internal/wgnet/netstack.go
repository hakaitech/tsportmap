package wgnet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"syscall"

	"github.com/tailscale/wireguard-go/tun"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// nicID is the one NIC every tunnel stack has. A userspace WireGuard interface
// has exactly one link — the encrypted tunnel — so there is nothing to
// distinguish and the identifier is a constant rather than a counter.
const nicID tcpip.NICID = 1

// queueDepth is how many outbound packets the link endpoint buffers before it
// drops. It bounds the memory a burst can pin between the netstack producing a
// packet and the WireGuard device encrypting it; WireGuard is a datagram
// transport, so a drop here is indistinguishable to a peer from a drop on the
// wire and TCP above it recovers exactly as it would from either.
const queueDepth = 1024

// netTUN presents a gVisor network stack to wireguard-go as a tun.Device.
//
// This is the whole reason tsportmap can speak WireGuard without /dev/net/tun,
// NET_ADMIN or a network namespace: wireguard-go moves plaintext IP packets
// across this interface instead of across a kernel TUN device, and the stack on
// the other side of it is an ordinary in-process gVisor stack whose sockets are
// Go values rather than file descriptors. It is the same shape of trick tsnet
// plays for the tailnet, which is why a node can hold both and stay unprivileged.
//
// wireguard-go's own tun/netstack does this too, and this is deliberately not
// that package: it is pinned to a 2023 gVisor and no longer compiles against
// the much newer gVisor that tailscale.com requires, and the two cannot both be
// in one build. Owning the adapter is what lets one process hold a tailnet node
// and a WireGuard interface at once.
type netTUN struct {
	ep    *channel.Endpoint
	stack *stack.Stack
	mtu   int

	// events is wireguard-go's device-state channel. It is written once, at
	// construction, and never again: a userspace interface has no link that can
	// go down underneath it, so there is no EventDown or EventMTUUpdate to
	// report.
	events chan tun.Event

	// outbound carries packets from the stack to wireguard-go's Read. It is
	// unbuffered: channel.Endpoint already buffers queueDepth packets, and a
	// second queue behind it would only add latency to the same backlog.
	//
	// It is never closed. A send on a closed channel is a ready case in a
	// select and panics when chosen, so closing it would turn a Close racing a
	// packet in flight into a crash that takes down every other mapping in the
	// process. Both ends leave through closed instead.
	outbound chan *buffer.View

	closeOnce sync.Once
	// closed releases anything parked on outbound, in either direction.
	closed chan struct{}
}

var _ tun.Device = (*netTUN)(nil)

// newNetTUN builds the stack, assigns addrs to its only NIC and installs a
// default route in each family the interface has an address in.
//
// The routes are unconditional defaults because the WireGuard device, not this
// stack, decides where a packet may go: a destination outside every peer's
// AllowedIPs is dropped by wireguard-go with no peer to send it to. Encoding
// AllowedIPs here as well would duplicate that table in a second place that
// could disagree with it; what this package does instead is check a destination
// against AllowedIPs before dialling, so the refusal names the reason rather
// than presenting as a connection that never completes.
func newNetTUN(addrs []netip.Prefix, mtu int) (*netTUN, error) {
	if mtu <= 0 {
		return nil, fmt.Errorf("wgnet: mtu %d is not positive", mtu)
	}
	if len(addrs) == 0 {
		return nil, errors.New("wgnet: the interface has no address, so its stack has nothing to send from")
	}

	d := &netTUN{
		ep: channel.New(queueDepth, uint32(mtu), ""),
		stack: stack.New(stack.Options{
			NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
			TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
			// HandleLocal keeps a packet addressed to one of this interface's
			// own addresses inside the stack instead of handing it to
			// wireguard-go, which would encrypt it to a peer and never deliver
			// it. It is what makes an ingress mapping's target reachable when
			// an operator points it at the interface's own address.
			HandleLocal: true,
		}),
		mtu:      mtu,
		events:   make(chan tun.Event, 1),
		outbound: make(chan *buffer.View),
		closed:   make(chan struct{}),
	}

	// SACK is off by default in gVisor and costs a great deal on a lossy or
	// high-latency path, which a tunnel over the public internet usually is.
	sack := tcpip.TCPSACKEnabled(true)
	if err := d.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &sack); err != nil {
		return nil, fmt.Errorf("wgnet: enabling TCP SACK: %v", err)
	}

	d.ep.AddNotify(d)
	if err := d.stack.CreateNIC(nicID, d.ep); err != nil {
		return nil, fmt.Errorf("wgnet: creating the tunnel NIC: %v", err)
	}

	var has4, has6 bool
	for _, p := range addrs {
		ip := p.Addr()
		proto := ipv6.ProtocolNumber
		if ip.Is4() {
			proto = ipv4.ProtocolNumber
		}
		pa := tcpip.ProtocolAddress{
			Protocol: proto,
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   tcpip.AddrFromSlice(ip.AsSlice()),
				PrefixLen: p.Bits(),
			},
		}
		if err := d.stack.AddProtocolAddress(nicID, pa, stack.AddressProperties{}); err != nil {
			return nil, fmt.Errorf("wgnet: assigning %s to the tunnel NIC: %v", p, err)
		}
		has4 = has4 || ip.Is4()
		has6 = has6 || ip.Is6()
	}
	if has4 {
		d.stack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: nicID})
	}
	if has6 {
		d.stack.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: nicID})
	}

	d.events <- tun.EventUp
	return d, nil
}

// Name reports the interface name to wireguard-go, which uses it only for
// logging: there is no kernel interface to name.
func (d *netTUN) Name() (string, error) { return "wgnet", nil }

// File returns nil because this interface is not backed by a descriptor.
func (d *netTUN) File() *os.File { return nil }

func (d *netTUN) Events() <-chan tun.Event { return d.events }

func (d *netTUN) MTU() (int, error) { return d.mtu, nil }

// BatchSize is 1 because WriteNotify hands over one packet at a time. Batching
// exists upstream for a kernel TUN device that can read several packets per
// syscall; here there is no syscall to amortise.
func (d *netTUN) BatchSize() int { return 1 }

// WriteNotify is called by the link endpoint when the stack has produced a
// packet. Handing it to Read is what sends it onward to a peer, encrypted.
func (d *netTUN) WriteNotify() {
	pkt := d.ep.Read()
	if pkt == nil {
		return
	}
	view := pkt.ToView()
	pkt.DecRef()

	select {
	case d.outbound <- view:
	case <-d.closed:
		// Dropped: the interface is going away, and blocking here would hold
		// the stack's write path open past Close.
	}
}

// Read hands wireguard-go the next plaintext packet the stack wants to send.
func (d *netTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	var view *buffer.View
	select {
	case view = <-d.outbound:
	case <-d.closed:
		// os.ErrClosed is what wireguard-go reads as "this interface is gone,
		// stop reading from it".
		return 0, os.ErrClosed
	}
	n, err := view.Read(bufs[0][offset:])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	return 1, nil
}

// Write injects a decrypted packet from a peer into the stack.
func (d *netTUN) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		pkt := b[offset:]
		if len(pkt) == 0 {
			continue
		}
		var proto tcpip.NetworkProtocolNumber
		switch pkt[0] >> 4 {
		case 4:
			proto = header.IPv4ProtocolNumber
		case 6:
			proto = header.IPv6ProtocolNumber
		default:
			// Not IP. A peer that is allowed to send here is already
			// authenticated, so this is a bug or a corrupt frame rather than an
			// attack, but it still must not reach the stack.
			return 0, syscall.EAFNOSUPPORT
		}
		pb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(pkt)})
		d.ep.InjectInbound(proto, pb)
		pb.DecRef()
	}
	return len(bufs), nil
}

// Close tears the stack down. It is safe to call more than once, because
// wireguard-go's Device.Close closes the TUN it was given and tsportmap's own
// shutdown path closes the interface too.
func (d *netTUN) Close() error {
	d.closeOnce.Do(func() {
		// closed is shut first so that a WriteNotify already inside its select,
		// and a Read already parked, both leave rather than waiting on a
		// counterpart that is going away.
		close(d.closed)
		d.stack.RemoveNIC(nicID)
		d.ep.Close()
		// events is closed because ranging over it is how wireguard-go's event
		// reader terminates. outbound is deliberately not; see its field.
		close(d.events)
	})
	return nil
}

// Stack is the socket API of a userspace WireGuard interface: the same Dial and
// Listen surface the standard library offers, over the tunnel instead of over
// the host's network.
//
// Every address it takes is an IP literal. There is deliberately no resolver:
// the tunnel has no DNS of its own, and resolving a tunnel-side name on the
// container's own resolver is exactly the silent-wrong-destination failure the
// tailnet destination guard exists to prevent. tsportmap rejects a non-literal
// target for a WireGuard mapping at configuration time instead.
type Stack struct{ tun *netTUN }

func (s *Stack) fullAddr(ip netip.Addr, port uint16) (tcpip.FullAddress, tcpip.NetworkProtocolNumber) {
	ip = ip.Unmap()
	proto := ipv6.ProtocolNumber
	if ip.Is4() {
		proto = ipv4.ProtocolNumber
	}
	fa := tcpip.FullAddress{NIC: nicID, Port: port}
	if ip.IsValid() && !ip.IsUnspecified() {
		fa.Addr = tcpip.AddrFromSlice(ip.AsSlice())
	}
	return fa, proto
}

// DialContext opens a connection over the tunnel. network is "tcp", "tcp4",
// "tcp6", "udp", "udp4" or "udp6"; address must be a literal ip:port.
func (s *Stack) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	ap, err := parseAddrPort(address)
	if err != nil {
		return nil, err
	}
	fa, proto := s.fullAddr(ap.Addr(), ap.Port())
	switch network {
	case "tcp", "tcp4", "tcp6":
		return gonet.DialContextTCP(ctx, s.tun.stack, fa, proto)
	case "udp", "udp4", "udp6":
		// gonet's UDP dial takes no context. A UDP "dial" only binds a local
		// endpoint and records the remote address — there is no handshake to
		// wait on and so nothing a deadline could cut short — but a context
		// already cancelled must still not produce a usable connection, since
		// the caller has stopped wanting it.
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return gonet.DialUDP(s.tun.stack, nil, &fa, proto)
	default:
		return nil, fmt.Errorf("wgnet: unsupported network %q", network)
	}
}

// Listen accepts connections arriving over the tunnel. An unspecified host
// ("", "0.0.0.0" or "::") listens on every address the interface holds.
func (s *Stack) Listen(network, address string) (net.Listener, error) {
	ip, port, err := parseListenAddr(address)
	if err != nil {
		return nil, err
	}
	switch network {
	case "tcp", "tcp4", "tcp6":
		fa, proto := s.fullAddr(ip, port)
		return gonet.ListenTCP(s.tun.stack, fa, proto)
	default:
		return nil, fmt.Errorf("wgnet: unsupported network %q for a stream listener", network)
	}
}

// ListenPacket accepts datagrams arriving over the tunnel.
//
// Unlike tsnet, a wildcard bind is accepted here: gVisor picks the reply source
// address from the route to the peer, so a datagram listener does not have to
// be pinned to one of the interface's addresses.
func (s *Stack) ListenPacket(network, address string) (net.PacketConn, error) {
	ip, port, err := parseListenAddr(address)
	if err != nil {
		return nil, err
	}
	switch network {
	case "udp", "udp4", "udp6":
		fa, proto := s.fullAddr(ip, port)
		return gonet.DialUDP(s.tun.stack, &fa, nil, proto)
	default:
		return nil, fmt.Errorf("wgnet: unsupported network %q for a packet listener", network)
	}
}

func parseAddrPort(address string) (netip.AddrPort, error) {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("wgnet: %q is not a literal ip:port: a WireGuard tunnel carries no resolver, "+
			"so a destination reached over one must be written as an address", address)
	}
	return ap, nil
}

// parseListenAddr accepts the wildcard spellings a bind address may use, which
// netip.ParseAddrPort does not: ":8080" has no host at all, and an operator
// writing "0.0.0.0:8080" means the same thing.
func parseListenAddr(address string) (netip.Addr, uint16, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("wgnet: listen address %q is not host:port: %w", address, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return netip.Addr{}, 0, fmt.Errorf("wgnet: listen address %q has port %q; want a number from 1 to 65535", address, portStr)
	}
	if host == "" {
		return netip.Addr{}, uint16(port), nil
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("wgnet: listen address %q has host %q, which is not an IP address: "+
			"a WireGuard interface listens on its own addresses, which are literals", address, host)
	}
	return ip.Unmap(), uint16(port), nil
}
