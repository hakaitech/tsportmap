package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hakaitech/tsportmap/internal/config"
	"github.com/hakaitech/tsportmap/internal/obs"
	"github.com/hakaitech/tsportmap/internal/tsnode"
	"github.com/hakaitech/tsportmap/internal/wgnet"
)

// stubWG stands in for a userspace WireGuard interface. Its listeners are real
// loopback sockets, which is what lets the wiring — bind order, dialer choice,
// shutdown order — be exercised without a tunnel.
type stubWG struct {
	name     string
	startErr error

	mu      sync.Mutex
	started bool
	closed  bool
	dialed  []string
	stats   []wgnet.PeerStat
}

func (s *stubWG) Name() string { return s.name }

func (s *stubWG) Start(context.Context) error {
	if s.startErr != nil {
		return s.startErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.started = true
	return nil
}

func (s *stubWG) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

func (s *stubWG) Running(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.started {
		return errors.New("stub wireguard interface has not started")
	}
	return nil
}

func (s *stubWG) DialContext(_ context.Context, _, address string) (net.Conn, error) {
	s.mu.Lock()
	s.dialed = append(s.dialed, address)
	s.mu.Unlock()
	return nil, errors.New("stub wireguard dial")
}

// Listen and ListenPacket bind loopback rather than the address asked for: the
// point of the stub is that the listener is real and closeable, not that it
// lives at a particular address.
func (s *stubWG) Listen(string, string) (net.Listener, error) {
	return net.Listen("tcp", "127.0.0.1:0")
}

func (s *stubWG) ListenPacket(string, string) (net.PacketConn, error) {
	return net.ListenPacket("udp", "127.0.0.1:0")
}

func (s *stubWG) Stats() []wgnet.PeerStat { return s.stats }

func (s *stubWG) isStarted() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.started
}

func (s *stubWG) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (s *stubWG) dials() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.dialed...)
}

// wgFactoryFor hands out interfaces that were built before the run started, so
// a test can hold a reference to one without racing the goroutine that builds
// it. Every field a test reads on a stub is guarded by the stub's own mutex.
func wgFactoryFor(ifaces ...*stubWG) wgFactory {
	return func(c config.WGInterface, _ *slog.Logger) (wgInterface, error) {
		for _, s := range ifaces {
			if strings.EqualFold(s.name, c.Name) {
				return s, nil
			}
		}
		return nil, fmt.Errorf("this test declares no WireGuard interface named %q", c.Name)
	}
}

const testWGConf = `
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEE=
Address = 10.8.0.2/24
ListenPort = 51820

[Peer]
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAUE=
AllowedIPs = 10.8.0.0/24
Endpoint = vpn.example.com:51820
`

// A configuration whose mappings never name the tailnet must not build a
// Tailscale node at all: no credential, no device registration, and no startup
// that can fail because a coordination server is unreachable.
func TestRunWithoutAnyTailnetMappingStartsNoNode(t *testing.T) {
	t.Parallel()

	home := &stubWG{name: "HOME"}
	environ := []string{
		"TSPM_WG_HOME=" + testWGConf,
		"TSPM_OUT_DB=tcp," + freePort(t) + ",10.8.0.5:5432,via=wg:home",
		"TSPM_OUT_ECHO=tcp," + freePort(t) + ",127.0.0.1:9999,via=local",
		"TSPM_METRICS_ADDR=" + freePort(t),
		"TSPM_SHUTDOWN_GRACE=1s",
	}

	var nodeBuilt atomic.Bool
	failIfNodeBuilt := nodeFactory(func(*config.Config, *slog.Logger) (node, error) {
		nodeBuilt.Store(true)
		return nil, errors.New("a Tailscale node was built for a configuration that uses none")
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, environ, "test", io.Discard, failIfNodeBuilt, wgFactoryFor(home)) }()

	waitFor := time.After(5 * time.Second)
	for {
		if home.isStarted() {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("run returned early: %v", err)
		case <-waitFor:
			t.Fatal("the WireGuard interface never started")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("run: %v", err)
	}
	if nodeBuilt.Load() {
		t.Error("a Tailscale node was built even though no mapping uses the tailnet")
	}
	if !home.isClosed() {
		t.Error("the WireGuard interface was not closed on shutdown")
	}
}

// A WireGuard interface that fails to start must take the process down and must
// not leave the ones that did start running.
func TestRunReportsWireGuardStartFailure(t *testing.T) {
	t.Parallel()

	failing := &stubWG{name: "HOME", startErr: errors.New("the device rejected its configuration")}

	listen := freePort(t)
	err := run(context.Background(),
		[]string{
			"TSPM_WG_HOME=" + testWGConf,
			"TSPM_OUT_DB=tcp," + listen + ",10.8.0.5:5432,via=wg:home",
			"TSPM_METRICS_ADDR=" + freePort(t),
		},
		"test", io.Discard, factory(&stubNode{}), wgFactoryFor(failing))
	if err == nil || !strings.Contains(err.Error(), "rejected its configuration") {
		t.Fatalf("got %v, want the interface's own start error", err)
	}
	if !failing.isClosed() {
		t.Error("the interface was not closed after a failed start")
	}
	// A failed start must not leave the mapping's port claimed, so a restart
	// does not fail for a second, unrelated-looking reason.
	ln, lerr := net.Listen("tcp", listen)
	if lerr != nil {
		t.Errorf("the mapping's port is still claimed after a failed start: %v", lerr)
	} else {
		ln.Close()
	}
}

// Each mapping must get the dialer of the network it names, and no other.
func TestDialerFollowsTheMappingsNetwork(t *testing.T) {
	t.Parallel()

	home := &stubWG{name: "HOME"}
	n := &stubNode{}
	ns := &networks{node: n, wg: map[string]wgInterface{"home": home}, localDialer: &net.Dialer{}}

	dialOver := func(m config.Mapping) {
		t.Helper()
		d, err := ns.dialer(m)
		if err != nil {
			t.Fatalf("building a dialer for %s: %v", m.Name, err)
		}
		// Both stubs record the address and then fail; the failure is expected
		// and it is the record that is being asserted on.
		d(context.Background(), "tcp", m.Target)
	}

	dialOver(config.Mapping{Name: "WG", Dir: config.Out, Target: "10.8.0.5:5432", Via: config.Network{Kind: config.NetWireGuard, Name: "home"}})
	dialOver(config.Mapping{Name: "TS", Dir: config.Out, Target: "db-1:5432", Via: config.Network{Kind: config.NetTailnet}})
	// An ingress mapping always delivers to the container's own network, even
	// though it listens on a tunnel. Dialling back down the tunnel would loop.
	dialOver(config.Mapping{Name: "IN", Dir: config.In, Target: "127.0.0.1:9000", Via: config.Network{Kind: config.NetWireGuard, Name: "home"}})

	if got := home.dials(); len(got) != 1 || got[0] != "10.8.0.5:5432" {
		t.Errorf("the WireGuard interface saw dials %v, want just the egress target", got)
	}
	if _, _, _, got := n.snapshot(); len(got) != 1 || got[0] != "tcp/db-1:5432" {
		t.Errorf("the node saw dials %v, want just the tailnet target", got)
	}
}

func TestDialerRejectsAnUnknownNetwork(t *testing.T) {
	t.Parallel()
	ns := &networks{wg: map[string]wgInterface{}, localDialer: &net.Dialer{}}

	if _, err := ns.dialer(config.Mapping{Dir: config.Out, Via: config.Network{Kind: config.NetWireGuard, Name: "nope"}}); err == nil {
		t.Error("a mapping naming an interface that does not exist produced a dialer")
	}
	if _, err := ns.dialer(config.Mapping{Dir: config.Out, Via: config.Network{Kind: config.NetTailnet}}); err == nil {
		t.Error("a tailnet mapping produced a dialer with no node running")
	}
}

func TestDialFailureReasonNamesTheNetworkThatRefused(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"tailnet guard", tsnode.ErrNotTailnet, obs.ReasonNotTailnet},
		{"wireguard route", wgnet.ErrNoRoute, obs.ReasonNoRoute},
		{"wrapped wireguard route", errors.Join(errors.New("dial"), wgnet.ErrNoRoute), obs.ReasonNoRoute},
		{"anything else", errors.New("connection reset"), obs.ReasonOther},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := dialFailureReason(tc.err); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// Readiness must fail while any one network is down, not only the tailnet.
func TestReadinessCoversEveryNetwork(t *testing.T) {
	t.Parallel()

	home := &stubWG{name: "HOME"}
	ns := &networks{node: &stubNode{}, wg: map[string]wgInterface{"home": home}, localDialer: &net.Dialer{}}

	if err := ns.Running(context.Background()); err == nil {
		t.Error("readiness passed while the WireGuard interface had not started")
	}
	home.Start(context.Background())
	if err := ns.Running(context.Background()); err != nil {
		t.Errorf("readiness failed with every network up: %v", err)
	}
}

func TestWireGuardStatsAreOmittedWithoutInterfaces(t *testing.T) {
	t.Parallel()
	ns := &networks{wg: map[string]wgInterface{}, localDialer: &net.Dialer{}}
	if ns.wireGuardStats() != nil {
		t.Error("a node with no WireGuard interface offers a stats source")
	}

	home := &stubWG{name: "HOME", stats: []wgnet.PeerStat{{
		Interface:     "HOME",
		Peer:          "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAUE=",
		LastHandshake: time.Unix(1700000000, 0),
		RxBytes:       11,
		TxBytes:       22,
	}}}
	ns.wg["home"] = home

	src := ns.wireGuardStats()
	if src == nil {
		t.Fatal("a node with a WireGuard interface offers no stats source")
	}
	got := src()
	if len(got) != 1 || got[0].Interface != "HOME" || got[0].RxBytes != 11 || got[0].TxBytes != 22 {
		t.Fatalf("got %+v, want the interface's one peer", got)
	}
}
