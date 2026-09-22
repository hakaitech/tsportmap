package wgnet

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hakaitech/tsportmap/internal/config"

	"golang.org/x/crypto/curve25519"
)

// keypair generates a Curve25519 keypair in the base64 spelling the
// configuration uses.
func keypair(t *testing.T) (priv, pub string) {
	t.Helper()
	var sk [32]byte
	if _, err := rand.Read(sk[:]); err != nil {
		t.Fatalf("reading random bytes: %v", err)
	}
	// The clamping WireGuard applies to a private key. Without it the public
	// key derived here would not be the one the device derives from the same
	// private key, and the two ends would never agree.
	sk[0] &= 248
	sk[31] = (sk[31] & 127) | 64

	pk, err := curve25519.X25519(sk[:], curve25519.Basepoint)
	if err != nil {
		t.Fatalf("deriving public key: %v", err)
	}
	return base64.StdEncoding.EncodeToString(sk[:]), base64.StdEncoding.EncodeToString(pk)
}

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("parsing prefix %q: %v", s, err)
	}
	return p
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// peeredPair brings up two userspace WireGuard interfaces that carry traffic to
// each other over loopback, with no kernel interface and no privileges on
// either side. It is the closest thing to a real tunnel a unit test can hold,
// and it is what makes the relay path over WireGuard testable at all.
//
// It returns them with a and b already started, and registers their teardown.
func peeredPair(t *testing.T) (a, b *Interface) {
	t.Helper()

	privA, pubA := keypair(t)
	privB, pubB := keypair(t)

	// Two ephemeral UDP ports are claimed and released so the devices can bind
	// them. The window between release and bind is a race in principle; in a
	// test process that is the only thing binding ports it does not lose, and
	// wireguard-go offers no way to hand it an already-bound socket.
	portA, portB := freeUDPPort(t), freeUDPPort(t)

	cfgA := config.WGInterface{
		Name:       "a",
		PrivateKey: privA,
		Addresses:  []netip.Prefix{mustPrefix(t, "10.55.0.1/24")},
		ListenPort: portA,
		MTU:        config.DefaultWGMTU,
		Peers: []config.WGPeer{{
			PublicKey:  pubB,
			AllowedIPs: []netip.Prefix{mustPrefix(t, "10.55.0.2/32")},
			Endpoint:   fmt.Sprintf("127.0.0.1:%d", portB),
			Keepalive:  time.Second,
		}},
	}
	cfgB := config.WGInterface{
		Name:       "b",
		PrivateKey: privB,
		Addresses:  []netip.Prefix{mustPrefix(t, "10.55.0.2/24")},
		ListenPort: portB,
		MTU:        config.DefaultWGMTU,
		Peers: []config.WGPeer{{
			PublicKey:  pubA,
			AllowedIPs: []netip.Prefix{mustPrefix(t, "10.55.0.1/32")},
			Endpoint:   fmt.Sprintf("127.0.0.1:%d", portA),
			Keepalive:  time.Second,
		}},
	}

	var err error
	if a, err = New(cfgA, testLogger()); err != nil {
		t.Fatalf("building interface a: %v", err)
	}
	t.Cleanup(func() { a.Close() })
	if b, err = New(cfgB, testLogger()); err != nil {
		t.Fatalf("building interface b: %v", err)
	}
	t.Cleanup(func() { b.Close() })

	ctx := context.Background()
	if err := a.Start(ctx); err != nil {
		t.Fatalf("starting interface a: %v", err)
	}
	if err := b.Start(ctx); err != nil {
		t.Fatalf("starting interface b: %v", err)
	}
	return a, b
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a UDP port: %v", err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	pc.Close()
	return port
}

func TestInterfaceRelaysTCPOverTheTunnel(t *testing.T) {
	t.Parallel()
	a, b := peeredPair(t)

	ln, err := b.Listen("tcp", "10.55.0.2:9000")
	if err != nil {
		t.Fatalf("listening inside interface b: %v", err)
	}
	defer ln.Close()

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		io.Copy(c, c)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	conn, err := a.DialContext(ctx, "tcp", "10.55.0.2:9000")
	if err != nil {
		t.Fatalf("dialling over the tunnel: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))

	const msg = "tsportmap over wireguard"
	if _, err := io.WriteString(conn, msg); err != nil {
		t.Fatalf("writing to the tunnelled connection: %v", err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("reading back from the tunnelled connection: %v", err)
	}
	if string(got) != msg {
		t.Errorf("echoed %q, want %q", got, msg)
	}
}

func TestInterfaceRelaysUDPOverTheTunnel(t *testing.T) {
	t.Parallel()
	a, b := peeredPair(t)

	pc, err := b.ListenPacket("udp", "10.55.0.2:9001")
	if err != nil {
		t.Fatalf("listening for packets inside interface b: %v", err)
	}
	defer pc.Close()

	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err := pc.WriteTo(buf[:n], from); err != nil {
				return
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := a.DialContext(ctx, "udp", "10.55.0.2:9001")
	if err != nil {
		t.Fatalf("dialling UDP over the tunnel: %v", err)
	}
	defer conn.Close()

	const msg = "datagram"
	// The first datagram can be lost: WireGuard drops what it cannot yet
	// encrypt while the handshake it triggered is still in flight, which is
	// normal and is why UDP over a tunnel is retried rather than trusted.
	deadline := time.Now().Add(15 * time.Second)
	for attempt := 0; ; attempt++ {
		if time.Now().After(deadline) {
			t.Fatal("no datagram came back over the tunnel before the deadline")
		}
		conn.SetDeadline(time.Now().Add(time.Second))
		if _, err := io.WriteString(conn, msg); err != nil {
			t.Fatalf("writing a datagram: %v", err)
		}
		buf := make([]byte, 1500)
		n, err := conn.Read(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			t.Fatalf("reading a datagram: %v", err)
		}
		if string(buf[:n]) != msg {
			t.Fatalf("echoed %q, want %q", buf[:n], msg)
		}
		return
	}
}

func TestInterfaceRefusesUnroutedDestination(t *testing.T) {
	t.Parallel()
	a, _ := peeredPair(t)

	// 10.99.0.1 is outside every AllowedIPs on this interface. WireGuard would
	// silently drop the packet, so the dial has to be refused here or it hangs
	// until the caller's timeout with nothing to explain why.
	_, err := a.DialContext(context.Background(), "tcp", "10.99.0.1:80")
	if !errors.Is(err, ErrNoRoute) {
		t.Fatalf("dial to an unrouted address: got %v, want ErrNoRoute", err)
	}
	if !strings.Contains(err.Error(), "10.55.0.2/32") {
		t.Errorf("the refusal does not name the routes that are configured: %v", err)
	}
}

func TestInterfaceRefusesNonLiteralDestination(t *testing.T) {
	t.Parallel()
	a, _ := peeredPair(t)

	_, err := a.DialContext(context.Background(), "tcp", "db.internal:5432")
	if err == nil {
		t.Fatal("dialling a name over a tunnel with no resolver: got no error")
	}
	if errors.Is(err, ErrNoRoute) {
		t.Errorf("a name should be refused for having no resolver, not for having no route: %v", err)
	}
	if !strings.Contains(err.Error(), "resolver") {
		t.Errorf("the refusal does not explain that the tunnel has no resolver: %v", err)
	}
}

func TestInterfaceStatsReportPeerHandshake(t *testing.T) {
	t.Parallel()
	a, b := peeredPair(t)

	ln, err := b.Listen("tcp", "10.55.0.2:9002")
	if err != nil {
		t.Fatalf("listening inside interface b: %v", err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			c.Close()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := a.DialContext(ctx, "tcp", "10.55.0.2:9002")
	if err != nil {
		t.Fatalf("dialling over the tunnel: %v", err)
	}
	conn.Close()

	stats := a.Stats()
	if len(stats) != 1 {
		t.Fatalf("got %d peer stats, want 1", len(stats))
	}
	s := stats[0]
	if s.Interface != "a" {
		t.Errorf("interface label is %q, want %q", s.Interface, "a")
	}
	if s.LastHandshake.IsZero() {
		t.Error("no handshake recorded after a connection completed over the tunnel")
	}
	if s.TxBytes == 0 || s.RxBytes == 0 {
		t.Errorf("byte counters are rx=%d tx=%d; both should have moved", s.RxBytes, s.TxBytes)
	}
}

func TestInterfaceStatsBeforeStart(t *testing.T) {
	t.Parallel()
	priv, _ := keypair(t)
	_, pub := keypair(t)

	i, err := New(config.WGInterface{
		Name:       "idle",
		PrivateKey: priv,
		Addresses:  []netip.Prefix{mustPrefix(t, "10.56.0.1/24")},
		Peers:      []config.WGPeer{{PublicKey: pub, AllowedIPs: []netip.Prefix{mustPrefix(t, "10.56.0.2/32")}}},
	}, testLogger())
	if err != nil {
		t.Fatalf("building the interface: %v", err)
	}
	t.Cleanup(func() { i.Close() })

	if got := i.Stats(); got != nil {
		t.Errorf("an interface that never started reports %d peer stats, want none", len(got))
	}
	if err := i.Running(context.Background()); err == nil {
		t.Error("an interface that never started reports itself running")
	}
	// Close must work on an interface whose Start never ran: the shutdown path
	// runs it unconditionally after a failure anywhere in startup.
	if err := i.Close(); err != nil {
		t.Errorf("closing an unstarted interface: %v", err)
	}
	if err := i.Close(); err != nil {
		t.Errorf("closing twice: %v", err)
	}
}

func TestNewRejectsIncompleteConfig(t *testing.T) {
	t.Parallel()
	priv, pub := keypair(t)
	full := config.WGInterface{
		Name:       "x",
		PrivateKey: priv,
		Addresses:  []netip.Prefix{mustPrefix(t, "10.57.0.1/24")},
		Peers:      []config.WGPeer{{PublicKey: pub, AllowedIPs: []netip.Prefix{mustPrefix(t, "10.57.0.2/32")}}},
	}

	tests := []struct {
		name string
		edit func(*config.WGInterface)
		want string
	}{
		{"no name", func(c *config.WGInterface) { c.Name = "" }, "no name"},
		{"no private key", func(c *config.WGInterface) { c.PrivateKey = "" }, "no private key"},
		{"no peers", func(c *config.WGInterface) { c.Peers = nil }, "no peers"},
		{"no address", func(c *config.WGInterface) { c.Addresses = nil }, "no address"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := full
			tc.edit(&c)
			i, err := New(c, testLogger())
			if err == nil {
				i.Close()
				t.Fatalf("got no error, want one mentioning %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// Closing an interface while it is carrying traffic must be clean: no panic, no
// hang, and afterwards no claim to be running and no stats to report.
//
// This exercises the teardown path under load; it does not by itself prove the
// packet channel is safe to close, because the window in which that would panic
// is far too narrow for a test to land on reliably. That hazard is closed by
// construction instead — netTUN never closes the channel, for the reason its
// field documents — and this test is what would catch a teardown that deadlocks
// or that leaves the interface reporting itself usable.
func TestInterfaceCloseUnderLoad(t *testing.T) {
	t.Parallel()
	a, b := peeredPair(t)

	ln, err := b.Listen("tcp", "10.55.0.2:9003")
	if err != nil {
		t.Fatalf("listening inside interface b: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()

	// Establish the tunnel first, so the traffic below is really flowing when
	// the close lands rather than still waiting on a handshake.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	warm, err := a.DialContext(ctx, "tcp", "10.55.0.2:9003")
	if err != nil {
		t.Fatalf("dialling over the tunnel: %v", err)
	}
	warm.Close()

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 4096)
			for {
				select {
				case <-stop:
					return
				default:
				}
				// Bounded, because a dial on an interface that has just been
				// closed has nothing left to complete it. In the relay that
				// bound is TSPM_DIAL_TIMEOUT; here it only has to be short
				// enough that the test does not wait on it.
				dctx, dcancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
				c, err := a.DialContext(dctx, "tcp", "10.55.0.2:9003")
				dcancel()
				if err != nil {
					// Expected once the interface is closed.
					continue
				}
				c.SetDeadline(time.Now().Add(time.Second))
				c.Write(buf)
				c.Read(buf)
				c.Close()
			}
		}()
	}

	time.Sleep(100 * time.Millisecond)
	if err := a.Close(); err != nil {
		t.Errorf("closing under load: %v", err)
	}
	// A second close, which the shutdown path also performs, must be a no-op.
	if err := a.Close(); err != nil {
		t.Errorf("closing twice under load: %v", err)
	}

	close(stop)
	wg.Wait()

	if err := a.Running(context.Background()); err == nil {
		t.Error("a closed interface still reports itself running")
	}
	if got := a.Stats(); got != nil {
		t.Errorf("a closed interface reports %d peer stats, want none", len(got))
	}
}
