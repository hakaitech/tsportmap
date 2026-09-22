package app

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hakaitech/tsportmap/internal/config"
	"github.com/hakaitech/tsportmap/internal/obs"
	"github.com/hakaitech/tsportmap/internal/tsnode"
)

// --- test doubles -----------------------------------------------------------

// stubNode stands in for the embedded Tailscale node. Everything a test needs
// to observe about the wiring — which addresses were asked for, which listen
// method was used, what was dialled — is recorded here, and the listeners it
// hands back are real loopback sockets so the relays above them behave exactly
// as they would in production.
type stubNode struct {
	startErr   error
	listenErr  error
	runningErr error
	ip4, ip6   netip.Addr

	// dial, when set, is the onward dial for egress mappings.
	dial func(ctx context.Context, network, address string) (net.Conn, error)

	mu          sync.Mutex
	started     bool
	closed      bool
	tcpListens  []string
	tlsListens  []string
	packetBinds []string
	dialed      []string
}

func (s *stubNode) Start(context.Context) error {
	if s.startErr != nil {
		return s.startErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.started = true
	return nil
}

func (s *stubNode) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

func (s *stubNode) Running(context.Context) error { return s.runningErr }

// TLSConfig is part of the tsnode.Listener contract. The wiring reaches for
// ListenTLS instead, so nothing here should ever call this.
func (s *stubNode) TLSConfig() *tls.Config { return &tls.Config{MinVersion: tls.VersionTLS12} }

func (s *stubNode) TailnetIPs() (netip.Addr, netip.Addr) { return s.ip4, s.ip6 }

func (s *stubNode) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	s.mu.Lock()
	s.dialed = append(s.dialed, network+"/"+address)
	dial := s.dial
	s.mu.Unlock()
	if dial == nil {
		return nil, fmt.Errorf("stub node: no dialer configured for %s", address)
	}
	return dial(ctx, network, address)
}

// loopbackAddr rewrites the tailnet-side address a mapping asked for into
// something a test machine can actually bind. The address as written is
// recorded first, because that is what the wiring is being tested for.
func loopbackAddr(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "127.0.0.1:0"
	}
	return net.JoinHostPort("127.0.0.1", port)
}

func (s *stubNode) Listen(network, addr string) (net.Listener, error) {
	s.mu.Lock()
	s.tcpListens = append(s.tcpListens, addr)
	s.mu.Unlock()
	if s.listenErr != nil {
		return nil, s.listenErr
	}
	return net.Listen(network, loopbackAddr(addr))
}

func (s *stubNode) ListenTLS(network, addr string) (net.Listener, error) {
	s.mu.Lock()
	s.tlsListens = append(s.tlsListens, addr)
	s.mu.Unlock()
	if s.listenErr != nil {
		return nil, s.listenErr
	}
	return net.Listen(network, loopbackAddr(addr))
}

func (s *stubNode) ListenPacket(network, addr string) (net.PacketConn, error) {
	s.mu.Lock()
	s.packetBinds = append(s.packetBinds, addr)
	s.mu.Unlock()
	if s.listenErr != nil {
		return nil, s.listenErr
	}
	// tsnet refuses a wildcard packet bind, and so does this stub: a test that
	// hands it ":53" must fail the same way production would.
	if host, _, err := net.SplitHostPort(addr); err == nil {
		if host == "" {
			return nil, errors.New("cannot ListenPacket on a wildcard address")
		}
		if ip, perr := netip.ParseAddr(host); perr == nil && ip.IsUnspecified() {
			return nil, errors.New("cannot ListenPacket on a wildcard address")
		}
	}
	return net.ListenPacket(network, loopbackAddr(addr))
}

func (s *stubNode) snapshot() (tcp, tls, packet, dialed []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.tcpListens...),
		append([]string(nil), s.tlsListens...),
		append([]string(nil), s.packetBinds...),
		append([]string(nil), s.dialed...)
}

func (s *stubNode) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func factory(n node) nodeFactory {
	return func(*config.Config, *slog.Logger) (node, error) { return n, nil }
}

// noWG is the WireGuard factory for a test whose configuration declares no
// interfaces. It fails loudly rather than returning a stub, because a test that
// reached it would have declared an interface it did not mean to.
func noWG(c config.WGInterface, _ *slog.Logger) (wgInterface, error) {
	return nil, fmt.Errorf("this test declares no WireGuard interfaces, but one named %q was built", c.Name)
}

// syncBuffer collects log output. The relays log from their own goroutines
// through the default logger, so a test that reads the log while the process
// is still running needs its own lock rather than relying on the handler's.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// freePort returns a loopback address that nothing is listening on. There is an
// unavoidable window between the probe closing and the caller binding; it is
// accepted here because the alternative — a fixed port — collides with whatever
// else is running on the machine.
func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probing for a free port: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func portOf(t *testing.T, addr string) string {
	t.Helper()
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("splitting %q: %v", addr, err)
	}
	return port
}

// --- configuration failures -------------------------------------------------

func TestRunRejectsBadConfiguration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		environ []string
		want    string
	}{
		{
			name:    "no mappings at all",
			environ: []string{"TSPM_HOSTNAME=relay"},
			want:    "no mappings configured",
		},
		{
			name:    "egress without a listen host",
			environ: []string{"TSPM_OUT_DB=tcp,:5432,db:5432"},
			want:    "has no host",
		},
		{
			name:    "unknown mapping option",
			environ: []string{"TSPM_OUT_DB=tcp,127.0.0.1:5432,db:5432,retries=3"},
			want:    `unknown option "retries"`,
		},
		{
			name:    "tls on an egress mapping",
			environ: []string{"TSPM_OUT_DB=tcp,127.0.0.1:5432,db:5432,tls=true"},
			want:    "tls=true is only valid",
		},
		{
			name:    "unparseable proto",
			environ: []string{"TSPM_IN_WEB=sctp,:443,127.0.0.1:8080"},
			want:    "is not tcp or udp",
		},
		{
			name:    "bad duration",
			environ: []string{"TSPM_OUT_DB=tcp,127.0.0.1:5432,db:5432", "TSPM_DIAL_TIMEOUT=ten seconds"},
			want:    "is not a duration",
		},
		{
			name:    "bad log level",
			environ: []string{"TSPM_OUT_DB=tcp,127.0.0.1:5432,db:5432", "TSPM_LOG_LEVEL=chatty"},
			want:    "is not a level",
		},
		{
			name:    "two mappings on one socket",
			environ: []string{"TSPM_OUT_A=tcp,127.0.0.1:5432,a:5432", "TSPM_OUT_B=tcp,127.0.0.1:5432,b:5432"},
			want:    "must be unique",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			n := &stubNode{}
			err := run(context.Background(), tc.environ, "test", io.Discard, factory(n), noWG)
			if err == nil {
				t.Fatal("want a configuration error, got nil")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
			// Nothing may touch the network before the configuration parses.
			if n.started {
				t.Error("the node was started despite a configuration error")
			}
		})
	}
}

func TestRunReportsNodeStartFailure(t *testing.T) {
	t.Parallel()

	listen := freePort(t)
	n := &stubNode{startErr: errors.New("the supplied auth key was not accepted")}
	err := run(context.Background(),
		[]string{"TSPM_OUT_DB=tcp," + listen + ",db:5432", "TSPM_METRICS_ADDR=" + freePort(t)},
		"test", io.Discard, factory(n), noWG)
	if err == nil || !strings.Contains(err.Error(), "auth key was not accepted") {
		t.Fatalf("got %v, want the node's own start error", err)
	}
	if !n.isClosed() {
		t.Error("the node was not closed after a failed start")
	}
	// A failed start must not leave the mapping's port claimed.
	mustBind(t, listen)
}

// --- bind failures ----------------------------------------------------------

func TestRunReportsBindFailureNamingTheMapping(t *testing.T) {
	t.Parallel()

	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupying a port: %v", err)
	}
	defer taken.Close()

	// APP sorts before DB, so the first mapping binds and the second fails.
	// That is the case worth testing: the error has to name the mapping that
	// failed, and the listener already opened has to be released.
	first := freePort(t)
	environ := []string{
		"TSPM_OUT_APP=tcp," + first + ",app:8080",
		"TSPM_OUT_DB=tcp," + taken.Addr().String() + ",db:5432",
		"TSPM_METRICS_ADDR=" + freePort(t),
	}

	runErr := run(context.Background(), environ, "test", io.Discard, factory(&stubNode{}), noWG)
	if runErr == nil {
		t.Fatal("want a bind error, got nil")
	}
	for _, want := range []string{"mapping DB", "TSPM_OUT_DB", taken.Addr().String()} {
		if !strings.Contains(runErr.Error(), want) {
			t.Errorf("error %q does not mention %q", runErr, want)
		}
	}
	mustBind(t, first)
}

func TestRunReportsStatusAddressInUse(t *testing.T) {
	t.Parallel()

	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupying a port: %v", err)
	}
	defer taken.Close()

	listen := freePort(t)
	environ := []string{
		"TSPM_OUT_DB=tcp," + listen + ",db:5432",
		"TSPM_METRICS_ADDR=" + taken.Addr().String(),
	}
	runErr := run(context.Background(), environ, "test", io.Discard, factory(&stubNode{}), noWG)
	if runErr == nil || !strings.Contains(runErr.Error(), "TSPM_METRICS_ADDR") {
		t.Fatalf("got %v, want an error naming the status address variable", runErr)
	}
	// The mapping bound before the status server did, and must not stay bound.
	mustBind(t, listen)
}

func mustBind(t *testing.T, addr string) {
	t.Helper()
	// The listener is closed from a goroutine that Run does not wait for in
	// every path, so allow a moment for the socket to be released.
	deadline := time.Now().Add(2 * time.Second)
	for {
		ln, err := net.Listen("tcp", addr)
		if err == nil {
			ln.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s is still bound after shutdown: %v", addr, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// --- a full run -------------------------------------------------------------

// echoDial answers every dial with one end of an in-memory pipe whose other end
// echoes. It stands in for a tailnet peer.
func echoDial(ctx context.Context, network, address string) (net.Conn, error) {
	local, remote := net.Pipe()
	go func() {
		defer remote.Close()
		io.Copy(remote, remote)
	}()
	return local, nil
}

func TestRunServesMappingsAndShutsDownCleanly(t *testing.T) {
	outTCP := freePort(t)
	inTCPPort := portOf(t, freePort(t))
	inUDPPort := portOf(t, freePort(t))
	status := freePort(t)

	n := &stubNode{
		ip4:  netip.MustParseAddr("100.101.102.103"),
		ip6:  netip.MustParseAddr("fd7a:115c:a1e0::1"),
		dial: echoDial,
	}
	environ := []string{
		"TSPM_OUT_DB=tcp," + outTCP + ",db:5432",
		"TSPM_IN_WEB=tcp,:" + inTCPPort + ",127.0.0.1:8080",
		"TSPM_IN_DNS=udp,:" + inUDPPort + ",127.0.0.1:5353",
		"TSPM_METRICS_ADDR=" + status,
		"TSPM_SHUTDOWN_GRACE=2s",
		"TSPM_LOG_LEVEL=info",
	}

	ctx, cancel := context.WithCancel(context.Background())
	var logs syncBuffer
	done := make(chan error, 1)
	go func() { done <- run(ctx, environ, "test", &logs, factory(n), noWG) }()

	waitReady(t, status)

	// The egress listener relays to the stub node's dialer, which proves the
	// out+tcp pair is wired to the tailnet side and not to a plain dialer.
	conn, err := net.Dial("tcp", outTCP)
	if err != nil {
		t.Fatalf("dialling the egress mapping: %v", err)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("writing to the egress mapping: %v", err)
	}
	buf := make([]byte, 4)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("reading the echo back: %v", err)
	}
	if got := string(buf); got != "ping" {
		t.Errorf("relayed %q, want %q", got, "ping")
	}
	conn.Close()

	_, _, packet, dialed := n.snapshot()
	// tsnet rejects a wildcard packet bind, so the ingress UDP mapping must
	// have been pinned to the node's own IPv4 address.
	wantPacket := "100.101.102.103:" + inUDPPort
	if len(packet) != 1 || packet[0] != wantPacket {
		t.Errorf("ingress udp bound %v, want [%s]", packet, wantPacket)
	}
	if len(dialed) != 1 || dialed[0] != "tcp/db:5432" {
		t.Errorf("node dials were %v, want [tcp/db:5432]", dialed)
	}

	if body := get(t, "http://"+status+"/metrics"); !strings.Contains(body, `tsportmap_sessions_opened_total{mapping="DB"} 1`) {
		t.Errorf("metrics do not record the session:\n%s", body)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("clean shutdown returned %v, want nil", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Run did not return after its context was cancelled")
	}

	if !n.isClosed() {
		t.Error("the node was not closed on shutdown")
	}
	mustBind(t, outTCP)
	mustBind(t, status)

	// One line per mapping, naming what is exposed.
	log := logs.String()
	for _, want := range []string{
		`mapping=DB dir=out proto=tcp via=ts listen=` + outTCP + ` target=db:5432`,
		`mapping=WEB dir=in proto=tcp`,
		`mapping=DNS dir=in proto=udp`,
	} {
		if !strings.Contains(log, want) {
			t.Errorf("log does not contain %q:\n%s", want, log)
		}
	}
}

// hangingDial answers every dial with one end of a pipe whose other end is
// never read, written or closed. It stands in for a session that will not end
// on its own: a stream with no traffic, or a peer that went quiet without
// hanging up.
func hangingDial(ctx context.Context, network, address string) (net.Conn, error) {
	local, _ := net.Pipe()
	return local, nil
}

// waitMetric polls the status endpoint until the exposition contains want.
func waitMetric(t *testing.T, status, want string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if strings.Contains(get(t, "http://"+status+"/metrics"), want) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("metric %q never appeared", want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A session that never ends must not cost the whole force-close window.
//
// The relay closes its own listener as it returns, so closing the listener
// again after the grace expires reaches nothing; only closing the accepted
// connections lets the relay finish. Without that, shutdown always ran the
// full grace plus forceCloseGrace and then abandoned the session anyway.
func TestRunForceClosesStuckSessionsWithoutBurningTheWindow(t *testing.T) {
	const grace = 200 * time.Millisecond

	outTCP := freePort(t)
	status := freePort(t)
	n := &stubNode{dial: hangingDial}
	environ := []string{
		"TSPM_OUT_DB=tcp," + outTCP + ",db:5432",
		"TSPM_METRICS_ADDR=" + status,
		"TSPM_SHUTDOWN_GRACE=" + grace.String(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var logs syncBuffer
	done := make(chan error, 1)
	go func() { done <- run(ctx, environ, "test", &logs, factory(n), noWG) }()

	waitReady(t, status)

	conn, err := net.Dial("tcp", outTCP)
	if err != nil {
		t.Fatalf("dialling the egress mapping: %v", err)
	}
	defer conn.Close()
	// The session has to be established before the shutdown, or there would be
	// nothing for the force close to reach.
	waitMetric(t, status, `tsportmap_sessions_active{mapping="DB"} 1`)

	start := time.Now()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("shutdown returned %v, want nil", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Run did not return after its context was cancelled")
	}
	elapsed := time.Since(start)

	if elapsed < grace {
		t.Errorf("shutdown took %v, under the configured grace of %v: the live session lost its drain window", elapsed, grace)
	}
	// A force close that cannot reach the session costs grace+forceCloseGrace.
	// Half of the second window is generous room for the relays to unwind.
	if limit := grace + forceCloseGrace/2; elapsed > limit {
		t.Errorf("shutdown took %v with one stuck session, want under %v", elapsed, limit)
	}

	mustBind(t, outTCP)
}

func TestRunReadinessTracksTheNode(t *testing.T) {
	status := freePort(t)
	environ := []string{
		"TSPM_OUT_DB=tcp," + freePort(t) + ",db:5432",
		"TSPM_METRICS_ADDR=" + status,
	}
	n := &stubNode{runningErr: errors.New("tailnet backend state is \"NeedsLogin\"")}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- run(ctx, environ, "test", io.Discard, factory(n), noWG) }()

	// Liveness is process-local and must stay up even while the tailnet is
	// unhealthy; readiness must not.
	waitStatus(t, "http://"+status+"/healthz", http.StatusOK)
	waitStatus(t, "http://"+status+"/readyz", http.StatusServiceUnavailable)

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run returned %v, want nil", err)
	}
}

func waitReady(t *testing.T, status string) {
	t.Helper()
	waitStatus(t, "http://"+status+"/readyz", http.StatusOK)
}

func waitStatus(t *testing.T, url string, want int) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	var last string
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err != nil {
			last = err.Error()
		} else {
			code := resp.StatusCode
			resp.Body.Close()
			if code == want {
				return
			}
			last = fmt.Sprintf("status %d", code)
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s never returned %d: last was %s", url, want, last)
}

func get(t *testing.T, url string) string {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading %s: %v", url, err)
	}
	return string(b)
}

// --- ingress UDP address resolution ----------------------------------------

func TestIngressPacketAddr(t *testing.T) {
	t.Parallel()

	ip4 := netip.MustParseAddr("100.64.0.1")
	ip6 := netip.MustParseAddr("fd7a:115c:a1e0::1")

	tests := []struct {
		name     string
		listen   string
		ip4, ip6 netip.Addr
		want     string
		wantErr  string
	}{
		{
			name:   "empty host takes the node's IPv4",
			listen: ":5353",
			ip4:    ip4, ip6: ip6,
			want: "100.64.0.1:5353",
		},
		{
			name:   "IPv4 wildcard takes the node's IPv4",
			listen: "0.0.0.0:5353",
			ip4:    ip4, ip6: ip6,
			want: "100.64.0.1:5353",
		},
		{
			name:   "IPv6 wildcard prefers the node's IPv6",
			listen: "[::]:5353",
			ip4:    ip4, ip6: ip6,
			want: "[fd7a:115c:a1e0::1]:5353",
		},
		{
			name:   "empty host falls back to IPv6 when there is no IPv4",
			listen: ":5353",
			ip6:    ip6,
			want:   "[fd7a:115c:a1e0::1]:5353",
		},
		{
			name:   "IPv6 wildcard falls back to IPv4",
			listen: "[::]:5353",
			ip4:    ip4,
			want:   "100.64.0.1:5353",
		},
		{
			// config.canonicalHost folds this to 0.0.0.0 when it looks for
			// conflicting binds, so it has to be a wildcard here too.
			name:   "IPv4-mapped IPv6 wildcard takes the node's IPv4",
			listen: "[::ffff:0.0.0.0]:5353",
			ip4:    ip4, ip6: ip6,
			want: "100.64.0.1:5353",
		},
		{
			name:   "IPv4-mapped IPv6 wildcard falls back to IPv6",
			listen: "[::ffff:0.0.0.0]:5353",
			ip6:    ip6,
			want:   "[fd7a:115c:a1e0::1]:5353",
		},
		{
			name:   "a concrete address is left alone",
			listen: "100.64.0.1:5353",
			ip4:    ip4, ip6: ip6,
			want: "100.64.0.1:5353",
		},
		{
			name:    "no tailnet address to substitute",
			listen:  ":5353",
			wantErr: "no tailnet address to substitute",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := ingressPacketAddr(config.Mapping{Name: "DNS", Dir: config.In, Proto: config.UDP, Listen: tc.listen}, tc.ip4, tc.ip6)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("got (%q, %v), want an error mentioning %q", got, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// --- metric classification --------------------------------------------------

func TestDialFailureReason(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want string
	}{
		{"guard refusal", fmt.Errorf("dial %q: %w", "db:5432", tsnode.ErrNotTailnet), obs.ReasonNotTailnet},
		{"dial deadline", fmt.Errorf("dialing: %w", context.DeadlineExceeded), obs.ReasonDialTimeout},
		{"anything else", errors.New("connection reset by peer"), obs.ReasonOther},
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

// --- validation summary -----------------------------------------------------

func TestValidateSummary(t *testing.T) {
	t.Parallel()

	environ := []string{
		"TSPM_HOSTNAME=relay",
		"TSPM_AUTHKEY=tskey-auth-super-secret",
		"TSPM_TAGS=tag:proxy",
		"TSPM_STATE_DIR=/data/tsportmap",
		"TSPM_OUT_DB=tcp,0.0.0.0:5432,db:5432,idle=5m",
		"TSPM_IN_WEB=tcp,:443,127.0.0.1:8080,tls=true",
		"TSPM_IN_DNS=udp,:53,127.0.0.1:5353",
		"TSPM_OUT_CACHE=tcp,127.0.0.1:6379,cache:6379,allow=127.0.0.0/8",
	}

	var out bytes.Buffer
	if err := Validate(environ, "v1.2.3", &out); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	got := out.String()

	for _, want := range []string{
		"tsportmap v1.2.3: configuration is valid",
		"hostname:", "relay",
		"auth key:", "set (redacted)",
		"state dir:", "/data/tsportmap",
		"require tailnet dest:", "true",
		"mappings (4):",
		"CACHE", "out", "tcp", "127.0.0.1:6379", "cache:6379", "127.0.0.0/8",
		"WEB", "in", "127.0.0.1:8080",
		"DNS", "udp",
		// The two things a summary must volunteer: a wildcard UDP bind is not
		// what will really be bound, and a non-loopback egress bind with no
		// allow list is reachable by anything on that network.
		"note: DNS:", "tsnet rejects for UDP",
		"note: DB:", "has no allow list",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("summary does not contain %q:\n%s", want, got)
		}
	}

	if strings.Contains(got, "super-secret") {
		t.Fatalf("the summary leaked the auth key:\n%s", got)
	}
}

func TestValidateReportsConfigurationErrors(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	err := Validate([]string{"TSPM_OUT_DB=tcp,127.0.0.1:5432"}, "test", &out)
	if err == nil || !strings.Contains(err.Error(), "is not a mapping") {
		t.Fatalf("got %v, want a parse error", err)
	}
	if out.Len() != 0 {
		t.Errorf("a rejected configuration still produced a summary: %s", out.String())
	}
}

func TestValidateNeverLeaksAKeyReadFromAFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := dir + "/authkey"
	if err := os.WriteFile(path, []byte("tskey-auth-from-a-file\n"), 0o600); err != nil {
		t.Fatalf("writing the key file: %v", err)
	}

	var out bytes.Buffer
	err := Validate([]string{
		"TSPM_AUTHKEY=file:" + path,
		"TSPM_OUT_DB=tcp,127.0.0.1:5432,db:5432",
	}, "test", &out)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if strings.Contains(out.String(), "from-a-file") {
		t.Fatalf("the summary leaked the auth key:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "set (redacted)") {
		t.Errorf("the summary does not report that a key was supplied:\n%s", out.String())
	}
}

func TestMappingNotesTreatAMappedWildcardAsAWildcard(t *testing.T) {
	t.Parallel()

	notes := mappingNotes(config.Mapping{
		Name: "DNS", Dir: config.In, Proto: config.UDP, Listen: "[::ffff:0.0.0.0]:53",
	})
	joined := strings.Join(notes, "\n")
	if !strings.Contains(joined, "tsnet rejects for UDP") {
		t.Errorf("no wildcard note for a mapped wildcard bind: %q", joined)
	}
}

// --- validation as a startup gate -------------------------------------------

func TestValidateRejectsAMappingOnTheDefaultStatusAddress(t *testing.T) {
	t.Parallel()

	for _, listen := range []string{"127.0.0.1:9090", "0.0.0.0:9090", "[::]:9090"} {
		t.Run(listen, func(t *testing.T) {
			t.Parallel()
			var out bytes.Buffer
			err := Validate([]string{"TSPM_OUT_STATUS=tcp," + listen + ",peer:9090"}, "test", &out)
			if err == nil {
				t.Fatalf("Validate accepted a mapping on the default status address:\n%s", out.String())
			}
			for _, want := range []string{"TSPM_OUT_STATUS", listen, "DEFAULT status address", config.DefaultMetricsAddr, config.EnvMetricsAddr} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not mention %q", err, want)
				}
			}
			if out.Len() != 0 {
				t.Errorf("a rejected configuration still produced a summary:\n%s", out.String())
			}
		})
	}
}

func TestValidateRejectsAMappingOnAnExplicitStatusAddress(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	err := Validate([]string{
		"TSPM_METRICS_ADDR=127.0.0.1:9999",
		"TSPM_OUT_STATUS=tcp,0.0.0.0:9999,peer:9999",
	}, "test", &out)
	if err == nil {
		t.Fatalf("Validate accepted a mapping on the configured status address:\n%s", out.String())
	}
	for _, want := range []string{"TSPM_OUT_STATUS", "0.0.0.0:9999", "set by " + config.EnvMetricsAddr, "127.0.0.1:9999"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

// Binds that share the status port without being able to take it.
func TestValidateAcceptsMappingsTheStatusServerCanCoexistWith(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		environ []string
	}{{
		// An ingress listener lives in tsnet's netstack, not on a host socket.
		name:    "ingress on the status address",
		environ: []string{"TSPM_IN_WEB=tcp,127.0.0.1:9090,127.0.0.1:8080"},
	}, {
		name:    "udp on the status port",
		environ: []string{"TSPM_OUT_DNS=udp,127.0.0.1:9090,dns:53"},
	}, {
		name:    "same port on another address",
		environ: []string{"TSPM_OUT_X=tcp,192.168.1.5:9090,peer:9090"},
	}, {
		name: "the status server was moved out of the way",
		environ: []string{
			"TSPM_METRICS_ADDR=127.0.0.1:9091",
			"TSPM_OUT_X=tcp,127.0.0.1:9090,peer:9090",
		},
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var out bytes.Buffer
			if err := Validate(tc.environ, "test", &out); err != nil {
				t.Fatalf("Validate(%q) = %v, want nil", tc.environ, err)
			}
		})
	}
}

func TestValidateRejectsAnOAuthSecretWithoutTags(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	err := Validate([]string{
		"TSPM_AUTHKEY=tskey-client-supersecret",
		"TSPM_OUT_DB=tcp,127.0.0.1:5432,db:5432",
	}, "test", &out)
	if err == nil {
		t.Fatalf("Validate accepted an OAuth client secret with no tags:\n%s", out.String())
	}
	for _, want := range []string{config.EnvAuthKey, config.EnvTags, "OAuth client secret", "tag:proxy"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "supersecret") {
		t.Fatalf("the error leaked the client secret: %v", err)
	}
	if out.Len() != 0 {
		t.Errorf("a rejected configuration still produced a summary:\n%s", out.String())
	}
}

func TestValidateAcceptsAnOAuthSecretWithTags(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	err := Validate([]string{
		"TSPM_AUTHKEY=tskey-client-supersecret",
		"TSPM_TAGS=tag:proxy",
		"TSPM_OUT_DB=tcp,127.0.0.1:5432,db:5432",
	}, "test", &out)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	// A plain auth key is not an OAuth secret and never needs tags.
	out.Reset()
	err = Validate([]string{
		"TSPM_AUTHKEY=tskey-auth-plain",
		"TSPM_OUT_DB=tcp,127.0.0.1:5432,db:5432",
	}, "test", &out)
	if err != nil {
		t.Fatalf("Validate rejected a plain auth key with no tags: %v", err)
	}
}

// --- session tracking -------------------------------------------------------

// pipeListener hands out net.Pipe conns, which have no CloseWrite.
type pipeListener struct {
	conns chan net.Conn
	addr  net.Addr
}

func (l *pipeListener) Accept() (net.Conn, error) { return <-l.conns, nil }
func (l *pipeListener) Close() error              { return nil }
func (l *pipeListener) Addr() net.Addr            { return l.addr }

// The relay decides whether it can half-close by type-asserting the connection
// it was handed, so the wrapper has to answer for the transport underneath it
// rather than for itself: claiming CloseWrite on a transport without one would
// swallow the EOF, and hiding a real one would truncate the reply still coming
// back the other way.
func TestTrackingListenerPreservesCloseWriteExactly(t *testing.T) {
	t.Parallel()

	type closeWriter interface{ CloseWrite() error }

	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	tl := newTrackingListener(raw)
	defer tl.closeSessions()

	client, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatalf("dialling: %v", err)
	}
	defer client.Close()

	server, err := tl.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	cw, ok := server.(closeWriter)
	if !ok {
		t.Fatalf("a tracked TCP conn (%T) lost CloseWrite", server)
	}
	if err := cw.CloseWrite(); err != nil {
		t.Errorf("CloseWrite on a tracked TCP conn: %v", err)
	}

	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	pl := newTrackingListener(&pipeListener{conns: make(chan net.Conn, 1), addr: raw.Addr()})
	pl.Listener.(*pipeListener).conns <- local
	piped, err := pl.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if _, ok := piped.(closeWriter); ok {
		t.Errorf("a tracked pipe conn (%T) gained a CloseWrite its transport does not have", piped)
	}
}

// A tracked connection must leave the table when the relay closes it, or the
// set of live sessions grows for the lifetime of the process.
func TestTrackingListenerForgetsClosedSessions(t *testing.T) {
	t.Parallel()

	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	tl := newTrackingListener(raw)
	defer tl.closeSessions()

	for i := 0; i < 3; i++ {
		client, err := net.Dial("tcp", raw.Addr().String())
		if err != nil {
			t.Fatalf("dialling: %v", err)
		}
		server, err := tl.Accept()
		if err != nil {
			t.Fatalf("Accept: %v", err)
		}
		server.Close()
		client.Close()
	}

	tl.mu.Lock()
	live := len(tl.conns)
	tl.mu.Unlock()
	if live != 0 {
		t.Errorf("%d closed sessions are still tracked, want 0", live)
	}
}
