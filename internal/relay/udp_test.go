package relay

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Every test here stays on loopback UDP: the relay's contract is about session
// bookkeeping and datagram framing, neither of which needs a tailnet to prove.

const udpTestWait = 3 * time.Second

// udpQuietLogs silences the relay's own warnings for tests that deliberately
// trigger them, so a passing run is not a wall of expected noise.
func udpQuietLogs(t *testing.T) {
	t.Helper()
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
}

type udpFakeRecorder struct {
	mu          sync.Mutex
	opened      int
	closed      int
	up, down    int64
	dialFailure []string
	rejections  []string
}

func (r *udpFakeRecorder) SessionOpened(string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.opened++
}

func (r *udpFakeRecorder) SessionClosed(_ string, up, down int64, _ time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed++
	r.up += up
	r.down += down
}

func (r *udpFakeRecorder) DialFailed(_, reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.dialFailure = append(r.dialFailure, reason)
}

func (r *udpFakeRecorder) Rejected(_, reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rejections = append(r.rejections, reason)
}

func (r *udpFakeRecorder) counts() (opened, closed int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.opened, r.closed
}

func (r *udpFakeRecorder) bytes() (up, down int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.up, r.down
}

func (r *udpFakeRecorder) reasons(which *[]string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), *which...)
}

func (r *udpFakeRecorder) dialFailures() []string { return r.reasons(&r.dialFailure) }
func (r *udpFakeRecorder) rejected() []string     { return r.reasons(&r.rejections) }

// udpTrackedConn reports when the relay closed the onward leg.
type udpTrackedConn struct {
	net.Conn
	once   sync.Once
	closed chan struct{}
}

func (c *udpTrackedConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

// udpTrackedDialer is a real loopback dialer that keeps the conns it handed out
// and counts how many times it was asked for one.
type udpTrackedDialer struct {
	calls atomic.Int32
	mu    sync.Mutex
	conns []*udpTrackedConn

	// gate, when non-nil, holds the first dial until it is closed. It models a
	// target that is slow to reach.
	gate chan struct{}
	// fail, when non-nil, is returned instead of dialling.
	fail error
	// block, when true, ignores the target entirely and waits for ctx.
	block bool
}

func (d *udpTrackedDialer) dial(ctx context.Context, network, address string) (net.Conn, error) {
	first := d.calls.Add(1) == 1
	if first && d.gate != nil {
		select {
		case <-d.gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if d.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if d.fail != nil {
		return nil, d.fail
	}
	var nd net.Dialer
	c, err := nd.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	tc := &udpTrackedConn{Conn: c, closed: make(chan struct{})}
	d.mu.Lock()
	d.conns = append(d.conns, tc)
	d.mu.Unlock()
	return tc, nil
}

func (d *udpTrackedDialer) conn(t *testing.T, i int) *udpTrackedConn {
	t.Helper()
	d.mu.Lock()
	defer d.mu.Unlock()
	if i >= len(d.conns) {
		t.Fatalf("wanted onward conn %d, only %d were dialled", i, len(d.conns))
	}
	return d.conns[i]
}

// udpEchoServer answers every datagram with transform(payload) and records the
// distinct source addresses it saw, which is how a test proves the relay opened
// one onward socket per client rather than sharing one.
type udpEchoServer struct {
	addr string

	mu      sync.Mutex
	sources map[string]int
}

func (e *udpEchoServer) distinctSources() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.sources)
}

func newUDPEchoServer(t *testing.T, transform func([]byte) []byte) *udpEchoServer {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo: %v", err)
	}
	t.Cleanup(func() { pc.Close() })

	e := &udpEchoServer{addr: pc.LocalAddr().String(), sources: make(map[string]int)}
	go func() {
		buf := make([]byte, udpMaxDatagram)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			e.mu.Lock()
			e.sources[from.String()]++
			e.mu.Unlock()

			out := buf[:n]
			if transform != nil {
				out = transform(buf[:n])
			}
			if _, err := pc.WriteTo(out, from); err != nil {
				return
			}
		}
	}()
	return e
}

// udpRelay is a running serveUDP under test.
type udpRelay struct {
	addr   string
	cancel context.CancelFunc

	errCh chan error
	once  sync.Once
	err   error
}

// wait cancels nothing; it collects serveUDP's return value at most once, so a
// test and the cleanup can both call it.
func (r *udpRelay) wait(t *testing.T) error {
	t.Helper()
	r.once.Do(func() {
		select {
		case r.err = <-r.errCh:
		case <-time.After(udpTestWait):
			t.Error("serveUDP did not return after cancellation")
		}
	})
	return r.err
}

func startUDPRelay(t *testing.T, dial DialFunc, opts Options, maxSessions int) *udpRelay {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen relay: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &udpRelay{addr: pc.LocalAddr().String(), cancel: cancel, errCh: make(chan error, 1)}
	go func() { r.errCh <- serveUDP(ctx, pc, dial, opts, maxSessions) }()
	t.Cleanup(func() {
		cancel()
		r.wait(t)
		pc.Close()
	})
	return r
}

func udpDialClient(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func udpSend(t *testing.T, c net.Conn, b []byte) {
	t.Helper()
	if _, err := c.Write(b); err != nil {
		t.Fatalf("send: %v", err)
	}
}

func udpRecv(t *testing.T, c net.Conn) []byte {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(udpTestWait)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	buf := make([]byte, udpMaxDatagram)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	return buf[:n]
}

func udpExpectSilence(t *testing.T, c net.Conn, d time.Duration) {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(d)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	buf := make([]byte, udpMaxDatagram)
	n, err := c.Read(buf)
	if err == nil {
		t.Fatalf("expected no reply, got %d bytes: %q", n, buf[:n])
	}
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("expected read timeout, got %v", err)
	}
}

func udpWaitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(udpTestWait)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func udpPrefixes(t *testing.T, cidrs ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			t.Fatalf("parse prefix %q: %v", c, err)
		}
		out = append(out, p)
	}
	return out
}

func TestServeUDPRoundTrip(t *testing.T) {
	echo := newUDPEchoServer(t, func(b []byte) []byte { return append([]byte("echo:"), b...) })
	rec := &udpFakeRecorder{}
	d := &udpTrackedDialer{}
	r := startUDPRelay(t, d.dial, Options{
		Name:    "roundtrip",
		Target:  echo.addr,
		Idle:    time.Minute,
		Metrics: rec,
	}, udpMaxSessions)

	c := udpDialClient(t, r.addr)
	udpSend(t, c, []byte("ping"))

	if got, want := udpRecv(t, c), []byte("echo:ping"); !bytes.Equal(got, want) {
		t.Fatalf("reply = %q, want %q", got, want)
	}
	udpWaitFor(t, "session opened", func() bool { o, _ := rec.counts(); return o == 1 })

	// Teardown must account the session, in both directions.
	r.cancel()
	if err := r.wait(t); err != nil {
		t.Fatalf("serveUDP = %v, want nil", err)
	}
	if o, cl := rec.counts(); o != 1 || cl != 1 {
		t.Fatalf("opened=%d closed=%d, want 1/1", o, cl)
	}
	if up, down := rec.bytes(); up != int64(len("ping")) || down != int64(len("echo:ping")) {
		t.Fatalf("up=%d down=%d, want %d/%d", up, down, len("ping"), len("echo:ping"))
	}
}

// TestServeUDPSessionsAreNotCrossed is the property the session table exists
// for: two source addresses must never see each other's replies.
func TestServeUDPSessionsAreNotCrossed(t *testing.T) {
	echo := newUDPEchoServer(t, nil)
	d := &udpTrackedDialer{}
	r := startUDPRelay(t, d.dial, Options{
		Name:   "crosstalk",
		Target: echo.addr,
		Idle:   time.Minute,
	}, udpMaxSessions)

	a := udpDialClient(t, r.addr)
	b := udpDialClient(t, r.addr)

	for i := range 5 {
		wantA := fmt.Appendf(nil, "alpha-%d", i)
		wantB := fmt.Appendf(nil, "bravo-%d", i)

		// Interleaved, so a crossed table would show up as b reading alpha.
		udpSend(t, a, wantA)
		udpSend(t, b, wantB)

		if got := udpRecv(t, a); !bytes.Equal(got, wantA) {
			t.Fatalf("round %d: client a got %q, want %q", i, got, wantA)
		}
		if got := udpRecv(t, b); !bytes.Equal(got, wantB) {
			t.Fatalf("round %d: client b got %q, want %q", i, got, wantB)
		}
	}

	if got := d.calls.Load(); got != 2 {
		t.Fatalf("onward dials = %d, want 2 (one per client address)", got)
	}
	if got := echo.distinctSources(); got != 2 {
		t.Fatalf("target saw %d source addresses, want 2", got)
	}
}

// TestServeUDPPreservesDatagramBoundaries sends differently-sized payloads back
// to back. A stream copy would be free to merge or split them; a datagram relay
// must not.
func TestServeUDPPreservesDatagramBoundaries(t *testing.T) {
	echo := newUDPEchoServer(t, nil)
	r := startUDPRelay(t, (&udpTrackedDialer{}).dial, Options{
		Name:   "boundaries",
		Target: echo.addr,
		Idle:   time.Minute,
	}, udpMaxSessions)

	// Zero length is included deliberately: an empty datagram is legal and must
	// arrive as an empty datagram rather than being dropped.
	sizes := []int{0, 1, 7, 512, 1400, 8000, 20000}
	sent := make([][]byte, len(sizes))
	c := udpDialClient(t, r.addr)
	for i, size := range sizes {
		payload := bytes.Repeat([]byte{byte('a' + i)}, size)
		sent[i] = payload
		udpSend(t, c, payload)
	}

	for i := range sizes {
		got := udpRecv(t, c)
		if !bytes.Equal(got, sent[i]) {
			t.Fatalf("datagram %d: got %d bytes, want %d (boundaries not preserved)", i, len(got), len(sent[i]))
		}
	}
}

func TestServeUDPIdleEviction(t *testing.T) {
	echo := newUDPEchoServer(t, nil)
	rec := &udpFakeRecorder{}
	d := &udpTrackedDialer{}
	const idle = 80 * time.Millisecond
	r := startUDPRelay(t, d.dial, Options{
		Name:    "idle",
		Target:  echo.addr,
		Idle:    idle,
		Metrics: rec,
	}, udpMaxSessions)

	c := udpDialClient(t, r.addr)
	udpSend(t, c, []byte("first"))
	udpRecv(t, c)

	select {
	case <-d.conn(t, 0).closed:
	case <-time.After(udpTestWait):
		t.Fatal("idle session's onward conn was never closed")
	}
	udpWaitFor(t, "session accounted closed", func() bool { _, cl := rec.counts(); return cl == 1 })

	// The client is not blacklisted by eviction: sending again rebuilds a
	// session, which is what proves the entry left the table.
	udpSend(t, c, []byte("second"))
	if got, want := udpRecv(t, c), []byte("second"); !bytes.Equal(got, want) {
		t.Fatalf("reply after eviction = %q, want %q", got, want)
	}
	udpWaitFor(t, "second dial", func() bool { return d.calls.Load() == 2 })
}

func TestServeUDPSessionCapRejectsNewClients(t *testing.T) {
	udpQuietLogs(t)
	echo := newUDPEchoServer(t, nil)
	rec := &udpFakeRecorder{}
	d := &udpTrackedDialer{}
	r := startUDPRelay(t, d.dial, Options{
		Name:    "capped",
		Target:  echo.addr,
		Idle:    time.Minute,
		Metrics: rec,
	}, 2)

	a := udpDialClient(t, r.addr)
	b := udpDialClient(t, r.addr)
	udpSend(t, a, []byte("a1"))
	udpRecv(t, a)
	udpSend(t, b, []byte("b1"))
	udpRecv(t, b)

	over := udpDialClient(t, r.addr)
	udpSend(t, over, []byte("c1"))
	udpExpectSilence(t, over, 200*time.Millisecond)

	if got := rec.rejected(); len(got) != 1 || got[0] != ReasonSessionCap {
		t.Fatalf("rejections = %v, want one \"session table full\"", got)
	}
	if got := d.calls.Load(); got != 2 {
		t.Fatalf("onward dials = %d, want 2: a rejected client must not dial", got)
	}
	if o, cl := rec.counts(); o != 2 || cl != 0 {
		t.Fatalf("opened=%d closed=%d, want 2/0: an established session must not be evicted to admit a new one", o, cl)
	}

	// The sessions that were already there keep working.
	for _, tc := range []struct {
		name string
		c    net.Conn
		msg  string
	}{{"a", a, "a2"}, {"b", b, "b2"}} {
		udpSend(t, tc.c, []byte(tc.msg))
		if got := udpRecv(t, tc.c); !bytes.Equal(got, []byte(tc.msg)) {
			t.Fatalf("client %s reply = %q, want %q", tc.name, got, tc.msg)
		}
	}
}

func TestServeUDPAllowList(t *testing.T) {
	udpQuietLogs(t)
	tests := []struct {
		name    string
		allow   []string
		wantOK  bool
		wantErr string
	}{
		{name: "empty allows everything", allow: nil, wantOK: true},
		{name: "matching v4 prefix", allow: []string{"127.0.0.0/8"}, wantOK: true},
		{name: "host route on the client", allow: []string{"127.0.0.1/32"}, wantOK: true},
		{name: "one of several matches", allow: []string{"10.0.0.0/8", "127.0.0.0/8"}, wantOK: true},
		{name: "non-matching v4 prefix", allow: []string{"10.0.0.0/8"}, wantErr: ReasonAllowList},
		{name: "v6 prefix does not cover a v4 source", allow: []string{"::1/128"}, wantErr: ReasonAllowList},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			echo := newUDPEchoServer(t, nil)
			rec := &udpFakeRecorder{}
			d := &udpTrackedDialer{}
			r := startUDPRelay(t, d.dial, Options{
				Name:    "allow",
				Target:  echo.addr,
				Idle:    time.Minute,
				Allow:   udpPrefixes(t, tt.allow...),
				Metrics: rec,
			}, udpMaxSessions)

			c := udpDialClient(t, r.addr)
			udpSend(t, c, []byte("knock"))

			if tt.wantOK {
				if got := udpRecv(t, c); !bytes.Equal(got, []byte("knock")) {
					t.Fatalf("reply = %q, want %q", got, "knock")
				}
				if got := rec.rejected(); len(got) != 0 {
					t.Fatalf("rejections = %v, want none", got)
				}
				return
			}

			udpExpectSilence(t, c, 200*time.Millisecond)
			if got := rec.rejected(); len(got) == 0 || got[0] != tt.wantErr {
				t.Fatalf("rejections = %v, want %q", got, tt.wantErr)
			}
			if got := d.calls.Load(); got != 0 {
				t.Fatalf("onward dials = %d, want 0: a disallowed source must be refused before any dial", got)
			}
			if o, _ := rec.counts(); o != 0 {
				t.Fatalf("opened = %d, want 0", o)
			}
		})
	}
}

func TestServeUDPDialFailure(t *testing.T) {
	udpQuietLogs(t)
	tests := []struct {
		name        string
		dialer      *udpTrackedDialer
		dialTimeout time.Duration
		wantReason  string
	}{
		{
			name:       "target refuses",
			dialer:     &udpTrackedDialer{fail: errors.New("no route to host")},
			wantReason: ReasonOther,
		},
		{
			name:        "dial exceeds DialTimeout",
			dialer:      &udpTrackedDialer{block: true},
			dialTimeout: 50 * time.Millisecond,
			wantReason:  ReasonDialTimeout,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := &udpFakeRecorder{}
			r := startUDPRelay(t, tt.dialer.dial, Options{
				Name:        "dialfail",
				Target:      "198.51.100.1:9",
				Idle:        time.Minute,
				DialTimeout: tt.dialTimeout,
				Metrics:     rec,
			}, udpMaxSessions)

			c := udpDialClient(t, r.addr)
			udpSend(t, c, []byte("hello"))

			udpWaitFor(t, "dial failure recorded", func() bool { return len(rec.dialFailures()) == 1 })
			if got := rec.dialFailures(); got[0] != tt.wantReason {
				t.Fatalf("dial failure reason = %q, want %q", got[0], tt.wantReason)
			}
			if o, cl := rec.counts(); o != 0 || cl != 0 {
				t.Fatalf("opened=%d closed=%d, want 0/0: a session that never dialled is never open", o, cl)
			}
			udpExpectSilence(t, c, 100*time.Millisecond)

			// The failed session must have left the table, or the client could
			// never retry.
			udpSend(t, c, []byte("hello again"))
			udpWaitFor(t, "second dial attempt", func() bool { return tt.dialer.calls.Load() >= 2 })
		})
	}
}

// TestServeUDPSlowDialDoesNotBlockOtherClients pins the reason the onward dial
// runs off the read loop.
func TestServeUDPSlowDialDoesNotBlockOtherClients(t *testing.T) {
	echo := newUDPEchoServer(t, nil)
	gate := make(chan struct{})
	d := &udpTrackedDialer{gate: gate}
	r := startUDPRelay(t, d.dial, Options{
		Name:   "slowdial",
		Target: echo.addr,
		Idle:   time.Minute,
	}, udpMaxSessions)

	slow := udpDialClient(t, r.addr)
	udpSend(t, slow, []byte("slow"))
	udpWaitFor(t, "first dial to start", func() bool { return d.calls.Load() == 1 })

	fast := udpDialClient(t, r.addr)
	udpSend(t, fast, []byte("fast"))
	if got := udpRecv(t, fast); !bytes.Equal(got, []byte("fast")) {
		t.Fatalf("second client reply = %q, want %q", got, "fast")
	}

	// Releasing the stalled dial delivers the datagram that was queued behind it
	// rather than dropping it.
	close(gate)
	if got := udpRecv(t, slow); !bytes.Equal(got, []byte("slow")) {
		t.Fatalf("first client reply = %q, want %q", got, "slow")
	}
}

func TestServeUDPCancellationTearsDownSessions(t *testing.T) {
	echo := newUDPEchoServer(t, nil)
	rec := &udpFakeRecorder{}
	d := &udpTrackedDialer{}
	r := startUDPRelay(t, d.dial, Options{
		Name:    "cancel",
		Target:  echo.addr,
		Idle:    time.Minute,
		Metrics: rec,
	}, udpMaxSessions)

	clients := []net.Conn{udpDialClient(t, r.addr), udpDialClient(t, r.addr)}
	for i, c := range clients {
		msg := fmt.Appendf(nil, "client-%d", i)
		udpSend(t, c, msg)
		if got := udpRecv(t, c); !bytes.Equal(got, msg) {
			t.Fatalf("client %d reply = %q, want %q", i, got, msg)
		}
	}

	r.cancel()
	if err := r.wait(t); err != nil {
		t.Fatalf("serveUDP = %v, want nil on cancellation", err)
	}
	// Returning implies every session goroutine has already been waited for, so
	// these are not races.
	for i := range clients {
		select {
		case <-d.conn(t, i).closed:
		default:
			t.Fatalf("onward conn %d still open after serveUDP returned", i)
		}
	}
	if o, cl := rec.counts(); o != 2 || cl != 2 {
		t.Fatalf("opened=%d closed=%d, want 2/2", o, cl)
	}
}

func TestServeUDPClosedPacketConnReturnsNil(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- ServeUDP(context.Background(), pc, (&udpTrackedDialer{}).dial, Options{
			Name:   "closed",
			Target: "127.0.0.1:9",
			Idle:   time.Minute,
		})
	}()

	// Give the read loop time to block in ReadFrom before pulling the conn.
	udpWaitFor(t, "relay to start reading", func() bool {
		c, err := net.Dial("udp", pc.LocalAddr().String())
		if err != nil {
			return false
		}
		c.Close()
		return true
	})
	pc.Close()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("ServeUDP = %v, want nil when the PacketConn is closed", err)
		}
	case <-time.After(udpTestWait):
		t.Fatal("ServeUDP did not return after its PacketConn was closed")
	}
}

func TestServeUDPReadErrorIsReported(t *testing.T) {
	// A read failure that is neither cancellation nor a closed conn is a real
	// error and must reach the caller, which supervises the mapping.
	want := errors.New("interface went away")
	pc := &udpBrokenPacketConn{err: want}
	err := ServeUDP(context.Background(), pc, (&udpTrackedDialer{}).dial, Options{Name: "broken", Target: "127.0.0.1:9"})
	if !errors.Is(err, want) {
		t.Fatalf("ServeUDP = %v, want it to wrap %v", err, want)
	}
}

// udpBrokenPacketConn fails every read with a non-recoverable error.
type udpBrokenPacketConn struct {
	net.PacketConn
	err error
}

func (c *udpBrokenPacketConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, c.err }
func (c *udpBrokenPacketConn) SetReadDeadline(time.Time) error        { return nil }
func (c *udpBrokenPacketConn) Close() error                           { return nil }

func TestUDPReapInterval(t *testing.T) {
	tests := []struct {
		name string
		idle time.Duration
		want time.Duration
	}{
		{"quarter of the window", 60 * time.Second, 15 * time.Second},
		{"clamped up for a tiny window", time.Millisecond, udpMinReapInterval},
		{"clamped down for a huge window", 24 * time.Hour, udpMaxReapInterval},
		{"exactly the lower clamp", 4 * udpMinReapInterval, udpMinReapInterval},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := udpReapInterval(tt.idle); got != tt.want {
				t.Fatalf("udpReapInterval(%v) = %v, want %v", tt.idle, got, tt.want)
			}
		})
	}
}

func TestUDPTableIdentityOnRemove(t *testing.T) {
	// A client whose session was evicted can be back in the table under the same
	// key before the old session's goroutine finishes unwinding. That goroutine
	// must not delete the replacement.
	tbl := &udpTable{sessions: make(map[string]*udpSession), max: 4}
	old := &udpSession{key: "203.0.113.5:1234"}
	if !tbl.add(old) {
		t.Fatal("add(old) = false, want true")
	}
	tbl.remove(old)

	fresh := &udpSession{key: old.key}
	if !tbl.add(fresh) {
		t.Fatal("add(fresh) = false, want true")
	}
	tbl.remove(old)

	if got, ok := tbl.get(fresh.key); !ok || got != fresh {
		t.Fatalf("get(%q) = %v/%v, want the replacement session", fresh.key, got, ok)
	}
	if got := tbl.len(); got != 1 {
		t.Fatalf("table len = %d, want 1", got)
	}
}
