package relay

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"
)

// waitTimeout bounds every "eventually" assertion. It is generous because a
// failure to converge is a real bug, not slow CI.
const waitTimeout = 5 * time.Second

// --- test doubles -----------------------------------------------------------

type closedSession struct {
	name     string
	up, down int64
	dur      time.Duration
}

// testRecorder records every accounting call. It is written to from session
// goroutines and read from the test goroutine, so every field is behind mu.
type testRecorder struct {
	mu         sync.Mutex
	opened     int
	closed     []closedSession
	dialFailed []string
	rejected   []string
}

func (r *testRecorder) SessionOpened(string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.opened++
}

func (r *testRecorder) SessionClosed(name string, up, down int64, d time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = append(r.closed, closedSession{name: name, up: up, down: down, dur: d})
}

func (r *testRecorder) DialFailed(_, reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.dialFailed = append(r.dialFailed, reason)
}

func (r *testRecorder) Rejected(_, reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rejected = append(r.rejected, reason)
}

func (r *testRecorder) snapshot() (opened int, closed []closedSession, dialFailed, rejected []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.opened, append([]closedSession(nil), r.closed...),
		append([]string(nil), r.dialFailed...), append([]string(nil), r.rejected...)
}

func (r *testRecorder) closedCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.closed)
}

// scriptedListener replays a fixed sequence of Accept results, then blocks
// until Close. It exists to drive accept-loop error handling, which a real
// listener will not reproduce on demand.
type scriptedListener struct {
	mu     sync.Mutex
	steps  []acceptStep
	closed chan struct{}
	once   sync.Once
}

type acceptStep struct {
	conn net.Conn
	err  error
}

func newScriptedListener(steps ...acceptStep) *scriptedListener {
	return &scriptedListener{steps: steps, closed: make(chan struct{})}
}

func (l *scriptedListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if len(l.steps) > 0 {
		s := l.steps[0]
		l.steps = l.steps[1:]
		l.mu.Unlock()
		return s.conn, s.err
	}
	l.mu.Unlock()
	<-l.closed
	return nil, net.ErrClosed
}

func (l *scriptedListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *scriptedListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4zero} }

// tempError models an Accept failure that concerned a single connection.
type tempError struct{}

func (tempError) Error() string   { return "scripted temporary accept failure" }
func (tempError) Temporary() bool { return true }
func (tempError) Timeout() bool   { return false }

// --- helpers ----------------------------------------------------------------

// startServer runs handle for each connection on a loopback listener and
// returns its address. Real sockets are used wherever half-close matters,
// because net.Pipe cannot express it.
func startServer(t *testing.T, handle func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() {
		ln.Close()
		wg.Wait()
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				handle(c)
			}()
		}
	}()
	return ln.Addr().String()
}

// echoHandler copies a connection back to itself until the peer half-closes.
func echoHandler(c net.Conn) { io.Copy(c, c) }

func loopbackDial(ctx context.Context, network, address string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}

type harness struct {
	addr   string
	cancel context.CancelFunc
	errCh  chan error

	once sync.Once
	err  error
}

// start runs ServeTCP on a loopback listener. The returned harness both cancels
// and collects the result, so a test can assert on the return value and the
// cleanup can still verify it exited.
func start(t *testing.T, dial DialFunc, opts Options) *harness {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	h := &harness{addr: ln.Addr().String(), cancel: cancel, errCh: make(chan error, 1)}
	go func() { h.errCh <- ServeTCP(ctx, ln, dial, opts) }()
	t.Cleanup(func() {
		cancel()
		if err := h.wait(); err != nil {
			t.Errorf("ServeTCP returned %v, want nil", err)
		}
	})
	return h
}

func (h *harness) wait() error {
	h.once.Do(func() {
		select {
		case h.err = <-h.errCh:
		case <-time.After(waitTimeout):
			h.err = errors.New("ServeTCP did not return")
		}
	})
	return h.err
}

func (h *harness) returned() bool {
	select {
	case err := <-h.errCh:
		h.once.Do(func() { h.err = err })
		return true
	default:
		return false
	}
}

func (h *harness) dial(t *testing.T) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", h.addr, waitTimeout)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// expectClosed asserts that the far side closed c. The distinction from a plain
// "read failed" matters: a read that ends on the test's own deadline is exactly
// what a leaked connection looks like, so that case is a failure too.
func expectClosed(t *testing.T, c net.Conn) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(waitTimeout))
	n, err := c.Read(make([]byte, 8))
	var netErr net.Error
	switch {
	case err == nil:
		t.Fatalf("read returned %d bytes, want the connection to be closed", n)
	case errors.Is(err, os.ErrDeadlineExceeded), errors.As(err, &netErr) && netErr.Timeout():
		t.Fatalf("read hit the test deadline after %v: the connection was leaked, not closed", waitTimeout)
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("parse prefix %q: %v", s, err)
	}
	return p
}

func writeAll(t *testing.T, c net.Conn, b []byte) {
	t.Helper()
	if _, err := c.Write(b); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func closeWriteSide(t *testing.T, c net.Conn) {
	t.Helper()
	tc, ok := c.(*net.TCPConn)
	if !ok {
		t.Fatalf("conn %T cannot half-close", c)
	}
	if err := tc.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
}

// --- tests ------------------------------------------------------------------

func TestServeTCPRelaysBothDirections(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		payload []byte
	}{
		{name: "small", payload: []byte("ping")},
		{name: "one buffer", payload: bytes.Repeat([]byte("a"), copyBufferSize)},
		{name: "many buffers", payload: bytes.Repeat([]byte("bc"), 5*copyBufferSize)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rec := &testRecorder{}
			target := startServer(t, echoHandler)
			h := start(t, loopbackDial, Options{Name: "echo", Target: target, Metrics: rec})

			c := h.dial(t)
			// A payload larger than the socket buffers only completes once the
			// reader below drains it, so the write runs concurrently.
			werr := make(chan error, 1)
			go func() {
				_, err := c.Write(tc.payload)
				werr <- err
			}()

			got := make([]byte, len(tc.payload))
			if _, err := io.ReadFull(c, got); err != nil {
				t.Fatalf("read echo: %v", err)
			}
			if err := <-werr; err != nil {
				t.Fatalf("write: %v", err)
			}
			if !bytes.Equal(got, tc.payload) {
				t.Fatalf("echo mismatch: got %d bytes, want %d", len(got), len(tc.payload))
			}

			c.Close()
			waitFor(t, "session accounting", func() bool { return rec.closedCount() == 1 })
			opened, closed, _, _ := rec.snapshot()
			if opened != 1 {
				t.Fatalf("SessionOpened called %d times, want 1", opened)
			}
			if closed[0].name != "echo" {
				t.Fatalf("SessionClosed name = %q, want %q", closed[0].name, "echo")
			}
		})
	}
}

// TestServeTCPHalfCloseDeliversFinalBytes is the regression test for the
// classic truncation bug: the client signals end-of-request by closing its
// write side, and the whole response must still arrive.
func TestServeTCPHalfCloseDeliversFinalBytes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		size int
	}{
		{name: "single write", size: 11},
		{name: "spanning buffers", size: 3*copyBufferSize + 7},
		{name: "megabyte", size: 1 << 20},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			want := make([]byte, tc.size)
			for i := range want {
				want[i] = byte(i % 251)
			}
			request := []byte("SELECT 1")

			// The server answers only after it has seen end-of-request, so the
			// response cannot be delivered at all unless the half-close was
			// propagated onward.
			target := startServer(t, func(c net.Conn) {
				got, err := io.ReadAll(c)
				if err != nil {
					t.Errorf("target read request: %v", err)
					return
				}
				if !bytes.Equal(got, request) {
					t.Errorf("target got request %q, want %q", got, request)
					return
				}
				if _, err := c.Write(want); err != nil {
					t.Errorf("target write response: %v", err)
				}
			})

			rec := &testRecorder{}
			h := start(t, loopbackDial, Options{Name: "db", Target: target, Metrics: rec})

			c := h.dial(t)
			writeAll(t, c, request)
			closeWriteSide(t, c)

			got, err := io.ReadAll(c)
			if err != nil {
				t.Fatalf("read response: %v", err)
			}
			if len(got) != len(want) {
				t.Fatalf("response truncated: got %d bytes, want %d", len(got), len(want))
			}
			if !bytes.Equal(got, want) {
				t.Fatal("response corrupted")
			}

			waitFor(t, "session accounting", func() bool { return rec.closedCount() == 1 })
			_, closed, _, _ := rec.snapshot()
			if closed[0].up != int64(len(request)) || closed[0].down != int64(len(want)) {
				t.Fatalf("accounting = up %d down %d, want up %d down %d",
					closed[0].up, closed[0].down, len(request), len(want))
			}
		})
	}
}

func TestServeTCPAllowList(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		allow      []string
		wantReject bool
	}{
		{name: "empty allows everything", allow: nil},
		{name: "matching prefix", allow: []string{"127.0.0.0/8"}},
		{name: "second prefix matches", allow: []string{"198.51.100.0/24", "127.0.0.1/32"}},
		{name: "no prefix matches", allow: []string{"198.51.100.0/24"}, wantReject: true},
		{name: "v6 prefix does not match v4 source", allow: []string{"::1/128"}, wantReject: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rec := &testRecorder{}
			target := startServer(t, echoHandler)

			var dialled int64
			var mu sync.Mutex
			dial := func(ctx context.Context, network, address string) (net.Conn, error) {
				mu.Lock()
				dialled++
				mu.Unlock()
				return loopbackDial(ctx, network, address)
			}

			var allow []netip.Prefix
			for _, p := range tc.allow {
				allow = append(allow, mustPrefix(t, p))
			}
			h := start(t, dial, Options{Name: "guarded", Target: target, Allow: allow, Metrics: rec})

			c := h.dial(t)
			writeAll(t, c, []byte("hello"))

			if tc.wantReject {
				// A rejected connection is closed without a dial, so the read
				// ends rather than echoing.
				expectClosed(t, c)
				waitFor(t, "rejection", func() bool {
					_, _, _, rejected := rec.snapshot()
					return len(rejected) == 1
				})
				opened, _, _, rejected := rec.snapshot()
				if rejected[0] == "" {
					t.Fatal("Rejected recorded an empty reason")
				}
				if opened != 0 {
					t.Fatalf("SessionOpened called %d times for a rejected source", opened)
				}
				mu.Lock()
				defer mu.Unlock()
				if dialled != 0 {
					t.Fatalf("dialled %d times for a rejected source, want 0", dialled)
				}
				return
			}

			got := make([]byte, 5)
			if _, err := io.ReadFull(c, got); err != nil {
				t.Fatalf("read echo: %v", err)
			}
			_, _, _, rejected := rec.snapshot()
			if len(rejected) != 0 {
				t.Fatalf("Rejected recorded %v for an allowed source", rejected)
			}
		})
	}
}

func TestServeTCPDialFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		dialErr    error
		wantReason string
	}{
		{name: "generic", dialErr: errors.New("connection refused"), wantReason: ReasonOther},
		{name: "deadline", dialErr: context.DeadlineExceeded, wantReason: ReasonDialTimeout},
		{name: "canceled", dialErr: context.Canceled, wantReason: ReasonCanceled},
		{
			name:       "dns",
			dialErr:    &net.DNSError{Err: "no such host", Name: "nowhere.example", IsNotFound: true},
			wantReason: ReasonDNS,
		},
		{
			name:       "wrapped deadline",
			dialErr:    fmt.Errorf("dial onward: %w", context.DeadlineExceeded),
			wantReason: ReasonDialTimeout,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rec := &testRecorder{}
			dial := func(context.Context, string, string) (net.Conn, error) { return nil, tc.dialErr }
			h := start(t, dial, Options{Name: "broken", Target: "nowhere.example:1", Metrics: rec})

			c := h.dial(t)
			// The accepted conn must be closed, not leaked, when the onward leg
			// fails.
			expectClosed(t, c)

			waitFor(t, "dial failure", func() bool {
				_, _, failed, _ := rec.snapshot()
				return len(failed) == 1
			})
			opened, closed, failed, _ := rec.snapshot()
			if failed[0] != tc.wantReason {
				t.Fatalf("DialFailed reason = %q, want %q", failed[0], tc.wantReason)
			}
			if opened != 0 || len(closed) != 0 {
				t.Fatalf("session accounted for a failed dial: opened %d closed %d", opened, len(closed))
			}
		})
	}
}

// TestServeTCPDialTimeout checks that Options.DialTimeout actually bounds the
// onward dial rather than being carried but ignored.
func TestServeTCPDialTimeout(t *testing.T) {
	t.Parallel()

	rec := &testRecorder{}
	dialCtx := make(chan context.Context, 1)
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		select {
		case dialCtx <- ctx:
		default:
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	h := start(t, dial, Options{
		Name:        "slow",
		Target:      "192.0.2.1:9",
		DialTimeout: 40 * time.Millisecond,
		Metrics:     rec,
	})

	start := time.Now()
	c := h.dial(t)
	expectClosed(t, c)
	if elapsed := time.Since(start); elapsed > waitTimeout/2 {
		t.Fatalf("dial took %v, want it bounded by DialTimeout", elapsed)
	}

	waitFor(t, "dial failure", func() bool {
		_, _, failed, _ := rec.snapshot()
		return len(failed) == 1
	})
	_, _, failed, _ := rec.snapshot()
	if failed[0] != ReasonDialTimeout {
		t.Fatalf("DialFailed reason = %q, want %q", failed[0], "timeout")
	}

	select {
	case ctx := <-dialCtx:
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("dial context carried no deadline")
		}
	default:
		t.Fatal("dial was never called")
	}
}

func TestServeTCPIdleTimeout(t *testing.T) {
	t.Parallel()

	const idle = 100 * time.Millisecond

	t.Run("reaps a silent session", func(t *testing.T) {
		t.Parallel()
		rec := &testRecorder{}
		target := startServer(t, echoHandler)
		h := start(t, loopbackDial, Options{Name: "idle", Target: target, Idle: idle, Metrics: rec})

		c := h.dial(t)
		expectClosed(t, c)
		waitFor(t, "session accounting", func() bool { return rec.closedCount() == 1 })
		_, closed, _, _ := rec.snapshot()
		if closed[0].up != 0 || closed[0].down != 0 {
			t.Fatalf("accounting = up %d down %d, want 0/0", closed[0].up, closed[0].down)
		}
		if closed[0].dur <= 0 {
			t.Fatalf("session duration = %v, want a positive value", closed[0].dur)
		}
	})

	t.Run("spares an active session", func(t *testing.T) {
		t.Parallel()
		rec := &testRecorder{}
		target := startServer(t, echoHandler)
		h := start(t, loopbackDial, Options{Name: "busy", Target: target, Idle: idle, Metrics: rec})

		c := h.dial(t)
		// Keep the session alive for several idle periods with a trickle of
		// traffic: a long-lived but active connection must never be reaped.
		buf := make([]byte, 1)
		for i := 0; i < 15; i++ {
			c.SetDeadline(time.Now().Add(waitTimeout))
			writeAll(t, c, []byte{byte(i)})
			if _, err := io.ReadFull(c, buf); err != nil {
				t.Fatalf("iteration %d: read echo: %v", i, err)
			}
			if buf[0] != byte(i) {
				t.Fatalf("iteration %d: echo = %d", i, buf[0])
			}
			time.Sleep(idle / 4)
		}
		if n := rec.closedCount(); n != 0 {
			t.Fatalf("%d sessions closed while traffic was flowing", n)
		}

		// Once the traffic stops the same session is reaped.
		expectClosed(t, c)
		waitFor(t, "session accounting", func() bool { return rec.closedCount() == 1 })
		_, closed, _, _ := rec.snapshot()
		if closed[0].up != 15 || closed[0].down != 15 {
			t.Fatalf("accounting = up %d down %d, want 15/15", closed[0].up, closed[0].down)
		}
	})
}

// TestServeTCPContextCancelDrains asserts that cancellation stops the listener,
// waits for a session that is still running, and reports a clean exit.
func TestServeTCPContextCancelDrains(t *testing.T) {
	t.Parallel()

	rec := &testRecorder{}
	gate := make(chan struct{})
	release := sync.OnceFunc(func() { close(gate) })
	target := startServer(t, func(c net.Conn) {
		<-gate
		io.Copy(c, c)
	})
	// Registered after startServer so cleanup, which runs last-first, releases
	// the handler before startServer waits for it: a failing assertion must not
	// turn into a deadlock that hides the failure.
	t.Cleanup(release)
	h := start(t, loopbackDial, Options{Name: "draining", Target: target, Metrics: rec})

	c := h.dial(t)
	waitFor(t, "session to open", func() bool {
		opened, _, _, _ := rec.snapshot()
		return opened == 1
	})

	h.cancel()

	// The listener is gone, so nothing new is accepted.
	waitFor(t, "listener to close", func() bool {
		nc, err := net.DialTimeout("tcp", h.addr, 100*time.Millisecond)
		if err != nil {
			return true
		}
		nc.Close()
		return false
	})

	// The established session is drained, not killed.
	time.Sleep(50 * time.Millisecond)
	if h.returned() {
		t.Fatal("ServeTCP returned while a session was still running")
	}
	release()
	writeAll(t, c, []byte("still here"))
	got := make([]byte, len("still here"))
	c.SetReadDeadline(time.Now().Add(waitTimeout))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("in-flight session was cut short: %v", err)
	}
	c.Close()

	if err := h.wait(); err != nil {
		t.Fatalf("ServeTCP returned %v, want nil after cancellation", err)
	}
	if n := rec.closedCount(); n != 1 {
		t.Fatalf("%d sessions accounted as closed, want 1", n)
	}
}

func TestServeTCPAcceptErrors(t *testing.T) {
	t.Parallel()

	permanent := errors.New("listener is broken")

	tests := []struct {
		name        string
		steps       []acceptStep
		closeAfter  bool
		wantErr     error
		wantHandled bool
	}{
		{
			name:       "closed listener is a clean exit",
			steps:      []acceptStep{{err: net.ErrClosed}},
			closeAfter: false,
			wantErr:    nil,
		},
		{
			name:    "permanent error is returned",
			steps:   []acceptStep{{err: permanent}},
			wantErr: permanent,
		},
		{
			name: "temporary errors do not kill the listener",
			steps: []acceptStep{
				{err: tempError{}},
				{err: tempError{}},
				{err: tempError{}},
			},
			closeAfter:  true,
			wantHandled: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rec := &testRecorder{}
			steps := tc.steps
			var client net.Conn
			if tc.wantHandled {
				// A connection accepted after the temporary failures proves the
				// loop recovered instead of exiting.
				var served net.Conn
				client, served = net.Pipe()
				steps = append(steps, acceptStep{conn: served})
			}
			ln := newScriptedListener(steps...)

			// net.Pipe has no useful peer address, so the onward leg is a pipe
			// too: this test is about the accept loop, not about copying.
			dial := func(context.Context, string, string) (net.Conn, error) {
				a, b := net.Pipe()
				b.Close()
				return a, nil
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			errCh := make(chan error, 1)
			go func() { errCh <- ServeTCP(ctx, ln, dial, Options{Name: "flaky", Metrics: rec}) }()

			if tc.wantHandled {
				waitFor(t, "session after temporary errors", func() bool { return rec.closedCount() == 1 })
				client.Close()
			}
			if tc.closeAfter {
				ln.Close()
			}

			select {
			case err := <-errCh:
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("ServeTCP returned %v, want %v", err, tc.wantErr)
				}
			case <-time.After(waitTimeout):
				t.Fatal("ServeTCP did not return")
			}
		})
	}
}

// TestServeTCPNilMetrics covers the documented tolerance for Options.Metrics
// being nil, on every path that records something.
func TestServeTCPNilMetrics(t *testing.T) {
	t.Parallel()

	t.Run("session", func(t *testing.T) {
		t.Parallel()
		target := startServer(t, echoHandler)
		h := start(t, loopbackDial, Options{Name: "quiet", Target: target})
		c := h.dial(t)
		writeAll(t, c, []byte("hi"))
		got := make([]byte, 2)
		if _, err := io.ReadFull(c, got); err != nil {
			t.Fatalf("read echo: %v", err)
		}
	})

	t.Run("rejected and failed", func(t *testing.T) {
		t.Parallel()
		h := start(t, func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("no route")
		}, Options{Name: "quiet", Target: "192.0.2.1:9", Allow: []netip.Prefix{mustPrefix(t, "203.0.113.0/24")}})
		c := h.dial(t)
		expectClosed(t, c)
	})
}

func TestServeTCPByteAccounting(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		request      []byte
		responseSize int
	}{
		{name: "tiny", request: []byte("q"), responseSize: 1},
		{name: "asymmetric", request: bytes.Repeat([]byte("r"), 1000), responseSize: 3000},
		{name: "response spans buffers", request: []byte("q"), responseSize: 5*copyBufferSize + 3},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			response := bytes.Repeat([]byte("z"), tc.responseSize)
			target := startServer(t, func(c net.Conn) {
				if _, err := io.ReadAll(c); err != nil {
					t.Errorf("target read: %v", err)
					return
				}
				if _, err := c.Write(response); err != nil {
					t.Errorf("target write: %v", err)
				}
			})

			rec := &testRecorder{}
			h := start(t, loopbackDial, Options{Name: "counted", Target: target, Metrics: rec})

			c := h.dial(t)
			writeAll(t, c, tc.request)
			closeWriteSide(t, c)
			got, err := io.ReadAll(c)
			if err != nil {
				t.Fatalf("read response: %v", err)
			}
			if len(got) != tc.responseSize {
				t.Fatalf("read %d bytes, want %d", len(got), tc.responseSize)
			}

			waitFor(t, "session accounting", func() bool { return rec.closedCount() == 1 })
			_, closed, _, _ := rec.snapshot()
			if closed[0].up != int64(len(tc.request)) {
				t.Errorf("up = %d, want %d", closed[0].up, len(tc.request))
			}
			if closed[0].down != int64(tc.responseSize) {
				t.Errorf("down = %d, want %d", closed[0].down, tc.responseSize)
			}
			if closed[0].dur <= 0 {
				t.Errorf("duration = %v, want a positive value", closed[0].dur)
			}
		})
	}
}

func TestDialFailureReasonsAreBounded(t *testing.T) {
	t.Parallel()

	// The reason is a metric label, so it must never carry the error text.
	err := errors.New("dial tcp 10.0.0.7:5432: connect: connection refused")
	if got := ReasonForError(err); got != ReasonOther {
		t.Fatalf("ReasonForError = %q, want %q", got, ReasonOther)
	}
}

func TestHalfCloseWriteReportsUnsupportedTransport(t *testing.T) {
	t.Parallel()

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer tcpLn.Close()
	tcpConn, err := net.Dial("tcp", tcpLn.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer tcpConn.Close()

	pipeConn, other := net.Pipe()
	defer pipeConn.Close()
	defer other.Close()

	tests := []struct {
		name string
		conn net.Conn
		want bool
	}{
		{name: "tcp half-closes", conn: tcpConn, want: true},
		{name: "pipe cannot", conn: pipeConn, want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := halfCloseWrite(tc.conn); got != tc.want {
				t.Fatalf("halfCloseWrite = %v, want %v", got, tc.want)
			}
		})
	}
}

// nilAddrConn is a conn that reports no peer address, which is what
// *gonet.TCPConn — the conn type tsnet hands an ingress listener — does once
// its gVisor endpoint has moved to an error or closed state. A tailnet peer
// that connects and immediately resets lands in exactly that window, so the
// relay sees a live conn whose RemoteAddr is nil.
type nilAddrConn struct {
	net.Conn
}

func (nilAddrConn) RemoteAddr() net.Addr { return nil }

// serveScripted runs ServeTCP over ln and returns a function that closes ln and
// waits for the loop to exit, so a test can assert the relay ended cleanly.
func serveScripted(t *testing.T, ln *scriptedListener, dial DialFunc, opts Options) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- ServeTCP(ctx, ln, dial, opts) }()
	return func() {
		t.Helper()
		ln.Close()
		select {
		case err := <-errCh:
			if err != nil {
				t.Errorf("ServeTCP returned %v, want nil", err)
			}
		case <-time.After(waitTimeout):
			t.Error("ServeTCP did not return")
		}
		cancel()
	}
}

// TestServeTCPNilRemoteAddr covers a source the transport cannot name. Reading
// it used to panic the whole process on the per-session goroutine; it must now
// be refused, with or without an allow list configured, because an address that
// cannot be identified is not one an empty allow list was ever meant to admit.
func TestServeTCPNilRemoteAddr(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		allow []string
	}{
		{name: "with allow list", allow: []string{"127.0.0.0/8"}},
		{name: "without allow list"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var allow []netip.Prefix
			for _, p := range tc.allow {
				allow = append(allow, mustPrefix(t, p))
			}

			var mu sync.Mutex
			var dialled int
			dial := func(context.Context, string, string) (net.Conn, error) {
				mu.Lock()
				dialled++
				mu.Unlock()
				return nil, errors.New("must not be dialled")
			}

			client, served := net.Pipe()
			defer client.Close()
			ln := newScriptedListener(acceptStep{conn: nilAddrConn{served}})
			rec := &testRecorder{}
			stop := serveScripted(t, ln, dial, Options{Name: "ingress", Target: "192.0.2.1:9", Allow: allow, Metrics: rec})
			defer stop()

			waitFor(t, "rejection", func() bool {
				_, _, _, rejected := rec.snapshot()
				return len(rejected) == 1
			})
			opened, _, _, rejected := rec.snapshot()
			if rejected[0] != ReasonAllowList {
				t.Fatalf("Rejected reason = %q, want %q", rejected[0], ReasonAllowList)
			}
			if opened != 0 {
				t.Fatalf("SessionOpened called %d times for an unidentifiable source", opened)
			}

			// The refused conn must be closed, not leaked.
			client.SetReadDeadline(time.Now().Add(waitTimeout))
			if _, err := client.Read(make([]byte, 1)); err == nil {
				t.Fatal("read succeeded, want the refused connection to be closed")
			}

			mu.Lock()
			defer mu.Unlock()
			if dialled != 0 {
				t.Fatalf("dialled %d times for an unidentifiable source, want 0", dialled)
			}
		})
	}
}

// TestAllowedNilAddr pins the decision down at its source: Allowed answers for
// a nil address instead of dereferencing it, and answers "no" whether or not a
// prefix list is configured.
func TestAllowedNilAddr(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		prefixes []netip.Prefix
	}{
		{name: "no allow list"},
		{name: "allow list", prefixes: []netip.Prefix{mustPrefix(t, "0.0.0.0/0")}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if Allowed(tc.prefixes, nil) {
				t.Fatal("Allowed(nil addr) = true, want false")
			}
		})
	}
}

// TestServeTCPSessionPanicDoesNotKillRelay exercises the recover on the session
// goroutine: a panic in one session is contained, and the listener goes on
// serving the next one instead of the process dying with every mapping in it.
func TestServeTCPSessionPanicDoesNotKillRelay(t *testing.T) {
	t.Parallel()

	poisonedClient, poisonedServed := net.Pipe()
	defer poisonedClient.Close()
	healthyClient, healthyServed := net.Pipe()
	defer healthyClient.Close()

	ln := newScriptedListener(
		acceptStep{conn: poisonedServed},
		acceptStep{conn: healthyServed},
	)

	var mu sync.Mutex
	var calls int
	dial := func(context.Context, string, string) (net.Conn, error) {
		mu.Lock()
		calls++
		first := calls == 1
		mu.Unlock()
		if first {
			panic("scripted session panic")
		}
		// The onward leg for the healthy session: closed immediately, so the
		// session completes on its own and is accounted for.
		a, b := net.Pipe()
		b.Close()
		return a, nil
	}

	rec := &testRecorder{}
	stop := serveScripted(t, ln, dial, Options{Name: "poisoned", Target: "192.0.2.1:9", Metrics: rec})
	defer stop()

	// The panicking session's conn is closed by the recover, not leaked.
	poisonedClient.SetReadDeadline(time.Now().Add(waitTimeout))
	if _, err := poisonedClient.Read(make([]byte, 1)); err == nil {
		t.Fatal("read succeeded, want the panicking session's connection to be closed")
	}

	// The relay survived: a later session on the same listener is still served.
	waitFor(t, "session after a panic", func() bool { return rec.closedCount() == 1 })
	opened, closed, _, _ := rec.snapshot()
	if opened != 1 {
		t.Fatalf("SessionOpened called %d times, want 1", opened)
	}
	if closed[0].name != "poisoned" {
		t.Fatalf("SessionClosed name = %q, want %q", closed[0].name, "poisoned")
	}
}
