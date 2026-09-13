package relay

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"
)

// copyBufferSize is the per-direction copy buffer. Two of these are alive for
// the lifetime of every session, so it trades memory per concurrent session
// against syscalls per megabyte.
const copyBufferSize = 32 * 1024

// Accept backoff bounds. A listener that fails for a per-connection reason
// (the accept queue aborted a handshake, the process is momentarily out of
// file descriptors) recovers on its own, so the loop sleeps briefly instead of
// spinning at 100% CPU, and gives up more of the CPU the longer it persists.
const (
	acceptBackoffMin = 5 * time.Millisecond
	acceptBackoffMax = time.Second
)

// minIdleTick floors the idle sweep interval so a very short idle setting
// cannot turn the reaper into a busy loop.
const minIdleTick = 5 * time.Millisecond

// ServeTCP accepts from ln until ctx is cancelled or ln fails permanently,
// relaying each connection to opts.Target via dial.
//
// ServeTCP owns ln for its lifetime and closes it before returning: Accept
// blocks in the kernel and cannot observe ctx, so closing the listener is how
// cancellation is delivered to it.
//
// Cancellation drains rather than kills. Once ctx is cancelled no new session
// starts, but sessions already established are left to finish so an in-flight
// request is not truncated on redeploy, and ServeTCP returns only when the last
// one has ended. A session with no traffic and no opts.Idle can therefore
// outlive the cancellation; bounding total shutdown time is the caller's job,
// since only the caller knows its grace period.
//
// It returns nil for the expected ends — ctx cancellation, or a closed
// listener — and an error only when the listener fails in a way that leaves it
// unusable.
func ServeTCP(ctx context.Context, ln net.Listener, dial DialFunc, opts Options) error {
	rec := recorderOrNoop(opts.Metrics)

	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			ln.Close()
		case <-stop:
		}
	}()

	// Registered so the run order on return is: close the listener, drain live
	// sessions, then release the cancellation watcher.
	var wg sync.WaitGroup
	defer wg.Wait()
	defer ln.Close()

	var backoff time.Duration
	for {
		conn, err := ln.Accept()
		if err != nil {
			switch {
			case ctx.Err() != nil, errors.Is(err, net.ErrClosed):
				return nil
			case !isTemporaryAccept(err):
				return err
			}

			backoff *= 2
			if backoff < acceptBackoffMin {
				backoff = acceptBackoffMin
			} else if backoff > acceptBackoffMax {
				backoff = acceptBackoffMax
			}
			slog.WarnContext(ctx, "relay: accept failed, retrying",
				"mapping", opts.Name, "backoff", backoff, "error", err)

			t := time.NewTimer(backoff)
			select {
			case <-ctx.Done():
				t.Stop()
				return nil
			case <-t.C:
			}
			continue
		}
		backoff = 0

		wg.Add(1)
		go func() {
			defer wg.Done()
			// Defence in depth rather than a fix for any one bug: a panic on
			// this goroutine is otherwise fatal to the whole program, so one
			// poisoned session would take down every other mapping in the
			// process along with it. The sessions sharing this process belong
			// to unrelated mappings that did nothing wrong, so the blast radius
			// is held to the session that caused it.
			defer func() {
				if r := recover(); r != nil {
					slog.ErrorContext(ctx, "relay: session panicked",
						"mapping", opts.Name, "panic", r, "stack", string(debug.Stack()))
					conn.Close()
				}
			}()
			handleTCP(ctx, conn, dial, opts, rec)
		}()
	}
}

// handleTCP owns client from the moment it is accepted: every path below either
// hands it to pipe, which closes it, or closes it directly.
func handleTCP(ctx context.Context, client net.Conn, dial DialFunc, opts Options, rec Recorder) {
	// The peer address is read once and reused. tsnet's gVisor-backed conn
	// derives it from live endpoint state, so a second call can answer
	// differently — including with nil — from the one the allow-list decision
	// was made on, which is how a check and the log line describing it end up
	// disagreeing about the same connection.
	remote := client.RemoteAddr()
	if !Allowed(opts.Allow, remote) {
		rec.Rejected(opts.Name, ReasonAllowList)
		slog.WarnContext(ctx, "relay: source rejected by allow list",
			"mapping", opts.Name, "remote", addrString(remote))
		client.Close()
		return
	}

	upstream, err := dialOnward(ctx, dial, opts)
	if err != nil {
		reason := ReasonForError(err)
		rec.DialFailed(opts.Name, reason)
		slog.WarnContext(ctx, "relay: onward dial failed",
			"mapping", opts.Name, "target", opts.Target, "reason", reason, "error", err)
		client.Close()
		return
	}

	rec.SessionOpened(opts.Name)
	up, down, d := pipe(client, upstream, opts.Idle)
	rec.SessionClosed(opts.Name, up, down, d)
	slog.DebugContext(ctx, "relay: session closed",
		"mapping", opts.Name, "target", opts.Target,
		"up_bytes", up, "down_bytes", down, "duration", d)
}

// addrString renders an address as a log field without assuming there is one.
// A net.Addr can be nil — see Allowed — and the line reporting a refused
// connection is the last place in the relay that should be able to panic.
func addrString(a net.Addr) string {
	if a == nil {
		return "unknown"
	}
	return a.String()
}

// dialOnward bounds a single dial. The timeout context is released as soon as
// the dial returns so its timer does not live as long as the session.
func dialOnward(ctx context.Context, dial DialFunc, opts Options) (net.Conn, error) {
	if opts.DialTimeout <= 0 {
		return dial(ctx, "tcp", opts.Target)
	}
	dctx, cancel := context.WithTimeout(ctx, opts.DialTimeout)
	defer cancel()
	return dial(dctx, "tcp", opts.Target)
}

// pipe copies in both directions until both are finished, then closes both
// sides and reports what moved. up is client->upstream, down is
// upstream->client.
func pipe(client, upstream net.Conn, idle time.Duration) (up, down int64, d time.Duration) {
	start := time.Now()

	// One activity timestamp shared by both directions, rather than a read
	// deadline per direction. "Idle" means no bytes in EITHER direction: a bulk
	// download is quiet in the client->target direction for minutes at a time,
	// and a per-direction deadline would reap it mid-transfer. A deadline set
	// once at the start would instead cap total session length, killing a
	// healthy long-lived database connection. Both are the bugs this exists to
	// avoid.
	var upN, downN, last atomic.Int64
	last.Store(start.UnixNano())

	done := make(chan struct{})
	if idle > 0 {
		go reapIdle(done, &last, idle, client, upstream)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		relayHalf(upstream, client, &upN, &last)
	}()
	go func() {
		defer wg.Done()
		relayHalf(client, upstream, &downN, &last)
	}()

	// Both directions, not the first one to finish: a client that has sent its
	// request and half-closed is still owed the whole response.
	wg.Wait()
	close(done)

	client.Close()
	upstream.Close()
	return upN.Load(), downN.Load(), time.Since(start)
}

// relayHalf copies one direction and then tells dst's peer that no more data is
// coming, without disturbing the opposite direction.
func relayHalf(dst, src net.Conn, n, last *atomic.Int64) {
	if err := copyTracked(dst, src, n, last); err == nil {
		// src reached EOF. Propagating a write-close lets a request/response
		// peer see the end of the request and answer it; tearing the whole
		// session down here is what truncates the final response.
		if halfCloseWrite(dst) {
			return
		}
	}
	// Either the copy failed, or dst cannot signal EOF on its own without a
	// full close. Both mean the session is over, so close both sides to unblock
	// the opposite direction rather than leaving it reading forever.
	dst.Close()
	src.Close()
}

// copyTracked is io.Copy with accounting. It cannot use io.Copy because the
// byte counter and the shared activity timestamp have to be updated as the
// bytes move, not once at the end.
func copyTracked(dst, src net.Conn, n, last *atomic.Int64) error {
	buf := make([]byte, copyBufferSize)
	for {
		nr, rerr := src.Read(buf)
		if nr > 0 {
			last.Store(time.Now().UnixNano())
			nw, werr := dst.Write(buf[:nr])
			if nw > 0 {
				n.Add(int64(nw))
				last.Store(time.Now().UnixNano())
			}
			if werr != nil {
				return werr
			}
			if nw != nr {
				return io.ErrShortWrite
			}
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				return nil
			}
			return rerr
		}
	}
}

// reapIdle closes both sides of a session that has moved no bytes in either
// direction for idle. Closing is the only way to interrupt a Read already
// blocked in the kernel.
func reapIdle(done <-chan struct{}, last *atomic.Int64, idle time.Duration, conns ...net.Conn) {
	interval := idle / 4
	if interval < minIdleTick {
		interval = minIdleTick
	}
	if interval > idle {
		interval = idle
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case now := <-t.C:
			if now.Sub(time.Unix(0, last.Load())) < idle {
				continue
			}
			for _, c := range conns {
				c.Close()
			}
			return
		}
	}
}

// halfCloseWrite shuts down c's write direction and reports whether it could.
// *net.TCPConn and tsnet's gVisor-backed conn both implement CloseWrite; a
// transport that does not (net.Pipe, a TLS conn wrapping either) has no way to
// say "no more data" short of closing outright.
func halfCloseWrite(c net.Conn) bool {
	cw, ok := c.(interface{ CloseWrite() error })
	if !ok {
		return false
	}
	// A failure here means the peer is already gone, which the opposite
	// direction will observe on its own.
	cw.CloseWrite()
	return true
}

// isTemporaryAccept reports whether an Accept error concerned one connection
// rather than the listener itself.
//
// Temporary() is deprecated as a general error-handling idiom, but for Accept
// it remains the portable signal the standard library itself exposes for
// EINTR, EMFILE and an aborted handshake — all of which the next Accept can
// recover from.
func isTemporaryAccept(err error) bool {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var t interface{ Temporary() bool }
	return errors.As(err, &t) && t.Temporary()
}

// noopRecorder absorbs accounting when Options.Metrics is nil, so the relay
// path has one code path instead of a nil check at every call site.
type noopRecorder struct{}

func (noopRecorder) SessionOpened(string)                              {}
func (noopRecorder) SessionClosed(string, int64, int64, time.Duration) {}
func (noopRecorder) DialFailed(string, string)                         {}
func (noopRecorder) Rejected(string, string)                           {}

func recorderOrNoop(r Recorder) Recorder {
	if r == nil {
		return noopRecorder{}
	}
	return r
}
