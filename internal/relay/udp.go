package relay

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// udpMaxDatagram is the read buffer for a single datagram. 65535 is the
	// largest value a UDP length field can carry, so a buffer this size can
	// never truncate a datagram. Truncation matters more here than the memory
	// does: a short read is silent corruption that the receiving protocol sees
	// as a malformed message, not as an error anyone can log.
	udpMaxDatagram = 65535

	// udpMaxSessions bounds the session table.
	//
	// A UDP session costs one onward socket, one goroutine and — while that
	// goroutine is parked in Read — one udpMaxDatagram buffer, and it is minted
	// by a single datagram from a new source address. Nothing about UDP makes
	// the sender prove it exists first, so a scan or a spoofed source can mint
	// them as fast as it can send. The cap turns unbounded growth into a bounded
	// worst case of roughly udpMaxSessions*udpMaxDatagram (~256 MiB) of buffer
	// plus udpMaxSessions descriptors, while sitting far above the fan-in a
	// single declared mapping sees in practice: hitting it means something is
	// wrong, not that something is busy.
	udpMaxSessions = 4096

	// udpMaxPending is the depth of one session's egress queue: the client
	// datagrams held while that session's writer is still dialling, or is
	// parked inside a write the target is not draining. Neither the dial nor
	// the write may happen on the read loop, and this queue is what decouples
	// them from it. It is bounded because a client that sends faster than its
	// target accepts must not grow a buffer without limit. Overflow is dropped,
	// which is the same loss a UDP sender must already tolerate from the
	// network.
	udpMaxPending = 8

	// udpFallbackIdle applies when Options.Idle is zero. For TCP zero
	// legitimately means "never reap", because a peer that goes away eventually
	// closes the connection. UDP has no close, so a session with no idle bound
	// is never removed and the table only grows; there is no safe way to honour
	// "never" here.
	udpFallbackIdle = 60 * time.Second

	// The reaper wakes several times per idle window so that eviction lag is a
	// fraction of the window rather than a whole extra one. The clamps stop a
	// tiny Idle from spinning the CPU and a huge one from checking so rarely
	// that the table's size stops tracking reality.
	udpMinReapInterval = 10 * time.Millisecond
	udpMaxReapInterval = 15 * time.Second
)

// udpBufPool hands out datagram buffers. Every datagram in both directions is
// read into one of these; without the pool each datagram would allocate 64 KiB,
// which at any real packet rate is the dominant cost of the relay.
var udpBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, udpMaxDatagram)
		return &b
	},
}

// ServeUDP reads datagrams from pc and relays them to opts.Target via dial,
// maintaining one onward session per distinct client address.
//
// UDP has no connection, so a "session" here is synthetic: the first datagram
// from a source address opens one onward conn, every later datagram from that
// address reuses it, and every reply read from that conn goes back to the
// address that opened it. A session ends on idle timeout, on an onward read
// error, or on teardown — there is no close handshake to wait for.
//
// Datagram boundaries are preserved end to end: one Read produces exactly one
// WriteTo. A stream copy would be free to merge or split, which for a datagram
// protocol is corruption.
//
// ServeUDP returns nil when ctx is cancelled or pc is closed, and an error only
// when the read loop fails for some other reason. It does not close pc; that
// belongs to the caller that opened it.
func ServeUDP(ctx context.Context, pc net.PacketConn, dial DialFunc, opts Options) error {
	return serveUDP(ctx, pc, dial, opts, udpMaxSessions)
}

// serveUDP is ServeUDP with the session cap injected, so that a test can fill
// the table without opening udpMaxSessions sockets.
func serveUDP(ctx context.Context, pc net.PacketConn, dial DialFunc, opts Options, maxSessions int) error {
	// Sessions outlive the read loop by however long their goroutines take to
	// notice teardown, and an in-flight dial has to be cancellable even when the
	// read loop exits for a reason of its own. Everything below hangs off this
	// context, not off the caller's.
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()

	rec := udpMetrics{opts.Metrics}
	tbl := &udpTable{sessions: make(map[string]*udpSession), max: maxSessions}
	log := slog.With("mapping", opts.Name, "proto", "udp")

	idle := opts.Idle
	if idle <= 0 {
		idle = udpFallbackIdle
	}

	// A blocking ReadFrom does not observe context cancellation, so something
	// has to interrupt it. A read deadline is preferred over Close because pc
	// belongs to the caller: closing it would break a caller that wants to shut
	// the listener down itself, or that reports its own close error. Not every
	// PacketConn implements deadlines, so fall back to Close when it refuses.
	stopWatch := make(chan struct{})
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		select {
		case <-sctx.Done():
			if err := pc.SetReadDeadline(time.Now()); err != nil {
				_ = pc.Close()
			}
		case <-stopWatch:
		}
	}()

	reapDone := make(chan struct{})
	go func() {
		defer close(reapDone)
		tick := time.NewTicker(udpReapInterval(idle))
		defer tick.Stop()
		for {
			select {
			case <-sctx.Done():
				return
			case now := <-tick.C:
				for _, s := range tbl.expire(now, idle) {
					log.Debug("udp session idle", "client", s.key, "idle", idle)
					s.close(rec, opts.Name)
				}
			}
		}
	}()

	var wg sync.WaitGroup
	err := udpReadLoop(sctx, pc, dial, opts, rec, tbl, log, &wg)

	// Order matters: stop the watcher before cancelling, so a normal return does
	// not leave a read deadline on the caller's PacketConn.
	close(stopWatch)
	cancel()
	<-watchDone
	<-reapDone
	for _, s := range tbl.drain() {
		s.close(rec, opts.Name)
	}
	// Every session goroutine either observes its closed conn or its cancelled
	// dial context, so this cannot outlast the dial timeout.
	wg.Wait()
	return err
}

// udpReadLoop owns pc's read side. It is the only goroutine that admits
// sessions, which is why admission needs no coordination beyond the table lock.
//
// The invariant this loop is built on: it blocks on nothing but pc.ReadFrom.
// Everything that can wait on a peer — the onward dial, the onward write — is
// handed to a session goroutine, every lock it takes is held only across
// bookkeeping, and every queue it pushes to is bounded and pushed to without
// blocking. One unresponsive target must cost its own client datagrams and
// nobody else's, because this loop is the only reader every session on the
// mapping shares.
func udpReadLoop(ctx context.Context, pc net.PacketConn, dial DialFunc, opts Options, rec udpMetrics, tbl *udpTable, log *slog.Logger, wg *sync.WaitGroup) error {
	for {
		bp := udpBufPool.Get().(*[]byte)
		n, addr, err := pc.ReadFrom(*bp)
		if err != nil {
			udpBufPool.Put(bp)
			// Cancellation reaches this loop as a deadline or a closed conn
			// depending on which lever the watcher could pull, and a caller
			// closing its own listener is an ordinary shutdown too. Neither is
			// a relay failure.
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("relay %s: read udp: %w", opts.Name, err)
		}

		s, ok := tbl.get(addr.String())
		if !ok {
			s = udpAdmit(ctx, addr, dial, opts, rec, tbl, pc, log, wg)
		}
		if s != nil {
			// A zero-length datagram is legal and meaningful to some protocols,
			// so it is relayed like any other.
			s.send((*bp)[:n], rec, opts.Name, log)
		}
		udpBufPool.Put(bp)
	}
}

// udpAdmit creates the session for a source address seen for the first time and
// starts its onward dial. It returns nil when the datagram must be dropped,
// having already recorded why.
func udpAdmit(ctx context.Context, addr net.Addr, dial DialFunc, opts Options, rec udpMetrics, tbl *udpTable, pc net.PacketConn, log *slog.Logger, wg *sync.WaitGroup) *udpSession {
	// The allow-list is checked on the source of the first datagram only:
	// afterwards the session itself is the proof that the source was allowed,
	// and re-parsing the address per datagram would put a parse on the hot path.
	if !Allowed(opts.Allow, addr) {
		rec.rejected(opts.Name, ReasonAllowList)
		// Debug, not Warn: this runs on the read loop, once per rejected
		// datagram, and the record carries a source address the sender chose.
		// A flood would otherwise spend the mapping's read budget formatting
		// log lines about the flood, taking datagrams away from the clients
		// that are allowed. The rejected counter is the signal to alert on; the
		// line is only there for someone already debugging one allow list.
		log.Debug("udp datagram from disallowed source", "client", addr.String())
		return nil
	}

	s := newUDPSession(addr)
	if !tbl.add(s) {
		// An established session is never evicted to make room: the sources
		// already being served did nothing wrong, and a flood of new addresses
		// would otherwise let an attacker displace legitimate traffic.
		rec.rejected(opts.Name, ReasonSessionCap)
		// Debug for the same reason as the allow-list rejection above: the
		// table fills when new source addresses arrive faster than sessions
		// retire, which is exactly when per-datagram logging is least
		// affordable.
		log.Debug("udp session table full, dropping datagram", "client", s.key, "max", tbl.max)
		return nil
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		udpDialOnward(ctx, s, dial, opts, rec, tbl, pc, log, wg)
	}()
	return s
}

// udpDialOnward opens the far leg for s. It runs on its own goroutine so that a
// target which is slow to dial delays only its own client's datagrams; the read
// loop keeps serving every other session meanwhile.
func udpDialOnward(ctx context.Context, s *udpSession, dial DialFunc, opts Options, rec udpMetrics, tbl *udpTable, pc net.PacketConn, log *slog.Logger, wg *sync.WaitGroup) {
	dctx := ctx
	if opts.DialTimeout > 0 {
		var cancel context.CancelFunc
		dctx, cancel = context.WithTimeout(ctx, opts.DialTimeout)
		defer cancel()
	}

	conn, err := dial(dctx, "udp", opts.Target)
	if err != nil {
		rec.dialFailed(opts.Name, ReasonForError(err))
		log.Warn("udp onward dial failed", "client", s.key, "target", opts.Target, "error", err)
		// Drop the half-built session so the next datagram from this client
		// retries rather than being silently swallowed forever.
		tbl.remove(s)
		s.close(rec, opts.Name)
		return
	}
	if !s.activate(conn) {
		// Teardown or idle eviction won the race with the dial. The conn was
		// never reachable from the table, so nobody else will close it.
		_ = conn.Close()
		return
	}

	rec.opened(opts.Name)
	log.Debug("udp session opened", "client", s.key, "target", opts.Target)

	// Safe to Add while Wait may be running: this goroutine is itself counted,
	// so the counter cannot be at zero here.
	//
	// The writer starts only now, after activate has installed conn, so it can
	// take conn as an argument and never look at s.conn. Whatever queued during
	// the dial is already in s.egress and is drained first, which is what keeps
	// the pre-dial and post-dial datagrams in one order.
	wg.Add(2)
	go func() {
		defer wg.Done()
		udpWriteLoop(s, conn, log)
	}()
	go func() {
		defer wg.Done()
		udpReplyLoop(s, conn, pc, rec, opts, tbl, log)
	}()
}

// udpWriteLoop is the only goroutine that writes to a session's onward conn,
// and the reason send does no I/O.
//
// A write to the onward leg can park for an unbounded time: tsnet's conns come
// from a gVisor stack, where a full send buffer parks the writer on the
// endpoint's writability signal, and nothing in this relay sets a write
// deadline that would cut it short. On the read loop that stall would freeze
// every session on the mapping; on this goroutine it costs one client, which is
// the client whose target stopped reading.
//
// Draining a single FIFO queue is also what preserves order: datagrams reach
// the target in the order the read loop took them off the wire, including
// across the moment the dial completed.
func udpWriteLoop(s *udpSession, conn net.Conn, log *slog.Logger) {
	// The range ends when close closes s.egress, so teardown retires this
	// goroutine even while the write below is parked: close also closes conn,
	// which is what makes the parked write return.
	for b := range s.egress {
		n, err := conn.Write(b)
		if err != nil {
			// A datagram write failure is per-datagram, not per-session: a
			// connected UDP socket reports a refused port here and on the next
			// read alike, and the reply loop is the one that decides the session
			// is finished. Tearing down from the write side as well would just
			// race with it.
			log.Debug("udp onward write failed", "client", s.key, "error", err)
			continue
		}
		s.up.Add(int64(n))
	}
}

// udpReplyLoop carries the target's datagrams back to the one client address
// that opened this session.
func udpReplyLoop(s *udpSession, conn net.Conn, pc net.PacketConn, rec udpMetrics, opts Options, tbl *udpTable, log *slog.Logger) {
	for {
		bp := udpBufPool.Get().(*[]byte)
		n, err := conn.Read(*bp)
		if n > 0 || err == nil {
			s.touch()
			s.down.Add(int64(n))
			// One Read, one WriteTo. io.Copy would be free to coalesce two
			// replies into one write or split one across two, and either is a
			// different message as far as the client's parser is concerned.
			if _, werr := pc.WriteTo((*bp)[:n], s.client); werr != nil {
				udpBufPool.Put(bp)
				log.Debug("udp reply write failed", "client", s.key, "error", werr)
				break
			}
		}
		udpBufPool.Put(bp)
		if err != nil {
			log.Debug("udp onward read ended", "client", s.key, "error", err)
			break
		}
	}
	tbl.remove(s)
	s.close(rec, opts.Name)
}

func udpReapInterval(idle time.Duration) time.Duration {
	iv := idle / 4
	if iv < udpMinReapInterval {
		iv = udpMinReapInterval
	}
	if iv > udpMaxReapInterval {
		iv = udpMaxReapInterval
	}
	return iv
}

// udpSession is the relay state for one client address.
type udpSession struct {
	// key is client.String(); it is the table key and is fixed for the
	// session's life, so it can be read without the mutex.
	key     string
	client  net.Addr
	started time.Time

	// lastSeen holds UnixNano of the most recent datagram in either direction.
	// The reaper reads it while the read loop and the reply loop write it, so it
	// is atomic rather than mutex-guarded: taking the session lock per datagram
	// would serialise the two directions against each other for no benefit.
	lastSeen atomic.Int64
	up       atomic.Int64
	down     atomic.Int64

	// egress carries datagrams from the read loop to this session's writer
	// goroutine. It is created with the session and never reassigned, so the
	// writer ranges over it without holding mu. Its buffer is also the queue
	// for datagrams that arrive before the dial finishes: one queue for both
	// phases is what makes ordering across the handover automatic instead of
	// something a flush has to arrange.
	egress chan []byte

	// mu guards the onward conn, the closed flag, and sends on egress. It is
	// what makes teardown final: closed is set under mu before conn is closed
	// and before egress is closed, so no goroutine can write to a conn that
	// close has already handed to Close, and no send can race the channel close
	// into a send-on-closed-channel panic.
	mu     sync.Mutex
	conn   net.Conn
	opened bool
	closed bool
}

func newUDPSession(addr net.Addr) *udpSession {
	s := &udpSession{
		key:     addr.String(),
		client:  addr,
		started: time.Now(),
		egress:  make(chan []byte, udpMaxPending),
	}
	s.touch()
	return s
}

func (s *udpSession) touch() { s.lastSeen.Store(time.Now().UnixNano()) }

func (s *udpSession) idleSince(now time.Time) time.Duration {
	return now.Sub(time.Unix(0, s.lastSeen.Load()))
}

// send hands one client datagram to this session's writer goroutine. b is only
// valid for the duration of the call, so what is queued is a copy.
//
// send runs on the read loop that every session on the mapping shares, so it
// does no I/O and never blocks: it holds mu only across a closed check and a
// non-blocking channel send, neither of which can wait on anything but another
// holder of mu, and every other holder does bookkeeping only.
//
// An overflowing queue drops the datagram rather than waiting for room. Waiting
// is what turns one target that has stopped reading into a mapping that has
// stopped relaying, while loss is what a UDP sender already tolerates from the
// network.
func (s *udpSession) send(b []byte, rec udpMetrics, name string, log *slog.Logger) {
	q := make([]byte, len(b))
	copy(q, b)

	dropped := false
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.touch()
	select {
	case s.egress <- q:
	default:
		dropped = true
	}
	s.mu.Unlock()

	if dropped {
		// Reported outside the lock: Recorder is supplied by the caller, and
		// nothing a caller writes should be able to hold up the read loop.
		//
		// ReasonQueueFull, not ReasonSessionCap: this client was admitted and
		// is now losing traffic because its target stopped draining, which is
		// a different alert from a new client being turned away.
		rec.rejected(name, ReasonQueueFull)
		log.Debug("udp egress queue full, dropping datagram", "client", s.key, "queue", cap(s.egress))
	}
}

// activate installs the dialled conn. It reports false if the session was
// already torn down, in which case the caller owns conn.
//
// Nothing is flushed here: whatever arrived during the dial is sitting in
// egress, and the writer goroutine the caller starts next drains it in order.
func (s *udpSession) activate(conn net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.conn = conn
	s.opened = true
	return true
}

// close tears the session down exactly once. Closing the onward conn is what
// unblocks the reply loop and any write the writer goroutine is parked in,
// which is why nothing waits for either goroutine here.
func (s *udpSession) close(rec udpMetrics, name string) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	// Closing egress under the lock that also guards send is the whole reason
	// send takes the lock: a send in flight holds mu, so it can never be
	// choosing a channel that this line has already closed. Closing rather than
	// abandoning the channel is also what retires the writer goroutine, so
	// serveUDP's WaitGroup can drain.
	close(s.egress)
	conn := s.conn
	s.conn = nil
	opened := s.opened
	s.mu.Unlock()

	if conn != nil {
		_ = conn.Close()
	}
	// A session whose dial never succeeded was never reported open, so
	// reporting it closed would leave the gauge below zero.
	if opened {
		rec.closed(name, s.up.Load(), s.down.Load(), time.Since(s.started))
	}
}

// udpTable is the session table, touched by the read loop, the reaper and every
// reply goroutine.
type udpTable struct {
	mu       sync.Mutex
	sessions map[string]*udpSession
	max      int
}

func (t *udpTable) get(key string) (*udpSession, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s, ok := t.sessions[key]
	return s, ok
}

// add reports false when the table is full.
func (t *udpTable) add(s *udpSession) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.sessions) >= t.max {
		return false
	}
	t.sessions[s.key] = s
	return true
}

// remove deletes s only if it is still the session registered for its key. The
// identity check matters because a client whose session was just evicted can
// have a fresh session under the same key before the old goroutine gets here.
func (t *udpTable) remove(s *udpSession) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if cur, ok := t.sessions[s.key]; ok && cur == s {
		delete(t.sessions, s.key)
	}
}

// expire removes and returns the sessions idle for at least idle. They leave
// the table before they are closed so that no one can hand a datagram to a
// session that is on its way out.
func (t *udpTable) expire(now time.Time, idle time.Duration) []*udpSession {
	t.mu.Lock()
	defer t.mu.Unlock()
	var dead []*udpSession
	for key, s := range t.sessions {
		if s.idleSince(now) >= idle {
			delete(t.sessions, key)
			dead = append(dead, s)
		}
	}
	return dead
}

// drain empties the table and returns everything that was in it.
func (t *udpTable) drain() []*udpSession {
	t.mu.Lock()
	defer t.mu.Unlock()
	all := make([]*udpSession, 0, len(t.sessions))
	for key, s := range t.sessions {
		delete(t.sessions, key)
		all = append(all, s)
	}
	return all
}

func (t *udpTable) len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.sessions)
}

// udpMetrics absorbs a nil Options.Metrics so the relay paths carry no nil
// checks of their own.
type udpMetrics struct{ r Recorder }

func (m udpMetrics) opened(name string) {
	if m.r != nil {
		m.r.SessionOpened(name)
	}
}

func (m udpMetrics) closed(name string, up, down int64, d time.Duration) {
	if m.r != nil {
		m.r.SessionClosed(name, up, down, d)
	}
}

func (m udpMetrics) dialFailed(name, reason string) {
	if m.r != nil {
		m.r.DialFailed(name, reason)
	}
}

func (m udpMetrics) rejected(name, reason string) {
	if m.r != nil {
		m.r.Rejected(name, reason)
	}
}
