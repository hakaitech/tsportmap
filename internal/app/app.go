// Package app wires tsportmap's parts together: it turns an environment into a
// configuration, brings up every network the configuration names — the embedded
// Tailscale node, the userspace WireGuard interfaces, or neither — binds every
// declared mapping to the network it belongs on, and runs them until it is
// asked to stop.
//
// Everything here is startup order and shutdown order. The relays, the networks
// and the metrics registry each work on their own; what this package owns is the
// sequence that makes them safe together — bind before ready, drain before
// close, and close the networks after everything that might still dial through
// one of them.
package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"text/tabwriter"
	"time"

	"github.com/hakaitech/tsportmap/internal/config"
	"github.com/hakaitech/tsportmap/internal/obs"
	"github.com/hakaitech/tsportmap/internal/relay"
	"github.com/hakaitech/tsportmap/internal/tsnode"
	"github.com/hakaitech/tsportmap/internal/wgnet"
)

// metricsShutdownTimeout bounds draining the status server. It is short because
// nothing important is served there: a scrape that loses its connection is
// retried by the collector seconds later, and holding the process open for a
// slow /metrics reader delays the node teardown that actually matters.
const metricsShutdownTimeout = 5 * time.Second

// forceCloseGrace is the upper bound on how long relays get after their
// listeners and their live sessions have been closed out from under them.
// Closing is what unblocks a goroutine parked in Read, so this only has to
// cover the return trip, not any real work, and shutdown returns as soon as
// the relays are actually done rather than waiting the window out.
const forceCloseGrace = 2 * time.Second

// node is the slice of the embedded Tailscale node this package uses.
//
// It exists as an interface so the wiring — bind order, address resolution,
// shutdown order — can be tested without a tailnet, which is the only part of
// this package that has interesting failure modes. *tsnode.Node implements it.
type node interface {
	tsnode.Dialer
	tsnode.Listener

	// Start brings the node up and blocks until it is running.
	Start(ctx context.Context) error
	// Close tears the node down. It is safe whether or not Start succeeded.
	Close() error
	// TailnetIPs reports this node's own tailnet addresses. Either may be
	// invalid if the tailnet does not hand out that family.
	TailnetIPs() (ip4, ip6 netip.Addr)
	// Running reports nil while the node is up.
	Running(ctx context.Context) error
}

// nodeFactory builds the node. Injected so tests can supply a stub.
type nodeFactory func(*config.Config, *slog.Logger) (node, error)

func newTailscaleNode(cfg *config.Config, log *slog.Logger) (node, error) {
	return tsnode.New(cfg, log)
}

// Run parses configuration from environ, brings up the node, serves every
// mapping, and blocks until ctx is cancelled. It returns nil on a clean
// shutdown.
//
// environ is an os.Environ()-style slice rather than being read from the
// process, so the whole startup path is exercisable from a test.
func Run(ctx context.Context, environ []string, version string, stderr io.Writer) error {
	return run(ctx, environ, version, stderr, newTailscaleNode, newWireGuardInterface)
}

func run(ctx context.Context, environ []string, version string, stderr io.Writer, newNode nodeFactory, newWG wgFactory) error {
	if stderr == nil {
		stderr = os.Stderr
	}

	cfg, err := config.FromEnv(environ)
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}

	logger := newLogger(stderr, cfg.LogLevel)
	// The relay package and the status server log through the default logger:
	// the relays because a per-session log line must not cost a logger lookup
	// through three layers of struct, and the status server because it resolves
	// its error log once at construction. Installing the configured logger as
	// the default is therefore load-bearing, not a convenience. The previous
	// default is restored so that a caller which runs this more than once — a
	// test — is left as it was found.
	restore := slog.Default()
	slog.SetDefault(logger)
	defer slog.SetDefault(restore)

	logger.Info("starting tsportmap", "version", version, "config", cfg)

	reg := obs.NewRegistry()

	nets, err := buildNetworks(cfg, logger, newNode, newWG)
	if err != nil {
		return err
	}
	// closeNetworks runs exactly once. The deferred call is the backstop for
	// the early returns below; the ordered shutdown at the end calls it
	// explicitly so that every network outlives the relays that might still be
	// dialling through it.
	var closeOnce sync.Once
	closeNetworks := func() {
		closeOnce.Do(func() { nets.Close(logger) })
	}
	defer closeNetworks()

	if err := nets.Start(ctx); err != nil {
		return err
	}
	reg.SetWireGuard(nets.wireGuardStats())

	// Every listener is bound before anything is declared ready. A mapping that
	// cannot bind is a mapping an operator declared and is not getting, and a
	// half-served configuration hides that behind the mappings that did work.
	bounds, err := bindAll(cfg, nets, reg)
	if err != nil {
		return err
	}

	var ready atomic.Bool
	srv := obs.NewServer(cfg.MetricsAddr, reg, nil, func(ctx context.Context) error {
		if !ready.Load() {
			return errors.New("listeners are not serving")
		}
		return nets.Running(ctx)
	})

	// The status listener is bound here rather than inside ListenAndServe so
	// that an address already in use fails startup instead of being reported
	// asynchronously to a process that has already claimed to be running.
	statusLn, err := net.Listen("tcp", cfg.MetricsAddr)
	if err != nil {
		closeBounds(bounds)
		return fmt.Errorf("binding status address %s (%s): %w", cfg.MetricsAddr, config.EnvMetricsAddr, err)
	}
	srvErr := make(chan error, 1)
	go func() {
		if err := srv.Serve(statusLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			srvErr <- err
		}
	}()
	logger.Info("status endpoints listening", "addr", statusLn.Addr().String(), "paths", "/healthz /readyz /metrics")

	// Relays hang off a context of their own so that the first fatal failure
	// can stop the rest without waiting for a signal.
	relayCtx, stopRelays := context.WithCancel(ctx)
	defer stopRelays()

	rec := relayRecorder{reg: reg}
	var wg sync.WaitGroup
	fatal := make(chan error, len(bounds))
	for _, b := range bounds {
		logger.Info("mapping serving",
			"mapping", b.m.Name,
			"dir", string(b.m.Dir),
			"proto", string(b.m.Proto),
			"via", b.m.Via.String(),
			"listen", b.addr,
			"target", b.m.Target,
			"tls", b.m.TLS,
			"allow", allowString(b.m),
			"idle", b.m.Idle,
		)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := b.serve(relayCtx, cfg, rec); err != nil {
				fatal <- fmt.Errorf("mapping %s: %w", b.m.Name, err)
				stopRelays()
			}
		}()
	}
	ready.Store(true)
	logger.Info("tsportmap ready", "mappings", len(bounds))

	var runErr error
	select {
	case <-ctx.Done():
		logger.Info("shutting down", "grace", cfg.ShutdownGrace)
	case runErr = <-fatal:
		logger.Error("relay failed, shutting down", "error", runErr)
	case err := <-srvErr:
		runErr = fmt.Errorf("status server on %s: %w", cfg.MetricsAddr, err)
		logger.Error("status server failed, shutting down", "error", err)
	}

	// Readiness drops first so that a load balancer stops sending new work
	// while the sessions already in flight are still being drained.
	ready.Store(false)
	stopRelays()

	if !waitFor(&wg, cfg.ShutdownGrace) {
		// Cancellation stops the relays accepting but deliberately lets live
		// sessions finish, and a session with no idle bound can outlast any
		// grace period. Closing them out from under the relays is the only
		// lever left.
		logger.Warn("shutdown grace expired with sessions still open, closing them", "grace", cfg.ShutdownGrace)
		closeBounds(bounds)
		if !waitFor(&wg, forceCloseGrace) {
			logger.Warn("relays did not stop after their listeners were closed; exiting anyway")
		}
	}

	// The status server outlives the relays so a probe during the drain sees
	// "not ready" rather than a refused connection, which reads as a crash.
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), metricsShutdownTimeout)
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Warn("shutting down status server", "error", err)
	}
	cancel()

	// The networks go last: a relay still finishing a session is still using a
	// dialer and a listener that belongs to one, and tearing a tunnel out from
	// under it turns an orderly drain into a truncated response.
	closeNetworks()
	logger.Info("stopped")
	return runErr
}

// bound is one mapping with its listener open and its onward dialer chosen.
// Exactly one of ln and pc is set.
type bound struct {
	m    config.Mapping
	addr string
	ln   net.Listener
	pc   net.PacketConn
	dial relay.DialFunc
}

// close makes this mapping stop, up to and including the sessions it has
// already accepted.
//
// Closing the listener alone is not enough for TCP: relay.ServeTCP owns its
// listener and closes it as it returns, so by the time shutdown reaches here
// the listener is already closed and closing it again does nothing at all,
// while the relay goes on waiting for sessions that may never end on their
// own. The tracking listener is what still has a handle on those sessions.
func (b *bound) close() {
	if b.ln != nil {
		if t, ok := b.ln.(*trackingListener); ok {
			t.closeSessions()
		} else {
			b.ln.Close()
		}
	}
	if b.pc != nil {
		b.pc.Close()
	}
}

// serve runs the relay for this mapping until ctx is cancelled or it fails.
func (b *bound) serve(ctx context.Context, cfg *config.Config, rec relay.Recorder) error {
	opts := relay.Options{
		Name:        b.m.Name,
		Target:      b.m.Target,
		DialTimeout: cfg.DialTimeout,
		Idle:        b.m.Idle,
		Allow:       b.m.Allow,
		Metrics:     rec,
	}
	if b.ln != nil {
		// ServeTCP owns the listener and closes it on the way out.
		return relay.ServeTCP(ctx, b.ln, b.dial, opts)
	}
	// ServeUDP leaves the PacketConn to whoever opened it.
	defer b.pc.Close()
	return relay.ServeUDP(ctx, b.pc, b.dial, opts)
}

// trackingListener is a net.Listener that remembers the connections it has
// handed out, so that shutdown can close them once the grace period is spent.
//
// The relay hands each accepted connection straight to a session goroutine and
// never exposes it, and a session with no idle bound can outlive any grace
// period, so wrapping the listener is the only place from which those
// connections can still be reached.
type trackingListener struct {
	net.Listener

	mu     sync.Mutex
	closed bool
	conns  map[net.Conn]struct{}
}

func newTrackingListener(ln net.Listener) *trackingListener {
	return &trackingListener{Listener: ln, conns: make(map[net.Conn]struct{})}
}

func (l *trackingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		c.Close()
		// A connection that raced the force close is dropped rather than
		// served. net.ErrClosed is what the relay already reads as "the
		// listener is gone, stop accepting".
		return nil, net.ErrClosed
	}
	l.conns[c] = struct{}{}
	l.mu.Unlock()
	return trackConn(l, c), nil
}

func (l *trackingListener) forget(c net.Conn) {
	l.mu.Lock()
	delete(l.conns, c)
	l.mu.Unlock()
}

// closeSessions closes the listener and every session still running on it, and
// refuses to hand out any more.
func (l *trackingListener) closeSessions() {
	l.Listener.Close()

	l.mu.Lock()
	l.closed = true
	conns := make([]net.Conn, 0, len(l.conns))
	for c := range l.conns {
		conns = append(conns, c)
	}
	clear(l.conns)
	l.mu.Unlock()

	for _, c := range conns {
		c.Close()
	}
}

// trackedConn deregisters itself when the relay closes it, so that the set of
// live sessions does not grow for the lifetime of the process.
type trackedConn struct {
	net.Conn
	l *trackingListener
}

func (c *trackedConn) Close() error {
	c.l.forget(c.Conn)
	return c.Conn.Close()
}

// trackedCloseWriter preserves CloseWrite for a transport that has it. The
// relay type-asserts for CloseWrite to propagate a half-close, and a wrapper
// that hid the method would turn every EOF into a full teardown, truncating
// the response still coming the other way. The method is exposed only when the
// wrapped connection really has it, so the assertion keeps answering for the
// transport rather than for the wrapper.
type trackedCloseWriter struct{ *trackedConn }

func (c trackedCloseWriter) CloseWrite() error {
	return c.Conn.(interface{ CloseWrite() error }).CloseWrite()
}

func trackConn(l *trackingListener, c net.Conn) net.Conn {
	t := &trackedConn{Conn: c, l: l}
	if _, ok := c.(interface{ CloseWrite() error }); ok {
		return trackedCloseWriter{t}
	}
	return t
}

func closeBounds(bounds []*bound) {
	for _, b := range bounds {
		b.close()
	}
}

// bindAll opens a listener for every mapping. On the first failure it closes
// everything it has already opened: a process that exits holding half its
// listeners open would keep those ports claimed for as long as it takes the
// supervisor to notice, and the restart would then fail to bind for a second,
// unrelated-looking reason.
func bindAll(cfg *config.Config, nets *networks, reg *obs.Registry) ([]*bound, error) {
	ip4, ip6 := nets.tailnetIPs()

	bounds := make([]*bound, 0, len(cfg.Maps))
	for _, m := range cfg.Maps {
		b, err := bindOne(m, nets, ip4, ip6, reg)
		if err != nil {
			closeBounds(bounds)
			return nil, fmt.Errorf("mapping %s (%s): %w", m.Name, envVarFor(m), err)
		}
		bounds = append(bounds, b)
	}
	return bounds, nil
}

func bindOne(m config.Mapping, nets *networks, ip4, ip6 netip.Addr, reg *obs.Registry) (*bound, error) {
	dial, err := nets.dialer(m)
	if err != nil {
		return nil, err
	}
	b := &bound{m: m, addr: m.Listen, dial: recordingDial(m, dial, reg)}

	switch {
	case m.Proto == config.TCP:
		ln, err := nets.listen(m, m.Listen)
		if err != nil {
			return nil, fmt.Errorf("listening on %s at %s: %w", listenNetworkDescription(m), m.Listen, err)
		}
		b.ln = newTrackingListener(ln)

	case m.Proto == config.UDP:
		addr := m.Listen
		// Only a tailnet ingress mapping needs its wildcard resolved: tsnet
		// rejects a wildcard packet bind, while the host stack and a WireGuard
		// interface both accept one.
		if m.Dir == config.In && m.Via.IsTailnet() {
			resolved, err := ingressPacketAddr(m, ip4, ip6)
			if err != nil {
				return nil, err
			}
			addr = resolved
		}
		pc, err := nets.listenPacket(m, addr)
		if err != nil {
			return nil, fmt.Errorf("listening on %s at %s: %w", listenNetworkDescription(m), addr, err)
		}
		b.addr, b.pc = addr, pc

	default:
		return nil, fmt.Errorf("no listener for direction %q over %q", m.Dir, m.Proto)
	}

	// The address the kernel or tsnet actually chose, which is not always the
	// one that was asked for: a port of 0 is assigned here, and an operator
	// reading the log needs the number that was really claimed.
	if b.ln != nil && b.ln.Addr() != nil {
		b.addr = b.ln.Addr().String()
	}
	if b.pc != nil && b.pc.LocalAddr() != nil {
		b.addr = b.pc.LocalAddr().String()
	}
	return b, nil
}

// ingressPacketAddr resolves the bind address for an ingress UDP mapping.
//
// tsnet refuses a wildcard packet bind — ":53", "0.0.0.0:53" and "[::]:53" are
// all rejected — because a datagram listener has no per-connection local
// address to reply from and so must be pinned to one of the node's own tailnet
// addresses. An operator writing ":53" means "this node", which is what is
// substituted here; the address that was actually bound is then logged, since
// it is no longer the one in the configuration.
func ingressPacketAddr(m config.Mapping, ip4, ip6 netip.Addr) (string, error) {
	host, port, err := net.SplitHostPort(m.Listen)
	if err != nil {
		return "", fmt.Errorf("listen %q is not host:port: %w", m.Listen, err)
	}

	preferV6 := false
	if host != "" {
		addr, perr := netip.ParseAddr(host)
		// Unmapped before the test: netip.Addr.IsUnspecified compares against
		// 0.0.0.0 and ::, and answers false for the IPv4-mapped spelling
		// "::ffff:0.0.0.0" even though it names the same wildcard. The
		// configuration parser folds that spelling to 0.0.0.0 when it looks
		// for conflicting binds, so this must read it the same way or a
		// wildcard the parser recognised would be handed to tsnet, which
		// rejects it.
		if perr == nil {
			addr = addr.Unmap()
		}
		if perr != nil || !addr.IsUnspecified() {
			// A concrete address, or a name tsnet will resolve itself. Either
			// way it is not a wildcard, so it stands as written.
			return m.Listen, nil
		}
		// "[::]" asks for the IPv6 stack, so honour that preference when the
		// node has an address in both families. An unmapped "::ffff:0.0.0.0"
		// is an IPv4 address and expresses no such preference.
		preferV6 = addr.Is6()
	}

	order := [2]netip.Addr{ip4, ip6}
	if preferV6 {
		order = [2]netip.Addr{ip6, ip4}
	}
	for _, a := range order {
		if a.IsValid() {
			return net.JoinHostPort(a.String(), port), nil
		}
	}
	return "", fmt.Errorf("listen %q binds every address, which tsnet rejects for UDP, and this node has no tailnet address to substitute; "+
		"name one of the node's own tailnet addresses explicitly once it has been assigned", m.Listen)
}

// recordingDial wraps a mapping's onward dialer so that a failure is recorded
// here, classified from the error.
//
// This is the only place that can tell a destination a guard refused from an
// ordinary connection failure, and that distinction is the one an operator most
// needs to see in a metric: a refusal is a configuration mistake with a fix, a
// connection failure is usually somebody else's outage.
func recordingDial(m config.Mapping, dial relay.DialFunc, reg *obs.Registry) relay.DialFunc {
	name := m.Name
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		c, err := dial(ctx, network, address)
		if err != nil && reg != nil {
			reg.DialFailed(name, dialFailureReason(err))
		}
		return c, err
	}
}

func dialFailureReason(err error) string {
	switch {
	case errors.Is(err, tsnode.ErrNotTailnet):
		return obs.ReasonNotTailnet
	case errors.Is(err, wgnet.ErrNoRoute):
		return obs.ReasonNoRoute
	default:
		return obs.ReasonForError(err)
	}
}

// listenNetworkDescription names, for an error message, the network a
// mapping's listener lives on.
func listenNetworkDescription(m config.Mapping) string {
	if m.Dir == config.Out {
		return "the container's own network"
	}
	switch m.Via.Kind {
	case config.NetWireGuard:
		return "WireGuard interface " + m.Via.Name
	default:
		return "the tailnet"
	}
}

// relayRecorder adapts the relay's accounting to the metric registry.
//
// Both sides now speak the same closed reason vocabulary, declared in package
// relay, so a rejection passes straight through. The only thing this type still
// does is drop DialFailed.
type relayRecorder struct{ reg *obs.Registry }

func (r relayRecorder) SessionOpened(name string) { r.reg.SessionOpened(name) }

func (r relayRecorder) SessionClosed(name string, up, down int64, d time.Duration) {
	r.reg.SessionClosed(name, up, down, d)
}

// DialFailed is deliberately dropped. The dial function installed by dialFunc
// already recorded this failure classified from the error itself, which is the
// only classification that can report a destination refused by the tailnet
// guard. Recording again here would double-count every failed dial.
func (relayRecorder) DialFailed(string, string) {}

func (r relayRecorder) Rejected(name, reason string) { r.reg.Rejected(name, reason) }

// waitFor reports whether wg finished within d.
func waitFor(wg *sync.WaitGroup, d time.Duration) bool {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	if d <= 0 {
		select {
		case <-done:
			return true
		default:
			return false
		}
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-done:
		return true
	case <-t.C:
		return false
	}
}

func newLogger(w io.Writer, level string) *slog.Logger {
	var lv slog.Level
	switch level {
	case "debug":
		lv = slog.LevelDebug
	case "warn":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		lv = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: lv}))
}

// envVarFor reconstructs the variable that declared a mapping, so an error
// names the thing an operator has to edit rather than the name we parsed out
// of it.
func envVarFor(m config.Mapping) string {
	if m.Dir == config.In {
		return config.EnvPrefixIn + m.Name
	}
	return config.EnvPrefixOut + m.Name
}

func prefixesString(ps []netip.Prefix) string {
	parts := make([]string, len(ps))
	for i, p := range ps {
		parts[i] = p.String()
	}
	return strings.Join(parts, ",")
}

func allowString(m config.Mapping) string {
	if len(m.Allow) == 0 {
		return "any"
	}
	parts := make([]string, len(m.Allow))
	for i, p := range m.Allow {
		parts[i] = p.String()
	}
	return strings.Join(parts, "|")
}

// Validate parses environ and writes a human-readable summary of the resolved
// configuration to w without touching the network.
//
// This is what runs in CI and in a container's entrypoint smoke test. Its value
// is that it answers "what will this actually expose?" from the same parser the
// real startup uses, so a summary that looks right cannot be produced by a
// configuration that would start differently.
func Validate(environ []string, version string, w io.Writer) error {
	cfg, err := config.FromEnv(environ)
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}
	if err := checkStartup(environ, cfg); err != nil {
		return err
	}
	return writeSummary(w, cfg, version)
}

// oauthSecretPrefix is the prefix Tailscale gives OAuth client secrets. tsnet
// exchanges a secret with this prefix for an auth key rather than presenting
// it as one, and the minted key has to be tagged, so tsnode refuses the
// combination of such a secret and no tags. The prefix is repeated here rather
// than shared because this is a copy of a rule owned by tsnet, not by us.
const oauthSecretPrefix = "tskey-client-"

// checkStartup reports the configurations that parse cleanly but cannot start.
//
// The parser's job ends at the mappings' own consistency; these are conflicts
// between a mapping and something outside it. They belong here because the
// point of --validate is to be a gate: a configuration it passes and startup
// then rejects is worse than no gate at all, and each of these fails at a
// point where the error names a symptom rather than the setting at fault.
func checkStartup(environ []string, cfg *config.Config) error {
	// The credential is only read when a node is actually started, so a
	// WireGuard-only configuration must not be failed over the shape of a key
	// nothing will present.
	if needsTailnet(cfg) && strings.HasPrefix(cfg.AuthKey, oauthSecretPrefix) && len(cfg.Tags) == 0 {
		return fmt.Errorf("%s holds an OAuth client secret (it begins %q) but %s is empty: "+
			"the auth key minted from a client secret is always tagged, so the node cannot register without tags. "+
			"Set %s to the tags the OAuth client is authorised for, for example %s=tag:proxy",
			config.EnvAuthKey, oauthSecretPrefix, config.EnvTags, config.EnvTags, config.EnvTags)
	}
	return checkStatusAddrFree(environ, cfg)
}

// checkStatusAddrFree rejects a mapping that would take the address the status
// server needs.
//
// Only an egress TCP mapping can: an ingress listener is opened inside tsnet's
// netstack and never touches a host socket, and a UDP bind does not exclude a
// TCP one. At startup the mappings are bound before the status server, so the
// operator sees "address already in use" attributed to TSPM_METRICS_ADDR — a
// variable they very likely never set, since the address in the message is the
// built-in default.
func checkStatusAddrFree(environ []string, cfg *config.Config) error {
	statusHost, statusPort, err := net.SplitHostPort(cfg.MetricsAddr)
	if err != nil {
		// config.FromEnv already accepted this address.
		return nil
	}

	// Named so the message can point at whichever of the two an operator can
	// actually act on.
	explicit := envValue(environ, config.EnvMetricsAddr) != ""

	for _, m := range cfg.Maps {
		if m.Dir != config.Out || m.Proto != config.TCP {
			continue
		}
		host, port, err := net.SplitHostPort(m.Listen)
		if err != nil || port != statusPort {
			continue
		}
		if !hostsOverlap(host, statusHost) {
			continue
		}
		if explicit {
			return fmt.Errorf("mapping %s (%s) listens on %s, which is the status address set by %s (%s); "+
				"the mappings are bound before the status server, so startup would fail to bind it. "+
				"Move the mapping to another port, or point %s somewhere else",
				m.Name, envVarFor(m), m.Listen, config.EnvMetricsAddr, cfg.MetricsAddr, config.EnvMetricsAddr)
		}
		return fmt.Errorf("mapping %s (%s) listens on %s, which collides with the DEFAULT status address %s "+
			"(/healthz, /readyz and /metrics); the mappings are bound before the status server, so startup would fail to bind it "+
			"and would blame %s, which is not set. Move the mapping to another port, or move the status endpoints by setting "+
			"%s explicitly, for example %s=127.0.0.1:9091",
			m.Name, envVarFor(m), m.Listen, config.DefaultMetricsAddr,
			config.EnvMetricsAddr, config.EnvMetricsAddr, config.EnvMetricsAddr)
	}
	return nil
}

// hostsOverlap reports whether two bind hosts on the same port can claim the
// same socket. A wildcard on either side covers the other, which is why this
// is not a string comparison.
func hostsOverlap(a, b string) bool {
	if isWildcard(a) || isWildcard(b) {
		return true
	}
	return canonicalHost(a) == canonicalHost(b)
}

func isWildcard(host string) bool {
	if host == "" {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.Unmap().IsUnspecified()
}

func canonicalHost(host string) string {
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Unmap().String()
	}
	return strings.ToLower(host)
}

// envValue reads one variable out of an os.Environ()-style slice, taking the
// first occurrence exactly as os.Getenv and the configuration parser do.
func envValue(environ []string, name string) string {
	for _, kv := range environ {
		if k, v, ok := strings.Cut(kv, "="); ok && k == name {
			return v
		}
	}
	return ""
}

func writeSummary(w io.Writer, cfg *config.Config, version string) error {
	var b strings.Builder

	fmt.Fprintf(&b, "tsportmap %s: configuration is valid\n\n", version)

	tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	// The auth key is reported only as present or absent. Neither a prefix nor
	// a length belongs in output an operator will paste into an issue.
	authKey := "not set"
	if cfg.AuthKey != "" {
		authKey = "set (redacted)"
	}
	controlURL := cfg.ControlURL
	if controlURL == "" {
		controlURL = "(default Tailscale coordination server)"
	}
	tags := strings.Join(cfg.Tags, ",")
	if tags == "" {
		tags = "(none)"
	}
	rows := [][2]string{}
	if !needsTailnet(cfg) {
		// Everything below this line describes a node that is not going to be
		// started, so say so before an operator debugs an auth key that is
		// never read.
		rows = append(rows, [2]string{"tailnet node", "not started (no mapping uses via=ts)"})
	}
	for _, row := range append(rows, [][2]string{
		{"hostname", cfg.Hostname},
		{"auth key", authKey},
		{"tags", tags},
		{"state dir", cfg.StateDir},
		{"ephemeral", fmt.Sprint(cfg.Ephemeral)},
		{"control url", controlURL},
		{"accept routes", fmt.Sprint(cfg.AcceptRoutes)},
		{"require tailnet dest", fmt.Sprint(cfg.RequireTailnetDest)},
		{"status addr", cfg.MetricsAddr},
		{"dial timeout", cfg.DialTimeout.String()},
		{"up timeout", cfg.UpTimeout.String()},
		{"shutdown grace", cfg.ShutdownGrace.String()},
		{"log level", cfg.LogLevel},
	}...) {
		fmt.Fprintf(tw, "  %s:\t%s\n", row[0], row[1])
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	if len(cfg.WG) > 0 {
		fmt.Fprintf(&b, "\nwireguard interfaces (%d):\n", len(cfg.WG))
		wt := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
		// No key material is printed, not even the interface's public key,
		// which would be derived from the private one. The peers' public keys
		// are printed because they are public, and because matching them
		// against `wg show` on the far side is the first thing an operator does
		// when a tunnel is not carrying traffic.
		fmt.Fprintf(wt, "  NAME\tADDRESSES\tLISTEN PORT\tMTU\tPEER\tENDPOINT\tALLOWED IPS\tKEEPALIVE\n")
		for _, w := range cfg.WG {
			port := "ephemeral"
			if w.ListenPort > 0 {
				port = strconv.Itoa(w.ListenPort)
			}
			for i, p := range w.Peers {
				name, addrs, mtu := w.Name, prefixesString(w.Addresses), strconv.Itoa(w.MTU)
				if i > 0 {
					// One row per peer, with the interface's own columns blank
					// after the first so the grouping is visible at a glance.
					name, addrs, port, mtu = "", "", "", ""
				}
				endpoint := p.Endpoint
				if endpoint == "" {
					endpoint = "(peer must initiate)"
				}
				keepalive := "off"
				if p.Keepalive > 0 {
					keepalive = p.Keepalive.String()
				}
				fmt.Fprintf(wt, "  %s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					name, addrs, port, mtu, p.PublicKey, endpoint, prefixesString(p.AllowedIPs), keepalive)
			}
		}
		if err := wt.Flush(); err != nil {
			return err
		}
	}

	fmt.Fprintf(&b, "\nmappings (%d):\n", len(cfg.Maps))
	mt := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	fmt.Fprintf(mt, "  NAME\tDIR\tVIA\tPROTO\tLISTEN\tTARGET\tTLS\tALLOW\tIDLE\n")
	for _, m := range cfg.Maps {
		fmt.Fprintf(mt, "  %s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			m.Name, m.Dir, m.Via, m.Proto, m.Listen, m.Target,
			fmt.Sprint(m.TLS), allowString(m), m.Idle)
	}
	if err := mt.Flush(); err != nil {
		return err
	}

	for _, m := range cfg.Maps {
		for _, note := range mappingNotes(m) {
			fmt.Fprintf(&b, "\nnote: %s: %s\n", m.Name, note)
		}
	}

	_, err := io.WriteString(w, b.String())
	return err
}

// mappingNotes calls out what a mapping does that its one line above does not
// say — the things an operator would otherwise discover from a running system.
func mappingNotes(m config.Mapping) []string {
	var notes []string
	host, _, err := net.SplitHostPort(m.Listen)
	if err != nil {
		return nil
	}
	wildcard := host == ""
	if !wildcard {
		// Unmap for the same reason ingressPacketAddr does: "::ffff:0.0.0.0"
		// is the wildcard, and a note that failed to mention it would leave an
		// operator to discover the substitution from a running system.
		if addr, perr := netip.ParseAddr(host); perr == nil && addr.Unmap().IsUnspecified() {
			wildcard = true
		}
	}
	if m.Dir == config.In && m.Proto == config.UDP && wildcard && m.Via.IsTailnet() {
		notes = append(notes, fmt.Sprintf("listen %q binds every address, which tsnet rejects for UDP; "+
			"one of this node's own tailnet addresses is substituted at startup and the bound address is logged", m.Listen))
	}
	if m.Dir == config.Out && len(m.Allow) == 0 && !loopbackOnly(host) {
		notes = append(notes, fmt.Sprintf("listen %q is not loopback and has no allow list, so anything that can reach that address "+
			"can use this mapping to reach %s over %s", m.Listen, m.Target, viaDescription(m.Via)))
	}
	if m.Dir == config.Out && m.Via.Kind == config.NetLocal {
		// via=local is the one mapping kind with no tunnel and therefore no
		// destination guard of any sort. That is what it is for, and it is also
		// the thing least like the rest of this tool, so it is stated rather
		// than left to be inferred from the absence of a tailnet column.
		notes = append(notes, fmt.Sprintf("via=%s is a plain forwarder: %s is dialled on the container's own network, with no tunnel and no destination guard. "+
			"Whatever answers at that address on this network is what a client reaches", config.NetLocal, m.Target))
	}
	return notes
}

// viaDescription names a network the way a sentence needs it, as opposed to the
// way via= spells it.
func viaDescription(n config.Network) string {
	switch n.Kind {
	case config.NetWireGuard:
		return "WireGuard interface " + n.Name
	case config.NetLocal:
		return "the container's own network"
	default:
		return "the tailnet"
	}
}

func loopbackOnly(host string) bool {
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.IsLoopback()
}
