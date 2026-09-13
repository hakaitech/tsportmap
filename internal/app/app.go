// Package app wires tsportmap's parts together: it turns an environment into a
// configuration, brings the embedded Tailscale node up, binds every declared
// mapping, and runs them until it is asked to stop.
//
// Everything here is startup order and shutdown order. The relays, the node and
// the metrics registry each work on their own; what this package owns is the
// sequence that makes them safe together — bind before ready, drain before
// close, and close the node after everything that might still dial through it.
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
	"strings"
	"sync"
	"sync/atomic"
	"text/tabwriter"
	"time"

	"github.com/hakaitech/tsportmap/internal/config"
	"github.com/hakaitech/tsportmap/internal/obs"
	"github.com/hakaitech/tsportmap/internal/relay"
	"github.com/hakaitech/tsportmap/internal/tsnode"
)

// metricsShutdownTimeout bounds draining the status server. It is short because
// nothing important is served there: a scrape that loses its connection is
// retried by the collector seconds later, and holding the process open for a
// slow /metrics reader delays the node teardown that actually matters.
const metricsShutdownTimeout = 5 * time.Second

// forceCloseGrace is how long relays get after their listeners have been closed
// out from under them. Closing is what unblocks a goroutine parked in Read, so
// this only has to cover the return trip, not any real work.
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
	return run(ctx, environ, version, stderr, newTailscaleNode)
}

func run(ctx context.Context, environ []string, version string, stderr io.Writer, newNode nodeFactory) error {
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

	n, err := newNode(cfg, logger)
	if err != nil {
		return err
	}
	// closeNode runs exactly once. The deferred call is the backstop for the
	// early returns below; the ordered shutdown at the end calls it explicitly
	// so that the node outlives every relay that might still be dialling
	// through it.
	var closeOnce sync.Once
	closeNode := func() {
		closeOnce.Do(func() {
			if err := n.Close(); err != nil {
				logger.Warn("closing tailnet node", "error", err)
			}
		})
	}
	defer closeNode()

	if err := n.Start(ctx); err != nil {
		return err
	}

	// Every listener is bound before anything is declared ready. A mapping that
	// cannot bind is a mapping an operator declared and is not getting, and a
	// half-served configuration hides that behind the mappings that did work.
	bounds, err := bindAll(cfg, n, reg)
	if err != nil {
		return err
	}

	var ready atomic.Bool
	srv := obs.NewServer(cfg.MetricsAddr, reg, nil, func(ctx context.Context) error {
		if !ready.Load() {
			return errors.New("listeners are not serving")
		}
		return n.Running(ctx)
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
		// grace period. Closing the listeners is the only lever left.
		logger.Warn("shutdown grace expired with sessions still open, closing listeners", "grace", cfg.ShutdownGrace)
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

	// The node goes last: a relay still finishing a session is still using its
	// dialer and its listeners, and tearing the tailnet out from under one
	// turns an orderly drain into a truncated response.
	closeNode()
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

func (b *bound) close() {
	if b.ln != nil {
		b.ln.Close()
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
func bindAll(cfg *config.Config, n node, reg *obs.Registry) ([]*bound, error) {
	ip4, ip6 := n.TailnetIPs()

	bounds := make([]*bound, 0, len(cfg.Maps))
	for _, m := range cfg.Maps {
		b, err := bindOne(m, n, ip4, ip6, reg)
		if err != nil {
			closeBounds(bounds)
			return nil, fmt.Errorf("mapping %s (%s): %w", m.Name, envVarFor(m), err)
		}
		bounds = append(bounds, b)
	}
	return bounds, nil
}

func bindOne(m config.Mapping, n node, ip4, ip6 netip.Addr, reg *obs.Registry) (*bound, error) {
	b := &bound{m: m, addr: m.Listen, dial: dialFunc(m, n, reg)}

	switch {
	case m.Dir == config.Out && m.Proto == config.TCP:
		ln, err := net.Listen("tcp", m.Listen)
		if err != nil {
			return nil, fmt.Errorf("listening on %s: %w", m.Listen, err)
		}
		b.ln = ln

	case m.Dir == config.Out && m.Proto == config.UDP:
		pc, err := net.ListenPacket("udp", m.Listen)
		if err != nil {
			return nil, fmt.Errorf("listening on %s: %w", m.Listen, err)
		}
		b.pc = pc

	case m.Dir == config.In && m.Proto == config.TCP:
		listen := n.Listen
		if m.TLS {
			listen = n.ListenTLS
		}
		ln, err := listen("tcp", m.Listen)
		if err != nil {
			return nil, fmt.Errorf("listening on the tailnet at %s: %w", m.Listen, err)
		}
		b.ln = ln

	case m.Dir == config.In && m.Proto == config.UDP:
		addr, err := ingressPacketAddr(m, ip4, ip6)
		if err != nil {
			return nil, err
		}
		pc, err := n.ListenPacket("udp", addr)
		if err != nil {
			return nil, fmt.Errorf("listening on the tailnet at %s: %w", addr, err)
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
		if perr != nil || !addr.IsUnspecified() {
			// A concrete address, or a name tsnet will resolve itself. Either
			// way it is not a wildcard, so it stands as written.
			return m.Listen, nil
		}
		// "[::]" asks for the IPv6 stack, so honour that preference when the
		// node has an address in both families.
		preferV6 = addr.Is6() && !addr.Is4In6()
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

// dialFunc builds the onward leg for a mapping.
//
// The direction decides the dialer and nothing else does: an egress mapping
// dials a tailnet peer through the node, where the destination guard can refuse
// a target that is not on the tailnet, while an ingress mapping dials a target
// that is local to this container and must not go through the tailnet at all.
//
// The wrapper records dial failures itself, from the error, because it is the
// only place that can tell a destination the guard refused from an ordinary
// connection failure — and that distinction is the one an operator most needs
// to see in a metric.
func dialFunc(m config.Mapping, n node, reg *obs.Registry) relay.DialFunc {
	dial := relay.DialFunc(n.DialContext)
	if m.Dir == config.In {
		d := &net.Dialer{}
		dial = d.DialContext
	}
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
	if errors.Is(err, tsnode.ErrNotTailnet) {
		return obs.ReasonNotTailnet
	}
	return obs.ReasonForError(err)
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
	return writeSummary(w, cfg, version)
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
	for _, row := range [][2]string{
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
	} {
		fmt.Fprintf(tw, "  %s:\t%s\n", row[0], row[1])
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	fmt.Fprintf(&b, "\nmappings (%d):\n", len(cfg.Maps))
	mt := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	fmt.Fprintf(mt, "  NAME\tDIR\tPROTO\tLISTEN\tTARGET\tTLS\tALLOW\tIDLE\n")
	for _, m := range cfg.Maps {
		fmt.Fprintf(mt, "  %s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			m.Name, m.Dir, m.Proto, m.Listen, m.Target,
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
		if addr, perr := netip.ParseAddr(host); perr == nil && addr.IsUnspecified() {
			wildcard = true
		}
	}
	if m.Dir == config.In && m.Proto == config.UDP && wildcard {
		notes = append(notes, fmt.Sprintf("listen %q binds every address, which tsnet rejects for UDP; "+
			"one of this node's own tailnet addresses is substituted at startup and the bound address is logged", m.Listen))
	}
	if m.Dir == config.Out && len(m.Allow) == 0 && !loopbackOnly(host) {
		notes = append(notes, fmt.Sprintf("listen %q is not loopback and has no allow list, so anything that can reach that address "+
			"can use this mapping to reach %s over the tailnet", m.Listen, m.Target))
	}
	return notes
}

func loopbackOnly(host string) bool {
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.IsLoopback()
}
