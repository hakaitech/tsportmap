package tsnode

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/hakaitech/tsportmap/internal/config"

	"tailscale.com/client/local"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tsnet"
	"tailscale.com/types/logger"

	// Registering the OAuth hook is what lets a "tskey-client-" client secret be
	// exchanged for an auth key. Without this import tsnet passes the secret to
	// control verbatim as if it were a key, and the node fails to log in.
	_ "tailscale.com/feature/oauthkey"
)

// ErrNotTailnet reports a destination the guard refused because it could not be
// shown to be a tailnet peer or an accepted subnet route. It is a distinct
// sentinel because it is an operator configuration error - a wrong target - and
// not a transient network failure, so callers must not retry it.
var ErrNotTailnet = errors.New("destination is not a tailnet peer or an accepted route")

// oauthSecretPrefix is the prefix Tailscale gives OAuth client secrets. tsnet
// exchanges a secret with this prefix for an auth key, and that exchange
// requires tags because the minted key must be tagged.
const oauthSecretPrefix = "tskey-client-"

// defaultUpTimeout bounds the wait for Running when configuration supplies no
// bound. Zero is not honoured as "no timeout": an unbounded wait is the exact
// failure mode this package exists to avoid, and a zero-length timeout would
// expire before the node could possibly come up.
const defaultUpTimeout = 90 * time.Second

// diagnoseTimeout bounds the follow-up queries made to explain a failed start.
// Diagnosis runs when the node is already known to be unhealthy, so it must be
// short enough that it cannot itself become the hang it is reporting on.
const diagnoseTimeout = 5 * time.Second

// authProbeInterval is how often the startup watchdog asks the backend whether
// control has refused the credentials.
const authProbeInterval = time.Second

// Node is the embedded Tailscale node: one tsnet server, its lifecycle, the
// prefs tsnet does not persist, and the destination guard.
type Node struct {
	cfg *config.Config
	log *slog.Logger
	srv *tsnet.Server

	closeOnce sync.Once
	closeErr  error

	mu sync.Mutex
	// started records that tsnet.Server.Start returned nil. Close must consult
	// it: tsnet assigns the subsystems Close tears down only once Start has got
	// that far, so closing a server that never started dereferences nil.
	started bool
	lc      *local.Client
	guard   Guard
}

var _ Dialer = (*Node)(nil)
var _ Listener = (*Node)(nil)

// New constructs the node from cfg. It performs no network I/O: nothing here
// contacts the tailnet or the coordination server.
func New(cfg *config.Config, logger *slog.Logger) (*Node, error) {
	if cfg == nil {
		return nil, errors.New("tsnode: nil config")
	}
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.Hostname == "" {
		return nil, errors.New("tsnode: hostname is empty; set TSPM_HOSTNAME")
	}
	// tsnet unconditionally MkdirAlls Dir for its log buffer and falls back to
	// os.UserConfigDir when it is empty, which fails in a container with no
	// $HOME. An explicit directory is the only configuration that works
	// everywhere, so refuse to start without one.
	if strings.TrimSpace(cfg.StateDir) == "" {
		return nil, errors.New("tsnode: state directory is empty; set TSPM_STATE_DIR to a writable path")
	}

	srv := &tsnet.Server{
		Hostname:      cfg.Hostname,
		Dir:           cfg.StateDir,
		Ephemeral:     cfg.Ephemeral,
		ControlURL:    cfg.ControlURL,
		AdvertiseTags: cfg.Tags,
		Logf:          redactingLogf(logger, slog.LevelDebug, cfg.AuthKey),
		UserLogf:      redactingLogf(logger, slog.LevelInfo, cfg.AuthKey),
	}

	if isOAuthSecret(cfg.AuthKey) {
		if len(cfg.Tags) == 0 {
			return nil, errors.New("tsnode: an OAuth client secret requires tags; set TSPM_TAGS (for example \"tag:proxy\") " +
				"because the auth key minted from the secret must be tagged")
		}
		srv.ClientSecret = cfg.AuthKey
	} else {
		srv.AuthKey = cfg.AuthKey
	}

	return &Node{cfg: cfg, log: logger, srv: srv}, nil
}

func isOAuthSecret(key string) bool {
	return strings.HasPrefix(key, oauthSecretPrefix)
}

// Start brings the node up and blocks until it is Running or ctx expires.
func (n *Node) Start(ctx context.Context) error {
	if err := n.srv.Start(); err != nil {
		return fmt.Errorf("tsnode: starting tailscale node: %w", err)
	}
	n.mu.Lock()
	n.started = true
	n.mu.Unlock()

	lc, err := n.srv.LocalClient()
	if err != nil {
		return fmt.Errorf("tsnode: opening local API client: %w", err)
	}

	upTimeout := n.cfg.UpTimeout
	if upTimeout <= 0 {
		upTimeout = defaultUpTimeout
	}
	// tsnet.Server.Up loops until the backend reports Running: it deliberately
	// does not return on NeedsLogin or NeedsMachineAuth. The timeout is what
	// turns a bad auth key from a hang into a diagnosis.
	upCtx, cancel := context.WithTimeout(ctx, upTimeout)
	defer cancel()

	// Control usually reports a rejected key within a second, but Up would sit
	// out the whole timeout regardless. Waiting is pure waste on a platform
	// that bounds how long a deploy may take to become healthy, so a watchdog
	// abandons the wait as soon as the backend reports a rejection it cannot
	// recover from. Up then returns the cancellation and the same diagnosis
	// runs, just sooner.
	startedAt := time.Now()
	stopWatchdog := n.watchAuthRejection(upCtx, lc, cancel)

	st, err := n.srv.Up(upCtx)
	stopWatchdog()
	if err != nil {
		return n.explainUpFailure(ctx, lc, time.Since(startedAt), err)
	}

	n.mu.Lock()
	n.lc = lc
	n.guard = NewGuard(lc, n.log)
	n.mu.Unlock()

	if n.cfg.AcceptRoutes {
		if err := applyAcceptRoutes(ctx, lc); err != nil {
			return err
		}
	}

	ip4, ip6 := n.srv.TailscaleIPs()
	n.log.Info("tailnet node running",
		"hostname", n.cfg.Hostname,
		"ipv4", ip4.String(),
		"ipv6", ip6.String(),
		"tailnet", tailnetName(st),
		"accept_routes", n.cfg.AcceptRoutes,
		"require_tailnet_dest", n.cfg.RequireTailnetDest,
	)
	if !n.cfg.RequireTailnetDest {
		n.log.Warn("destination guard disabled: a target that is not a tailnet peer will be dialled on the container's own network instead of failing, " +
			"so a mistyped target can silently reach a neighbouring local service; set TSPM_REQUIRE_TAILNET_DEST=true to refuse those dials")
	}
	return nil
}

func tailnetName(st *ipnstate.Status) string {
	if st == nil || st.CurrentTailnet == nil {
		return ""
	}
	return st.CurrentTailnet.Name
}

// prefsEditor is the narrow slice of *local.Client needed to set and verify a
// pref, kept separate so the re-apply-and-verify step can be tested without a
// tailnet.
type prefsEditor interface {
	EditPrefs(ctx context.Context, mp *ipn.MaskedPrefs) (*ipn.Prefs, error)
	GetPrefs(ctx context.Context) (*ipn.Prefs, error)
}

// applyAcceptRoutes turns on RouteAll and verifies it took effect.
//
// This runs on every Start, not once at first login, because tsnet hands the
// backend a freshly-built ipn.Prefs as ipn.Options{UpdatePrefs}; the backend
// clones those prefs wholesale and carries over only Persist from the stored
// profile. RouteAll therefore reverts to false on every process start, and a
// node that relayed to a subnet-routed target yesterday would quietly stop
// being able to reach it after a restart.
//
// The read-back matters as much as the write: EditPrefs reports success for a
// pref the backend then declines to apply, and a silently-ignored RouteAll
// looks exactly like a routing problem somewhere else.
func applyAcceptRoutes(ctx context.Context, pe prefsEditor) error {
	if _, err := pe.EditPrefs(ctx, &ipn.MaskedPrefs{
		Prefs:       ipn.Prefs{RouteAll: true},
		RouteAllSet: true,
	}); err != nil {
		return fmt.Errorf("tsnode: enabling accept-routes: %w", err)
	}
	got, err := pe.GetPrefs(ctx)
	if err != nil {
		return fmt.Errorf("tsnode: reading back prefs after enabling accept-routes: %w", err)
	}
	if got == nil || !got.RouteAll {
		return errors.New("tsnode: accept-routes did not take effect: the backend accepted the change but does not report RouteAll=true, " +
			"so advertised subnet routes will not be used")
	}
	return nil
}

// explainUpFailure converts a failed wait for Running into an error that names
// the cause. A bare timeout here is the single most expensive message this tool
// could print: every plausible cause has a different fix and none of them is
// "wait longer".
func (n *Node) explainUpFailure(ctx context.Context, lc *local.Client, waited time.Duration, upErr error) error {
	// The diagnosis must still work when ctx is the reason Up gave up, so it
	// runs on a fresh deadline rather than the caller's expired one.
	dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), diagnoseTimeout)
	defer cancel()

	var (
		st      *ipnstate.Status
		statErr error
	)
	if lc != nil {
		st, statErr = lc.StatusWithoutPeers(dctx)
	} else {
		statErr = errors.New("no local API client")
	}
	diag := diagnoseUp(st, statErr, n.cfg.AuthKey != "", n.cfg.ControlURL, waited)
	return fmt.Errorf("tsnode: %s: %w", diag, upErr)
}

// watchAuthRejection polls the backend while the node is coming up and calls
// abort once control has definitively refused the credentials. It returns a
// function that stops the watch.
//
// It is deliberately conservative. A node that is merely slow, or briefly
// unreachable, must be given the full timeout; only a state the node cannot
// recover from on its own justifies cutting the wait short.
func (n *Node) watchAuthRejection(ctx context.Context, lc *local.Client, abort context.CancelFunc) (stop func()) {
	if lc == nil {
		return func() {}
	}
	done := make(chan struct{})
	var once sync.Once
	go func() {
		t := time.NewTicker(authProbeInterval)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-t.C:
			}
			st, err := lc.StatusWithoutPeers(ctx)
			if err != nil {
				continue
			}
			if unrecoverableAuthState(st) {
				n.log.Error("tailnet control rejected the credentials; abandoning the wait early",
					"backend_state", st.BackendState,
					"health", strings.Join(st.Health, "; "))
				abort()
				return
			}
		}
	}()
	return func() { once.Do(func() { close(done) }) }
}

// unrecoverableAuthState reports whether a backend snapshot shows a credential
// failure that more waiting cannot fix.
//
// The trade-off is deliberately lopsided. A false negative costs only the
// remainder of UpTimeout, which the operator already agreed to wait. A false
// positive turns a recoverable control-plane blip into a crash loop: a node
// with no stored key restarts, hits the same blip, and aborts again about a
// second in - and when the credential is an OAuth client secret, every one of
// those restarts mints a fresh API key. So this predicate answers "no"
// whenever it is not certain.
//
// Certainty has to come from the credential-specific part of the health text.
// The text as a whole cannot carry it: tailscale's health.LoginStateWarnable
// renders every failed attempt as "You are logged out. The last login error
// was: %v", and controlclient's auth routine feeds that warnable the error
// from EVERY TryLogin failure before it backs off and retries - a DNS timeout,
// an HTTP 503, a rate limit, a deadline exceeded. Matching the fixed part of
// that sentence therefore matches states the node would have recovered from on
// its own. Only the %v distinguishes a control plane that refused the
// credential from a control plane that was never reached.
func unrecoverableAuthState(st *ipnstate.Status) bool {
	if st == nil {
		return false
	}
	// NeedsMachineAuth is deliberately not a trigger. A device awaiting
	// approval is waiting on a human, and that human can approve it inside the
	// timeout window; aborting would take that chance away.
	if st.BackendState != ipn.NeedsLogin.String() {
		return false
	}
	for _, h := range st.Health {
		if credentialRejected(h) {
			return true
		}
	}
	return false
}

// credentialNouns and credentialRejections must BOTH appear in one health
// message before it counts as a refusal. Control reports a refused credential
// as a bare sentence about the credential itself ("invalid key: API key does
// not exist", "invalid key: single-use key has already been used"), which no
// transport failure produces.
var (
	credentialNouns = []string{"key", "credential", "secret", "token"}

	credentialRejections = []string{
		"invalid",
		"not valid",
		"expired",
		"already been used",
		"already used",
		"revoked",
		"does not exist",
	}
)

// recoverableEvidence disqualifies a health message outright, before the two
// lists above are consulted, because it shows the message is reporting on the
// attempt rather than on the credential.
//
// The URL entries do most of the work. Every error raised on the login path
// before control answers is a wrapped *url.Error and so carries the control
// URL, while a verdict from control never does. That also defuses the trap in
// the control URL itself: the endpoint that fetches control's public key is
// "/key", so a TLS or DNS failure fetching it produces a message containing
// both "key" and, via "certificate is not valid", a rejection word.
var recoverableEvidence = []string{
	"http://",
	"https://",
	"timeout",
	"timed out",
	"deadline exceeded",
	"context canceled",
	"context cancelled",
	"rate limit",
	"too many requests",
	"retry after",
	"connection refused",
	"connection reset",
	"no route to host",
	"network is unreachable",
	"no such host",
	"server misbehaving",
	"temporary failure",
	"unexpected eof",
	"x509",
	"certificate",
	"tls ",
	"http 4",
	"http 5",
	"status 4",
	"status 5",
}

func credentialRejected(healthMsg string) bool {
	h := strings.ToLower(healthMsg)
	if containsAny(h, recoverableEvidence) {
		return false
	}
	return containsAny(h, credentialNouns) && containsAny(h, credentialRejections)
}

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// diagnoseUp turns a backend snapshot into a sentence naming the likely cause.
// It is separated from the node so it can be tested against every state a first
// run actually hits.
func diagnoseUp(st *ipnstate.Status, statusErr error, haveAuthKey bool, controlURL string, waited time.Duration) string {
	control := controlURL
	if control == "" {
		control = "Tailscale's coordination server"
	}
	if st == nil || statusErr != nil {
		reason := "no reason available"
		if statusErr != nil {
			reason = statusErr.Error()
		}
		return fmt.Sprintf("the tailscale node never reached Running after %s and its own local API could not be queried (%s), "+
			"so the node did not finish starting", waited, reason)
	}

	var head string
	switch st.BackendState {
	case ipn.NeedsMachineAuth.String():
		head = "the node registered but is waiting for machine authorisation: approve this device on the Machines page of the tailnet admin console, " +
			"or use a pre-approved auth key"
	case ipn.NeedsLogin.String():
		if !haveAuthKey {
			head = "no auth key was supplied, so the node has nothing to log in with: set TSPM_AUTHKEY to a tailnet auth key, " +
				"or to file:/path/to/key to read it from a file"
			if st.AuthURL != "" {
				head += " (control offered an interactive login URL instead; tsnet logs it)"
			}
		} else {
			head = "the supplied auth key was not accepted: it is expired, already used, revoked, or was issued for a different tailnet"
		}
	case ipn.Stopped.String():
		head = "the node is logged out or stopped: its stored profile in the state directory says it must not connect"
	case ipn.NoState.String(), ipn.Starting.String():
		head = fmt.Sprintf("the node could not complete a control connection to %s: it never got past starting, "+
			"which usually means the coordination server is unreachable from this container or the control URL is wrong", control)
	case ipn.Running.String():
		head = "the node reports Running but the wait for it did not complete, so the local API and the backend disagree"
	default:
		head = fmt.Sprintf("the node stopped making progress in backend state %q", st.BackendState)
	}

	msg := fmt.Sprintf("%s (waited %s, tailnet backend state %q", head, waited, st.BackendState)
	if len(st.Health) > 0 {
		msg += fmt.Sprintf(", tailnet health: %s", strings.Join(st.Health, "; "))
	}
	return msg + ")"
}

// Close shuts the node down. It is safe to call whether or not Start succeeded,
// and safe to call more than once.
func (n *Node) Close() error {
	n.closeOnce.Do(func() {
		n.mu.Lock()
		started := n.started
		n.mu.Unlock()
		if !started {
			// tsnet.Server.Close tears down subsystems that Start assigns, so
			// closing a server whose Start never succeeded panics rather than
			// reporting an error. Nothing was started, so there is nothing to
			// close.
			return
		}
		n.closeErr = n.srv.Close()
	})
	return n.closeErr
}

// DialContext opens a connection to address over the tailnet, refusing any
// destination the guard cannot place in the tailnet when the guard is enabled.
func (n *Node) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	dialAddress, err := n.authorisedAddress(ctx, address)
	if err != nil {
		return nil, err
	}
	// Invariant: the string that was authorised is the string that gets
	// dialled. The guard matches a normalised host, tsnet's dialer does not
	// normalise at all, and the two disagree on IPv4-mapped IPv6: a route
	// lookup for 10.1.2.3 succeeds where the same lookup for ::ffff:10.1.2.3
	// misses, and a miss is what makes tsdial fall through to a plain dial on
	// the container's own network. Dialling the caller's original spelling
	// would therefore let an approved destination become an unapproved one
	// between the check and the dial.
	return n.srv.Dial(ctx, network, dialAddress)
}

// authorisedAddress runs the destination guard over address and returns the
// address that may be dialled, which is not always the one passed in: the
// guard reports the host in the exact form it approved, and that form is what
// the caller must use. When the guard is disabled the address is returned
// unchanged, because nothing was authorised and so there is nothing to hold
// the dial to.
func (n *Node) authorisedAddress(ctx context.Context, address string) (string, error) {
	if !n.cfg.RequireTailnetDest {
		return address, nil
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", fmt.Errorf("tsnode: dial %q: address must be host:port: %w", address, err)
	}
	g := n.currentGuard()
	if g == nil {
		return "", fmt.Errorf("tsnode: dial %q: the node is not running, so the destination guard cannot verify the target", address)
	}
	ok, approved, why, err := g.Check(ctx, host)
	if err != nil {
		// A guard that cannot answer must not be treated as a "yes": the
		// unverified dial is the one that escapes onto the host network.
		return "", fmt.Errorf("tsnode: dial %q: checking destination: %w", address, err)
	}
	if !ok {
		n.log.Error("refusing dial: destination is not on the tailnet", "address", address, "why", why)
		return "", fmt.Errorf("%w: %s: %s", ErrNotTailnet, address, why)
	}
	dialAddress := net.JoinHostPort(approved, port)
	n.log.Debug("destination allowed", "address", address, "dial_address", dialAddress, "why", why)
	return dialAddress, nil
}

func (n *Node) currentGuard() Guard {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.guard
}

// Listen accepts plaintext connections from the tailnet.
func (n *Node) Listen(network, addr string) (net.Listener, error) {
	return n.srv.Listen(network, addr)
}

// ListenTLS accepts TLS connections terminated with the node's Tailscale-issued
// certificate.
func (n *Node) ListenTLS(network, addr string) (net.Listener, error) {
	return n.srv.ListenTLS(network, addr)
}

// ListenPacket accepts datagrams from the tailnet. addr must name a concrete
// tailnet address: tsnet rejects a wildcard bind for packets.
func (n *Node) ListenPacket(network, addr string) (net.PacketConn, error) {
	return n.srv.ListenPacket(network, addr)
}

// TLSConfig returns a server config that serves the node's Tailscale-issued
// certificate. The certificate is fetched per handshake rather than once,
// because a Tailscale certificate is renewed while the process runs.
func (n *Node) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			lc, err := n.srv.LocalClient()
			if err != nil {
				return nil, err
			}
			return lc.GetCertificate(hi)
		},
	}
}

// TailnetIPs returns this node's own tailnet addresses. Either may be invalid
// if the tailnet does not hand out that family.
func (n *Node) TailnetIPs() (ip4, ip6 netip.Addr) {
	return n.srv.TailscaleIPs()
}

// CertDomains returns the DNS names the control plane will issue certificates
// for. It is empty until the node is up, or when HTTPS is off for the tailnet.
func (n *Node) CertDomains() []string {
	return n.srv.CertDomains()
}

// Running reports nil when the node is up. It never starts the node: the local
// API client is only consulted once Start has succeeded, because asking tsnet
// for one starts the server as a side effect.
func (n *Node) Running(ctx context.Context) error {
	n.mu.Lock()
	lc, started := n.lc, n.started
	n.mu.Unlock()
	if !started || lc == nil {
		return errors.New("tsnode: node has not started")
	}
	st, err := lc.StatusWithoutPeers(ctx)
	if err != nil {
		return fmt.Errorf("tsnode: reading tailnet status: %w", err)
	}
	if st.BackendState != ipn.Running.String() {
		return fmt.Errorf("tsnode: tailnet backend state is %q, want %q", st.BackendState, ipn.Running.String())
	}
	return nil
}

// redactingLogf adapts tsnet's printf-style logging to slog.
//
// The redaction is a backstop, not a theory about tsnet: an auth key that ever
// reaches a log line survives in log storage long after the key is rotated, so
// the value is stripped on the way out regardless of who formatted it.
func redactingLogf(l *slog.Logger, level slog.Level, secret string) logger.Logf {
	return func(format string, args ...any) {
		if !l.Enabled(context.Background(), level) {
			return
		}
		msg := strings.TrimRight(fmt.Sprintf(format, args...), "\n")
		if secret != "" && strings.Contains(msg, secret) {
			msg = strings.ReplaceAll(msg, secret, "[redacted]")
		}
		l.Log(context.Background(), level, msg, "src", "tsnet")
	}
}
