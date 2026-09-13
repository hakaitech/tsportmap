package tsnode

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/hakaitech/tsportmap/internal/config"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func baseConfig() *config.Config {
	return &config.Config{
		Hostname:           "tsportmap",
		StateDir:           "/var/lib/tsportmap",
		RequireTailnetDest: true,
		UpTimeout:          90 * time.Second,
		DialTimeout:        10 * time.Second,
	}
}

func TestNew(t *testing.T) {
	tests := []struct {
		name     string
		cfg      func() *config.Config
		wantErr  []string // substrings the error must contain
		checkSrv func(t *testing.T, n *Node)
	}{
		{
			name:    "nil config",
			cfg:     func() *config.Config { return nil },
			wantErr: []string{"nil config"},
		},
		{
			name: "empty state dir is refused because tsnet would fall back to os.UserConfigDir",
			cfg: func() *config.Config {
				c := baseConfig()
				c.StateDir = ""
				return c
			},
			wantErr: []string{"state directory is empty", "TSPM_STATE_DIR"},
		},
		{
			name: "whitespace state dir is refused",
			cfg: func() *config.Config {
				c := baseConfig()
				c.StateDir = "   "
				return c
			},
			wantErr: []string{"state directory is empty"},
		},
		{
			name: "empty hostname",
			cfg: func() *config.Config {
				c := baseConfig()
				c.Hostname = ""
				return c
			},
			wantErr: []string{"hostname is empty", "TSPM_HOSTNAME"},
		},
		{
			name: "oauth client secret without tags",
			cfg: func() *config.Config {
				c := baseConfig()
				c.AuthKey = "tskey-client-abc123"
				return c
			},
			wantErr: []string{"OAuth client secret requires tags", "TSPM_TAGS"},
		},
		{
			name: "oauth client secret with tags becomes ClientSecret",
			cfg: func() *config.Config {
				c := baseConfig()
				c.AuthKey = "tskey-client-abc123"
				c.Tags = []string{"tag:proxy"}
				return c
			},
			checkSrv: func(t *testing.T, n *Node) {
				if n.srv.ClientSecret != "tskey-client-abc123" {
					t.Errorf("ClientSecret not set from an OAuth secret")
				}
				if n.srv.AuthKey != "" {
					t.Errorf("AuthKey = %q, want empty: an OAuth secret is not an auth key", n.srv.AuthKey)
				}
				if len(n.srv.AdvertiseTags) != 1 || n.srv.AdvertiseTags[0] != "tag:proxy" {
					t.Errorf("AdvertiseTags = %v, want [tag:proxy]", n.srv.AdvertiseTags)
				}
			},
		},
		{
			name: "plain auth key becomes AuthKey",
			cfg: func() *config.Config {
				c := baseConfig()
				c.AuthKey = "tskey-auth-abc123"
				c.Tags = []string{"tag:proxy"}
				return c
			},
			checkSrv: func(t *testing.T, n *Node) {
				if n.srv.AuthKey != "tskey-auth-abc123" {
					t.Errorf("AuthKey = %q, want the supplied key", n.srv.AuthKey)
				}
				if n.srv.ClientSecret != "" {
					t.Errorf("ClientSecret = %q, want empty for a plain auth key", n.srv.ClientSecret)
				}
				if len(n.srv.AdvertiseTags) != 1 {
					t.Errorf("AdvertiseTags = %v, want tags to be advertised for a plain key too", n.srv.AdvertiseTags)
				}
			},
		},
		{
			name: "no auth key at all is allowed: a node with existing state can reuse it",
			cfg:  baseConfig,
			checkSrv: func(t *testing.T, n *Node) {
				if n.srv.Dir != "/var/lib/tsportmap" {
					t.Errorf("Dir = %q, want the configured state dir", n.srv.Dir)
				}
				if n.srv.Hostname != "tsportmap" {
					t.Errorf("Hostname = %q", n.srv.Hostname)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n, err := New(tt.cfg(), quietLogger())
			if len(tt.wantErr) > 0 {
				if err == nil {
					t.Fatalf("New() error = nil, want an error")
				}
				for _, want := range tt.wantErr {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("New() error = %q, want it to contain %q", err, want)
					}
				}
				if n != nil {
					t.Error("New() returned a node alongside an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			if n == nil {
				t.Fatal("New() returned a nil node with no error")
			}
			if tt.checkSrv != nil {
				tt.checkSrv(t, n)
			}
		})
	}
}

// TestNewNilLoggerUsesDefault keeps New usable from a caller that has not built
// a logger yet, rather than panicking on the first log line.
func TestNewNilLoggerUsesDefault(t *testing.T) {
	n, err := New(baseConfig(), nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if n.log == nil {
		t.Fatal("logger is nil")
	}
	n.srv.Logf("hello from tsnet")
}

// TestCloseBeforeStart covers the tsnet defect this package works around:
// tsnet.Server.Close tears down subsystems Start assigns, so closing a server
// that never started panics.
func TestCloseBeforeStart(t *testing.T) {
	n, err := New(baseConfig(), quietLogger())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := n.Close(); err != nil {
		t.Fatalf("Close() before Start error = %v, want nil", err)
	}
	if err := n.Close(); err != nil {
		t.Fatalf("second Close() error = %v, want nil: Close must be idempotent", err)
	}
}

// TestCloseIsIdempotentAfterStart proves the once-guard, without a network: the
// started flag is what Close consults, and the second call must not reach
// tsnet at all.
func TestCloseIsIdempotentAfterStart(t *testing.T) {
	n, err := New(baseConfig(), quietLogger())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	closes := 0
	n.started = true
	n.closeOnce.Do(func() { closes++ })
	if err := n.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if closes != 1 {
		t.Fatalf("close body ran %d times, want exactly 1", closes)
	}
}

func TestRunningBeforeStart(t *testing.T) {
	n, err := New(baseConfig(), quietLogger())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := n.Running(context.Background()); err == nil {
		t.Fatal("Running() = nil before Start; a node that never started is not running")
	}
}

type fakeGuard struct {
	ok   bool
	why  string
	err  error
	last string
}

func (f *fakeGuard) Check(_ context.Context, host string) (bool, string, error) {
	f.last = host
	return f.ok, f.why, f.err
}

func TestDialContextGuard(t *testing.T) {
	tests := []struct {
		name         string
		requireDest  bool
		guard        *fakeGuard
		address      string
		wantErr      []string
		wantSentinel bool
		wantHost     string
	}{
		{
			name:         "refused destination is reported as ErrNotTailnet",
			requireDest:  true,
			guard:        &fakeGuard{ok: false, why: "10.0.1.7 is not a tailnet peer address"},
			address:      "10.0.1.7:5432",
			wantErr:      []string{"10.0.1.7:5432", "not a tailnet peer address"},
			wantSentinel: true,
			wantHost:     "10.0.1.7",
		},
		{
			name:        "guard failure is not reported as ErrNotTailnet",
			requireDest: true,
			guard:       &fakeGuard{err: errors.New("local API down")},
			address:     "db:5432",
			wantErr:     []string{"checking destination", "local API down"},
			wantHost:    "db",
		},
		{
			name:        "address without a port",
			requireDest: true,
			guard:       &fakeGuard{ok: true},
			address:     "db",
			wantErr:     []string{"must be host:port"},
		},
		{
			name:         "ipv6 destination is split before the guard sees it",
			requireDest:  true,
			guard:        &fakeGuard{ok: false, why: "no"},
			address:      "[fd7a:115c:a1e0::2]:443",
			wantErr:      []string{"fd7a:115c:a1e0::2"},
			wantSentinel: true,
			wantHost:     "fd7a:115c:a1e0::2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n, err := New(baseConfig(), quietLogger())
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			n.cfg.RequireTailnetDest = tt.requireDest
			n.guard = tt.guard

			conn, err := n.DialContext(context.Background(), "tcp", tt.address)
			if conn != nil {
				conn.Close()
				t.Fatal("DialContext returned a connection; the guard should have stopped it before any dial")
			}
			if err == nil {
				t.Fatal("DialContext() error = nil, want an error")
			}
			for _, want := range tt.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error = %q, want it to contain %q", err, want)
				}
			}
			if got := errors.Is(err, ErrNotTailnet); got != tt.wantSentinel {
				t.Errorf("errors.Is(err, ErrNotTailnet) = %v, want %v (err: %v)", got, tt.wantSentinel, err)
			}
			if tt.wantHost != "" && tt.guard.last != tt.wantHost {
				t.Errorf("guard saw host %q, want %q", tt.guard.last, tt.wantHost)
			}
		})
	}
}

// TestDialContextWithoutGuard covers the window before Start: with the guard
// required but not yet built, a dial must fail rather than proceed unchecked.
func TestDialContextBeforeStart(t *testing.T) {
	n, err := New(baseConfig(), quietLogger())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	_, err = n.DialContext(context.Background(), "tcp", "db:5432")
	if err == nil {
		t.Fatal("DialContext() = nil error before Start, want a refusal")
	}
	if !strings.Contains(err.Error(), "not running") {
		t.Errorf("error = %q, want it to say the node is not running", err)
	}
	if errors.Is(err, ErrNotTailnet) {
		t.Error("an unstarted node must not report ErrNotTailnet: nothing was checked")
	}
}

func TestDiagnoseUp(t *testing.T) {
	const waited = 90 * time.Second

	tests := []struct {
		name        string
		st          *ipnstate.Status
		statusErr   error
		haveAuthKey bool
		controlURL  string
		want        []string
		notWant     []string
	}{
		{
			name:      "local api unreachable",
			statusErr: errors.New("dial localapi: connection refused"),
			want:      []string{"never reached Running", "local API could not be queried", "connection refused"},
		},
		{
			name: "no auth key supplied",
			st:   &ipnstate.Status{BackendState: ipn.NeedsLogin.String()},
			want: []string{"no auth key was supplied", "TSPM_AUTHKEY", "NeedsLogin"},
		},
		{
			name: "no auth key supplied but control offered a login url",
			st:   &ipnstate.Status{BackendState: ipn.NeedsLogin.String(), AuthURL: "https://login.tailscale.com/a/abc"},
			want: []string{"no auth key was supplied", "interactive login URL"},
			// The URL itself is a credential to attach a node; the message says
			// where to find it rather than reprinting it.
			notWant: []string{"https://login.tailscale.com/a/abc"},
		},
		{
			name:        "auth key rejected",
			st:          &ipnstate.Status{BackendState: ipn.NeedsLogin.String()},
			haveAuthKey: true,
			want:        []string{"auth key was not accepted", "expired", "different tailnet"},
			notWant:     []string{"no auth key was supplied"},
		},
		{
			name:        "waiting on machine authorisation",
			st:          &ipnstate.Status{BackendState: ipn.NeedsMachineAuth.String()},
			haveAuthKey: true,
			want:        []string{"waiting for machine authorisation", "admin console", "NeedsMachineAuth"},
		},
		{
			name:        "logged out",
			st:          &ipnstate.Status{BackendState: ipn.Stopped.String()},
			haveAuthKey: true,
			want:        []string{"logged out or stopped", "Stopped"},
		},
		{
			name:        "cannot reach the coordination server",
			st:          &ipnstate.Status{BackendState: ipn.NoState.String(), Health: []string{"control health: cannot reach control server"}},
			haveAuthKey: true,
			want: []string{
				"could not complete a control connection",
				"Tailscale's coordination server",
				"cannot reach control server",
			},
		},
		{
			name:        "cannot reach a custom control server",
			st:          &ipnstate.Status{BackendState: ipn.Starting.String()},
			haveAuthKey: true,
			controlURL:  "https://headscale.example.com",
			want:        []string{"could not complete a control connection", "https://headscale.example.com", "Starting"},
		},
		{
			name:        "running but the wait failed anyway",
			st:          &ipnstate.Status{BackendState: ipn.Running.String()},
			haveAuthKey: true,
			want:        []string{"reports Running", "Running"},
		},
		{
			name:        "unrecognised state still names the state",
			st:          &ipnstate.Status{BackendState: "Wedged"},
			haveAuthKey: true,
			want:        []string{"Wedged"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := diagnoseUp(tt.st, tt.statusErr, tt.haveAuthKey, tt.controlURL, waited)
			for _, want := range tt.want {
				if !strings.Contains(got, want) {
					t.Errorf("diagnosis = %q, want it to contain %q", got, want)
				}
			}
			for _, notWant := range tt.notWant {
				if strings.Contains(got, notWant) {
					t.Errorf("diagnosis = %q, want it NOT to contain %q", got, notWant)
				}
			}
			if strings.Contains(strings.ToLower(got), "timed out") {
				t.Errorf("diagnosis = %q: a bare timeout is exactly what this message exists to replace", got)
			}
		})
	}
}

// TestRedactingLogf pins the two properties tsnet's log adapter must have: the
// auth key never appears, and a level the handler discards costs nothing.
func TestRedactingLogf(t *testing.T) {
	var buf bytes.Buffer
	l := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	logf := redactingLogf(l, slog.LevelDebug, "tskey-auth-supersecret")
	logf("logging in with %s\n", "tskey-auth-supersecret")

	out := buf.String()
	if strings.Contains(out, "supersecret") {
		t.Errorf("log output contains the auth key: %q", out)
	}
	if !strings.Contains(out, "[redacted]") {
		t.Errorf("log output = %q, want the key replaced with [redacted]", out)
	}
	if strings.Contains(out, "\\n") {
		t.Errorf("log output = %q, want the trailing newline trimmed", out)
	}

	buf.Reset()
	infoOnly := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	redactingLogf(infoOnly, slog.LevelDebug, "")("chatty tsnet line")
	if buf.Len() != 0 {
		t.Errorf("debug line was emitted through an info-level handler: %q", buf.String())
	}
}

func TestIsOAuthSecret(t *testing.T) {
	tests := []struct {
		key  string
		want bool
	}{
		{"tskey-client-abc", true},
		{"tskey-auth-abc", false},
		{"", false},
		{"TSKEY-CLIENT-ABC", false},
	}
	for _, tt := range tests {
		if got := isOAuthSecret(tt.key); got != tt.want {
			t.Errorf("isOAuthSecret(%q) = %v, want %v", tt.key, got, tt.want)
		}
	}
}

type fakePrefs struct {
	edited   *ipn.MaskedPrefs
	editErr  error
	got      *ipn.Prefs
	getErr   error
	getCalls int
}

func (f *fakePrefs) EditPrefs(_ context.Context, mp *ipn.MaskedPrefs) (*ipn.Prefs, error) {
	f.edited = mp
	if f.editErr != nil {
		return nil, f.editErr
	}
	return &ipn.Prefs{RouteAll: mp.RouteAll}, nil
}

func (f *fakePrefs) GetPrefs(context.Context) (*ipn.Prefs, error) {
	f.getCalls++
	return f.got, f.getErr
}

// TestApplyAcceptRoutes covers the pref tsnet discards on every start. The
// read-back is the point: EditPrefs reporting success is not evidence that
// RouteAll is on.
func TestApplyAcceptRoutes(t *testing.T) {
	tests := []struct {
		name    string
		pe      *fakePrefs
		wantErr []string
	}{
		{
			name: "applied and verified",
			pe:   &fakePrefs{got: &ipn.Prefs{RouteAll: true}},
		},
		{
			name:    "edit rejected",
			pe:      &fakePrefs{editErr: errors.New("permission denied")},
			wantErr: []string{"enabling accept-routes", "permission denied"},
		},
		{
			name:    "read back fails",
			pe:      &fakePrefs{getErr: errors.New("local API down")},
			wantErr: []string{"reading back prefs", "local API down"},
		},
		{
			name:    "accepted but not applied",
			pe:      &fakePrefs{got: &ipn.Prefs{RouteAll: false}},
			wantErr: []string{"did not take effect", "RouteAll=true"},
		},
		{
			name:    "backend returns no prefs at all",
			pe:      &fakePrefs{got: nil},
			wantErr: []string{"did not take effect"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := applyAcceptRoutes(context.Background(), tt.pe)
			if len(tt.wantErr) == 0 {
				if err != nil {
					t.Fatalf("applyAcceptRoutes() error = %v", err)
				}
				if tt.pe.getCalls != 1 {
					t.Errorf("GetPrefs called %d times, want 1: the pref must be verified, not assumed", tt.pe.getCalls)
				}
			} else {
				if err == nil {
					t.Fatal("applyAcceptRoutes() error = nil, want an error")
				}
				for _, want := range tt.wantErr {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("error = %q, want it to contain %q", err, want)
					}
				}
			}
			if tt.pe.edited == nil {
				t.Fatal("EditPrefs was never called")
			}
			if !tt.pe.edited.RouteAllSet {
				t.Error("RouteAllSet is false: the mask decides which pref is written, so an unset mask changes nothing")
			}
			if !tt.pe.edited.RouteAll {
				t.Error("RouteAll is false in the edit: accept-routes would be turned off rather than on")
			}
		})
	}
}

func TestUnrecoverableAuthState(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		st   *ipnstate.Status
		want bool
	}{
		{name: "nil status", st: nil, want: false},
		{
			name: "rejected key",
			st: &ipnstate.Status{
				BackendState: ipn.NeedsLogin.String(),
				Health:       []string{"You are logged out. The last login error was: invalid key: API key does not exist"},
			},
			want: true,
		},
		{
			// The node passes through NeedsLogin before it has presented its
			// key. Aborting here would turn a slow start into a failed one.
			name: "needs login while still starting",
			st: &ipnstate.Status{
				BackendState: ipn.NeedsLogin.String(),
				Health:       []string{"Tailscale is starting. Please wait."},
			},
			want: false,
		},
		{
			name: "needs login with no health detail",
			st:   &ipnstate.Status{BackendState: ipn.NeedsLogin.String()},
			want: false,
		},
		{
			name: "awaiting machine authorisation after a login error",
			st: &ipnstate.Status{
				BackendState: ipn.NeedsMachineAuth.String(),
				Health:       []string{"login error: device not approved"},
			},
			want: true,
		},
		{
			// Health noise in a healthy state must never abort the wait.
			name: "running with unrelated health noise",
			st: &ipnstate.Status{
				BackendState: ipn.Running.String(),
				Health:       []string{"invalid key: API key does not exist"},
			},
			want: false,
		},
		{
			name: "starting and unreachable",
			st: &ipnstate.Status{
				BackendState: ipn.Starting.String(),
				Health:       []string{"cannot reach control server"},
			},
			want: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := unrecoverableAuthState(tc.st); got != tc.want {
				t.Errorf("unrecoverableAuthState = %v, want %v", got, tc.want)
			}
		})
	}
}
