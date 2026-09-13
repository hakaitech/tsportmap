package tsnode

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/key"
	"tailscale.com/types/ptr"
	"tailscale.com/types/views"
)

func addrs(t *testing.T, ss ...string) []netip.Addr {
	t.Helper()
	out := make([]netip.Addr, 0, len(ss))
	for _, s := range ss {
		a, err := netip.ParseAddr(s)
		if err != nil {
			t.Fatalf("bad test address %q: %v", s, err)
		}
		out = append(out, a)
	}
	return out
}

func prefixes(t *testing.T, ss ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			t.Fatalf("bad test prefix %q: %v", s, err)
		}
		out = append(out, p)
	}
	return out
}

// testPeer builds a peer as the local API would report it: DNSName carries the
// trailing dot, and AllowedIPs holds the peer's own addresses alongside any
// subnet routes control has approved for it.
func testPeer(t *testing.T, dnsName string, online bool, ips []netip.Addr, routes []netip.Prefix) *ipnstate.PeerStatus {
	t.Helper()
	allowed := make([]netip.Prefix, 0, len(ips)+len(routes))
	for _, ip := range ips {
		allowed = append(allowed, netip.PrefixFrom(ip, ip.BitLen()))
	}
	allowed = append(allowed, routes...)
	return &ipnstate.PeerStatus{
		HostName:     strings.Split(dnsName, ".")[0],
		DNSName:      dnsName,
		TailscaleIPs: ips,
		AllowedIPs:   ptr.To(views.SliceOf(allowed)),
		Online:       online,
	}
}

func statusOf(t *testing.T, self *ipnstate.PeerStatus, peers ...*ipnstate.PeerStatus) *ipnstate.Status {
	t.Helper()
	st := &ipnstate.Status{
		BackendState: ipn.Running.String(),
		Self:         self,
		Peer:         map[key.NodePublic]*ipnstate.PeerStatus{},
	}
	if self != nil {
		st.TailscaleIPs = self.TailscaleIPs
	}
	for _, p := range peers {
		st.Peer[key.NewNode().Public()] = p
	}
	return st
}

func TestCheckDest(t *testing.T) {
	selfIPs := addrs(t, "100.64.0.1", "fd7a:115c:a1e0::1")
	self := testPeer(t, "proxy.example-tailnet.ts.net.", true, selfIPs, nil)

	db := testPeer(t, "db.example-tailnet.ts.net.", true, addrs(t, "100.64.0.2", "fd7a:115c:a1e0::2"), nil)
	offline := testPeer(t, "backup.example-tailnet.ts.net.", false, addrs(t, "100.64.0.3"), nil)
	// A subnet router that advertises both a wide and a narrow route, plus an
	// exit-node default route.
	router := testPeer(t, "router.example-tailnet.ts.net.", true, addrs(t, "100.64.0.4"),
		prefixes(t, "192.168.0.0/16", "192.168.7.0/24", "0.0.0.0/0", "::/0"))

	full := statusOf(t, self, db, offline, router)

	tests := []struct {
		name         string
		st           *ipnstate.Status
		acceptRoutes bool
		host         string
		wantOK       bool
		wantWhy      []string // substrings the explanation must contain
	}{
		{
			name: "peer short magicdns name", st: full, host: "db", wantOK: true,
			wantWhy: []string{"short name", "db.example-tailnet.ts.net"},
		},
		{
			name: "peer fqdn", st: full, host: "db.example-tailnet.ts.net", wantOK: true,
			wantWhy: []string{"MagicDNS name of peer"},
		},
		{
			name: "peer fqdn with trailing dot", st: full, host: "db.example-tailnet.ts.net.", wantOK: true,
			wantWhy: []string{"MagicDNS name of peer"},
		},
		{
			name: "peer name is case insensitive", st: full, host: "DB.Example-Tailnet.TS.NET", wantOK: true,
			wantWhy: []string{"MagicDNS name of peer"},
		},
		{
			name: "peer short name upper case", st: full, host: "DB", wantOK: true,
			wantWhy: []string{"short name"},
		},
		{
			name: "peer tailnet ipv4", st: full, host: "100.64.0.2", wantOK: true,
			wantWhy: []string{"tailnet address of peer", "db.example-tailnet.ts.net"},
		},
		{
			name: "peer tailnet ipv6", st: full, host: "fd7a:115c:a1e0::2", wantOK: true,
			wantWhy: []string{"tailnet address of peer"},
		},
		{
			name: "bracketed ipv6 literal", st: full, host: "[fd7a:115c:a1e0::2]", wantOK: true,
			wantWhy: []string{"tailnet address of peer"},
		},
		{
			name: "own address", st: full, host: "100.64.0.1", wantOK: true,
			wantWhy: []string{"own tailnet address"},
		},
		{
			name: "own magicdns name", st: full, host: "proxy", wantOK: true,
			wantWhy: []string{"own MagicDNS name"},
		},
		{
			name: "offline peer is still a tailnet destination", st: full, host: "backup", wantOK: true,
			wantWhy: []string{"currently offline"},
		},
		{
			name: "accepted subnet route", st: full, acceptRoutes: true, host: "192.168.7.9", wantOK: true,
			wantWhy: []string{"subnet route", "192.168.7.0/24", "router.example-tailnet.ts.net"},
		},
		{
			name: "advertised route but routes not accepted", st: full, acceptRoutes: false, host: "192.168.7.9", wantOK: false,
			wantWhy: []string{"has not accepted subnet routes", "TSPM_ACCEPT_ROUTES", "container's own network"},
		},
		{
			name: "exit node default route does not make the internet a tailnet destination",
			st:   full, acceptRoutes: true, host: "1.1.1.1", wantOK: false,
			wantWhy: []string{"not a tailnet peer address", "container's own network"},
		},
		{
			name: "cgnat address with no peer is refused", st: full, acceptRoutes: true, host: "100.64.9.9", wantOK: false,
			wantWhy: []string{"Tailscale's address range but belongs to no peer", "container's own network"},
		},
		{
			name: "tailscale ula with no peer is refused", st: full, acceptRoutes: true, host: "fd7a:115c:a1e0::99", wantOK: false,
			wantWhy: []string{"belongs to no peer"},
		},
		{
			name: "private rfc1918 address with no accepted route is refused",
			st:   full, acceptRoutes: true, host: "10.0.1.7", wantOK: false,
			wantWhy: []string{"not a tailnet peer address", "is not inside any subnet route this node has accepted", "container's own network"},
		},
		{
			name: "unknown name is refused without consulting the host resolver",
			st:   full, acceptRoutes: true, host: "postgres.internal", wantOK: false,
			wantWhy: []string{"matches no peer", "only the container's resolver knows"},
		},
		{
			name: "name that only looks like a peer is refused", st: full, host: "db.other-tailnet.ts.net", wantOK: false,
			wantWhy: []string{"matches no peer"},
		},
		{
			name: "empty host", st: full, host: "", wantOK: false,
			wantWhy: []string{"empty"},
		},
		{
			name: "whitespace host", st: full, host: "   ", wantOK: false,
			wantWhy: []string{"empty"},
		},
		{
			name: "nil status refuses rather than assuming", st: nil, host: "db", wantOK: false,
			wantWhy: []string{"no tailnet status", "container's own network"},
		},
		{
			name: "status with no peers refuses", st: statusOf(t, self), host: "db", wantOK: false,
			wantWhy: []string{"matches no peer"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, approved, why := checkDest(tt.st, tt.acceptRoutes, tt.host)
			if ok != tt.wantOK {
				t.Fatalf("checkDest(%q) = %v, want %v (why: %s)", tt.host, ok, tt.wantOK, why)
			}
			for _, want := range tt.wantWhy {
				if !strings.Contains(why, want) {
					t.Errorf("why = %q, want it to contain %q", why, want)
				}
			}
			if why == "" {
				t.Error("why must never be empty: it is the only explanation an operator gets")
			}
			if ok && approved == "" {
				t.Error("an allowed destination must report the host it was allowed as: the caller dials that string, not the one it passed in")
			}
		})
	}
}

// TestCheckDestFQDNBeatsShortName pins the precedence rule: a fully-qualified
// destination must resolve to the peer that owns that name even when another
// peer shares its first label.
func TestCheckDestFQDNBeatsShortName(t *testing.T) {
	a := testPeer(t, "cache.aaa-tailnet.ts.net.", true, addrs(t, "100.64.0.10"), nil)
	b := testPeer(t, "cache.zzz-tailnet.ts.net.", true, addrs(t, "100.64.0.11"), nil)
	st := statusOf(t, nil, a, b)

	ok, _, why := checkDest(st, false, "cache.zzz-tailnet.ts.net")
	if !ok {
		t.Fatalf("checkDest refused a known FQDN: %s", why)
	}
	if !strings.Contains(why, "cache.zzz-tailnet.ts.net") || strings.Contains(why, "aaa") {
		t.Errorf("why = %q, want it to name the peer owning the FQDN", why)
	}
}

// TestCheckDestPrefersMostSpecificRoute keeps the explanation honest about
// which route actually covers the destination.
func TestCheckDestPrefersMostSpecificRoute(t *testing.T) {
	wide := testPeer(t, "wide.example-tailnet.ts.net.", true, addrs(t, "100.64.0.20"), prefixes(t, "10.0.0.0/8"))
	narrow := testPeer(t, "narrow.example-tailnet.ts.net.", true, addrs(t, "100.64.0.21"), prefixes(t, "10.1.2.0/24"))
	st := statusOf(t, nil, wide, narrow)

	ok, _, why := checkDest(st, true, "10.1.2.3")
	if !ok {
		t.Fatalf("checkDest refused an address inside an accepted route: %s", why)
	}
	if !strings.Contains(why, "10.1.2.0/24") {
		t.Errorf("why = %q, want the most specific route 10.1.2.0/24", why)
	}
}

// TestCheckDestPrimaryRoutes covers a peer whose routes arrive only as
// PrimaryRoutes.
func TestCheckDestPrimaryRoutes(t *testing.T) {
	p := testPeer(t, "router.example-tailnet.ts.net.", true, addrs(t, "100.64.0.30"), nil)
	p.PrimaryRoutes = ptr.To(views.SliceOf(prefixes(t, "172.20.0.0/16")))
	st := statusOf(t, nil, p)

	if ok, _, why := checkDest(st, true, "172.20.5.5"); !ok {
		t.Errorf("checkDest refused a primary-route destination: %s", why)
	}
	if ok, _, _ := checkDest(st, false, "172.20.5.5"); ok {
		t.Error("checkDest allowed a subnet route while accept-routes is off")
	}
}

type fakeState struct {
	st       *ipnstate.Status
	stErr    error
	prefs    *ipn.Prefs
	prefsErr error
}

func (f fakeState) Status(context.Context) (*ipnstate.Status, error) { return f.st, f.stErr }
func (f fakeState) GetPrefs(context.Context) (*ipn.Prefs, error)     { return f.prefs, f.prefsErr }

func TestGuardCheck(t *testing.T) {
	peer := testPeer(t, "db.example-tailnet.ts.net.", true, addrs(t, "100.64.0.2"), prefixes(t, "192.168.0.0/24"))
	st := statusOf(t, nil, peer)
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))

	tests := []struct {
		name    string
		state   fakeState
		host    string
		wantOK  bool
		wantErr bool
	}{
		{
			name:   "route allowed when the live prefs accept routes",
			state:  fakeState{st: st, prefs: &ipn.Prefs{RouteAll: true}},
			host:   "192.168.0.5",
			wantOK: true,
		},
		{
			name:   "route refused when the live prefs do not accept routes",
			state:  fakeState{st: st, prefs: &ipn.Prefs{RouteAll: false}},
			host:   "192.168.0.5",
			wantOK: false,
		},
		{
			name:   "nil prefs is treated as routes not accepted",
			state:  fakeState{st: st, prefs: nil},
			host:   "192.168.0.5",
			wantOK: false,
		},
		{
			name:   "peer still allowed",
			state:  fakeState{st: st, prefs: &ipn.Prefs{}},
			host:   "db",
			wantOK: true,
		},
		{
			name:    "status failure is an error, never an allow",
			state:   fakeState{stErr: errors.New("local API down"), prefs: &ipn.Prefs{}},
			host:    "db",
			wantErr: true,
		},
		{
			name:    "prefs failure is an error, never an allow",
			state:   fakeState{st: st, prefsErr: errors.New("local API down")},
			host:    "db",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := newGuard(tt.state, quiet)
			ok, _, why, err := g.Check(context.Background(), tt.host)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Check() error = nil, want an error (ok=%v why=%q)", ok, why)
				}
				if ok {
					t.Error("Check() reported ok alongside an error; an unanswerable check must never allow a dial")
				}
				return
			}
			if err != nil {
				t.Fatalf("Check() error = %v", err)
			}
			if ok != tt.wantOK {
				t.Fatalf("Check() = %v, want %v (why: %s)", ok, tt.wantOK, why)
			}
		})
	}
}

func TestNormaliseHost(t *testing.T) {
	tests := []struct{ in, want string }{
		{"db", "db"},
		{"DB.Example.TS.NET.", "db.example.ts.net"},
		{"  db.example.ts.net  ", "db.example.ts.net"},
		{"[fd7a:115c:a1e0::2]", "fd7a:115c:a1e0::2"},
		{"db..", "db"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := normaliseHost(tt.in); got != tt.want {
			t.Errorf("normaliseHost(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestCheckDestReportsUnmappedAddress covers the mismatch that made the guard
// bypassable: it accepts an IPv4-mapped IPv6 destination by matching the IPv4
// address inside it, so the form it approves has to be that IPv4 address.
// tsnet's dialer does no unmapping of its own - a route lookup for
// ::ffff:10.1.2.3 misses where 10.1.2.3 hits - so handing the caller back the
// mapped spelling would have it dial an address the guard never matched.
func TestCheckDestReportsUnmappedAddress(t *testing.T) {
	router := testPeer(t, "router.example-tailnet.ts.net.", true, addrs(t, "100.64.0.21"), prefixes(t, "10.1.2.0/24"))
	st := statusOf(t, nil, router)

	ok, approved, why := checkDest(st, true, "::ffff:10.1.2.3")
	if !ok {
		t.Fatalf("checkDest refused an IPv4-mapped address inside an accepted route: %s", why)
	}
	if approved != "10.1.2.3" {
		t.Errorf("approved = %q, want %q: the approved form must be the one the route was matched against", approved, "10.1.2.3")
	}
}

// TestGuardCheckReportsApprovedHost pins the same guarantee at the Guard
// boundary, which is the only part of it the dialler can see.
func TestGuardCheckReportsApprovedHost(t *testing.T) {
	peer := testPeer(t, "DB.Example-Tailnet.TS.NET.", true, addrs(t, "100.64.0.2", "fd7a:115c:a1e0::2"), prefixes(t, "192.168.0.0/24"))
	st := statusOf(t, nil, peer)
	g := newGuard(fakeState{st: st, prefs: &ipn.Prefs{RouteAll: true}}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	tests := []struct{ host, want string }{
		{"::ffff:192.168.0.5", "192.168.0.5"},
		{"::ffff:100.64.0.2", "100.64.0.2"},
		{"[fd7a:115c:a1e0::2]", "fd7a:115c:a1e0::2"},
		{"DB.Example-Tailnet.TS.NET.", "db.example-tailnet.ts.net"},
	}
	for _, tt := range tests {
		ok, approved, why, err := g.Check(context.Background(), tt.host)
		if err != nil {
			t.Fatalf("Check(%q) error = %v", tt.host, err)
		}
		if !ok {
			t.Fatalf("Check(%q) refused a destination it should allow: %s", tt.host, why)
		}
		if approved != tt.want {
			t.Errorf("Check(%q) approved = %q, want %q", tt.host, approved, tt.want)
		}
	}
}
