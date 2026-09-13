package tsnode

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"strings"

	"tailscale.com/client/local"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/tsaddr"
)

// fallthroughWarning is the second half of every refusal. It is spelled out in
// full on purpose: the failure it describes is silent everywhere else, so the
// log line is the only place an operator ever learns about it.
const fallthroughWarning = "dialling it would NOT use the tailnet - tsnet falls through to a plain dial on the container's own network, " +
	"which on a private RFC1918 network reaches whatever neighbouring service happens to answer, with no error"

// tailnetState is the narrow slice of *local.Client that the destination guard
// needs. Keeping it narrow is what makes the decision logic testable: a real
// tailnet cannot be joined from a unit test, but a status snapshot can be
// written by hand.
type tailnetState interface {
	Status(ctx context.Context) (*ipnstate.Status, error)
	GetPrefs(ctx context.Context) (*ipn.Prefs, error)
}

type guard struct {
	state tailnetState
	log   *slog.Logger
}

// NewGuard returns a Guard that answers from the node's own netmap, as reported
// by the local API.
func NewGuard(lc *local.Client, logger *slog.Logger) Guard {
	return newGuard(lc, logger)
}

func newGuard(state tailnetState, logger *slog.Logger) *guard {
	if logger == nil {
		logger = slog.Default()
	}
	return &guard{state: state, log: logger}
}

// Check implements Guard.
//
// Both the netmap and the prefs are read on every call rather than cached: a
// peer can be added, removed or re-addressed at any moment, and a stale "yes"
// is precisely the wrong answer to cache. The queries go to the in-process
// local API, so they cost far less than the connection setup that follows.
func (g *guard) Check(ctx context.Context, host string) (bool, string, string, error) {
	st, err := g.state.Status(ctx)
	if err != nil {
		return false, "", "", fmt.Errorf("reading tailnet status: %w", err)
	}
	prefs, err := g.state.GetPrefs(ctx)
	if err != nil {
		return false, "", "", fmt.Errorf("reading tailnet prefs: %w", err)
	}
	routeAll := prefs != nil && prefs.RouteAll
	ok, approved, why := checkDest(st, routeAll, host)
	g.log.Debug("destination guard decision", "host", host, "approved", approved, "allowed", ok, "why", why)
	return ok, approved, why, nil
}

// checkDest is the whole decision, as a pure function of a netmap snapshot.
//
// acceptRoutes must be the node's live RouteAll pref, not the configured one:
// a subnet route only carries traffic once this node has accepted it, and
// status reports routes the control plane approved for a peer whether or not
// this node uses them.
//
// It returns the host in the form the verdict was actually reached on, so a
// caller can dial exactly what was authorised. The rewrites are not cosmetic:
// unmapping ::ffff:10.1.2.3 to 10.1.2.3 is what lets it match a subnet route
// at all, and a dialer handed the mapped spelling would look it up as a
// different, unmatched address.
func checkDest(st *ipnstate.Status, acceptRoutes bool, host string) (ok bool, approved string, why string) {
	h := normaliseHost(host)
	if h == "" {
		return false, h, "the destination host is empty, so it cannot be matched against any tailnet peer"
	}
	if st == nil {
		return false, h, fmt.Sprintf("no tailnet status is available, so %q cannot be shown to be a tailnet peer; %s", h, fallthroughWarning)
	}
	if ip, err := netip.ParseAddr(h); err == nil {
		ip = ip.Unmap()
		allowed, reason := checkAddr(st, acceptRoutes, ip)
		return allowed, ip.String(), reason
	}
	allowed, reason := checkName(st, h)
	return allowed, h, reason
}

// normaliseHost reduces a host as written in a mapping to the form the netmap
// uses: no brackets, no trailing dot, lower case. DNS names are
// case-insensitive and a fully-qualified name may legitimately be written with
// the root dot, so neither difference may change the verdict.
func normaliseHost(host string) string {
	h := strings.TrimSpace(host)
	h = strings.TrimPrefix(h, "[")
	h = strings.TrimSuffix(h, "]")
	for strings.HasSuffix(h, ".") {
		h = strings.TrimSuffix(h, ".")
	}
	return strings.ToLower(h)
}

func checkAddr(st *ipnstate.Status, acceptRoutes bool, ip netip.Addr) (bool, string) {
	if st.Self != nil && containsAddr(st.Self.TailscaleIPs, ip) {
		return true, fmt.Sprintf("%s is this node's own tailnet address", ip)
	}
	if containsAddr(st.TailscaleIPs, ip) {
		return true, fmt.Sprintf("%s is this node's own tailnet address", ip)
	}
	for _, p := range sortedPeers(st) {
		if containsAddr(p.TailscaleIPs, ip) {
			return true, fmt.Sprintf("%s is the tailnet address of peer %s%s", ip, peerLabel(p), offlineNote(p))
		}
	}
	if pfx, owner, found := findRoute(st, ip); found {
		if acceptRoutes {
			return true, fmt.Sprintf("%s is inside subnet route %s advertised by peer %s, which this node accepts", ip, pfx, peerLabel(owner))
		}
		return false, fmt.Sprintf("%s is inside subnet route %s advertised by peer %s, but this node has not accepted subnet routes "+
			"(set TSPM_ACCEPT_ROUTES=true to use it); %s", ip, pfx, peerLabel(owner), fallthroughWarning)
	}
	if tsaddr.IsTailscaleIP(ip) {
		return false, fmt.Sprintf("%s is in Tailscale's address range but belongs to no peer in this node's netmap - the address is stale, "+
			"or that peer is not shared with this node; %s", ip, fallthroughWarning)
	}
	return false, fmt.Sprintf("%s is not a tailnet peer address and is not inside any subnet route this node has accepted; %s", ip, fallthroughWarning)
}

func checkName(st *ipnstate.Status, name string) (bool, string) {
	if st.Self != nil {
		if fqdn := normaliseHost(st.Self.DNSName); fqdn != "" && (fqdn == name || firstLabel(fqdn) == name) {
			return true, fmt.Sprintf("%q is this node's own MagicDNS name", name)
		}
	}
	// A fully-qualified match is tried across every peer before any short name,
	// so an FQDN always resolves to the peer that actually owns it even when an
	// unrelated peer in another tailnet shares its first label.
	peers := sortedPeers(st)
	for _, p := range peers {
		if fqdn := normaliseHost(p.DNSName); fqdn != "" && fqdn == name {
			return true, fmt.Sprintf("%q is the MagicDNS name of peer %s%s", name, peerLabel(p), offlineNote(p))
		}
	}
	for _, p := range peers {
		if short := firstLabel(normaliseHost(p.DNSName)); short != "" && short == name {
			return true, fmt.Sprintf("%q is the MagicDNS short name of peer %s%s", name, peerLabel(p), offlineNote(p))
		}
	}
	// PeerStatus.HostName is deliberately not consulted: it is the machine's
	// self-reported hostname, is not a DNS name, and is not unique in a tailnet.
	return false, fmt.Sprintf("%q matches no peer in this node's netmap. The tailnet peer set is the only name source consulted: "+
		"a name that only the container's resolver knows is exactly the case this check exists to refuse, because %s", name, fallthroughWarning)
}

// findRoute returns the most specific subnet route covering ip, if any peer
// advertises one.
//
// Exit-node routes are ignored. A default route says nothing about whether a
// destination is a tailnet destination - accepting it would make every address
// on the internet, and every address on the container's own network, look like
// a tailnet peer - and tsnet only sends traffic to an exit node when one is
// explicitly selected.
func findRoute(st *ipnstate.Status, ip netip.Addr) (netip.Prefix, *ipnstate.PeerStatus, bool) {
	var (
		best      netip.Prefix
		bestPeer  *ipnstate.PeerStatus
		bestFound bool
	)
	consider := func(p *ipnstate.PeerStatus, pfx netip.Prefix) {
		if tsaddr.IsExitRoute(pfx) || !pfx.Contains(ip) {
			return
		}
		// A peer's own addresses arrive as single-IP prefixes in AllowedIPs;
		// those are peer addresses, handled before routes are considered.
		if pfx.IsSingleIP() && containsAddr(p.TailscaleIPs, pfx.Addr()) {
			return
		}
		if !bestFound || pfx.Bits() > best.Bits() {
			best, bestPeer, bestFound = pfx, p, true
		}
	}
	for _, p := range sortedPeers(st) {
		if p.AllowedIPs != nil {
			for _, pfx := range p.AllowedIPs.All() {
				consider(p, pfx)
			}
		}
		if p.PrimaryRoutes != nil {
			for _, pfx := range p.PrimaryRoutes.All() {
				consider(p, pfx)
			}
		}
	}
	return best, bestPeer, bestFound
}

func containsAddr(addrs []netip.Addr, ip netip.Addr) bool {
	for _, a := range addrs {
		if a.Unmap() == ip {
			return true
		}
	}
	return false
}

// sortedPeers returns the peers in a stable order. Status keys peers by public
// key in a map, and an unstable iteration order would make the "why" string -
// which operators read and compare across runs - vary between identical dials.
func sortedPeers(st *ipnstate.Status) []*ipnstate.PeerStatus {
	peers := make([]*ipnstate.PeerStatus, 0, len(st.Peer))
	for _, p := range st.Peer {
		if p != nil {
			peers = append(peers, p)
		}
	}
	sort.Slice(peers, func(i, j int) bool {
		li, lj := normaliseHost(peers[i].DNSName), normaliseHost(peers[j].DNSName)
		if li != lj {
			return li < lj
		}
		return string(peers[i].ID) < string(peers[j].ID)
	})
	return peers
}

func peerLabel(p *ipnstate.PeerStatus) string {
	if p == nil {
		return "(unknown)"
	}
	if fqdn := normaliseHost(p.DNSName); fqdn != "" {
		return fqdn
	}
	if p.HostName != "" {
		return p.HostName
	}
	if p.ID != "" {
		return string(p.ID)
	}
	return "(unnamed peer)"
}

// offlineNote flags a peer that control believes is disconnected. Such a peer
// is still a tailnet destination, so the dial is allowed: it will fail loudly
// rather than reach the wrong host, which is the outcome this guard protects.
func offlineNote(p *ipnstate.PeerStatus) string {
	if p != nil && !p.Online {
		return " (peer is currently offline)"
	}
	return ""
}

func firstLabel(name string) string {
	if i := strings.Index(name, "."); i >= 0 {
		return name[:i]
	}
	return name
}
