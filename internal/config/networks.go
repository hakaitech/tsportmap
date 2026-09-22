package config

import (
	"cmp"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
)

// parseVia reads a via=<network> option.
//
// The spellings are deliberately few and exact. "ts" is the tailnet, "local" is
// the container's own network, and "wg:<name>" is one of the declared WireGuard
// interfaces. There is no spelling that means "whichever of these can reach it":
// a mapping that could fall back from one network to another would reintroduce,
// at the level of whole networks, precisely the silent-wrong-destination
// failure that the tailnet destination guard exists to close.
func parseVia(varName, v string) (Network, error) {
	raw := strings.ToLower(strings.TrimSpace(v))
	if raw == "" {
		return Network{}, fmt.Errorf("%s: via is empty; write %s, %s, or %s:<name> naming a %s<NAME> interface",
			varName, NetTailnet, NetLocal, NetWireGuard, EnvPrefixWG)
	}

	kind, name, hasName := strings.Cut(raw, ":")
	switch NetworkKind(kind) {
	case NetTailnet:
		if hasName {
			return Network{}, fmt.Errorf("%s: via=%q takes no name; the tailnet is written as via=%s", varName, v, NetTailnet)
		}
		return Network{Kind: NetTailnet}, nil
	case NetLocal:
		if hasName {
			return Network{}, fmt.Errorf("%s: via=%q takes no name; the container's own network is written as via=%s", varName, v, NetLocal)
		}
		return Network{Kind: NetLocal}, nil
	case NetWireGuard:
		if !hasName || name == "" {
			return Network{}, fmt.Errorf("%s: via=%q does not name an interface; write via=%s:<name> matching a %s<NAME> variable",
				varName, v, NetWireGuard, EnvPrefixWG)
		}
		return Network{Kind: NetWireGuard, Name: name}, nil
	default:
		return Network{}, fmt.Errorf("%s: via=%q is not a network; use %s (the tailnet), %s:<name> (a %s<NAME> interface), or %s (the container's own network)",
			varName, v, NetTailnet, NetWireGuard, EnvPrefixWG, NetLocal)
	}
}

// wgInterfaces finds every TSPM_WG_* variable and parses the wg-quick
// configuration it holds, sorted by name so that startup order, log order and
// error order are the same from one run to the next.
//
// A value may be the configuration itself or "file:/path" naming a file holding
// it. The file form is strongly preferred and is what the documentation shows:
// the text contains a private key, and an inline value puts that key in
// /proc/<pid>/environ, in `docker inspect`, and on a platform's environment
// dashboard.
func (e env) wgInterfaces() ([]WGInterface, error) {
	var vars []string
	for k := range e {
		if strings.HasPrefix(k, EnvPrefixWG) {
			vars = append(vars, k)
		}
	}
	slices.Sort(vars)

	var out []WGInterface
	seen := make(map[string]string, len(vars)) // lowercased name -> variable
	for _, k := range vars {
		name := strings.TrimPrefix(k, EnvPrefixWG)
		if name == "" {
			return nil, fmt.Errorf("%s: interface name is empty; the variable must be %s<NAME>", k, EnvPrefixWG)
		}
		// via=wg:<name> is matched case-insensitively, so two interfaces whose
		// names differ only in case would be indistinguishable to a mapping.
		lower := strings.ToLower(name)
		if other, dup := seen[lower]; dup {
			return nil, fmt.Errorf("%s: interface name %q duplicates %s; names must be unique and are compared case-insensitively because via=%s:<name> is",
				k, name, other, NetWireGuard)
		}
		seen[lower] = k

		text, err := wgConfigText(k, e[k])
		if err != nil {
			return nil, err
		}
		iface, err := parseWGQuick(k, name, text)
		if err != nil {
			return nil, err
		}
		if err := checkWGInterface(k, iface); err != nil {
			return nil, err
		}
		out = append(out, iface)
	}

	slices.SortFunc(out, func(a, b WGInterface) int {
		if n := cmp.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)); n != 0 {
			return n
		}
		return cmp.Compare(a.Name, b.Name)
	})
	return out, nil
}

// wgConfigText resolves the variable's value to the configuration text,
// following a "file:" prefix.
//
// No error here ever quotes the contents, only the path: the contents are a
// private key.
func wgConfigText(varName, v string) (string, error) {
	if strings.TrimSpace(v) == "" {
		// Blanking, rather than deleting, is how a dashboard-driven platform
		// removes a row. For a scalar that means "the default", but an
		// interface has no default, and an empty one would take every mapping
		// that names it down with a message about the mapping instead.
		return "", fmt.Errorf("%s: the value is empty. An interface is removed by deleting its variable, not by blanking it; "+
			"set it to file:/path/to/wg0.conf or to the configuration itself", varName)
	}
	path, isFile := strings.CutPrefix(v, "file:")
	if !isFile {
		return v, nil
	}
	if path == "" {
		return "", fmt.Errorf(`%s: "file:" prefix with no path after it`, varName)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		var pe *fs.PathError
		if errors.As(err, &pe) {
			err = pe.Err
		}
		return "", fmt.Errorf("%s: cannot read the WireGuard configuration %q: %w", varName, path, err)
	}
	if strings.TrimSpace(string(b)) == "" {
		return "", fmt.Errorf("%s: the WireGuard configuration %q is empty", varName, path)
	}
	return string(b), nil
}

// checkWGInterface reports the problems that are visible in one interface on
// its own, as opposed to those that only appear once mappings are read.
func checkWGInterface(varName string, iface WGInterface) error {
	// Two peers claiming one prefix is not something WireGuard resolves for
	// you: the later peer wins the route and the earlier one silently stops
	// receiving anything sent to it, which reads as one peer being down.
	claimed := make(map[netip.Prefix]string, len(iface.Peers))
	for _, p := range iface.Peers {
		for _, a := range p.AllowedIPs {
			if other, dup := claimed[a]; dup {
				return fmt.Errorf("%s: peers %s and %s both list %s in AllowedIPs; WireGuard routes a destination to exactly one peer, "+
					"so one of them would silently stop receiving traffic sent there", varName, other, p.PublicKey, a)
			}
			claimed[a] = p.PublicKey
		}
	}
	// A peer with no endpoint can only ever be reached after it has initiated,
	// which is a legitimate configuration for a road-warrior peer dialling in
	// and a broken one for the peer an egress mapping dials out to. The
	// distinction needs the mappings, so it is made in checkNetworks; here the
	// interface only has to have some way of being used at all.
	var reachable bool
	for _, p := range iface.Peers {
		if p.Endpoint != "" {
			reachable = true
		}
	}
	if !reachable && iface.ListenPort == 0 {
		return fmt.Errorf("%s: no peer has an Endpoint and the interface has no ListenPort, so nothing can ever establish a tunnel: "+
			"this interface cannot dial out (no endpoint to dial) and cannot be dialled in to (no fixed port to reach). "+
			"Give a peer an Endpoint, or set ListenPort so peers can reach this one", varName)
	}
	return nil
}

// checkNetworks reports conflicts between mappings and the networks they name.
//
// These checks exist for the same reason --validate does: every one of them
// describes a configuration that parses cleanly and then fails at a point where
// the error names a symptom rather than the setting at fault. A mapping naming
// an interface that does not exist fails at bind time as a nil dereference or a
// missing-network error; a WireGuard target written as a name fails on the
// first connection, in production, having started clean.
func checkNetworks(decls []declared, wg []WGInterface) error {
	byName := make(map[string]WGInterface, len(wg))
	for _, w := range wg {
		byName[strings.ToLower(w.Name)] = w
	}

	used := make(map[string]bool, len(wg))
	for _, d := range decls {
		via := d.m.Via
		if via.Kind != NetWireGuard {
			continue
		}
		iface, ok := byName[via.Name]
		if !ok {
			return fmt.Errorf("%s: via=%s names a WireGuard interface that is not declared; "+
				"add %s%s, or point the mapping at one of the interfaces that is declared (%s)",
				d.env, via, EnvPrefixWG, strings.ToUpper(via.Name), declaredList(wg))
		}
		used[via.Name] = true

		if err := checkWGMapping(d, iface); err != nil {
			return err
		}
	}

	// An interface nobody uses is brought up, claims a UDP socket and handshakes
	// with its peers for nothing. More to the point, it is almost always a
	// mapping that was meant to name it and does not — a typo in via= that the
	// check above cannot catch when the typo is in the interface's variable
	// instead of in the mapping's.
	for _, w := range wg {
		if !used[strings.ToLower(w.Name)] {
			return fmt.Errorf("%s%s declares a WireGuard interface that no mapping uses; "+
				"add via=%s:%s to the mapping that should go over it, or remove the interface",
				EnvPrefixWG, w.Name, NetWireGuard, strings.ToLower(w.Name))
		}
	}
	return nil
}

// checkWGMapping reports the problems of one mapping against the interface it
// names.
func checkWGMapping(d declared, iface WGInterface) error {
	m := d.m

	if m.Dir == Out {
		// A WireGuard tunnel has no resolver of its own. Resolving the target
		// on the container's resolver instead would answer with whatever that
		// network calls the name — which is the neighbouring-service failure the
		// tailnet guard exists to prevent, except that here there is no netmap
		// to check the answer against afterwards. So it is refused at the one
		// point where the error can name the setting: startup.
		host, _, err := net.SplitHostPort(m.Target)
		if err != nil {
			return fmt.Errorf("%s: target %q is not host:port", d.env, m.Target)
		}
		ip, err := netip.ParseAddr(strings.Trim(host, "[]"))
		if err != nil {
			return fmt.Errorf("%s: target host %q is a name, and a mapping using via=%s must name its destination by address. "+
				"A WireGuard tunnel carries no resolver, so the name would be resolved on the container's own network and answer with whatever that network calls it — "+
				"a different host from the one inside the tunnel, reached with no error. Write the address the peer holds inside the tunnel",
				d.env, host, m.Via)
		}
		ip = ip.Unmap()

		// The destination must be inside some peer's AllowedIPs, which is the
		// same check the dialer makes at run time. Making it here as well is
		// what turns "this connection times out" into "this mapping was never
		// going to work", at a point where the whole configuration is visible.
		peer, ok := peerFor(iface, ip)
		if !ok {
			return fmt.Errorf("%s: target %s is not covered by any AllowedIPs on interface %s (%s), so the tunnel has no peer to send it to "+
				"and the packet would be dropped with nothing to report it. Add the address to the AllowedIPs of the peer that holds it",
				d.env, ip, iface.Name, allowedIPsList(iface))
		}
		if peer.Endpoint == "" {
			return fmt.Errorf("%s: target %s is routed to peer %s on interface %s, but that peer has no Endpoint, so this node cannot open the tunnel to it. "+
				"An egress mapping needs a peer it can dial; give the peer an Endpoint, or use this interface only for ingress",
				d.env, ip, peer.PublicKey, iface.Name)
		}
		return nil
	}

	// Ingress: the listener lives on the interface's own stack, so it can only
	// bind an address the interface actually holds. A wildcard is fine and means
	// all of them.
	host, _, err := net.SplitHostPort(m.Listen)
	if err != nil {
		return fmt.Errorf("%s: listen %q is not host:port", d.env, m.Listen)
	}
	if host == "" {
		return nil
	}
	ip, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return fmt.Errorf("%s: listen host %q is a name, and an %q mapping using via=%s binds an address of the interface itself. "+
			"Write one of %s, or leave the host off to bind all of them",
			d.env, host, In, m.Via, addressList(iface))
	}
	ip = ip.Unmap()
	if ip.IsUnspecified() {
		return nil
	}
	for _, a := range iface.Addresses {
		if a.Addr().Unmap() == ip {
			return nil
		}
	}
	return fmt.Errorf("%s: listen address %s is not one of interface %s's own addresses (%s), so the bind would fail. "+
		"An ingress mapping listens on the interface's stack, which holds only the addresses its [Interface] Address line gives it",
		d.env, ip, iface.Name, addressList(iface))
}

func peerFor(iface WGInterface, ip netip.Addr) (WGPeer, bool) {
	var (
		best  WGPeer
		bits  = -1
		found bool
	)
	for _, p := range iface.Peers {
		for _, a := range p.AllowedIPs {
			if a.Contains(ip) && a.Bits() > bits {
				best, bits, found = p, a.Bits(), true
			}
		}
	}
	return best, found
}

func allowedIPsList(iface WGInterface) string {
	var parts []string
	for _, p := range iface.Peers {
		for _, a := range p.AllowedIPs {
			parts = append(parts, a.String())
		}
	}
	slices.Sort(parts)
	return strings.Join(slices.Compact(parts), ", ")
}

func addressList(iface WGInterface) string {
	parts := make([]string, len(iface.Addresses))
	for i, a := range iface.Addresses {
		parts[i] = a.Addr().String()
	}
	return strings.Join(parts, ", ")
}

func declaredList(wg []WGInterface) string {
	if len(wg) == 0 {
		return "none are"
	}
	parts := make([]string, len(wg))
	for i, w := range wg {
		parts[i] = NetWireGuard.String() + ":" + strings.ToLower(w.Name)
	}
	return strings.Join(parts, ", ")
}

// String lets a NetworkKind be written into a message without a conversion at
// every call site.
func (k NetworkKind) String() string { return string(k) }
