package config

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// wgKeyLen is the length of a Curve25519 key in bytes. Both WireGuard key types
// — private, public — and the optional preshared key are all this size.
const wgKeyLen = 32

// wgQuickUnsupported are the wg-quick directives that exist to drive a kernel
// interface: they run shell commands, set routing tables, or twiddle an
// interface that this implementation does not have.
//
// Every one of them is a startup error rather than an ignored line. An operator
// pasting a working wg-quick config here is entitled to know that the PostUp
// hook which installs their routes, or the Table setting that keeps traffic off
// the default route, is not going to run — silently dropping it would produce
// an interface that comes up looking correct and carries traffic nowhere near
// where the config says it should.
var wgQuickUnsupported = map[string]string{
	"preup":      "runs a shell command; tsportmap has no interface to prepare and executes nothing",
	"postup":     "runs a shell command; tsportmap has no interface to configure and executes nothing",
	"predown":    "runs a shell command; tsportmap has no interface to tear down and executes nothing",
	"postdown":   "runs a shell command; tsportmap has no interface to tear down and executes nothing",
	"table":      "selects a kernel routing table; this interface has no kernel presence and no routes outside its own stack",
	"fwmark":     "marks packets for kernel policy routing, which does not apply to a userspace socket",
	"saveconfig": "asks wg-quick to rewrite the file; configuration here is read once at startup and never written",
}

// parseWGQuick reads the wg-quick INI format into a WGInterface.
//
// The format is not reinvented here on purpose. Every WireGuard deployment
// already has a .conf file — from `wg genkey`, from a provider's download
// button, from an existing wg-quick unit — and an operator who has one should
// be able to point tsportmap at it unchanged rather than transliterating it
// into a bespoke grammar and getting one field wrong.
//
// varName names the variable that supplied the text so that every error points
// at something an operator can edit.
func parseWGQuick(varName, name, text string) (WGInterface, error) {
	iface := WGInterface{Name: name, MTU: DefaultWGMTU}

	var (
		section     string
		sawIface    bool
		listenPort  = -1
		mtu         = -1
		peer        WGPeer
		inPeer      bool
		peerSeen    map[string]bool
		ifaceSeen   = map[string]bool{}
		peerKeySeen = map[string]string{} // public key -> where it was first declared
	)

	flushPeer := func(at string) error {
		if !inPeer {
			return nil
		}
		if peer.PublicKey == "" {
			return fmt.Errorf("%s: the [Peer] section %s has no PublicKey; WireGuard cannot address a peer without one", varName, at)
		}
		if len(peer.AllowedIPs) == 0 {
			return fmt.Errorf("%s: peer %s has no AllowedIPs; WireGuard has no route to a peer without them, so the peer would never receive a packet",
				varName, peer.PublicKey)
		}
		if where, dup := peerKeySeen[peer.PublicKey]; dup {
			return fmt.Errorf("%s: peer %s is declared twice (%s and %s); WireGuard identifies a peer by its public key, so the second declaration would replace the first",
				varName, peer.PublicKey, where, at)
		}
		peerKeySeen[peer.PublicKey] = at
		iface.Peers = append(iface.Peers, peer)
		peer, inPeer = WGPeer{}, false
		return nil
	}

	for n, rawLine := range strings.Split(text, "\n") {
		lineNo := n + 1
		at := fmt.Sprintf("at line %d", lineNo)
		line := strings.TrimSpace(strings.TrimSuffix(rawLine, "\r"))
		// wg-quick treats both # and ; as comment introducers, and only at the
		// start of a line: a value may legitimately contain either.
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") {
				return WGInterface{}, fmt.Errorf("%s: line %d: section header %q is missing its closing bracket", varName, lineNo, line)
			}
			if err := flushPeer(at); err != nil {
				return WGInterface{}, err
			}
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			switch section {
			case "interface":
				if sawIface {
					return WGInterface{}, fmt.Errorf("%s: line %d: a second [Interface] section; one interface has exactly one", varName, lineNo)
				}
				sawIface = true
			case "peer":
				inPeer, peer, peerSeen = true, WGPeer{}, map[string]bool{}
			default:
				return WGInterface{}, fmt.Errorf("%s: line %d: unknown section [%s]; a WireGuard configuration has [Interface] and [Peer] sections", varName, lineNo, section)
			}
			continue
		}

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return WGInterface{}, fmt.Errorf("%s: line %d: %q is not <Key> = <Value>", varName, lineNo, line)
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)

		if why, bad := wgQuickUnsupported[key]; bad {
			return WGInterface{}, fmt.Errorf("%s: line %d: %s is not supported: it %s. "+
				"Remove the line once you have confirmed nothing depends on it; leaving it in place would give you an interface that starts and does not do what the file says",
				varName, lineNo, key, why)
		}

		switch section {
		case "interface":
			if ifaceSeen[key] {
				return WGInterface{}, fmt.Errorf("%s: line %d: [Interface] %s is set more than once", varName, lineNo, key)
			}
			ifaceSeen[key] = true
			switch key {
			case "privatekey":
				k, err := parseWGKey(value)
				if err != nil {
					// The value is a private key, so it is described and never
					// quoted, here or anywhere else.
					return WGInterface{}, fmt.Errorf("%s: line %d: [Interface] PrivateKey is not a WireGuard key: %s", varName, lineNo, err)
				}
				iface.PrivateKey = k
			case "address":
				addrs, err := parseWGPrefixList(value, true)
				if err != nil {
					return WGInterface{}, fmt.Errorf("%s: line %d: [Interface] Address: %s", varName, lineNo, err)
				}
				iface.Addresses = addrs
			case "listenport":
				p, err := strconv.Atoi(value)
				if err != nil || p < 0 || p > 65535 {
					return WGInterface{}, fmt.Errorf("%s: line %d: [Interface] ListenPort %q is not a port from 0 to 65535 (0 means let the kernel choose)", varName, lineNo, value)
				}
				listenPort = p
			case "mtu":
				m, err := strconv.Atoi(value)
				if err != nil {
					return WGInterface{}, fmt.Errorf("%s: line %d: [Interface] MTU %q is not a number", varName, lineNo, value)
				}
				if m < MinWGMTU || m > MaxWGMTU {
					return WGInterface{}, fmt.Errorf("%s: line %d: [Interface] MTU %d is outside %d-%d; %d is the smallest MTU that can carry an IPv6 packet and %d the largest jumbo frame",
						varName, lineNo, m, MinWGMTU, MaxWGMTU, MinWGMTU, MaxWGMTU)
				}
				mtu = m
			case "dns":
				// Accepted and ignored on purpose, and only because refusing it
				// would reject the unedited file a provider hands out. There is
				// no resolver inside the tunnel to point at it, and tsportmap
				// requires a literal target for a WireGuard mapping precisely so
				// that the absence of one can never be papered over by the
				// container's own resolver answering for a tunnel-side name.
				continue
			default:
				return WGInterface{}, fmt.Errorf("%s: line %d: unknown [Interface] key %q; tsportmap reads PrivateKey, Address, ListenPort and MTU", varName, lineNo, key)
			}

		case "peer":
			if peerSeen[key] {
				return WGInterface{}, fmt.Errorf("%s: line %d: [Peer] %s is set more than once for this peer", varName, lineNo, key)
			}
			peerSeen[key] = true
			switch key {
			case "publickey":
				k, err := parseWGKey(value)
				if err != nil {
					return WGInterface{}, fmt.Errorf("%s: line %d: [Peer] PublicKey %q is not a WireGuard key: %s", varName, lineNo, value, err)
				}
				peer.PublicKey = k
			case "presharedkey":
				k, err := parseWGKey(value)
				if err != nil {
					return WGInterface{}, fmt.Errorf("%s: line %d: [Peer] PresharedKey is not a WireGuard key: %s", varName, lineNo, err)
				}
				peer.PresharedKey = k
			case "allowedips":
				ips, err := parseWGPrefixList(value, false)
				if err != nil {
					return WGInterface{}, fmt.Errorf("%s: line %d: [Peer] AllowedIPs: %s", varName, lineNo, err)
				}
				peer.AllowedIPs = ips
			case "endpoint":
				ep, err := parseWGEndpoint(value)
				if err != nil {
					return WGInterface{}, fmt.Errorf("%s: line %d: [Peer] Endpoint %q: %s", varName, lineNo, value, err)
				}
				peer.Endpoint = ep
			case "persistentkeepalive":
				secs, err := strconv.Atoi(value)
				if err != nil || secs < 0 || secs > 65535 {
					return WGInterface{}, fmt.Errorf("%s: line %d: [Peer] PersistentKeepalive %q is not a number of seconds from 0 to 65535 (0 is off)", varName, lineNo, value)
				}
				peer.Keepalive = time.Duration(secs) * time.Second
			default:
				return WGInterface{}, fmt.Errorf("%s: line %d: unknown [Peer] key %q; tsportmap reads PublicKey, PresharedKey, AllowedIPs, Endpoint and PersistentKeepalive", varName, lineNo, key)
			}

		default:
			return WGInterface{}, fmt.Errorf("%s: line %d: %q appears before any [Interface] or [Peer] section", varName, lineNo, line)
		}
	}

	if err := flushPeer("at end of file"); err != nil {
		return WGInterface{}, err
	}

	if !sawIface {
		return WGInterface{}, fmt.Errorf("%s: there is no [Interface] section; a WireGuard configuration starts with one", varName)
	}
	if iface.PrivateKey == "" {
		return WGInterface{}, fmt.Errorf("%s: [Interface] has no PrivateKey; the interface has no identity without one", varName)
	}
	if len(iface.Addresses) == 0 {
		return WGInterface{}, fmt.Errorf("%s: [Interface] has no Address; the interface has no address inside the tunnel to send from or listen on", varName)
	}
	if len(iface.Peers) == 0 {
		return WGInterface{}, fmt.Errorf("%s: there are no [Peer] sections; an interface with no peer can reach nothing", varName)
	}
	if listenPort >= 0 {
		iface.ListenPort = listenPort
	}
	if mtu > 0 {
		iface.MTU = mtu
	}
	return iface, nil
}

// parseWGKey accepts a key in the standard base64 spelling and returns it
// canonicalised, so that two spellings of one key compare equal.
//
// The error text never repeats the input: this runs on private and preshared
// keys as well as public ones, and a parser that quotes what it was given is
// how a secret ends up in a log an operator pastes into an issue.
func parseWGKey(v string) (string, error) {
	if v == "" {
		return "", fmt.Errorf("the value is empty")
	}
	b, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return "", fmt.Errorf("it is not valid base64 (a WireGuard key is 44 base64 characters, as `wg genkey` prints)")
	}
	if len(b) != wgKeyLen {
		return "", fmt.Errorf("it decodes to %d bytes, but a WireGuard key is %d", len(b), wgKeyLen)
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// parseWGPrefixList reads a comma-separated list of CIDRs.
//
// hostBits distinguishes the two lists that look alike and mean different
// things. An Address is one address plus the prefix length of the subnet it
// sits in, so 10.8.0.2/24 is correct and its host bits are the point. An
// AllowedIPs entry is a route, so host bits set inside it — 10.8.0.2/24 where
// 10.8.0.0/24 was meant — is a mistake that WireGuard itself would mask away
// silently, leaving a route wider than the one that was written.
func parseWGPrefixList(v string, hostBits bool) ([]netip.Prefix, error) {
	if v == "" {
		return nil, fmt.Errorf("the value is empty")
	}
	var out []netip.Prefix
	for _, raw := range strings.Split(v, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			// A bare address is a common and unambiguous abbreviation: wg
			// itself accepts it and means the single host.
			if addr, aerr := netip.ParseAddr(raw); aerr == nil {
				p = netip.PrefixFrom(addr, addr.BitLen())
			} else {
				return nil, fmt.Errorf("%q is not a CIDR or an address", raw)
			}
		}
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits())
		if !hostBits && p.Addr() != p.Masked().Addr() {
			return nil, fmt.Errorf("%q has bits set below its prefix length; write the network (%s) if that is what you meant, or /%d for the single address",
				raw, p.Masked(), p.Addr().BitLen())
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("the list is empty")
	}
	return out, nil
}

// parseWGEndpoint validates a peer's endpoint on the container's own network.
//
// The host may be a name. That is not the hole the tunnel-side rule closes: an
// endpoint is reached outside the tunnel, on the same network and with the same
// resolver as any other process here, so a name is exactly as meaningful as it
// is for any other outbound connection.
func parseWGEndpoint(v string) (string, error) {
	host, port, err := net.SplitHostPort(v)
	if err != nil {
		return "", fmt.Errorf("it is not host:port (bracket an IPv6 address, e.g. [2001:db8::1]:51820)")
	}
	if host == "" {
		return "", fmt.Errorf("it has no host")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("port %q is not a number from 1 to 65535", port)
	}
	return v, nil
}
