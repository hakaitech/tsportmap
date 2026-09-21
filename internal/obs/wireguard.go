package obs

import (
	"bytes"
	"sort"
	"strconv"
	"time"
)

// WireGuardPeer is one peer's state at scrape time.
type WireGuardPeer struct {
	// Interface is the name from the TSPM_WG_<NAME> variable that declared it.
	Interface string
	// Peer is the peer's public key, which is what `wg show` prints and is not
	// a secret. Using it as the label is what lets an operator line a series up
	// against the configuration they wrote.
	Peer string
	// LastHandshake is zero when the peer has never completed one.
	LastHandshake time.Time
	RxBytes       int64
	TxBytes       int64
}

// WireGuardSource reports peer state for exposition. It is consulted at scrape
// time rather than sampled on a timer, so a scrape never reads a value older
// than itself.
type WireGuardSource func() []WireGuardPeer

// SetWireGuard installs the source of WireGuard peer state. A nil source, or no
// call at all, means the WireGuard metric families are omitted entirely rather
// than exposed empty — a node with no WireGuard interface should not publish
// series about one.
func (r *Registry) SetWireGuard(src WireGuardSource) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.wg = src
}

func (r *Registry) wireGuardPeers() []WireGuardPeer {
	r.mu.RLock()
	src := r.wg
	r.mu.RUnlock()
	if src == nil {
		return nil
	}
	peers := src()
	// Sorted for the same reason every other family is: a diff of two scrapes
	// should show what changed, not what happened to be iterated first.
	sort.Slice(peers, func(i, j int) bool {
		if peers[i].Interface != peers[j].Interface {
			return peers[i].Interface < peers[j].Interface
		}
		return peers[i].Peer < peers[j].Peer
	})
	return peers
}

const (
	metricWGHandshake = "tsportmap_wg_peer_last_handshake_seconds"
	metricWGBytes     = "tsportmap_wg_peer_bytes_total"
)

// writeWireGuard renders the WireGuard families, if there are any.
//
// The handshake timestamp is the metric that matters here and it is the only
// signal of its kind the process has. A WireGuard interface has no connect step
// and no liveness of its own: a peer with a wrong key, an unreachable endpoint
// or a firewall in the way is indistinguishable from a peer that is merely idle
// until something tries to use it. Readiness therefore cannot wait on a
// handshake — an idle tunnel would fail it forever — so the age of the last
// handshake is published instead and an operator alerts on it against their own
// knowledge of whether that tunnel should be carrying traffic.
//
// Zero means "never", which is why the timestamp is exposed rather than an age:
// an age would have to invent a value for a peer that has never handshaken, and
// any value it invented would be indistinguishable from a real one.
func (r *Registry) writeWireGuard(b *bytes.Buffer) {
	peers := r.wireGuardPeers()
	if len(peers) == 0 {
		return
	}

	writeHeader(b, metricWGHandshake, "gauge",
		"Unix time of a WireGuard peer's last completed handshake; 0 means it has never completed one, which is also the normal state of an idle tunnel.")
	for _, p := range peers {
		var secs int64
		if !p.LastHandshake.IsZero() {
			secs = p.LastHandshake.Unix()
		}
		writeSample(b, metricWGHandshake, wgLabels(p), strconv.FormatInt(secs, 10))
	}

	writeHeader(b, metricWGBytes, "counter",
		"Bytes carried over a WireGuard tunnel, by interface, peer and direction: rx is from the peer, tx is to the peer.")
	for _, p := range peers {
		writeSample(b, metricWGBytes, append(wgLabels(p), labelPair{"direction", "rx"}), strconv.FormatInt(p.RxBytes, 10))
		writeSample(b, metricWGBytes, append(wgLabels(p), labelPair{"direction", "tx"}), strconv.FormatInt(p.TxBytes, 10))
	}
}

// wgLabels returns a fresh slice each call, because the caller appends a third
// label to it and a shared backing array would let the rx sample's append
// overwrite what the tx sample's append wrote.
func wgLabels(p WireGuardPeer) []labelPair {
	return []labelPair{{"interface", p.Interface}, {"peer", p.Peer}}
}
