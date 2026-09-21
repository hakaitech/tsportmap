package obs

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func render(t *testing.T, r *Registry) string {
	t.Helper()
	var b bytes.Buffer
	if err := r.WritePrometheus(&b); err != nil {
		t.Fatalf("writing metrics: %v", err)
	}
	return b.String()
}

// A node with no WireGuard interface must expose no WireGuard series at all,
// not empty ones: the exposition of a tailnet-only node should be what it was
// before WireGuard existed.
func TestWireGuardFamiliesAbsentWithoutASource(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	r.SessionOpened("DB")

	out := render(t, r)
	if strings.Contains(out, "tsportmap_wg_") {
		t.Errorf("a node with no WireGuard interface exposes WireGuard metrics:\n%s", out)
	}

	// An installed-but-empty source is the same case: an interface that reports
	// no peers should not mint a family either.
	r.SetWireGuard(func() []WireGuardPeer { return nil })
	if out := render(t, r); strings.Contains(out, "tsportmap_wg_") {
		t.Errorf("a source reporting no peers still exposes WireGuard metrics:\n%s", out)
	}
}

func TestWireGuardFamilies(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	// Deliberately out of order, to prove the exposition sorts.
	r.SetWireGuard(func() []WireGuardPeer {
		return []WireGuardPeer{
			{Interface: "vpn", Peer: "zzz", LastHandshake: time.Unix(1700000200, 0), RxBytes: 5, TxBytes: 6},
			{Interface: "home", Peer: "bbb", RxBytes: 3, TxBytes: 4},
			{Interface: "home", Peer: "aaa", LastHandshake: time.Unix(1700000000, 0), RxBytes: 1, TxBytes: 2},
		}
	})

	out := render(t, r)
	want := []string{
		`tsportmap_wg_peer_last_handshake_seconds{interface="home",peer="aaa"} 1700000000`,
		// Never handshaken reports 0 rather than being omitted: the series has
		// to exist for an alert to fire on it.
		`tsportmap_wg_peer_last_handshake_seconds{interface="home",peer="bbb"} 0`,
		`tsportmap_wg_peer_last_handshake_seconds{interface="vpn",peer="zzz"} 1700000200`,
		`tsportmap_wg_peer_bytes_total{interface="home",peer="aaa",direction="rx"} 1`,
		`tsportmap_wg_peer_bytes_total{interface="home",peer="aaa",direction="tx"} 2`,
		`tsportmap_wg_peer_bytes_total{interface="vpn",peer="zzz",direction="rx"} 5`,
		`tsportmap_wg_peer_bytes_total{interface="vpn",peer="zzz",direction="tx"} 6`,
	}
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("the exposition is missing %q:\n%s", w, out)
		}
	}

	// Sorted by interface then peer, whatever order the source reported.
	if i, j := strings.Index(out, `interface="home",peer="aaa"`), strings.Index(out, `interface="home",peer="bbb"`); i > j {
		t.Error("peers are not sorted within an interface")
	}
	if i, j := strings.Index(out, `interface="home"`), strings.Index(out, `interface="vpn"`); i > j {
		t.Error("interfaces are not sorted")
	}
}

// The rx and tx samples each append a third label to a shared two-label slice.
// A shared backing array would let one append overwrite the other's label.
func TestWireGuardByteLabelsDoNotClobberEachOther(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	r.SetWireGuard(func() []WireGuardPeer {
		return []WireGuardPeer{{Interface: "home", Peer: "aaa", RxBytes: 1, TxBytes: 2}}
	})
	out := render(t, r)
	if strings.Count(out, `direction="rx"`) != 1 || strings.Count(out, `direction="tx"`) != 1 {
		t.Errorf("the two byte samples do not carry one direction each:\n%s", out)
	}
}

// no_route joins the closed reason set; it must not collapse into "other".
func TestNoRouteIsItsOwnReason(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	r.DialFailed("DB", ReasonNoRoute)

	out := render(t, r)
	if !strings.Contains(out, `tsportmap_dial_failures_total{mapping="DB",reason="no_route"} 1`) {
		t.Errorf("no_route did not get its own series:\n%s", out)
	}
	if strings.Contains(out, `reason="other"`) {
		t.Errorf("no_route collapsed into other:\n%s", out)
	}
}
