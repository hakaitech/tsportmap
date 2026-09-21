package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Two valid, distinct keys. They are only ever compared and re-encoded here, so
// any 32 bytes of base64 will do; these are fixed so a failure message is the
// same from one run to the next.
const (
	keyA = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEE="
	keyB = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAUE="
	keyC = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAkE="
)

// wgConf is a minimal working interface reaching one peer at 10.8.0.0/24.
const wgConf = `
[Interface]
PrivateKey = ` + keyA + `
Address = 10.8.0.2/24
ListenPort = 51820

[Peer]
PublicKey = ` + keyB + `
AllowedIPs = 10.8.0.0/24
Endpoint = vpn.example.com:51820
PersistentKeepalive = 25
`

func TestParseWGQuick(t *testing.T) {
	t.Parallel()
	got, err := parseWGQuick("TSPM_WG_HOME", "HOME", wgConf)
	if err != nil {
		t.Fatalf("parsing a valid configuration: %v", err)
	}
	if got.Name != "HOME" {
		t.Errorf("name is %q, want %q", got.Name, "HOME")
	}
	if got.PrivateKey != keyA {
		t.Error("the private key was not carried through")
	}
	if len(got.Addresses) != 1 || got.Addresses[0].String() != "10.8.0.2/24" {
		t.Errorf("addresses are %v, want [10.8.0.2/24]", got.Addresses)
	}
	if got.ListenPort != 51820 {
		t.Errorf("listen port is %d, want 51820", got.ListenPort)
	}
	if got.MTU != DefaultWGMTU {
		t.Errorf("mtu is %d, want the default %d", got.MTU, DefaultWGMTU)
	}
	if len(got.Peers) != 1 {
		t.Fatalf("got %d peers, want 1", len(got.Peers))
	}
	p := got.Peers[0]
	if p.PublicKey != keyB {
		t.Error("the peer's public key was not carried through")
	}
	if p.Endpoint != "vpn.example.com:51820" {
		t.Errorf("endpoint is %q", p.Endpoint)
	}
	if p.Keepalive != 25*time.Second {
		t.Errorf("keepalive is %s, want 25s", p.Keepalive)
	}
	if len(p.AllowedIPs) != 1 || p.AllowedIPs[0].String() != "10.8.0.0/24" {
		t.Errorf("allowed IPs are %v", p.AllowedIPs)
	}
}

func TestParseWGQuickAcceptsRealWorldSpellings(t *testing.T) {
	t.Parallel()
	conf := `
# A provider's file, comments and all
; both comment characters are used in the wild
[interface]
privatekey=` + keyA + `
address = 10.8.0.2/24, fd00:8::2/64
mtu=1380
DNS = 10.8.0.1

[PEER]
PublicKey = ` + keyB + `
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = [2001:db8::1]:51820
`
	got, err := parseWGQuick("TSPM_WG_VPN", "VPN", conf)
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	if len(got.Addresses) != 2 {
		t.Errorf("got %d addresses, want 2", len(got.Addresses))
	}
	if got.MTU != 1380 {
		t.Errorf("mtu is %d, want 1380", got.MTU)
	}
	if len(got.Peers[0].AllowedIPs) != 2 {
		t.Errorf("got %d allowed IPs, want 2", len(got.Peers[0].AllowedIPs))
	}
	if got.Peers[0].Endpoint != "[2001:db8::1]:51820" {
		t.Errorf("endpoint is %q", got.Peers[0].Endpoint)
	}
	// ListenPort is absent, which is correct for a client that only dials out.
	if got.ListenPort != 0 {
		t.Errorf("listen port is %d, want 0", got.ListenPort)
	}
}

func TestParseWGQuickErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		conf string
		want []string
	}{{
		name: "no interface section",
		conf: "[Peer]\nPublicKey = " + keyB + "\nAllowedIPs = 10.8.0.0/24\n",
		want: []string{"no [Interface] section"},
	}, {
		name: "no private key",
		conf: "[Interface]\nAddress = 10.8.0.2/24\n[Peer]\nPublicKey = " + keyB + "\nAllowedIPs = 10.8.0.0/24\n",
		want: []string{"no PrivateKey"},
	}, {
		name: "no address",
		conf: "[Interface]\nPrivateKey = " + keyA + "\n[Peer]\nPublicKey = " + keyB + "\nAllowedIPs = 10.8.0.0/24\n",
		want: []string{"no Address"},
	}, {
		name: "no peers",
		conf: "[Interface]\nPrivateKey = " + keyA + "\nAddress = 10.8.0.2/24\n",
		want: []string{"no [Peer] sections"},
	}, {
		name: "peer without allowed ips",
		conf: "[Interface]\nPrivateKey = " + keyA + "\nAddress = 10.8.0.2/24\n[Peer]\nPublicKey = " + keyB + "\n",
		want: []string{"no AllowedIPs"},
	}, {
		name: "peer without public key",
		conf: "[Interface]\nPrivateKey = " + keyA + "\nAddress = 10.8.0.2/24\n[Peer]\nAllowedIPs = 10.8.0.0/24\n",
		want: []string{"no PublicKey"},
	}, {
		name: "postup is refused rather than ignored",
		conf: "[Interface]\nPrivateKey = " + keyA + "\nAddress = 10.8.0.2/24\nPostUp = iptables -A FORWARD -j ACCEPT\n[Peer]\nPublicKey = " + keyB + "\nAllowedIPs = 10.8.0.0/24\n",
		want: []string{"postup", "not supported", "executes nothing"},
	}, {
		name: "table is refused rather than ignored",
		conf: "[Interface]\nPrivateKey = " + keyA + "\nAddress = 10.8.0.2/24\nTable = off\n[Peer]\nPublicKey = " + keyB + "\nAllowedIPs = 10.8.0.0/24\n",
		want: []string{"table", "not supported"},
	}, {
		name: "unknown interface key",
		conf: "[Interface]\nPrivateKey = " + keyA + "\nAddress = 10.8.0.2/24\nWibble = 3\n[Peer]\nPublicKey = " + keyB + "\nAllowedIPs = 10.8.0.0/24\n",
		want: []string{"unknown [Interface] key", "wibble"},
	}, {
		name: "unknown peer key",
		conf: "[Interface]\nPrivateKey = " + keyA + "\nAddress = 10.8.0.2/24\n[Peer]\nPublicKey = " + keyB + "\nAllowedIPs = 10.8.0.0/24\nWibble = 3\n",
		want: []string{"unknown [Peer] key"},
	}, {
		name: "bad key length",
		conf: "[Interface]\nPrivateKey = " + keyA + "\nAddress = 10.8.0.2/24\n[Peer]\nPublicKey = AAAA\nAllowedIPs = 10.8.0.0/24\n",
		want: []string{"PublicKey", "32"},
	}, {
		name: "allowed ips with host bits set",
		conf: "[Interface]\nPrivateKey = " + keyA + "\nAddress = 10.8.0.2/24\n[Peer]\nPublicKey = " + keyB + "\nAllowedIPs = 10.8.0.2/24\n",
		want: []string{"bits set below its prefix length", "10.8.0.0/24"},
	}, {
		name: "mtu out of range",
		conf: "[Interface]\nPrivateKey = " + keyA + "\nAddress = 10.8.0.2/24\nMTU = 14200\n[Peer]\nPublicKey = " + keyB + "\nAllowedIPs = 10.8.0.0/24\n",
		want: []string{"MTU", "outside"},
	}, {
		name: "two peers with the same key",
		conf: "[Interface]\nPrivateKey = " + keyA + "\nAddress = 10.8.0.2/24\n" +
			"[Peer]\nPublicKey = " + keyB + "\nAllowedIPs = 10.8.0.0/24\n" +
			"[Peer]\nPublicKey = " + keyB + "\nAllowedIPs = 10.9.0.0/24\n",
		want: []string{"declared twice"},
	}, {
		name: "duplicate key in one section",
		conf: "[Interface]\nPrivateKey = " + keyA + "\nAddress = 10.8.0.2/24\nAddress = 10.9.0.2/24\n[Peer]\nPublicKey = " + keyB + "\nAllowedIPs = 10.8.0.0/24\n",
		want: []string{"set more than once"},
	}, {
		name: "line before any section",
		conf: "PrivateKey = " + keyA + "\n[Interface]\nAddress = 10.8.0.2/24\n",
		want: []string{"before any [Interface] or [Peer] section"},
	}, {
		name: "bad endpoint",
		conf: "[Interface]\nPrivateKey = " + keyA + "\nAddress = 10.8.0.2/24\n[Peer]\nPublicKey = " + keyB + "\nAllowedIPs = 10.8.0.0/24\nEndpoint = vpn.example.com\n",
		want: []string{"Endpoint", "host:port"},
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := parseWGQuick("TSPM_WG_X", "X", tc.conf)
			if err == nil {
				t.Fatalf("got no error, want one mentioning %v", tc.want)
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q does not mention %q", err, w)
				}
			}
		})
	}
}

// A private key must never appear in an error, because errors are logged and a
// log outlives the rotation meant to retire the key.
func TestParseWGQuickNeverQuotesASecret(t *testing.T) {
	t.Parallel()
	const secret = "not-a-key-but-secret-looking"
	for _, field := range []string{"PrivateKey", "PresharedKey"} {
		conf := "[Interface]\nPrivateKey = " + keyA + "\nAddress = 10.8.0.2/24\n[Peer]\nPublicKey = " + keyB + "\nAllowedIPs = 10.8.0.0/24\n"
		if field == "PrivateKey" {
			conf = "[Interface]\nPrivateKey = " + secret + "\nAddress = 10.8.0.2/24\n[Peer]\nPublicKey = " + keyB + "\nAllowedIPs = 10.8.0.0/24\n"
		} else {
			conf += "PresharedKey = " + secret + "\n"
		}
		_, err := parseWGQuick("TSPM_WG_X", "X", conf)
		if err == nil {
			t.Fatalf("%s: got no error", field)
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("%s: the error quotes the value: %v", field, err)
		}
	}
}

func TestParseVia(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want Network
		err  string
	}{
		{in: "ts", want: Network{Kind: NetTailnet}},
		{in: "TS", want: Network{Kind: NetTailnet}},
		{in: "local", want: Network{Kind: NetLocal}},
		{in: "wg:home", want: Network{Kind: NetWireGuard, Name: "home"}},
		{in: "WG:HOME", want: Network{Kind: NetWireGuard, Name: "home"}},
		{in: "", err: "via is empty"},
		{in: "wg", err: "does not name an interface"},
		{in: "wg:", err: "does not name an interface"},
		{in: "ts:foo", err: "takes no name"},
		{in: "local:foo", err: "takes no name"},
		{in: "tailscale", err: "is not a network"},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			got, err := parseVia("TSPM_OUT_X", tc.in)
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("got (%v, %v), want an error mentioning %q", got, err, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestFromEnvWithWireGuard(t *testing.T) {
	t.Parallel()
	cfg, err := FromEnv([]string{
		"TSPM_WG_HOME=" + wgConf,
		"TSPM_OUT_DB=tcp,0.0.0.0:5432,10.8.0.5:5432,via=wg:home",
		"TSPM_IN_APP=tcp,10.8.0.2:8080,127.0.0.1:9000,via=wg:home",
		"TSPM_OUT_CACHE=tcp,0.0.0.0:6379,cache-1:6379",
		"TSPM_OUT_ECHO=tcp,0.0.0.0:7000,127.0.0.1:7001,via=local",
	})
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	if len(cfg.WG) != 1 || cfg.WG[0].Name != "HOME" {
		t.Fatalf("got interfaces %+v, want one named HOME", cfg.WG)
	}
	want := map[string]Network{
		"DB":    {Kind: NetWireGuard, Name: "home"},
		"APP":   {Kind: NetWireGuard, Name: "home"},
		"CACHE": {Kind: NetTailnet},
		"ECHO":  {Kind: NetLocal},
	}
	for _, m := range cfg.Maps {
		if got := m.Via; got != want[m.Name] {
			t.Errorf("mapping %s: via is %+v, want %+v", m.Name, got, want[m.Name])
		}
	}
}

func TestFromEnvWireGuardFromFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "wg0.conf")
	if err := os.WriteFile(path, []byte(wgConf), 0o600); err != nil {
		t.Fatalf("writing the config: %v", err)
	}
	cfg, err := FromEnv([]string{
		"TSPM_WG_HOME=file:" + path,
		"TSPM_OUT_DB=tcp,0.0.0.0:5432,10.8.0.5:5432,via=wg:home",
	})
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	if len(cfg.WG) != 1 || cfg.WG[0].PrivateKey != keyA {
		t.Fatalf("the interface was not read from the file: %+v", cfg.WG)
	}
}

func TestFromEnvNetworkErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		environ []string
		want    []string
	}{{
		name:    "via names an interface that does not exist",
		environ: []string{"TSPM_WG_HOME=" + wgConf, "TSPM_OUT_DB=tcp,0.0.0.0:5432,10.8.0.5:5432,via=wg:hme"},
		want:    []string{"not declared", "wg:home"},
	}, {
		name:    "no interfaces declared at all",
		environ: []string{"TSPM_OUT_DB=tcp,0.0.0.0:5432,10.8.0.5:5432,via=wg:home"},
		want:    []string{"not declared", "none are"},
	}, {
		name:    "an interface nobody uses",
		environ: []string{"TSPM_WG_HOME=" + wgConf, "TSPM_OUT_DB=tcp,0.0.0.0:5432,db:5432"},
		want:    []string{"no mapping uses", "via=wg:home"},
	}, {
		name:    "wireguard target written as a name",
		environ: []string{"TSPM_WG_HOME=" + wgConf, "TSPM_OUT_DB=tcp,0.0.0.0:5432,db.internal:5432,via=wg:home"},
		want:    []string{"is a name", "no resolver"},
	}, {
		name:    "wireguard target outside every allowed ip",
		environ: []string{"TSPM_WG_HOME=" + wgConf, "TSPM_OUT_DB=tcp,0.0.0.0:5432,10.9.0.5:5432,via=wg:home"},
		want:    []string{"not covered by any AllowedIPs", "10.8.0.0/24"},
	}, {
		name: "egress to a peer with no endpoint",
		environ: []string{
			"TSPM_WG_HUB=[Interface]\nPrivateKey = " + keyA + "\nAddress = 10.8.0.1/24\nListenPort = 51820\n" +
				"[Peer]\nPublicKey = " + keyB + "\nAllowedIPs = 10.8.0.2/32\n",
			"TSPM_OUT_DB=tcp,0.0.0.0:5432,10.8.0.2:5432,via=wg:hub",
		},
		want: []string{"no Endpoint", "cannot open the tunnel"},
	}, {
		name:    "ingress binding an address the interface does not hold",
		environ: []string{"TSPM_WG_HOME=" + wgConf, "TSPM_IN_APP=tcp,10.8.0.9:8080,127.0.0.1:9000,via=wg:home"},
		want:    []string{"not one of interface HOME's own addresses", "10.8.0.2"},
	}, {
		name:    "via=local on an ingress mapping",
		environ: []string{"TSPM_IN_APP=tcp,:8080,127.0.0.1:9000,via=local"},
		want:    []string{"not valid on an \"in\" mapping", "TSPM_OUT_APP"},
	}, {
		name:    "tls over wireguard",
		environ: []string{"TSPM_WG_HOME=" + wgConf, "TSPM_IN_APP=tcp,10.8.0.2:443,127.0.0.1:9000,via=wg:home,tls=true"},
		want:    []string{"tls=true needs via=ts", "MagicDNS"},
	}, {
		name: "two interfaces whose names differ only in case",
		environ: []string{
			"TSPM_WG_HOME=" + wgConf,
			"TSPM_WG_home=" + wgConf,
			"TSPM_OUT_DB=tcp,0.0.0.0:5432,10.8.0.5:5432,via=wg:home",
		},
		want: []string{"duplicates", "case-insensitively"},
	}, {
		name:    "blank interface variable",
		environ: []string{"TSPM_WG_HOME=", "TSPM_OUT_DB=tcp,0.0.0.0:5432,10.8.0.5:5432,via=wg:home"},
		want:    []string{"the value is empty", "deleting its variable"},
	}, {
		name: "an interface that can neither dial out nor be dialled in to",
		environ: []string{
			"TSPM_WG_DEAD=[Interface]\nPrivateKey = " + keyA + "\nAddress = 10.8.0.2/24\n" +
				"[Peer]\nPublicKey = " + keyB + "\nAllowedIPs = 10.8.0.0/24\n",
			"TSPM_OUT_DB=tcp,0.0.0.0:5432,10.8.0.5:5432,via=wg:dead",
		},
		want: []string{"nothing can ever establish a tunnel"},
	}, {
		name: "two peers claiming one prefix",
		environ: []string{
			"TSPM_WG_HOME=[Interface]\nPrivateKey = " + keyA + "\nAddress = 10.8.0.2/24\nListenPort = 51820\n" +
				"[Peer]\nPublicKey = " + keyB + "\nAllowedIPs = 10.8.0.0/24\nEndpoint = a.example:1\n" +
				"[Peer]\nPublicKey = " + keyC + "\nAllowedIPs = 10.8.0.0/24\nEndpoint = b.example:1\n",
			"TSPM_OUT_DB=tcp,0.0.0.0:5432,10.8.0.5:5432,via=wg:home",
		},
		want: []string{"both list 10.8.0.0/24", "exactly one peer"},
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := FromEnv(tc.environ)
			if err == nil {
				t.Fatalf("got config %+v, want an error mentioning %v", cfg, tc.want)
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q does not mention %q", err, w)
				}
			}
		})
	}
}

// Two ingress mappings on different networks do not share an address space, so
// they may claim the same port. An egress mapping always binds the container's
// own network, whatever it dials over, so those still collide.
func TestFromEnvBindConflictsAreScopedToTheListeningNetwork(t *testing.T) {
	t.Parallel()

	second := strings.Replace(wgConf, "10.8.0.", "10.9.0.", -1)
	second = strings.Replace(second, keyB, keyC, 1)
	second = strings.Replace(second, "51820", "51821", -1)

	t.Run("accepted across networks", func(t *testing.T) {
		t.Parallel()
		if _, err := FromEnv([]string{
			"TSPM_WG_A=" + wgConf,
			"TSPM_WG_B=" + second,
			"TSPM_IN_ONE=tcp,10.8.0.2:8080,127.0.0.1:9000,via=wg:a",
			"TSPM_IN_TWO=tcp,10.9.0.2:8080,127.0.0.1:9001,via=wg:b",
			"TSPM_IN_THREE=tcp,:8080,127.0.0.1:9002",
		}); err != nil {
			t.Fatalf("three ingress listeners on three networks should not collide: %v", err)
		}
	})

	t.Run("refused on one network", func(t *testing.T) {
		t.Parallel()
		_, err := FromEnv([]string{
			"TSPM_WG_A=" + wgConf,
			"TSPM_IN_ONE=tcp,10.8.0.2:8080,127.0.0.1:9000,via=wg:a",
			"TSPM_IN_TWO=tcp,10.8.0.2:8080,127.0.0.1:9001,via=wg:a",
		})
		if err == nil || !strings.Contains(err.Error(), "WireGuard interface a") {
			t.Fatalf("got %v, want a conflict naming the interface", err)
		}
	})

	t.Run("egress still shares the host stack", func(t *testing.T) {
		t.Parallel()
		_, err := FromEnv([]string{
			"TSPM_WG_A=" + wgConf,
			"TSPM_OUT_ONE=tcp,0.0.0.0:8080,10.8.0.5:80,via=wg:a",
			"TSPM_OUT_TWO=tcp,0.0.0.0:8080,peer:80",
		})
		if err == nil || !strings.Contains(err.Error(), "the container's own network") {
			t.Fatalf("got %v, want a conflict on the host stack", err)
		}
	})
}

// The tailnet stays the default, so a configuration written before WireGuard
// existed parses to exactly what it used to mean.
func TestFromEnvDefaultsToTheTailnet(t *testing.T) {
	t.Parallel()
	cfg, err := FromEnv([]string{"TSPM_OUT_DB=tcp,0.0.0.0:5432,db-1:5432"})
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	if got := cfg.Maps[0].Via; got.Kind != NetTailnet || got.Name != "" {
		t.Errorf("via is %+v, want the tailnet", got)
	}
	if got := cfg.Maps[0].Via.String(); got != "ts" {
		t.Errorf("via renders as %q, want %q", got, "ts")
	}
}

func TestLogValueOmitsWireGuardSecrets(t *testing.T) {
	t.Parallel()
	cfg, err := FromEnv([]string{
		"TSPM_WG_HOME=" + strings.Replace(wgConf, "PersistentKeepalive = 25", "PresharedKey = "+keyC, 1),
		"TSPM_OUT_DB=tcp,0.0.0.0:5432,10.8.0.5:5432,via=wg:home",
	})
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	rendered := cfg.LogValue().String()
	for _, secret := range []string{keyA, keyC} {
		if strings.Contains(rendered, secret) {
			t.Errorf("the rendered configuration contains a secret key:\n%s", rendered)
		}
	}
	// The public key is not a secret and is the identifier an operator matches
	// against `wg show`, so it must be there.
	if !strings.Contains(rendered, keyB) {
		t.Errorf("the rendered configuration omits the peer's public key:\n%s", rendered)
	}
	if !strings.Contains(rendered, "via=wg:home") && !strings.Contains(rendered, "wg:home") {
		t.Errorf("the rendered configuration omits the mapping's network:\n%s", rendered)
	}
}
