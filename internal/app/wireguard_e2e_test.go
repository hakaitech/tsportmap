package app

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/hakaitech/tsportmap/internal/config"
	"github.com/hakaitech/tsportmap/internal/wgnet"

	"golang.org/x/crypto/curve25519"
)

func e2eKeypair(t *testing.T) (priv, pub string) {
	t.Helper()
	var sk [32]byte
	if _, err := rand.Read(sk[:]); err != nil {
		t.Fatalf("reading random bytes: %v", err)
	}
	sk[0] &= 248
	sk[31] = (sk[31] & 127) | 64
	pk, err := curve25519.X25519(sk[:], curve25519.Basepoint)
	if err != nil {
		t.Fatalf("deriving public key: %v", err)
	}
	return base64.StdEncoding.EncodeToString(sk[:]), base64.StdEncoding.EncodeToString(pk)
}

func e2eFreeUDPPort(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a UDP port: %v", err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	pc.Close()
	return port
}

// A whole tsportmap process, configured only with a WireGuard interface, must
// carry a real client's bytes to a real service sitting on the far side of a
// real tunnel — with no tailnet involved and no privileges.
//
// Everything below the test's own client is production code: the configuration
// parser, the network registry, the relay, and the userspace WireGuard device.
// Only the far end of the tunnel is built by hand, because something has to be
// on the other side.
func TestEndToEndOverWireGuard(t *testing.T) {
	t.Parallel()

	nearPriv, nearPub := e2eKeypair(t)
	farPriv, farPub := e2eKeypair(t)
	nearPort, farPort := e2eFreeUDPPort(t), e2eFreeUDPPort(t)

	const (
		nearAddr = "10.77.0.1"
		farAddr  = "10.77.0.2"
		farPortN = 8080
	)

	// The far end: an ordinary WireGuard peer serving HTTP inside the tunnel.
	far, err := wgnet.New(config.WGInterface{
		Name:       "far",
		PrivateKey: farPriv,
		Addresses:  []netip.Prefix{netip.MustParsePrefix(farAddr + "/24")},
		ListenPort: farPort,
		MTU:        config.DefaultWGMTU,
		Peers: []config.WGPeer{{
			PublicKey:  nearPub,
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix(nearAddr + "/32")},
			Endpoint:   fmt.Sprintf("127.0.0.1:%d", nearPort),
			Keepalive:  time.Second,
		}},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("building the far interface: %v", err)
	}
	t.Cleanup(func() { far.Close() })
	if err := far.Start(context.Background()); err != nil {
		t.Fatalf("starting the far interface: %v", err)
	}

	farLn, err := far.Listen("tcp", fmt.Sprintf("%s:%d", farAddr, farPortN))
	if err != nil {
		t.Fatalf("listening inside the far interface: %v", err)
	}
	defer farLn.Close()
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "served over wireguard from %s", r.Host)
	})}
	go srv.Serve(farLn)
	defer srv.Close()

	// The near end: a real tsportmap process whose only network is WireGuard.
	listen := freePort(t)
	wgConf := fmt.Sprintf(`
[Interface]
PrivateKey = %s
Address = %s/24
ListenPort = %d

[Peer]
PublicKey = %s
AllowedIPs = %s/32
Endpoint = 127.0.0.1:%d
PersistentKeepalive = 1
`, nearPriv, nearAddr, nearPort, farPub, farAddr, farPort)

	environ := []string{
		"TSPM_WG_LAB=" + wgConf,
		fmt.Sprintf("TSPM_OUT_WEB=tcp,%s,%s:%d,via=wg:lab", listen, farAddr, farPortN),
		"TSPM_METRICS_ADDR=" + freePort(t),
		"TSPM_SHUTDOWN_GRACE=2s",
	}

	// A node factory that fails loudly: a WireGuard-only configuration must
	// never reach for a tailnet.
	noNode := nodeFactory(func(*config.Config, *slog.Logger) (node, error) {
		return nil, fmt.Errorf("a Tailscale node was built for a WireGuard-only configuration")
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, environ, "test", io.Discard, noNode, newWireGuardInterface) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("run: %v", err)
		}
	}()

	// The relay's listener is a plain local socket, so the client is a plain
	// HTTP client with no knowledge of WireGuard at all — which is the whole
	// point of the tool.
	client := &http.Client{Timeout: 5 * time.Second}
	deadline := time.Now().Add(30 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			t.Fatalf("run returned early: %v", err)
		default:
		}
		resp, err := client.Get("http://" + listen + "/")
		if err != nil {
			lastErr = err
			time.Sleep(50 * time.Millisecond)
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatalf("reading the response: %v", err)
		}
		if !strings.Contains(string(body), "served over wireguard") {
			t.Fatalf("got body %q, want the far side's response", body)
		}
		return
	}
	t.Fatalf("no response came back through the tunnel before the deadline; last error: %v", lastErr)
}

// The same process must be able to hold a WireGuard mapping and a plain
// forwarder at once, each reaching its own destination.
func TestEndToEndLocalForwarder(t *testing.T) {
	t.Parallel()

	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("starting the backend: %v", err)
	}
	defer backend.Close()
	go func() {
		for {
			c, err := backend.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()

	listen := freePort(t)
	environ := []string{
		"TSPM_OUT_ECHO=tcp," + listen + "," + backend.Addr().String() + ",via=local",
		"TSPM_METRICS_ADDR=" + freePort(t),
		"TSPM_SHUTDOWN_GRACE=1s",
	}
	noNode := nodeFactory(func(*config.Config, *slog.Logger) (node, error) {
		return nil, fmt.Errorf("a Tailscale node was built for a configuration that uses none")
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, environ, "test", io.Discard, noNode, noWG) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("run: %v", err)
		}
	}()

	const msg = "plain forwarder"
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", listen, time.Second)
		if err != nil {
			time.Sleep(20 * time.Millisecond)
			continue
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.WriteString(c, msg); err != nil {
			t.Fatalf("writing through the forwarder: %v", err)
		}
		got := make([]byte, len(msg))
		if _, err := io.ReadFull(c, got); err != nil {
			t.Fatalf("reading back through the forwarder: %v", err)
		}
		if string(got) != msg {
			t.Fatalf("echoed %q, want %q", got, msg)
		}
		return
	}
	t.Fatal("the forwarder never accepted a connection")
}
