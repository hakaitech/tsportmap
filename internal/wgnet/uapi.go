package wgnet

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/hakaitech/tsportmap/internal/config"
)

// uapiConfig renders an interface as the cross-platform UAPI text that
// wireguard-go's IpcSet reads.
//
// The format is WireGuard's own: lowercase key=value lines, keys in hex rather
// than base64, and a peer's settings following the public_key line that opens
// its record. replace_peers and replace_allowed_ips make the result declarative
// — what is written here is the device's whole configuration, not an amendment
// to whatever it held before — which matters because tsportmap reads its
// configuration once and an interface that merged would carry state from a
// configuration nobody can see any more.
func uapiConfig(c config.WGInterface) (string, error) {
	var b strings.Builder

	priv, err := hexKey(c.PrivateKey)
	if err != nil {
		// Never quotes the key; see parseWGKey.
		return "", fmt.Errorf("the private key is not a WireGuard key: %w", err)
	}
	fmt.Fprintf(&b, "private_key=%s\n", priv)
	// Always written, including the 0 that asks for an ephemeral port, so the
	// device's port is a property of the configuration and not of whatever the
	// device happened to be doing before.
	fmt.Fprintf(&b, "listen_port=%d\n", c.ListenPort)
	b.WriteString("replace_peers=true\n")

	for _, p := range c.Peers {
		pub, err := hexKey(p.PublicKey)
		if err != nil {
			return "", fmt.Errorf("peer %q has an invalid public key: %w", p.PublicKey, err)
		}
		fmt.Fprintf(&b, "public_key=%s\n", pub)
		if p.PresharedKey != "" {
			psk, err := hexKey(p.PresharedKey)
			if err != nil {
				return "", fmt.Errorf("peer %s has an invalid preshared key: %w", p.PublicKey, err)
			}
			fmt.Fprintf(&b, "preshared_key=%s\n", psk)
		}
		if p.Endpoint != "" {
			fmt.Fprintf(&b, "endpoint=%s\n", p.Endpoint)
		}
		if p.Keepalive > 0 {
			// UAPI counts keepalives in whole seconds. The parser only accepts
			// whole seconds, so this cannot round anything away.
			fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", int(p.Keepalive.Seconds()))
		}
		b.WriteString("replace_allowed_ips=true\n")
		for _, a := range p.AllowedIPs {
			fmt.Fprintf(&b, "allowed_ip=%s\n", a.String())
		}
	}
	return b.String(), nil
}

// hexKey converts a base64 WireGuard key to the hex spelling UAPI uses.
func hexKey(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("it is not valid base64")
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("it decodes to %d bytes, but a WireGuard key is 32", len(raw))
	}
	return hex.EncodeToString(raw), nil
}
