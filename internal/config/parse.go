package config

import (
	"cmp"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Environment variable names. Mappings are discovered by prefix scan rather
// than by an index or a count variable: an operator adds a relay by adding one
// variable, and removes it by deleting that variable, with nothing else to keep
// in sync.
const (
	// EnvPrefixOut declares an egress mapping: TSPM_OUT_<NAME>=<spec>.
	EnvPrefixOut = "TSPM_OUT_"
	// EnvPrefixIn declares an ingress mapping: TSPM_IN_<NAME>=<spec>.
	EnvPrefixIn = "TSPM_IN_"
	// EnvPrefixWG declares a userspace WireGuard interface:
	// TSPM_WG_<NAME>=<wg-quick config, or file:/path to one>. A mapping reaches
	// it with via=wg:<name>.
	EnvPrefixWG = "TSPM_WG_"

	EnvHostname           = "TSPM_HOSTNAME"
	EnvAuthKey            = "TSPM_AUTHKEY"
	EnvAuthKeyFallback    = "TS_AUTHKEY"
	EnvTags               = "TSPM_TAGS"
	EnvStateDir           = "TSPM_STATE_DIR"
	EnvEphemeral          = "TSPM_EPHEMERAL"
	EnvControlURL         = "TSPM_CONTROL_URL"
	EnvAcceptRoutes       = "TSPM_ACCEPT_ROUTES"
	EnvRequireTailnetDest = "TSPM_REQUIRE_TAILNET_DEST"
	EnvMetricsAddr        = "TSPM_METRICS_ADDR"
	EnvDialTimeout        = "TSPM_DIAL_TIMEOUT"
	EnvUpTimeout          = "TSPM_UP_TIMEOUT"
	EnvShutdownGrace      = "TSPM_SHUTDOWN_GRACE"
	EnvLogLevel           = "TSPM_LOG_LEVEL"
)

// Defaults for every scalar setting. They are exported so that documentation
// and operator-facing output cannot drift from what the parser actually does.
const (
	DefaultHostname = "tsportmap"

	// DefaultStateDir is set unconditionally because tsnet MkdirAlls its Dir
	// and falls back to os.UserConfigDir() when Dir is empty, which fails in a
	// container with no $HOME.
	DefaultStateDir = "/var/lib/tsportmap"

	// DefaultMetricsAddr is loopback because /metrics, /healthz and /readyz are
	// unauthenticated.
	DefaultMetricsAddr = "127.0.0.1:9090"

	DefaultDialTimeout = 10 * time.Second

	// DefaultUpTimeout bounds the wait for the node to come up. tsnet's Up()
	// does not error on NeedsLogin or NeedsMachineAuth, so without a bound a
	// rejected auth key presents as a hang rather than a message.
	DefaultUpTimeout = 90 * time.Second

	DefaultShutdownGrace = 25 * time.Second

	DefaultLogLevel = "info"

	// DefaultRequireTailnetDest is on because tsnet's dialer does not fail
	// closed: a destination that is not a peer is dialled on the host network
	// instead of erroring.
	DefaultRequireTailnetDest = true
)

// Mapping option keys, in the order they are reported to an operator who
// misspells one.
var mappingOptionKeys = []string{"allow", "idle", "tls", "via"}

// FromEnv builds a Config from an os.Environ()-style slice of "KEY=VALUE".
//
// Configuration is environment-only by design: the tool is one container on
// platforms whose configuration surface is the environment, and a second source
// of truth is one more thing that can disagree with the dashboard an operator
// is looking at.
//
// Every problem is reported as an error rather than a warning. A relay whose
// allow-list or target was quietly dropped is worse than a process that refuses
// to start, because nothing downstream can tell the difference between "no
// allow-list" and "the allow-list I wrote was ignored".
func FromEnv(environ []string) (*Config, error) {
	e := parseEnviron(environ)

	c := &Config{
		Hostname:           e.str(EnvHostname, DefaultHostname),
		StateDir:           e.str(EnvStateDir, DefaultStateDir),
		ControlURL:         e.str(EnvControlURL, ""),
		MetricsAddr:        e.str(EnvMetricsAddr, DefaultMetricsAddr),
		RequireTailnetDest: DefaultRequireTailnetDest,
	}

	var err error
	if c.AuthKey, err = e.authKey(); err != nil {
		return nil, err
	}
	if c.Tags, err = e.tags(); err != nil {
		return nil, err
	}
	if c.Ephemeral, err = e.boolean(EnvEphemeral, false); err != nil {
		return nil, err
	}
	if c.AcceptRoutes, err = e.boolean(EnvAcceptRoutes, false); err != nil {
		return nil, err
	}
	if c.RequireTailnetDest, err = e.boolean(EnvRequireTailnetDest, DefaultRequireTailnetDest); err != nil {
		return nil, err
	}
	if c.DialTimeout, err = e.duration(EnvDialTimeout, DefaultDialTimeout); err != nil {
		return nil, err
	}
	if c.UpTimeout, err = e.duration(EnvUpTimeout, DefaultUpTimeout); err != nil {
		return nil, err
	}
	if c.ShutdownGrace, err = e.duration(EnvShutdownGrace, DefaultShutdownGrace); err != nil {
		return nil, err
	}
	if c.LogLevel, err = e.logLevel(); err != nil {
		return nil, err
	}
	if _, _, err := splitHostPort(EnvMetricsAddr, "address", c.MetricsAddr); err != nil {
		return nil, err
	}

	if c.WG, err = e.wgInterfaces(); err != nil {
		return nil, err
	}

	decls, err := e.mappings()
	if err != nil {
		return nil, err
	}
	if len(decls) == 0 {
		return nil, fmt.Errorf("no mappings configured: declare at least one relay with %s<NAME> or %s<NAME>, "+
			"e.g. %sCACHE=tcp,127.0.0.1:6379,cache:6379 or %sWEB=tcp,:8080,127.0.0.1:8080",
			EnvPrefixOut, EnvPrefixIn, EnvPrefixOut, EnvPrefixIn)
	}
	if err := checkBinds(decls); err != nil {
		return nil, err
	}
	if err := checkNetworks(decls, c.WG); err != nil {
		return nil, err
	}

	c.Maps = make([]Mapping, len(decls))
	for i, d := range decls {
		c.Maps[i] = d.m
	}
	return c, nil
}

// env is a resolved environment. An absent variable and one set to the empty
// string are treated identically: platform dashboards routinely leave a
// declared variable blank, and "blank means the default" is the only reading of
// that which cannot produce an invalid hostname or an unbindable address.
type env map[string]string

func parseEnviron(environ []string) env {
	e := make(env, len(environ))
	for _, kv := range environ {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			// Not an assignment. os.Environ never produces these, but a caller
			// building a slice by hand can.
			continue
		}
		if _, dup := e[k]; dup {
			// First occurrence wins, matching os.Getenv on a duplicated key.
			continue
		}
		e[k] = v
	}
	return e
}

func (e env) str(name, def string) string {
	if v := e[name]; v != "" {
		return v
	}
	return def
}

func (e env) boolean(name string, def bool) (bool, error) {
	v := e[name]
	if v == "" {
		return def, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("%s: %q is not a boolean; use true or false (1/0, t/f and their cased spellings also work)", name, v)
	}
	return b, nil
}

func (e env) duration(name string, def time.Duration) (time.Duration, error) {
	v := e[name]
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %q is not a duration; write a unit, e.g. 250ms, 10s or 1m30s", name, v)
	}
	if d < 0 {
		return 0, fmt.Errorf("%s: %q is negative", name, v)
	}
	return d, nil
}

func (e env) logLevel() (string, error) {
	v := e.str(EnvLogLevel, DefaultLogLevel)
	level := strings.ToLower(strings.TrimSpace(v))
	switch level {
	case "debug", "info", "warn", "error":
		return level, nil
	}
	return "", fmt.Errorf("%s: %q is not a level; use debug, info, warn or error", EnvLogLevel, v)
}

// authKey resolves the node credential, preferring TSPM_AUTHKEY and falling
// back to TS_AUTHKEY so that a container already configured for Tailscale needs
// no second variable.
//
// A "file:" prefix reads the credential from a path instead, which keeps it out
// of /proc/<pid>/environ, out of a platform's environment dashboard and out of
// any crash dump that walks the environment. No error here ever quotes file
// contents; only the path.
func (e env) authKey() (string, error) {
	name, v := EnvAuthKey, e[EnvAuthKey]
	if v == "" {
		name, v = EnvAuthKeyFallback, e[EnvAuthKeyFallback]
	}
	if v == "" {
		return "", nil
	}
	path, isFile := strings.CutPrefix(v, "file:")
	if !isFile {
		return v, nil
	}
	if path == "" {
		return "", fmt.Errorf(`%s: "file:" prefix with no path after it`, name)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		// A PathError repeats the path we are about to print, so unwrap to the
		// bare cause. The contents are never in the error either way.
		var pe *fs.PathError
		if errors.As(err, &pe) {
			err = pe.Err
		}
		return "", fmt.Errorf("%s: cannot read auth key file %q: %w", name, path, err)
	}
	// Trimmed because a key file written by an editor or a `echo > file` ends
	// in a newline that control would reject as part of the key.
	key := strings.TrimSpace(string(b))
	if key == "" {
		return "", fmt.Errorf("%s: auth key file %q is empty", name, path)
	}
	return key, nil
}

func (e env) tags() ([]string, error) {
	raw := e[EnvTags]
	if raw == "" {
		return nil, nil
	}
	var tags []string
	for _, t := range strings.Split(raw, ",") {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if !strings.HasPrefix(t, "tag:") || t == "tag:" {
			return nil, fmt.Errorf("%s: tag %q must be of the form tag:<name>, e.g. tag:proxy", EnvTags, t)
		}
		tags = append(tags, t)
	}
	return tags, nil
}

// declared is a parsed mapping plus the variable that declared it, so that a
// conflict between two mappings can name both variables an operator has to edit.
type declared struct {
	m   Mapping
	env string
}

// mappings finds every TSPM_OUT_* and TSPM_IN_* variable and returns the parsed
// mappings sorted by name. The sort makes listener startup order, log order and
// error order identical from one run to the next, which map iteration would not.
func (e env) mappings() ([]declared, error) {
	// Sorted so that when two variables conflict, the same one is reported as
	// the offender every run.
	names := make([]string, 0, len(e))
	for k := range e {
		if strings.HasPrefix(k, EnvPrefixOut) || strings.HasPrefix(k, EnvPrefixIn) {
			names = append(names, k)
		}
	}
	slices.Sort(names)

	var decls []declared
	seen := make(map[string]string, len(names)) // lowercased mapping name -> variable
	for _, k := range names {
		dir, prefix := Out, EnvPrefixOut
		if strings.HasPrefix(k, EnvPrefixIn) {
			dir, prefix = In, EnvPrefixIn
		}
		name := strings.TrimPrefix(k, prefix)
		if name == "" {
			return nil, fmt.Errorf("%s: mapping name is empty; the variable must be %s<NAME>", k, prefix)
		}
		// Names label metrics series and log lines, where a case-only
		// difference between two mappings is indistinguishable to a human.
		lower := strings.ToLower(name)
		if other, dup := seen[lower]; dup {
			return nil, fmt.Errorf("%s: mapping name %q duplicates %s; names must be unique across %s and %s and are compared case-insensitively",
				k, name, other, EnvPrefixOut, EnvPrefixIn)
		}
		seen[lower] = k

		m, err := parseMapping(k, dir, name, e[k])
		if err != nil {
			return nil, err
		}
		decls = append(decls, declared{m: m, env: k})
	}

	slices.SortFunc(decls, func(a, b declared) int {
		if n := cmp.Compare(strings.ToLower(a.m.Name), strings.ToLower(b.m.Name)); n != 0 {
			return n
		}
		return cmp.Compare(a.m.Name, b.m.Name)
	})
	return decls, nil
}

// parseMapping reads one <proto>,<listen>,<target>[,<key>=<value>]... spec.
func parseMapping(varName string, dir Direction, name, spec string) (Mapping, error) {
	fields := strings.Split(spec, ",")
	for i := range fields {
		fields[i] = strings.TrimSpace(fields[i])
	}
	if len(fields) < 3 {
		return Mapping{}, fmt.Errorf("%s: %q is not a mapping; want <proto>,<listen>,<target>[,<key>=<value>]..., e.g. tcp,127.0.0.1:5432,db:5432",
			varName, spec)
	}

	// The tailnet is the default network so that a mapping written before
	// WireGuard existed keeps exactly the meaning it had.
	m := Mapping{Name: name, Dir: dir, Via: Network{Kind: NetTailnet}}

	switch p := Proto(strings.ToLower(fields[0])); p {
	case TCP, UDP:
		m.Proto = p
	default:
		return Mapping{}, fmt.Errorf("%s: proto %q is not %s or %s", varName, fields[0], TCP, UDP)
	}

	listenHost, _, err := splitHostPort(varName, "listen", fields[1])
	if err != nil {
		return Mapping{}, err
	}
	m.Listen = fields[1]

	targetHost, _, err := splitHostPort(varName, "target", fields[2])
	if err != nil {
		return Mapping{}, err
	}
	if targetHost == "" {
		return Mapping{}, fmt.Errorf("%s: target %q has no host; a mapping names exactly one destination", varName, fields[2])
	}
	m.Target = fields[2]

	// The listen host is required for egress and has no default: the right
	// value is a property of the platform, and guessing it wrong is either a
	// listener nothing can reach or an open relay.
	if m.Dir == Out && listenHost == "" {
		return Mapping{}, fmt.Errorf("%s: listen %q has no host, which %q mappings require; there is deliberately no default because the correct bind address is platform-specific "+
			"(0.0.0.0 on an IPv4-only private network, :: on an IPv6-only one, 127.0.0.1 for local-only access)",
			varName, fields[1], Out)
	}

	seen := make(map[string]bool, len(fields)-3)
	for _, f := range fields[3:] {
		if f == "" {
			return Mapping{}, fmt.Errorf("%s: %q has an empty option field; known options are %s", varName, spec, strings.Join(mappingOptionKeys, ", "))
		}
		k, v, ok := strings.Cut(f, "=")
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		if !ok {
			return Mapping{}, fmt.Errorf("%s: option %q is not <key>=<value>; known options are %s", varName, f, strings.Join(mappingOptionKeys, ", "))
		}
		if seen[k] {
			return Mapping{}, fmt.Errorf("%s: option %q is set more than once", varName, k)
		}
		seen[k] = true

		switch k {
		case "tls":
			b, err := strconv.ParseBool(v)
			if err != nil {
				return Mapping{}, fmt.Errorf("%s: tls=%q is not a boolean; use true or false", varName, v)
			}
			m.TLS = b
		case "idle":
			d, err := time.ParseDuration(v)
			if err != nil {
				return Mapping{}, fmt.Errorf("%s: idle=%q is not a duration; write a unit, e.g. 30s or 5m", varName, v)
			}
			if d < 0 {
				return Mapping{}, fmt.Errorf("%s: idle=%q is negative", varName, v)
			}
			m.Idle = d
		case "allow":
			prefixes, err := parseAllow(varName, v)
			if err != nil {
				return Mapping{}, err
			}
			m.Allow = prefixes
		case "via":
			n, err := parseVia(varName, v)
			if err != nil {
				return Mapping{}, err
			}
			m.Via = n
		default:
			// Unknown keys are fatal. A silently ignored option is how an
			// allow-list gets lost without anyone noticing.
			return Mapping{}, fmt.Errorf("%s: unknown option %q; known options are %s", varName, k, strings.Join(mappingOptionKeys, ", "))
		}
	}

	if m.TLS && !(m.Dir == In && m.Proto == TCP) {
		return Mapping{}, fmt.Errorf("%s: tls=true is only valid on an %q mapping over %s; this one is %q over %s. "+
			"TLS is terminated here with the node's own Tailscale certificate, which only makes sense for traffic arriving from the tailnet",
			varName, In, TCP, m.Dir, m.Proto)
	}
	// The certificate comes from the Tailscale control plane and is issued for
	// this node's MagicDNS name. There is no equivalent on a WireGuard
	// interface or on the container's own network — nothing there has a name
	// control would certify — so the combination is refused rather than left to
	// fail at bind time with a certificate error that names neither setting.
	if m.TLS && m.Via.Kind != NetTailnet {
		return Mapping{}, fmt.Errorf("%s: tls=true needs via=%s, but this mapping uses via=%s. "+
			"The certificate is issued by Tailscale for this node's MagicDNS name, and there is no such name on a WireGuard interface. "+
			"Terminate TLS in the backend, or put this mapping on the tailnet",
			varName, NetTailnet, m.Via)
	}
	// An ingress mapping listens on its network, and "the container's own
	// network" on both sides is what an egress mapping with via=local already
	// spells. One spelling for one thing keeps the conflict rules answerable.
	if m.Dir == In && m.Via.Kind == NetLocal {
		return Mapping{}, fmt.Errorf("%s: via=%s is not valid on an %q mapping: an %q mapping listens on the network it names, "+
			"and a listener on the container's own network that dials the container's own network is what %s<NAME> with via=%s already declares. "+
			"Write it as %s%s instead",
			varName, NetLocal, In, In, EnvPrefixOut, NetLocal, EnvPrefixOut, name)
	}

	// A UDP session has no close handshake, so without a deadline its entry in
	// the session table lives until the process exits. TCP keeps 0, which the
	// relay reads as "never reap".
	if m.Proto == UDP && m.Idle == 0 {
		m.Idle = DefaultUDPIdle
	}
	return m, nil
}

func parseAllow(varName, v string) ([]netip.Prefix, error) {
	if v == "" {
		return nil, fmt.Errorf("%s: allow is empty; list CIDRs separated by | or drop the option to allow any source", varName)
	}
	var prefixes []netip.Prefix
	for _, raw := range strings.Split(v, "|") {
		raw = strings.TrimSpace(raw)
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: allow entry %q is not a CIDR; write a prefix length, e.g. 10.0.0.0/8 or 100.64.0.0/10 (a single address is /32 or /128)", varName, raw)
		}
		prefixes = append(prefixes, p)
	}
	return prefixes, nil
}

func splitHostPort(varName, field, value string) (host, port string, err error) {
	h, p, splitErr := net.SplitHostPort(value)
	if splitErr != nil {
		return "", "", fmt.Errorf("%s: %s %q is not host:port; bracket an IPv6 address, e.g. [::1]:8080", varName, field, value)
	}
	n, convErr := strconv.Atoi(p)
	if convErr != nil || n < 1 || n > 65535 {
		return "", "", fmt.Errorf("%s: %s %q has port %q; want a number from 1 to 65535", varName, field, value, p)
	}
	return h, p, nil
}

// bind identifies a listening socket for conflict detection.
//
// The stack is part of the identity because tsportmap holds several that do not
// share an address space. An ingress listener is opened inside its network's own
// netstack — tsnet's, or a WireGuard interface's — and never creates a socket on
// the host, so an "in" and an "out" mapping written identically claim different
// things, and two "in" mappings on different WireGuard interfaces claim
// different things again. Every "out" mapping, whatever network it dials over,
// binds the one host stack and so shares an address space with all the others.
type bind struct {
	stack string
	proto Proto
	host  string
	port  string
}

// listenStack names the address space a mapping's listener occupies.
func listenStack(m Mapping) string {
	if m.Dir == Out {
		// The container's own network. Which network the onward dial uses
		// changes nothing about the socket that was opened here.
		return "host"
	}
	return "in:" + m.Via.String()
}

// stackDescription renders a stack for an operator, who has never seen the key
// above and should not have to.
func stackDescription(m Mapping) string {
	if m.Dir == Out {
		return "the container's own network"
	}
	if m.Via.Kind == NetWireGuard {
		return fmt.Sprintf("WireGuard interface %s", m.Via.Name)
	}
	return "the tailnet"
}

// checkBinds rejects two mappings that would try to occupy the same listening
// socket. Left undetected, whichever listener started second would fail at bind
// time or, worse, the two would split traffic depending on start order.
func checkBinds(decls []declared) error {
	exact := make(map[bind]declared, len(decls))
	type portKey struct {
		stack string
		proto Proto
		port  string
	}
	// A wildcard bind claims a port on every address of its stack, so it
	// conflicts with any other bind on that port in the same direction even
	// though the two strings differ.
	wildcards := make(map[portKey]declared, len(decls))
	onPort := make(map[portKey][]declared, len(decls))

	for _, d := range decls {
		host, port, err := net.SplitHostPort(d.m.Listen)
		if err != nil {
			// parseMapping already accepted this address.
			return fmt.Errorf("%s: listen %q is not host:port", d.env, d.m.Listen)
		}
		host = canonicalHost(host)
		stack := listenStack(d.m)
		where := stackDescription(d.m)

		key := bind{stack: stack, proto: d.m.Proto, host: host, port: port}
		if other, dup := exact[key]; dup {
			return fmt.Errorf("%s and %s both listen on %s %s on %s; a mapping's (listening network, proto, listen) triple must be unique",
				other.env, d.env, d.m.Proto, d.m.Listen, where)
		}
		exact[key] = d

		pk := portKey{stack: stack, proto: d.m.Proto, port: port}
		if isWildcardHost(host) {
			if others := onPort[pk]; len(others) > 0 {
				return fmt.Errorf("%s listens on %s %s, which covers every address on port %s, and %s already listens on %s %s on the same network (%s)",
					d.env, d.m.Proto, d.m.Listen, port, others[0].env, others[0].m.Proto, others[0].m.Listen, where)
			}
			wildcards[pk] = d
		} else if w, ok := wildcards[pk]; ok {
			return fmt.Errorf("%s listens on %s %s, but %s already listens on %s %s, which covers every address on port %s on the same network (%s)",
				d.env, d.m.Proto, d.m.Listen, w.env, w.m.Proto, w.m.Listen, port, where)
		}
		onPort[pk] = append(onPort[pk], d)
	}
	return nil
}

// canonicalHost folds spellings of the same address together so that
// [0:0:0:0:0:0:0:1]:80 and [::1]:80 are recognised as one socket. A name that
// is not an IP is compared case-insensitively, as DNS is.
func canonicalHost(host string) string {
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Unmap().String()
	}
	return strings.ToLower(host)
}

// isWildcardHost reports whether a bind host claims every address rather than
// one. The empty host and the unspecified addresses are treated alike, because
// an operator writing ":8080" and one writing "0.0.0.0:8080" mean the same
// thing and neither can share the port with a second listener.
func isWildcardHost(host string) bool {
	if host == "" {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.IsUnspecified()
}

// LogValue renders the configuration for logging with the credential removed.
//
// The auth key is never included, not even a prefix or a length: a prefix
// identifies the key type and a length narrows a search, and neither helps
// anyone reading a log. Whether a key was supplied is the only fact about it
// worth recording, and it is the fact an operator debugging a failed login
// actually needs.
func (c *Config) LogValue() slog.Value {
	if c == nil {
		return slog.StringValue("<nil>")
	}
	maps := make([]any, 0, len(c.Maps))
	for _, m := range c.Maps {
		attrs := []any{
			slog.String("dir", string(m.Dir)),
			slog.String("proto", string(m.Proto)),
			slog.String("via", m.Via.String()),
			slog.String("listen", m.Listen),
			slog.String("target", m.Target),
		}
		if m.TLS {
			attrs = append(attrs, slog.Bool("tls", true))
		}
		if len(m.Allow) > 0 {
			allow := make([]string, len(m.Allow))
			for i, p := range m.Allow {
				allow[i] = p.String()
			}
			attrs = append(attrs, slog.String("allow", strings.Join(allow, "|")))
		}
		if m.Idle > 0 {
			attrs = append(attrs, slog.Duration("idle", m.Idle))
		}
		maps = append(maps, slog.Group(m.Name, attrs...))
	}

	// Keys are named but never valued: the configuration text holds the
	// interface's private key and any preshared key, and a log line is the one
	// place a secret outlives the rotation that was supposed to retire it.
	wg := make([]any, 0, len(c.WG))
	for _, w := range c.WG {
		peers := make([]string, len(w.Peers))
		for i, p := range w.Peers {
			peers[i] = p.PublicKey
		}
		wg = append(wg, slog.Group(w.Name,
			slog.String("addrs", prefixesString(w.Addresses)),
			slog.Int("listen_port", w.ListenPort),
			slog.Int("mtu", w.MTU),
			slog.Int("peers", len(w.Peers)),
			slog.String("peer_keys", strings.Join(peers, ",")),
		))
	}

	return slog.GroupValue(
		slog.String("hostname", c.Hostname),
		slog.Bool("auth_key_set", c.AuthKey != ""),
		slog.String("tags", strings.Join(c.Tags, ",")),
		slog.String("state_dir", c.StateDir),
		slog.Bool("ephemeral", c.Ephemeral),
		slog.String("control_url", c.ControlURL),
		slog.Bool("accept_routes", c.AcceptRoutes),
		slog.Bool("require_tailnet_dest", c.RequireTailnetDest),
		slog.String("metrics_addr", c.MetricsAddr),
		slog.Duration("dial_timeout", c.DialTimeout),
		slog.Duration("up_timeout", c.UpTimeout),
		slog.Duration("shutdown_grace", c.ShutdownGrace),
		slog.String("log_level", c.LogLevel),
		slog.Group("wireguard", wg...),
		slog.Group("maps", maps...),
	)
}

func prefixesString(ps []netip.Prefix) string {
	parts := make([]string, len(ps))
	for i, p := range ps {
		parts[i] = p.String()
	}
	return strings.Join(parts, ",")
}
