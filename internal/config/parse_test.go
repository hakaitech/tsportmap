package config

import (
	"bytes"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// minimalOut is a valid egress mapping, used by tests that are exercising
// something other than mapping parsing.
const minimalOut = "TSPM_OUT_DB=tcp,127.0.0.1:5432,db:5432"

func mustFromEnv(t *testing.T, environ ...string) *Config {
	t.Helper()
	c, err := FromEnv(environ)
	if err != nil {
		t.Fatalf("FromEnv(%q) returned error: %v", environ, err)
	}
	return c
}

func TestFromEnvDefaults(t *testing.T) {
	c := mustFromEnv(t, minimalOut, "PATH=/usr/bin", "NOT_AN_ASSIGNMENT")

	if got, want := c.Hostname, DefaultHostname; got != want {
		t.Errorf("Hostname = %q, want %q", got, want)
	}
	if c.AuthKey != "" {
		t.Errorf("AuthKey = %q, want empty", c.AuthKey)
	}
	if len(c.Tags) != 0 {
		t.Errorf("Tags = %v, want none", c.Tags)
	}
	if got, want := c.StateDir, DefaultStateDir; got != want {
		t.Errorf("StateDir = %q, want %q", got, want)
	}
	if c.Ephemeral {
		t.Error("Ephemeral = true, want false")
	}
	if c.ControlURL != "" {
		t.Errorf("ControlURL = %q, want empty", c.ControlURL)
	}
	if c.AcceptRoutes {
		t.Error("AcceptRoutes = true, want false")
	}
	if !c.RequireTailnetDest {
		t.Error("RequireTailnetDest = false, want true: the guard must be on unless explicitly disabled")
	}
	if got, want := c.MetricsAddr, DefaultMetricsAddr; got != want {
		t.Errorf("MetricsAddr = %q, want %q", got, want)
	}
	if got, want := c.DialTimeout, DefaultDialTimeout; got != want {
		t.Errorf("DialTimeout = %v, want %v", got, want)
	}
	if got, want := c.UpTimeout, DefaultUpTimeout; got != want {
		t.Errorf("UpTimeout = %v, want %v", got, want)
	}
	if got, want := c.ShutdownGrace, DefaultShutdownGrace; got != want {
		t.Errorf("ShutdownGrace = %v, want %v", got, want)
	}
	if got, want := c.LogLevel, DefaultLogLevel; got != want {
		t.Errorf("LogLevel = %q, want %q", got, want)
	}

	if len(c.Maps) != 1 {
		t.Fatalf("Maps = %v, want exactly one mapping", c.Maps)
	}
	m := c.Maps[0]
	want := Mapping{Name: "DB", Dir: Out, Proto: TCP, Listen: "127.0.0.1:5432", Target: "db:5432"}
	if m.Name != want.Name || m.Dir != want.Dir || m.Proto != want.Proto || m.Listen != want.Listen || m.Target != want.Target {
		t.Errorf("mapping = %+v, want %+v", m, want)
	}
	if m.TLS {
		t.Error("TLS = true, want false by default")
	}
	if len(m.Allow) != 0 {
		t.Errorf("Allow = %v, want empty (no allow-list means any source)", m.Allow)
	}
	if m.Idle != 0 {
		t.Errorf("Idle = %v, want 0: TCP sessions are not reaped unless asked", m.Idle)
	}
}

// An empty value is treated as unset, because a platform dashboard that
// declares a variable and leaves it blank must not produce an empty hostname or
// an unbindable metrics address.
func TestFromEnvEmptyScalarsFallBackToDefaults(t *testing.T) {
	c := mustFromEnv(t, minimalOut,
		"TSPM_HOSTNAME=",
		"TSPM_STATE_DIR=",
		"TSPM_METRICS_ADDR=",
		"TSPM_LOG_LEVEL=",
		"TSPM_DIAL_TIMEOUT=",
		"TSPM_EPHEMERAL=",
		"TSPM_REQUIRE_TAILNET_DEST=",
	)
	if c.Hostname != DefaultHostname || c.StateDir != DefaultStateDir || c.MetricsAddr != DefaultMetricsAddr ||
		c.LogLevel != DefaultLogLevel || c.DialTimeout != DefaultDialTimeout || c.Ephemeral || !c.RequireTailnetDest {
		t.Errorf("blank values did not fall back to defaults: %+v", c)
	}
}

func TestFromEnvRealisticConfig(t *testing.T) {
	c := mustFromEnv(t,
		"TSPM_HOSTNAME=edge-relay",
		"TSPM_AUTHKEY=tskey-auth-secret",
		"TSPM_TAGS=tag:proxy, tag:edge",
		"TSPM_STATE_DIR=/data/tsportmap",
		"TSPM_EPHEMERAL=true",
		"TSPM_CONTROL_URL=https://headscale.example.com",
		"TSPM_ACCEPT_ROUTES=1",
		"TSPM_REQUIRE_TAILNET_DEST=false",
		"TSPM_METRICS_ADDR=0.0.0.0:9100",
		"TSPM_DIAL_TIMEOUT=3s",
		"TSPM_UP_TIMEOUT=2m",
		"TSPM_SHUTDOWN_GRACE=45s",
		"TSPM_LOG_LEVEL=DEBUG",
		"TSPM_OUT_PG=tcp,127.0.0.1:5432,db:5432,allow=127.0.0.1/32|10.0.0.0/8,idle=5m",
		"TSPM_OUT_RESOLVER=udp,127.0.0.1:5353,dns:53",
		"TSPM_IN_WEB=tcp,:8443,127.0.0.1:8080,tls=true",
		"TSPM_IN_SYSLOG=udp,:514,127.0.0.1:1514,idle=90s",
	)

	if c.Hostname != "edge-relay" || c.AuthKey != "tskey-auth-secret" || c.StateDir != "/data/tsportmap" {
		t.Errorf("scalars = %+v", c)
	}
	if want := []string{"tag:proxy", "tag:edge"}; strings.Join(c.Tags, ",") != strings.Join(want, ",") {
		t.Errorf("Tags = %v, want %v", c.Tags, want)
	}
	if !c.Ephemeral || !c.AcceptRoutes || c.RequireTailnetDest {
		t.Errorf("booleans = ephemeral:%v accept_routes:%v require_tailnet_dest:%v", c.Ephemeral, c.AcceptRoutes, c.RequireTailnetDest)
	}
	if c.ControlURL != "https://headscale.example.com" || c.MetricsAddr != "0.0.0.0:9100" {
		t.Errorf("ControlURL = %q, MetricsAddr = %q", c.ControlURL, c.MetricsAddr)
	}
	if c.DialTimeout != 3*time.Second || c.UpTimeout != 2*time.Minute || c.ShutdownGrace != 45*time.Second {
		t.Errorf("timeouts = %v %v %v", c.DialTimeout, c.UpTimeout, c.ShutdownGrace)
	}
	if c.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want %q", c.LogLevel, "debug")
	}

	// Sorted by name, case-insensitively, so startup and log order never move.
	wantNames := []string{"PG", "RESOLVER", "SYSLOG", "WEB"}
	var gotNames []string
	byName := map[string]Mapping{}
	for _, m := range c.Maps {
		gotNames = append(gotNames, m.Name)
		byName[m.Name] = m
	}
	if strings.Join(gotNames, ",") != strings.Join(wantNames, ",") {
		t.Fatalf("map order = %v, want %v", gotNames, wantNames)
	}

	pg := byName["PG"]
	if pg.Dir != Out || pg.Proto != TCP || pg.Listen != "127.0.0.1:5432" || pg.Target != "db:5432" || pg.Idle != 5*time.Minute {
		t.Errorf("PG = %+v", pg)
	}
	wantAllow := []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32"), netip.MustParsePrefix("10.0.0.0/8")}
	if len(pg.Allow) != len(wantAllow) {
		t.Fatalf("PG.Allow = %v, want %v", pg.Allow, wantAllow)
	}
	for i, p := range wantAllow {
		if pg.Allow[i] != p {
			t.Errorf("PG.Allow[%d] = %v, want %v", i, pg.Allow[i], p)
		}
	}

	// UDP without an explicit idle gets the default: a UDP session has no close
	// handshake, so an unbounded session table would grow forever.
	if r := byName["RESOLVER"]; r.Proto != UDP || r.Idle != DefaultUDPIdle {
		t.Errorf("RESOLVER = %+v, want proto udp and idle %v", r, DefaultUDPIdle)
	}
	if s := byName["SYSLOG"]; s.Dir != In || s.Proto != UDP || s.Listen != ":514" || s.Idle != 90*time.Second {
		t.Errorf("SYSLOG = %+v", s)
	}
	if w := byName["WEB"]; w.Dir != In || !w.TLS || w.Listen != ":8443" || w.Target != "127.0.0.1:8080" {
		t.Errorf("WEB = %+v", w)
	}
}

func TestFromEnvOrderingIsDeterministic(t *testing.T) {
	// Written in an order that is neither sorted nor reverse-sorted, so a
	// parser that leaked map iteration order would be caught.
	environ := []string{
		"TSPM_IN_zeta=tcp,:9001,127.0.0.1:9001",
		"TSPM_OUT_alpha=tcp,127.0.0.1:1001,a:1001",
		"TSPM_IN_Mid=udp,:9002,127.0.0.1:9002",
		"TSPM_OUT_beta=tcp,127.0.0.1:1002,b:1002",
	}
	want := "alpha,beta,Mid,zeta"
	for i := 0; i < 50; i++ {
		c := mustFromEnv(t, environ...)
		var names []string
		for _, m := range c.Maps {
			names = append(names, m.Name)
		}
		if got := strings.Join(names, ","); got != want {
			t.Fatalf("iteration %d: order = %q, want %q", i, got, want)
		}
	}
}

// Two independent conflicts must always report the same one, or an operator
// fixes a different error on every restart.
func TestFromEnvConflictReportingIsDeterministic(t *testing.T) {
	environ := []string{
		"TSPM_OUT_a1=tcp,127.0.0.1:1001,a:1001",
		"TSPM_OUT_a2=tcp,127.0.0.1:1001,a:1001",
		"TSPM_OUT_b1=tcp,127.0.0.1:1002,b:1002",
		"TSPM_OUT_b2=tcp,127.0.0.1:1002,b:1002",
	}
	_, first := FromEnv(environ)
	if first == nil {
		t.Fatal("FromEnv accepted two pairs of duplicate binds")
	}
	for i := 0; i < 50; i++ {
		if _, err := FromEnv(environ); err == nil || err.Error() != first.Error() {
			t.Fatalf("iteration %d: error = %v, want %v", i, err, first)
		}
	}
}

func TestFromEnvErrors(t *testing.T) {
	tests := []struct {
		name    string
		environ []string
		// want lists substrings every error message must contain: always the
		// offending variable, and the value it could not accept.
		want []string
	}{{
		name:    "no mappings at all",
		environ: []string{"TSPM_HOSTNAME=relay"},
		want:    []string{"no mappings configured", "TSPM_OUT_", "TSPM_IN_"},
	}, {
		name:    "empty environment",
		environ: nil,
		want:    []string{"no mappings configured"},
	}, {
		name:    "empty mapping name",
		environ: []string{"TSPM_OUT_=tcp,127.0.0.1:1,a:1"},
		want:    []string{"TSPM_OUT_", "name is empty"},
	}, {
		name:    "unknown proto",
		environ: []string{"TSPM_OUT_X=sctp,127.0.0.1:1,a:1"},
		want:    []string{"TSPM_OUT_X", `"sctp"`, "tcp", "udp"},
	}, {
		name:    "too few fields",
		environ: []string{"TSPM_OUT_X=tcp,127.0.0.1:1"},
		want:    []string{"TSPM_OUT_X", `"tcp,127.0.0.1:1"`, "<proto>,<listen>,<target>"},
	}, {
		name:    "empty spec",
		environ: []string{"TSPM_IN_X="},
		want:    []string{"TSPM_IN_X", "<proto>,<listen>,<target>"},
	}, {
		name:    "listen is not host:port",
		environ: []string{"TSPM_OUT_X=tcp,127.0.0.1,a:1"},
		want:    []string{"TSPM_OUT_X", "listen", `"127.0.0.1"`},
	}, {
		name:    "unbracketed IPv6 listen",
		environ: []string{"TSPM_OUT_X=tcp,::1:5432,a:1"},
		want:    []string{"TSPM_OUT_X", "listen", "[::1]:8080"},
	}, {
		name:    "non-numeric listen port",
		environ: []string{"TSPM_OUT_X=tcp,127.0.0.1:http,a:1"},
		want:    []string{"TSPM_OUT_X", `"http"`, "1 to 65535"},
	}, {
		name:    "listen port zero",
		environ: []string{"TSPM_OUT_X=tcp,127.0.0.1:0,a:1"},
		want:    []string{"TSPM_OUT_X", `"0"`, "1 to 65535"},
	}, {
		name:    "listen port out of range",
		environ: []string{"TSPM_OUT_X=tcp,127.0.0.1:65536,a:1"},
		want:    []string{"TSPM_OUT_X", `"65536"`, "1 to 65535"},
	}, {
		name:    "target is not host:port",
		environ: []string{"TSPM_OUT_X=tcp,127.0.0.1:1,a"},
		want:    []string{"TSPM_OUT_X", "target", `"a"`},
	}, {
		name:    "target port out of range",
		environ: []string{"TSPM_IN_X=tcp,:1,a:99999"},
		want:    []string{"TSPM_IN_X", "target", `"99999"`},
	}, {
		name:    "target without host",
		environ: []string{"TSPM_OUT_X=tcp,127.0.0.1:1,:5432"},
		want:    []string{"TSPM_OUT_X", "target", `":5432"`, "no host"},
	}, {
		name:    "out mapping without listen host",
		environ: []string{"TSPM_OUT_X=tcp,:5432,db:5432"},
		want:    []string{"TSPM_OUT_X", `":5432"`, "no host", "0.0.0.0", "::", "127.0.0.1", "platform-specific"},
	}, {
		name:    "tls on an out mapping",
		environ: []string{"TSPM_OUT_X=tcp,127.0.0.1:443,a:443,tls=true"},
		want:    []string{"TSPM_OUT_X", "tls=true", "out"},
	}, {
		name:    "tls on an in udp mapping",
		environ: []string{"TSPM_IN_X=udp,:443,127.0.0.1:443,tls=true"},
		want:    []string{"TSPM_IN_X", "tls=true", "udp"},
	}, {
		name:    "tls is not a boolean",
		environ: []string{"TSPM_IN_X=tcp,:443,127.0.0.1:443,tls=yes"},
		want:    []string{"TSPM_IN_X", `tls="yes"`},
	}, {
		name:    "unknown option key",
		environ: []string{"TSPM_OUT_X=tcp,127.0.0.1:1,a:1,deny=10.0.0.0/8"},
		want:    []string{"TSPM_OUT_X", "unknown option", `"deny"`, "allow", "idle", "tls"},
	}, {
		name:    "option without a value",
		environ: []string{"TSPM_IN_X=tcp,:1,a:1,tls"},
		want:    []string{"TSPM_IN_X", `"tls"`, "<key>=<value>"},
	}, {
		name:    "option repeated",
		environ: []string{"TSPM_IN_X=tcp,:1,a:1,tls=true,tls=false"},
		want:    []string{"TSPM_IN_X", `"tls"`, "more than once"},
	}, {
		name:    "empty option field",
		environ: []string{"TSPM_IN_X=tcp,:1,a:1,,idle=5s"},
		want:    []string{"TSPM_IN_X", "empty option"},
	}, {
		name:    "allow entry is not a CIDR",
		environ: []string{"TSPM_OUT_X=tcp,127.0.0.1:1,a:1,allow=10.0.0.1"},
		want:    []string{"TSPM_OUT_X", `"10.0.0.1"`, "not a CIDR"},
	}, {
		name:    "allow entry with a bad prefix length",
		environ: []string{"TSPM_OUT_X=tcp,127.0.0.1:1,a:1,allow=10.0.0.0/8|10.0.0.0/33"},
		want:    []string{"TSPM_OUT_X", `"10.0.0.0/33"`},
	}, {
		name:    "allow is empty",
		environ: []string{"TSPM_OUT_X=tcp,127.0.0.1:1,a:1,allow="},
		want:    []string{"TSPM_OUT_X", "allow is empty"},
	}, {
		name:    "idle is not a duration",
		environ: []string{"TSPM_OUT_X=tcp,127.0.0.1:1,a:1,idle=30"},
		want:    []string{"TSPM_OUT_X", `idle="30"`, "duration"},
	}, {
		name:    "idle is negative",
		environ: []string{"TSPM_OUT_X=tcp,127.0.0.1:1,a:1,idle=-30s"},
		want:    []string{"TSPM_OUT_X", `idle="-30s"`, "negative"},
	}, {
		name: "duplicate name across directions",
		environ: []string{
			"TSPM_OUT_db=tcp,127.0.0.1:5432,db:5432",
			"TSPM_IN_DB=tcp,:5432,127.0.0.1:5432",
		},
		want: []string{"TSPM_IN_DB", "TSPM_OUT_db", `"db"`, "case-insensitively"},
	}, {
		name: "duplicate listen address",
		environ: []string{
			"TSPM_OUT_a=tcp,127.0.0.1:5432,one:5432",
			"TSPM_OUT_b=tcp,127.0.0.1:5432,two:5432",
		},
		want: []string{"TSPM_OUT_a", "TSPM_OUT_b", "127.0.0.1:5432"},
	}, {
		name: "two out mappings spelled identically",
		environ: []string{
			"TSPM_OUT_a=tcp,0.0.0.0:8080,one:8080",
			"TSPM_OUT_b=tcp,0.0.0.0:8080,two:8080",
		},
		want: []string{"TSPM_OUT_a", "TSPM_OUT_b", "0.0.0.0:8080", `"out"`},
	}, {
		name: "two in mappings spelled identically",
		environ: []string{
			"TSPM_IN_a=tcp,:8080,127.0.0.1:8080",
			"TSPM_IN_b=tcp,:8080,127.0.0.1:8081",
		},
		want: []string{"TSPM_IN_a", "TSPM_IN_b", ":8080", `"in"`},
	}, {
		name: "duplicate listen written two ways",
		environ: []string{
			"TSPM_OUT_a=tcp,[::1]:5432,one:5432",
			"TSPM_OUT_b=tcp,[0:0:0:0:0:0:0:1]:5432,two:5432",
		},
		want: []string{"TSPM_OUT_a", "TSPM_OUT_b"},
	}, {
		name: "wildcard declared before a specific address",
		environ: []string{
			"TSPM_IN_a=tcp,:8080,127.0.0.1:8080",
			"TSPM_IN_b=tcp,100.64.0.1:8080,127.0.0.1:8081",
		},
		want: []string{"TSPM_IN_a", "TSPM_IN_b", "8080", "in"},
	}, {
		name: "wildcard declared after a specific address",
		environ: []string{
			"TSPM_IN_a=tcp,100.64.0.1:8080,127.0.0.1:8081",
			"TSPM_IN_z=tcp,:8080,127.0.0.1:8080",
		},
		want: []string{"TSPM_IN_a", "TSPM_IN_z", "8080", "in"},
	}, {
		name: "unspecified address is a wildcard too",
		environ: []string{
			"TSPM_OUT_a=tcp,0.0.0.0:8080,one:8080",
			"TSPM_OUT_b=tcp,127.0.0.1:8080,two:8080",
		},
		want: []string{"TSPM_OUT_a", "TSPM_OUT_b", "8080"},
	}, {
		name:    "boolean scalar is not a boolean",
		environ: []string{minimalOut, "TSPM_EPHEMERAL=yes"},
		want:    []string{"TSPM_EPHEMERAL", `"yes"`},
	}, {
		name:    "accept routes is not a boolean",
		environ: []string{minimalOut, "TSPM_ACCEPT_ROUTES=on"},
		want:    []string{"TSPM_ACCEPT_ROUTES", `"on"`},
	}, {
		name:    "require tailnet dest is not a boolean",
		environ: []string{minimalOut, "TSPM_REQUIRE_TAILNET_DEST=maybe"},
		want:    []string{"TSPM_REQUIRE_TAILNET_DEST", `"maybe"`},
	}, {
		name:    "duration scalar has no unit",
		environ: []string{minimalOut, "TSPM_DIAL_TIMEOUT=10"},
		want:    []string{"TSPM_DIAL_TIMEOUT", `"10"`, "duration"},
	}, {
		name:    "duration scalar is negative",
		environ: []string{minimalOut, "TSPM_UP_TIMEOUT=-1s"},
		want:    []string{"TSPM_UP_TIMEOUT", `"-1s"`, "negative"},
	}, {
		name:    "shutdown grace is not a duration",
		environ: []string{minimalOut, "TSPM_SHUTDOWN_GRACE=soon"},
		want:    []string{"TSPM_SHUTDOWN_GRACE", `"soon"`},
	}, {
		name:    "unknown log level",
		environ: []string{minimalOut, "TSPM_LOG_LEVEL=verbose"},
		want:    []string{"TSPM_LOG_LEVEL", `"verbose"`, "debug", "info", "warn", "error"},
	}, {
		name:    "metrics address is not host:port",
		environ: []string{minimalOut, "TSPM_METRICS_ADDR=9090"},
		want:    []string{"TSPM_METRICS_ADDR", `"9090"`},
	}, {
		name:    "metrics port out of range",
		environ: []string{minimalOut, "TSPM_METRICS_ADDR=127.0.0.1:0"},
		want:    []string{"TSPM_METRICS_ADDR", `"0"`},
	}, {
		name:    "tag without the tag: prefix",
		environ: []string{minimalOut, "TSPM_TAGS=proxy"},
		want:    []string{"TSPM_TAGS", `"proxy"`, "tag:"},
	}, {
		name:    "bare tag: prefix",
		environ: []string{minimalOut, "TSPM_TAGS=tag:"},
		want:    []string{"TSPM_TAGS", `"tag:"`},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := FromEnv(tt.environ)
			if err == nil {
				t.Fatalf("FromEnv(%q) = %+v, want an error", tt.environ, c)
			}
			if c != nil {
				t.Errorf("FromEnv returned a config alongside its error: %+v", c)
			}
			for _, want := range tt.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not mention %q", err, want)
				}
			}
		})
	}
}

// Configurations that look like conflicts but are not, so the duplicate
// detection cannot be tightened into rejecting workable setups.
func TestFromEnvAcceptsNonConflictingBinds(t *testing.T) {
	tests := []struct {
		name    string
		environ []string
	}{{
		name: "same port, different protocol",
		environ: []string{
			"TSPM_OUT_dnstcp=tcp,127.0.0.1:5353,dns:53",
			"TSPM_OUT_dnsudp=udp,127.0.0.1:5353,dns:53",
		},
	}, {
		name: "same port, different address",
		environ: []string{
			"TSPM_OUT_a=tcp,127.0.0.1:8080,one:80",
			"TSPM_OUT_b=tcp,192.168.1.5:8080,two:80",
		},
	}, {
		// An ingress listener is opened inside tsnet's netstack and never
		// creates a socket on the host, so it cannot take a port away from an
		// egress listener however the two are spelled.
		name: "wildcards in opposite directions",
		environ: []string{
			"TSPM_IN_web=tcp,:8080,127.0.0.1:8080",
			"TSPM_OUT_api=tcp,0.0.0.0:8080,api:8080",
		},
	}, {
		name: "in and out spelled identically",
		environ: []string{
			"TSPM_IN_web=tcp,0.0.0.0:8080,127.0.0.1:9000",
			"TSPM_OUT_api=tcp,0.0.0.0:8080,api:8080",
		},
	}, {
		name: "in and out spelled identically on a concrete address",
		environ: []string{
			"TSPM_IN_web=tcp,100.64.0.1:8080,127.0.0.1:9000",
			"TSPM_OUT_api=tcp,100.64.0.1:8080,api:8080",
		},
	}, {
		name: "same target reached by two mappings",
		environ: []string{
			"TSPM_OUT_a=tcp,127.0.0.1:5432,db:5432",
			"TSPM_OUT_b=tcp,127.0.0.1:5433,db:5432",
		},
	}, {
		// allow is documented as meaningful for egress, but an ingress relay
		// restricted to part of the tailnet is a legitimate thing to ask for.
		name:    "allow on an in mapping",
		environ: []string{"TSPM_IN_web=tcp,:8080,127.0.0.1:8080,allow=100.64.0.0/10"},
	}, {
		name:    "spaces around fields",
		environ: []string{"TSPM_OUT_a= tcp , 127.0.0.1:5432 , db:5432 , idle = 30s "},
	}, {
		name:    "uppercase proto",
		environ: []string{"TSPM_OUT_a=TCP,127.0.0.1:5432,db:5432"},
	}, {
		name:    "tls false on an out mapping",
		environ: []string{"TSPM_OUT_a=tcp,127.0.0.1:5432,db:5432,tls=false"},
	}, {
		name:    "IPv6 wildcard satisfies the out host requirement",
		environ: []string{"TSPM_OUT_a=tcp,[::]:5432,db:5432"},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := FromEnv(tt.environ); err != nil {
				t.Fatalf("FromEnv(%q) returned error: %v", tt.environ, err)
			}
		})
	}
}

func TestFromEnvTrimsMappingFields(t *testing.T) {
	c := mustFromEnv(t, "TSPM_OUT_a= tcp , 127.0.0.1:5432 , db:5432 , idle = 30s ")
	m := c.Maps[0]
	if m.Proto != TCP || m.Listen != "127.0.0.1:5432" || m.Target != "db:5432" || m.Idle != 30*time.Second {
		t.Errorf("mapping = %+v, want fields trimmed", m)
	}
}

func TestFromEnvAuthKey(t *testing.T) {
	dir := t.TempDir()
	const secret = "tskey-auth-kFakeKeyForTests"

	keyFile := filepath.Join(dir, "authkey")
	if err := os.WriteFile(keyFile, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	emptyFile := filepath.Join(dir, "empty")
	if err := os.WriteFile(emptyFile, []byte("  \n\t\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "absent")

	t.Run("literal value", func(t *testing.T) {
		c := mustFromEnv(t, minimalOut, "TSPM_AUTHKEY="+secret)
		if c.AuthKey != secret {
			t.Errorf("AuthKey = %q, want the literal value", c.AuthKey)
		}
	})

	t.Run("TS_AUTHKEY fallback", func(t *testing.T) {
		c := mustFromEnv(t, minimalOut, "TS_AUTHKEY="+secret)
		if c.AuthKey != secret {
			t.Errorf("AuthKey = %q, want the TS_AUTHKEY value", c.AuthKey)
		}
	})

	t.Run("TSPM_AUTHKEY wins over TS_AUTHKEY", func(t *testing.T) {
		c := mustFromEnv(t, minimalOut, "TSPM_AUTHKEY="+secret, "TS_AUTHKEY=tskey-auth-other")
		if c.AuthKey != secret {
			t.Errorf("AuthKey = %q, want the TSPM_AUTHKEY value", c.AuthKey)
		}
	})

	t.Run("file: reads and trims", func(t *testing.T) {
		c := mustFromEnv(t, minimalOut, "TSPM_AUTHKEY=file:"+keyFile)
		if c.AuthKey != secret {
			t.Errorf("AuthKey = %q, want %q with the trailing newline removed", c.AuthKey, secret)
		}
	})

	t.Run("file: honoured on the fallback variable too", func(t *testing.T) {
		c := mustFromEnv(t, minimalOut, "TS_AUTHKEY=file:"+keyFile)
		if c.AuthKey != secret {
			t.Errorf("AuthKey = %q, want %q", c.AuthKey, secret)
		}
	})

	errTests := []struct {
		name    string
		environ []string
		want    []string
	}{{
		name:    "missing file",
		environ: []string{minimalOut, "TSPM_AUTHKEY=file:" + missing},
		want:    []string{"TSPM_AUTHKEY", missing},
	}, {
		name:    "path is a directory",
		environ: []string{minimalOut, "TSPM_AUTHKEY=file:" + dir},
		want:    []string{"TSPM_AUTHKEY", dir},
	}, {
		name:    "empty file",
		environ: []string{minimalOut, "TSPM_AUTHKEY=file:" + emptyFile},
		want:    []string{"TSPM_AUTHKEY", emptyFile, "empty"},
	}, {
		name:    "file: with no path",
		environ: []string{minimalOut, "TSPM_AUTHKEY=file:"},
		want:    []string{"TSPM_AUTHKEY", "no path"},
	}, {
		name:    "fallback variable is named in the error",
		environ: []string{minimalOut, "TS_AUTHKEY=file:" + missing},
		want:    []string{"TS_AUTHKEY", missing},
	}}
	for _, tt := range errTests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := FromEnv(tt.environ)
			if err == nil {
				t.Fatal("FromEnv accepted an unusable auth key file")
			}
			for _, want := range tt.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not mention %q", err, want)
				}
			}
		})
	}

	t.Run("error never quotes the file contents", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root can read a 0o000 file, so the read cannot be made to fail this way")
		}
		unreadable := filepath.Join(dir, "unreadable")
		if err := os.WriteFile(unreadable, []byte(secret), 0o000); err != nil {
			t.Fatal(err)
		}
		_, err := FromEnv([]string{minimalOut, "TSPM_AUTHKEY=file:" + unreadable})
		if err == nil {
			t.Fatal("FromEnv read a file with no read permission")
		}
		if strings.Contains(err.Error(), secret) {
			t.Error("error message leaked the auth key")
		}
		if !strings.Contains(err.Error(), unreadable) {
			t.Errorf("error %q does not name the path", err)
		}
	})
}

func TestFromEnvFirstOccurrenceOfADuplicateVariableWins(t *testing.T) {
	// os.Getenv resolves a repeated key to its first occurrence; the parser
	// must not disagree with the rest of the process about what is set.
	c := mustFromEnv(t, minimalOut, "TSPM_HOSTNAME=first", "TSPM_HOSTNAME=second")
	if c.Hostname != "first" {
		t.Errorf("Hostname = %q, want %q", c.Hostname, "first")
	}
}

func TestConfigLogValueRedactsAuthKey(t *testing.T) {
	const secret = "tskey-auth-kFakeKeyForTests"
	c := mustFromEnv(t,
		"TSPM_AUTHKEY="+secret,
		"TSPM_TAGS=tag:proxy",
		"TSPM_OUT_PG=tcp,127.0.0.1:5432,db:5432,allow=10.0.0.0/8,idle=5m",
		"TSPM_IN_WEB=tcp,:8443,127.0.0.1:8080,tls=true",
	)

	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})).
		Info("config", slog.Any("config", c))
	out := buf.String()

	if strings.Contains(out, secret) {
		t.Fatalf("log output leaked the auth key: %s", out)
	}
	// Guard against a partial disclosure: no run of the key is acceptable.
	for _, fragment := range []string{secret[:8], secret[len(secret)-8:], "kFakeKey"} {
		if strings.Contains(out, fragment) {
			t.Errorf("log output leaked a fragment of the auth key (%q): %s", fragment, out)
		}
	}
	for _, want := range []string{
		"auth_key_set=true",
		"hostname=tsportmap",
		"tags=tag:proxy",
		"require_tailnet_dest=true",
		"config.maps.PG.listen=127.0.0.1:5432",
		"config.maps.PG.allow=10.0.0.0/8",
		"config.maps.PG.idle=5m0s",
		"config.maps.WEB.tls=true",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("log output does not contain %q: %s", want, out)
		}
	}
}

func TestConfigLogValueWithoutAuthKey(t *testing.T) {
	c := mustFromEnv(t, minimalOut)
	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Info("config", slog.Any("config", c))
	if got := buf.String(); !strings.Contains(got, "auth_key_set=false") {
		t.Errorf("log output = %s, want auth_key_set=false", got)
	}
}

func TestConfigLogValueNil(t *testing.T) {
	var c *Config
	if got := c.LogValue().String(); got != "<nil>" {
		t.Errorf("(*Config)(nil).LogValue() = %q, want %q", got, "<nil>")
	}
}
