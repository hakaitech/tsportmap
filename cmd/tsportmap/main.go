// Command tsportmap relays declared port mappings in both directions across a
// tailnet, through a single embedded Tailscale node.
//
// It is configured entirely from the environment; see the internal/config
// package for the grammar. Only pre-declared mappings work: there is
// deliberately no SOCKS5 and no HTTP CONNECT, so a caller can only ever reach
// what an operator wrote down.
//
// This file is a shell. It resolves flags, installs signal handling and hands
// off to internal/app, which owns every decision about startup and shutdown.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"

	"github.com/hakaitech/tsportmap/internal/app"
	"github.com/hakaitech/tsportmap/internal/obs"
)

const usage = `tsportmap relays declared port mappings across a tailnet.

Usage:
  tsportmap [flags]

Configuration comes from the environment:
  TSPM_OUT_<NAME>=<proto>,<listen>,<target>[,<key>=<value>]...   egress: listen locally, dial a tailnet peer
  TSPM_IN_<NAME>=<proto>,<listen>,<target>[,<key>=<value>]...    ingress: listen on the tailnet, dial a local target

  proto   tcp | udp
  listen  host:port; bracket IPv6. Required host for out; in may omit it.
  target  host:port
  options tls=true (in+tcp only), allow=CIDR|CIDR..., idle=<duration>

Run with --validate to check the configuration and print what it would expose
without touching the network.

Flags:
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("tsportmap", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, usage)
		fs.PrintDefaults()
	}
	showVersion := fs.Bool("version", false, "print the version and exit")
	validate := fs.Bool("validate", false, "parse and validate the configuration, print what it would expose, and exit without touching the network")
	if err := fs.Parse(args); err != nil {
		// ContinueOnError has already printed the problem and the usage.
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "tsportmap: unexpected argument %q; tsportmap is configured from the environment, not from arguments\n", fs.Arg(0))
		return 2
	}

	v := version()
	if *showVersion {
		fmt.Fprintf(stdout, "tsportmap %s\n", v)
		return 0
	}

	if *validate {
		if err := app.Validate(os.Environ(), v, stdout); err != nil {
			fmt.Fprintf(stderr, "tsportmap: %v\n", err)
			return 1
		}
		return 0
	}

	// A default logger is installed before anything can log, so a message from
	// a dependency emitted before app.Run builds the configured logger still
	// reaches stderr in the same format. app.Run replaces it once the log level
	// is known.
	slog.SetDefault(slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	// SIGTERM is how an orchestrator asks for a drain and SIGINT is how a
	// person does; both cancel the context, which app.Run turns into a
	// graceful shutdown. NotifyContext restores the default disposition on the
	// second signal, so an operator who is out of patience can still kill an
	// instance that is refusing to finish draining.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := app.Run(ctx, os.Environ(), v, stderr); err != nil {
		fmt.Fprintf(stderr, "tsportmap: %v\n", err)
		return 1
	}
	return 0
}

// version identifies this build.
//
// A release stamps internal/obs.Version with
// -ldflags "-X github.com/hakaitech/tsportmap/internal/obs.Version=v1.2.3",
// which is the same variable the tsportmap_build_info metric reports, so the
// banner and the metric cannot disagree. An unstamped binary falls back to what
// the module system recorded, which is what a `go install`ed build has.
func version() string {
	if v := strings.TrimSpace(obs.Version); v != "" && v != "dev" {
		return v
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" && s.Value != "" {
			return s.Value
		}
	}
	if info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}
