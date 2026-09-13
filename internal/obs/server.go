package obs

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"time"
)

// readyTimeout bounds a readiness check. It is short because a probe that
// hangs is indistinguishable from a probe that failed, except that the hanging
// one also occupies a connection until the orchestrator gives up.
const readyTimeout = 5 * time.Second

// contentTypeMetrics is the media type of the Prometheus text exposition
// format, version 0.0.4.
const contentTypeMetrics = "text/plain; version=0.0.4; charset=utf-8"

// NewServer returns an http.Server exposing /healthz, /readyz and /metrics.
//
// None of these endpoints is authenticated: anything that can reach the bind
// address can read every mapping name and byte counter this node relays, which
// is a description of an operator's private topology. That is why the default
// bind is loopback and why exposing it more widely is a deliberate act.
//
// live must only examine process-local state; see the /healthz handler for
// why. ready may examine remote state, such as whether the tsnet node has
// reached Running. Either may be nil, which means "always healthy" and
// "always ready" respectively.
//
// The returned server is not started; the caller owns ListenAndServe and
// Shutdown so that the status endpoints can outlive the relays during a
// graceful drain.
func NewServer(addr string, reg *Registry, live, ready func(context.Context) error) *http.Server {
	mux := http.NewServeMux()

	// Liveness answers exactly one question: can this process still serve a
	// request? It deliberately does not reach out to the tailnet, to a peer,
	// or to a relay target. A liveness probe that depends on a remote host
	// turns someone else's outage into a restart loop here, and restarting
	// tsportmap cannot repair a peer that is down. Remote state belongs in
	// readiness, where failing merely removes this instance from service.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if live != nil {
			if err := live(r.Context()); err != nil {
				http.Error(w, err.Error(), http.StatusServiceUnavailable)
				return
			}
		}
		writeOK(w)
	})

	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if ready != nil {
			ctx, cancel := context.WithTimeout(r.Context(), readyTimeout)
			defer cancel()
			if err := ready(ctx); err != nil {
				http.Error(w, err.Error(), http.StatusServiceUnavailable)
				return
			}
		}
		writeOK(w)
	})

	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		if reg == nil {
			http.Error(w, "metrics registry not configured", http.StatusServiceUnavailable)
			return
		}
		// Rendered into a buffer first so a failure can still be reported as a
		// status code. Writing straight to the ResponseWriter would commit a
		// 200 before the first byte could fail.
		var buf bytes.Buffer
		if err := reg.WritePrometheus(&buf); err != nil {
			http.Error(w, "rendering metrics: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", contentTypeMetrics)
		w.Write(buf.Bytes())
	})

	return &http.Server{
		Addr:    addr,
		Handler: mux,
		// An http.Server with no timeouts holds a connection open for as long
		// as a peer keeps dribbling bytes, so a handful of idle sockets can
		// exhaust it. These bound every phase of a request; WriteTimeout is
		// set above readyTimeout so a slow readiness check reports 503 rather
		// than having its response cut off.
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      readyTimeout + 10*time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 16,
		// Routes the server's own protocol errors into the structured log
		// rather than the standard logger's stderr. The handler is resolved
		// once, so the process should install its default logger before
		// building the server.
		ErrorLog: slog.NewLogLogger(slog.Default().Handler(), slog.LevelWarn),
	}
}

func writeOK(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Write([]byte("ok\n"))
}
