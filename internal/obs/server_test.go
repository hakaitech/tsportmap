package obs

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func okCheck(context.Context) error { return nil }

func failCheck(msg string) func(context.Context) error {
	return func(context.Context) error { return errors.New(msg) }
}

func TestServerStatusCodes(t *testing.T) {
	tests := []struct {
		name         string
		method       string
		path         string
		reg          *Registry
		live         func(context.Context) error
		ready        func(context.Context) error
		wantCode     int
		wantContains string
	}{
		{
			name:     "healthz with no check is live",
			method:   http.MethodGet,
			path:     "/healthz",
			wantCode: http.StatusOK, wantContains: "ok",
		},
		{
			name:   "healthz with passing check",
			method: http.MethodGet, path: "/healthz",
			live:     okCheck,
			wantCode: http.StatusOK, wantContains: "ok",
		},
		{
			name:   "healthz with failing check",
			method: http.MethodGet, path: "/healthz",
			live:     failCheck("relay loop wedged"),
			wantCode: http.StatusServiceUnavailable, wantContains: "relay loop wedged",
		},
		{
			name:   "readyz with no check is ready",
			method: http.MethodGet, path: "/readyz",
			wantCode: http.StatusOK, wantContains: "ok",
		},
		{
			name:   "readyz with passing check",
			method: http.MethodGet, path: "/readyz",
			ready:    okCheck,
			wantCode: http.StatusOK, wantContains: "ok",
		},
		{
			name:   "readyz reports why it is not ready",
			method: http.MethodGet, path: "/readyz",
			ready:    failCheck("tsnet node not running"),
			wantCode: http.StatusServiceUnavailable, wantContains: "tsnet node not running",
		},
		{
			name:   "readyz failure does not affect healthz",
			method: http.MethodGet, path: "/healthz",
			ready:    failCheck("tsnet node not running"),
			wantCode: http.StatusOK, wantContains: "ok",
		},
		{
			name:   "metrics",
			method: http.MethodGet, path: "/metrics",
			reg:      NewRegistry(),
			wantCode: http.StatusOK, wantContains: metricBuildInfo,
		},
		{
			name:   "metrics without a registry",
			method: http.MethodGet, path: "/metrics",
			wantCode: http.StatusServiceUnavailable, wantContains: "registry",
		},
		{
			name:   "head is allowed",
			method: http.MethodHead, path: "/healthz",
			wantCode: http.StatusOK,
		},
		{
			name:   "writes are rejected",
			method: http.MethodPost, path: "/metrics",
			reg:      NewRegistry(),
			wantCode: http.StatusMethodNotAllowed,
		},
		{
			name:   "unknown path",
			method: http.MethodGet, path: "/debug/pprof/",
			wantCode: http.StatusNotFound,
		},
		{
			name:   "root is not a status endpoint",
			method: http.MethodGet, path: "/",
			wantCode: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := NewServer("127.0.0.1:0", tt.reg, tt.live, tt.ready)
			rec := httptest.NewRecorder()
			srv.Handler.ServeHTTP(rec, httptest.NewRequest(tt.method, tt.path, nil))

			if rec.Code != tt.wantCode {
				t.Errorf("%s %s = %d, want %d (body %q)", tt.method, tt.path, rec.Code, tt.wantCode, rec.Body.String())
			}
			if tt.wantContains != "" && !strings.Contains(rec.Body.String(), tt.wantContains) {
				t.Errorf("body = %q, want it to contain %q", rec.Body.String(), tt.wantContains)
			}
		})
	}
}

// The two probes answer different questions, and wiring them to each other's
// check is the mistake this test exists to catch: a liveness probe that
// consults remote state restarts a healthy process because a peer is down.
func TestProbesCallOnlyTheirOwnCheck(t *testing.T) {
	var liveCalls, readyCalls atomic.Int64
	srv := NewServer("127.0.0.1:0", NewRegistry(),
		func(context.Context) error { liveCalls.Add(1); return nil },
		func(context.Context) error { readyCalls.Add(1); return nil },
	)

	tests := []struct {
		path      string
		wantLive  int64
		wantReady int64
	}{
		{"/healthz", 1, 0},
		{"/readyz", 1, 1},
		{"/metrics", 1, 1},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			srv.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tt.path, nil))
			if got := liveCalls.Load(); got != tt.wantLive {
				t.Errorf("cumulative live calls = %d, want %d", got, tt.wantLive)
			}
			if got := readyCalls.Load(); got != tt.wantReady {
				t.Errorf("cumulative ready calls = %d, want %d", got, tt.wantReady)
			}
		})
	}
}

func TestReadyzBoundsTheCheck(t *testing.T) {
	var (
		deadline time.Time
		hasDl    bool
	)
	srv := NewServer("127.0.0.1:0", NewRegistry(), nil, func(ctx context.Context) error {
		deadline, hasDl = ctx.Deadline()
		return nil
	})

	rec := httptest.NewRecorder()
	srv.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if !hasDl {
		t.Fatal("ready was called with a context that has no deadline; a hung check would hold the probe open")
	}
	if d := time.Until(deadline); d <= 0 || d > readyTimeout {
		t.Errorf("ready deadline is %v away, want (0, %v]", d, readyTimeout)
	}
}

func TestReadyzReportsAnExpiredCheck(t *testing.T) {
	srv := NewServer("127.0.0.1:0", NewRegistry(), nil, func(ctx context.Context) error {
		// Stands in for a check that outlives its budget: the handler must
		// surface the failure rather than wait.
		ctx, cancel := context.WithTimeout(ctx, time.Nanosecond)
		defer cancel()
		<-ctx.Done()
		return ctx.Err()
	})

	rec := httptest.NewRecorder()
	srv.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	if body := rec.Body.String(); !strings.Contains(body, context.DeadlineExceeded.Error()) {
		t.Errorf("body = %q, want the deadline error", body)
	}
}

func TestMetricsResponse(t *testing.T) {
	reg := NewRegistry()
	reg.SessionOpened("alpha")
	reg.SessionClosed("alpha", 12, 34, time.Second)

	srv := NewServer("127.0.0.1:0", reg, nil, nil)
	ts := httptest.NewServer(srv.Handler)
	t.Cleanup(ts.Close)

	resp, err := ts.Client().Get(ts.URL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != contentTypeMetrics {
		t.Errorf("Content-Type = %q, want %q", got, contentTypeMetrics)
	}
	for _, want := range []string{
		`tsportmap_bytes_total{mapping="alpha",direction="up"} 12`,
		`tsportmap_bytes_total{mapping="alpha",direction="down"} 34`,
		`tsportmap_session_duration_seconds_count{mapping="alpha"} 1`,
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("body missing %q\n%s", want, body)
		}
	}
}

// An http.Server with no timeouts is a slowloris target: a client that opens a
// connection and never finishes its headers occupies it indefinitely.
func TestServerHasTimeouts(t *testing.T) {
	srv := NewServer("127.0.0.1:9090", NewRegistry(), nil, nil)

	if srv.Addr != "127.0.0.1:9090" {
		t.Errorf("Addr = %q, want the address passed in", srv.Addr)
	}
	tests := []struct {
		name string
		got  time.Duration
	}{
		{"ReadHeaderTimeout", srv.ReadHeaderTimeout},
		{"ReadTimeout", srv.ReadTimeout},
		{"WriteTimeout", srv.WriteTimeout},
		{"IdleTimeout", srv.IdleTimeout},
	}
	for _, tt := range tests {
		if tt.got <= 0 {
			t.Errorf("%s = %v, want a positive timeout", tt.name, tt.got)
		}
	}
	// A response must be allowed to outlast the readiness check it reports on.
	if srv.WriteTimeout <= readyTimeout {
		t.Errorf("WriteTimeout %v does not exceed readyTimeout %v; a slow check would be cut off mid-response", srv.WriteTimeout, readyTimeout)
	}
	if srv.MaxHeaderBytes <= 0 {
		t.Errorf("MaxHeaderBytes = %d, want a positive bound", srv.MaxHeaderBytes)
	}
}
