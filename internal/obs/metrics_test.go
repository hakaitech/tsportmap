package obs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/hakaitech/tsportmap/internal/relay"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// newTestRegistry pins the build version so exposition output does not depend
// on how the test binary was built.
func newTestRegistry(t *testing.T) *Registry {
	t.Helper()
	r := NewRegistry()
	r.version = "1.2.3"
	return r
}

func TestReasonID(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"known reason", ReasonNotTailnet, ReasonNotTailnet},
		{"allow list", ReasonAllowList, ReasonAllowList},
		{"session cap", ReasonSessionCap, ReasonSessionCap},
		{"mixed case is folded", "Dial_Timeout", ReasonDialTimeout},
		{"surrounding space is trimmed", "  refused\t", ReasonRefused},
		{"empty collapses", "", ReasonOther},
		{"raw error text collapses", "dial tcp 10.0.0.1:5432: i/o timeout", ReasonOther},
		{"near miss collapses", "dial-timeout", ReasonOther},
		{"quote injection collapses", `x" evil="1`, ReasonOther},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := reasons[reasonID(tt.input)]; got != tt.want {
				t.Errorf("reasonID(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// timeoutError is a net.Error that reports a timeout without wrapping any
// standard sentinel, as several dialers do.
type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return false }

func TestReasonForError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"nil is a misuse", nil, ReasonOther},
		{"context deadline", context.DeadlineExceeded, ReasonDialTimeout},
		{"wrapped context deadline", fmt.Errorf("dial: %w", context.DeadlineExceeded), ReasonDialTimeout},
		{"os deadline", os.ErrDeadlineExceeded, ReasonDialTimeout},
		{"net timeout", &net.OpError{Op: "dial", Err: timeoutError{}}, ReasonDialTimeout},
		{
			"connection refused",
			&net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)},
			ReasonRefused,
		},
		{"cancelled is its own reason, not a timeout", context.Canceled, ReasonCanceled},
		{"unknown error", errors.New("no such host"), ReasonOther},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ReasonForError(tt.err); got != tt.want {
				t.Errorf("ReasonForError(%v) = %q, want %q", tt.err, got, tt.want)
			}
		})
	}
}

func TestEscapeLabelValue(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"plain", "postgres", "postgres"},
		{"backslash", `a\b`, `a\\b`},
		{"double quote", `a"b`, `a\"b`},
		{"newline", "a\nb", `a\nb`},
		{"all three", "a\\\"\n", `a\\\"\n`},
		{"carriage return is left alone", "a\rb", "a\rb"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := escapeLabelValue(tt.input); got != tt.want {
				t.Errorf("escapeLabelValue(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestFormatSeconds(t *testing.T) {
	tests := []struct {
		name  string
		input time.Duration
		want  string
	}{
		{"zero", 0, "0"},
		{"one second", time.Second, "1"},
		{"fraction", 1500 * time.Millisecond, "1.5"},
		{"sub millisecond keeps no exponent", 250 * time.Microsecond, "0.00025"},
		{"large", 3 * time.Hour, "10800"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatSeconds(int64(tt.input)); got != tt.want {
				t.Errorf("formatSeconds(%v) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestBuildVersion(t *testing.T) {
	orig := Version
	t.Cleanup(func() { Version = orig })

	Version = "v1.2.3"
	if got := buildVersion(); got != "v1.2.3" {
		t.Errorf("buildVersion() = %q, want stamped version", got)
	}

	// An unstamped build must still report something, because an empty label
	// value in build_info is indistinguishable from a missing exporter.
	Version = "dev"
	if got := buildVersion(); got == "" {
		t.Error("buildVersion() = empty, want a fallback value")
	}
}

// exposition renders the registry, failing the test if rendering does.
func exposition(t *testing.T, r *Registry) string {
	t.Helper()
	var b bytes.Buffer
	if err := r.WritePrometheus(&b); err != nil {
		t.Fatalf("WritePrometheus: %v", err)
	}
	return b.String()
}

func TestWritePrometheusGolden(t *testing.T) {
	r := newTestRegistry(t)

	r.SessionOpened("alpha")
	r.SessionOpened("alpha")
	r.SessionClosed("alpha", 100, 200, 1500*time.Millisecond)
	r.Rejected("alpha", ReasonAllowList)

	r.SessionOpened("beta")
	r.SessionClosed("beta", 1, 2, 250*time.Millisecond)
	r.DialFailed("beta", ReasonRefused)
	r.DialFailed("beta", ReasonRefused)
	r.DialFailed("beta", "dial tcp 100.64.0.9:5432: no such host")

	want := `# HELP tsportmap_build_info Build information for the running tsportmap binary.
# TYPE tsportmap_build_info gauge
tsportmap_build_info{version="1.2.3"} 1
# HELP tsportmap_sessions_opened_total Sessions accepted, by mapping.
# TYPE tsportmap_sessions_opened_total counter
tsportmap_sessions_opened_total{mapping="alpha"} 2
tsportmap_sessions_opened_total{mapping="beta"} 1
# HELP tsportmap_sessions_closed_total Sessions finished, by mapping.
# TYPE tsportmap_sessions_closed_total counter
tsportmap_sessions_closed_total{mapping="alpha"} 1
tsportmap_sessions_closed_total{mapping="beta"} 1
# HELP tsportmap_sessions_active Sessions currently open, by mapping.
# TYPE tsportmap_sessions_active gauge
tsportmap_sessions_active{mapping="alpha"} 1
tsportmap_sessions_active{mapping="beta"} 0
# HELP tsportmap_bytes_total Bytes relayed, by mapping and direction: up is client to target, down is target to client.
# TYPE tsportmap_bytes_total counter
tsportmap_bytes_total{mapping="alpha",direction="down"} 200
tsportmap_bytes_total{mapping="alpha",direction="up"} 100
tsportmap_bytes_total{mapping="beta",direction="down"} 2
tsportmap_bytes_total{mapping="beta",direction="up"} 1
# HELP tsportmap_dial_failures_total Onward dials that failed, by mapping and reason.
# TYPE tsportmap_dial_failures_total counter
tsportmap_dial_failures_total{mapping="beta",reason="other"} 1
tsportmap_dial_failures_total{mapping="beta",reason="refused"} 2
# HELP tsportmap_rejected_total Sessions refused before any dial, by mapping and reason.
# TYPE tsportmap_rejected_total counter
tsportmap_rejected_total{mapping="alpha",reason="allow_list"} 1
# HELP tsportmap_session_duration_seconds Lifetime of finished sessions in seconds, by mapping.
# TYPE tsportmap_session_duration_seconds summary
tsportmap_session_duration_seconds_sum{mapping="alpha"} 1.5
tsportmap_session_duration_seconds_count{mapping="alpha"} 1
tsportmap_session_duration_seconds_sum{mapping="beta"} 0.25
tsportmap_session_duration_seconds_count{mapping="beta"} 1
`
	if got := exposition(t, r); got != want {
		t.Errorf("exposition mismatch\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestWritePrometheusEmptyRegistry(t *testing.T) {
	// A registry that has seen no traffic still identifies the build, so a
	// scrape of a freshly started node is not silently empty.
	want := `# HELP tsportmap_build_info Build information for the running tsportmap binary.
# TYPE tsportmap_build_info gauge
tsportmap_build_info{version="1.2.3"} 1
`
	got := exposition(t, newTestRegistry(t))
	if !strings.HasPrefix(got, want) {
		t.Fatalf("exposition = %q, want prefix %q", got, want)
	}
	for _, line := range strings.Split(got, "\n") {
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, metricBuildInfo) {
			continue
		}
		t.Errorf("unexpected sample from empty registry: %q", line)
	}
}

func TestWritePrometheusEscapesLabelValues(t *testing.T) {
	r := newTestRegistry(t)
	// A mapping name comes from the environment, so it can contain anything an
	// operator managed to type.
	r.SessionOpened("we\\ird\"name\nhere")

	got := exposition(t, r)
	want := `tsportmap_sessions_opened_total{mapping="we\\ird\"name\nhere"} 1`
	if !strings.Contains(got, want+"\n") {
		t.Errorf("exposition missing escaped sample %q\ngot:\n%s", want, got)
	}
	// The raw newline must not survive into the output: it would terminate the
	// sample line and corrupt the whole scrape.
	for _, line := range strings.Split(got, "\n") {
		if strings.HasPrefix(line, "here") || line == `name` {
			t.Errorf("unescaped newline split a sample line: %q", line)
		}
	}
}

func TestWritePrometheusIsDeterministic(t *testing.T) {
	r := newTestRegistry(t)
	// Enough mappings that Go's randomised map iteration would show up.
	for i := 0; i < 32; i++ {
		name := fmt.Sprintf("map-%02d", i)
		r.SessionOpened(name)
		r.SessionClosed(name, int64(i), int64(2*i), time.Duration(i)*time.Millisecond)
		r.DialFailed(name, ReasonNotTailnet)
	}

	first := exposition(t, r)
	for i := 0; i < 5; i++ {
		if got := exposition(t, r); got != first {
			t.Fatalf("exposition %d differs from the first render", i)
		}
	}

	// Within a family, samples must be ordered by mapping name.
	var names []string
	for _, line := range strings.Split(first, "\n") {
		if !strings.HasPrefix(line, metricOpened+"{") {
			continue
		}
		names = append(names, line)
	}
	if len(names) != 32 {
		t.Fatalf("got %d opened samples, want 32", len(names))
	}
	for i := 1; i < len(names); i++ {
		if names[i-1] >= names[i] {
			t.Errorf("samples out of order: %q then %q", names[i-1], names[i])
		}
	}
}

var (
	helpLine   = regexp.MustCompile(`^# (HELP|TYPE) ([a-zA-Z_:][a-zA-Z0-9_:]*) (.+)$`)
	sampleLine = regexp.MustCompile(`^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{([a-zA-Z_][a-zA-Z0-9_]*="(?:[^"\\\n]|\\.)*"(?:,[a-zA-Z_][a-zA-Z0-9_]*="(?:[^"\\\n]|\\.)*")*)\})? (\S+)$`)
)

func TestWritePrometheusIsWellFormed(t *testing.T) {
	r := newTestRegistry(t)
	r.SessionOpened(`odd"name`)
	r.SessionClosed(`odd"name`, 7, 11, 3*time.Second)
	r.SessionOpened("plain")
	r.Rejected("plain", ReasonSessionCap)
	r.DialFailed("plain", ReasonDialTimeout)

	declared := map[string]string{}
	seen := map[string]bool{}
	for i, line := range strings.Split(exposition(t, r), "\n") {
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			m := helpLine.FindStringSubmatch(line)
			if m == nil {
				t.Errorf("line %d: malformed metadata: %q", i+1, line)
				continue
			}
			if m[1] == "TYPE" {
				declared[m[2]] = m[3]
			}
			continue
		}

		m := sampleLine.FindStringSubmatch(line)
		if m == nil {
			t.Errorf("line %d: malformed sample: %q", i+1, line)
			continue
		}
		family := strings.TrimSuffix(strings.TrimSuffix(m[1], "_sum"), "_count")
		if _, ok := declared[family]; !ok {
			t.Errorf("line %d: sample for %q precedes or lacks its # TYPE", i+1, family)
		}
		if _, err := strconv.ParseFloat(m[3], 64); err != nil {
			t.Errorf("line %d: value %q is not a number: %v", i+1, m[3], err)
		}
		series := m[1] + "{" + m[2] + "}"
		if seen[series] {
			t.Errorf("line %d: duplicate series %q", i+1, series)
		}
		seen[series] = true
	}

	for _, want := range []string{metricBuildInfo, metricOpened, metricClosed, metricActive, metricBytes, metricDialFailures, metricRejected, metricDuration} {
		if _, ok := declared[want]; !ok {
			t.Errorf("no # TYPE emitted for %q", want)
		}
	}
	if got := declared[metricDuration]; got != "summary" {
		t.Errorf("%s declared as %q, want summary", metricDuration, got)
	}
	if got := declared[metricActive]; got != "gauge" {
		t.Errorf("%s declared as %q, want gauge", metricActive, got)
	}
}

func TestUnknownReasonsCollapseToOther(t *testing.T) {
	r := newTestRegistry(t)
	// Every one of these is a distinct error string of the kind a network
	// stack produces; none of them may become its own time series.
	for i := 0; i < 50; i++ {
		r.DialFailed("gateway", fmt.Sprintf("dial tcp 100.64.0.%d:443: i/o timeout", i))
		r.Rejected("gateway", fmt.Sprintf("peer %d not permitted", i))
	}
	r.DialFailed("gateway", ReasonNotTailnet)

	got := exposition(t, r)
	wants := []string{
		`tsportmap_dial_failures_total{mapping="gateway",reason="not_tailnet"} 1`,
		`tsportmap_dial_failures_total{mapping="gateway",reason="other"} 50`,
		`tsportmap_rejected_total{mapping="gateway",reason="other"} 50`,
	}
	for _, want := range wants {
		if !strings.Contains(got, want+"\n") {
			t.Errorf("exposition missing %q\ngot:\n%s", want, got)
		}
	}
	if n := strings.Count(got, `tsportmap_dial_failures_total{`); n != 2 {
		t.Errorf("got %d dial failure series, want 2 (the reason set must be closed)\n%s", n, got)
	}
	if n := strings.Count(got, `tsportmap_rejected_total{`); n != 1 {
		t.Errorf("got %d rejected series, want 1\n%s", n, got)
	}
}

func TestSessionsActiveReturnsToZero(t *testing.T) {
	r := newTestRegistry(t)
	r.SessionOpened("db")
	r.SessionOpened("db")
	if want := `tsportmap_sessions_active{mapping="db"} 2` + "\n"; !strings.Contains(exposition(t, r), want) {
		t.Errorf("active gauge did not reach 2")
	}

	r.SessionClosed("db", 1, 1, time.Second)
	r.SessionClosed("db", 1, 1, time.Second)
	if want := `tsportmap_sessions_active{mapping="db"} 0` + "\n"; !strings.Contains(exposition(t, r), want) {
		t.Errorf("active gauge did not return to zero\n%s", exposition(t, r))
	}
}

func TestConcurrentRecording(t *testing.T) {
	const (
		goroutines = 8
		iterations = 500
	)
	names := []string{"alpha", "beta", "gamma", "delta"}

	r := newTestRegistry(t)
	stop := make(chan struct{})
	var scrapes sync.WaitGroup
	scrapes.Add(1)
	go func() {
		// Scraping concurrently with recording is the normal case, so it is
		// what the race detector must see.
		defer scrapes.Done()
		for {
			select {
			case <-stop:
				return
			default:
				var b bytes.Buffer
				if err := r.WritePrometheus(&b); err != nil {
					t.Errorf("WritePrometheus: %v", err)
					return
				}
			}
		}
	}()

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				name := names[(g+i)%len(names)]
				r.SessionOpened(name)
				r.SessionClosed(name, 3, 5, 2*time.Millisecond)
				r.DialFailed(name, ReasonRefused)
				r.Rejected(name, fmt.Sprintf("unrecognised %d", i))
			}
		}(g)
	}
	wg.Wait()
	close(stop)
	scrapes.Wait()

	const total = goroutines * iterations
	var (
		opened, closed, up, down int64
		nanos, durCount          int64
		refused, other           int64
	)
	for _, name := range names {
		s := r.forName(name)
		opened += s.opened.Load()
		closed += s.closed.Load()
		up += s.bytesUp.Load()
		down += s.bytesDn.Load()
		nanos += s.durNanos.Load()
		durCount += s.durCount.Load()
		refused += s.dialFailures[reasonIndex[ReasonRefused]].Load()
		other += s.rejected[otherIndex].Load()

		if active := s.opened.Load() - s.closed.Load(); active != 0 {
			t.Errorf("%s: active sessions = %d, want 0", name, active)
		}
	}

	checks := []struct {
		name string
		got  int64
		want int64
	}{
		{"sessions opened", opened, total},
		{"sessions closed", closed, total},
		{"bytes up", up, 3 * total},
		{"bytes down", down, 5 * total},
		{"duration count", durCount, total},
		{"duration nanos", nanos, int64(2*time.Millisecond) * total},
		{"dial failures refused", refused, total},
		{"rejections collapsed to other", other, total},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
}

// errWriter fails on the first byte, standing in for a client that hung up
// mid-scrape.
type errWriter struct{ err error }

func (w errWriter) Write([]byte) (int, error) { return 0, w.err }

func TestWritePrometheusWriteError(t *testing.T) {
	r := newTestRegistry(t)
	r.SessionOpened("alpha")

	sentinel := errors.New("client went away")
	err := r.WritePrometheus(errWriter{err: sentinel})
	if !errors.Is(err, sentinel) {
		t.Fatalf("WritePrometheus err = %v, want %v", err, sentinel)
	}
}

// TestEveryRelayReasonIsRecognised pins the seam between the package that
// produces reasons and the package that exposes them.
//
// These were once two independent vocabularies: relay said "source not
// allowed" and "session table full" while the registry only recognised
// "allow_list" and "session_cap", so every rejection and every dial failure
// silently collapsed into reason="other" — including not_tailnet, the one
// failure this tool exists to catch. Aliasing the constants makes that
// impossible, and this test fails if anyone reintroduces a private literal.
func TestEveryRelayReasonIsRecognised(t *testing.T) {
	t.Parallel()

	all := []string{
		relay.ReasonAllowList,
		relay.ReasonCanceled,
		relay.ReasonDNS,
		relay.ReasonDialTimeout,
		relay.ReasonNotTailnet,
		relay.ReasonOther,
		relay.ReasonRefused,
		relay.ReasonSessionCap,
	}
	for _, reason := range all {
		if reason == relay.ReasonOther {
			continue
		}
		if got := reasonID(reason); got == otherIndex {
			t.Errorf("reason %q collapsed to %q; the registry does not know it",
				reason, ReasonOther)
		}
	}

	// A reason the registry genuinely does not know must still be bounded.
	if got := reasonID("a phrase someone invented"); got != otherIndex {
		t.Errorf("unknown reason mapped to index %d, want the %q bucket", got, ReasonOther)
	}
}
