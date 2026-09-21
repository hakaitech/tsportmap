// Package obs holds tsportmap's observability surface: a metrics registry that
// implements relay.Recorder and the small HTTP server that exposes it.
//
// The Prometheus text exposition format is hand-written here rather than
// pulled from a client library. tsportmap ships as one container image whose
// only third-party module is tailscale.com, and keeping it that way is worth
// more than the features of a metrics library that this tool would not use:
// the whole exposition is a handful of counters over a closed set of labels.
package obs

import (
	"bytes"
	"io"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hakaitech/tsportmap/internal/relay"
)

// Registry implements relay.Recorder.
var _ relay.Recorder = (*Registry)(nil)

// Version is the build version reported by tsportmap_build_info. It is a
// variable so a release build can stamp it with
// -ldflags "-X github.com/hakaitech/tsportmap/internal/obs.Version=v1.2.3";
// when it is left at its default the registry falls back to the version
// recorded in the binary by the module system.
var Version = "dev"

// Reasons for a dial failure or a rejection. These are the only values that
// ever reach the "reason" label: the label set is closed so that a novel error
// string from the network stack cannot mint a new time series on every
// connection. Anything unrecognised becomes ReasonOther.
//
// Each is an alias of the constant in package relay, which produces the values.
// Aliasing rather than restating them means a reason cannot be renamed on one
// side and silently collapse into "other" on the other.
const (
	// ReasonAllowList is a source address outside a mapping's allow list.
	ReasonAllowList = relay.ReasonAllowList
	// ReasonCanceled is a dial abandoned because its context was cancelled.
	ReasonCanceled = relay.ReasonCanceled
	// ReasonDNS is a name that could not be resolved.
	ReasonDNS = relay.ReasonDNS
	// ReasonDialTimeout is an onward dial that ran out of time.
	ReasonDialTimeout = relay.ReasonDialTimeout
	// ReasonNoRoute is a destination outside every AllowedIPs on the WireGuard
	// interface a mapping uses.
	ReasonNoRoute = relay.ReasonNoRoute
	// ReasonNotTailnet is a destination the guard could not confirm is a
	// tailnet peer or an eligible route, so the dial was refused rather than
	// allowed to fall through to the host network.
	ReasonNotTailnet = relay.ReasonNotTailnet
	// ReasonOther is every reason not named here.
	ReasonOther = relay.ReasonOther
	// ReasonQueueFull is a datagram dropped because the session's egress queue
	// was full.
	ReasonQueueFull = relay.ReasonQueueFull
	// ReasonRefused is an onward dial actively refused by the target.
	ReasonRefused = relay.ReasonRefused
	// ReasonSessionCap is a session refused because a limit was already
	// reached.
	ReasonSessionCap = relay.ReasonSessionCap
)

// reasons is the closed reason set in the order it is exposed. It is sorted by
// label value so exposition output is byte-stable across runs.
var reasons = [...]string{
	ReasonAllowList,
	ReasonCanceled,
	ReasonDNS,
	ReasonDialTimeout,
	ReasonNoRoute,
	ReasonNotTailnet,
	ReasonOther,
	ReasonQueueFull,
	ReasonRefused,
	ReasonSessionCap,
}

// directions are the values of the "direction" label on the byte counters,
// alphabetically ordered for the same stability reason as reasons.
var directions = [...]string{directionDown, directionUp}

const (
	directionDown = "down"
	directionUp   = "up"
)

var (
	reasonIndex = func() map[string]int {
		m := make(map[string]int, len(reasons))
		for i, r := range reasons {
			m[r] = i
		}
		return m
	}()
	otherIndex = reasonIndex[ReasonOther]
)

// reasonID maps a caller-supplied reason onto the closed set. Surrounding
// space and letter case are forgiven because they change nothing about which
// series a sample belongs in; anything else unrecognised collapses to
// ReasonOther.
func reasonID(reason string) int {
	if i, ok := reasonIndex[strings.ToLower(strings.TrimSpace(reason))]; ok {
		return i
	}
	return otherIndex
}

// ReasonForError classifies a dial error into the closed reason set. The
// classification itself lives in package relay so that the producer of a reason
// and the exposer of it can never disagree.
func ReasonForError(err error) string {
	return relay.ReasonForError(err)
}

// mapStats is one mapping's counters. Every field is an atomic so recording is
// lock-free once the mapping has been looked up: the registry's mutex is taken
// only to find or create this struct, never to increment it. The reason
// counters are a fixed-size array rather than a map, which makes the bounded
// label set a property of the type instead of a rule to remember.
type mapStats struct {
	opened   atomic.Int64
	closed   atomic.Int64
	bytesUp  atomic.Int64
	bytesDn  atomic.Int64
	durNanos atomic.Int64
	durCount atomic.Int64

	dialFailures [len(reasons)]atomic.Int64
	rejected     [len(reasons)]atomic.Int64
}

// Registry records relay activity and renders it as Prometheus text.
//
// Mapping names are not collapsed the way reasons are: a name can only come
// from a mapping an operator declared in the environment, so the set is fixed
// at startup and small.
type Registry struct {
	version string

	mu    sync.RWMutex
	stats map[string]*mapStats
	// wg is consulted at scrape time; see SetWireGuard.
	wg WireGuardSource
}

// NewRegistry returns a Recorder that also exposes Prometheus text metrics.
func NewRegistry() *Registry {
	return &Registry{
		version: buildVersion(),
		stats:   make(map[string]*mapStats),
	}
}

// buildVersion prefers the stamped Version and otherwise reports what the
// module system recorded, so a `go install`ed binary still identifies itself.
func buildVersion() string {
	if v := strings.TrimSpace(Version); v != "" && v != "dev" {
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

// forName returns the counters for a mapping, creating them on first use. The
// read lock carries the common case; the write lock is taken once per mapping
// for the lifetime of the process.
func (r *Registry) forName(name string) *mapStats {
	r.mu.RLock()
	s, ok := r.stats[name]
	r.mu.RUnlock()
	if ok {
		return s
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.stats[name]; ok {
		return s
	}
	s = &mapStats{}
	r.stats[name] = s
	return s
}

// SessionOpened records an accepted session.
func (r *Registry) SessionOpened(name string) {
	r.forName(name).opened.Add(1)
}

// SessionClosed records a finished session, the bytes it moved in each
// direction and how long it lived.
func (r *Registry) SessionClosed(name string, up, down int64, d time.Duration) {
	s := r.forName(name)
	s.closed.Add(1)
	s.bytesUp.Add(up)
	s.bytesDn.Add(down)
	// Durations accumulate in nanoseconds and are divided only at exposition
	// time: an integer sum is exact and needs no compare-and-swap loop, which
	// a float64 accumulator would.
	s.durNanos.Add(int64(d))
	s.durCount.Add(1)
}

// DialFailed records an onward dial that did not succeed.
func (r *Registry) DialFailed(name, reason string) {
	s := r.forName(name)
	s.dialFailures[reasonID(reason)].Add(1)
}

// Rejected records a session refused before any dial.
func (r *Registry) Rejected(name, reason string) {
	s := r.forName(name)
	s.rejected[reasonID(reason)].Add(1)
}

type namedStats struct {
	name  string
	stats *mapStats
}

// snapshot lists the mappings in name order. It copies the map under the read
// lock and reads the counters outside it, so exposition never blocks recording.
func (r *Registry) snapshot() []namedStats {
	r.mu.RLock()
	out := make([]namedStats, 0, len(r.stats))
	for name, s := range r.stats {
		out = append(out, namedStats{name: name, stats: s})
	}
	r.mu.RUnlock()

	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

const (
	metricBuildInfo    = "tsportmap_build_info"
	metricOpened       = "tsportmap_sessions_opened_total"
	metricClosed       = "tsportmap_sessions_closed_total"
	metricActive       = "tsportmap_sessions_active"
	metricBytes        = "tsportmap_bytes_total"
	metricDialFailures = "tsportmap_dial_failures_total"
	metricRejected     = "tsportmap_rejected_total"
	metricDuration     = "tsportmap_session_duration_seconds"
)

// WritePrometheus renders the registry in the Prometheus text exposition
// format. The output is deterministic — families in a fixed order, series
// sorted by mapping name and then by label value — so a diff of two scrapes
// shows only what actually changed.
func (r *Registry) WritePrometheus(w io.Writer) error {
	all := r.snapshot()
	var b bytes.Buffer

	writeHeader(&b, metricBuildInfo, "gauge", "Build information for the running tsportmap binary.")
	writeSample(&b, metricBuildInfo, []labelPair{{"version", r.version}}, "1")

	writeHeader(&b, metricOpened, "counter", "Sessions accepted, by mapping.")
	for _, m := range all {
		writeSample(&b, metricOpened, mappingLabel(m.name), strconv.FormatInt(m.stats.opened.Load(), 10))
	}

	writeHeader(&b, metricClosed, "counter", "Sessions finished, by mapping.")
	for _, m := range all {
		writeSample(&b, metricClosed, mappingLabel(m.name), strconv.FormatInt(m.stats.closed.Load(), 10))
	}

	writeHeader(&b, metricActive, "gauge", "Sessions currently open, by mapping.")
	for _, m := range all {
		// Derived rather than tracked separately so the gauge cannot drift
		// away from the two counters that define it.
		//
		// closed is loaded first because the pair is not read atomically: a
		// session that finishes between the two loads would otherwise be
		// counted in closed but not in opened, publishing a negative gauge
		// for a scrape that happened to land in that window. Reading closed
		// first can only understate the closes relative to the opens, so the
		// worst case is a momentarily stale value that is still >= 0.
		closed := m.stats.closed.Load()
		active := m.stats.opened.Load() - closed
		writeSample(&b, metricActive, mappingLabel(m.name), strconv.FormatInt(active, 10))
	}

	writeHeader(&b, metricBytes, "counter", "Bytes relayed, by mapping and direction: up is client to target, down is target to client.")
	for _, m := range all {
		for _, dir := range directions {
			var v int64
			switch dir {
			case directionUp:
				v = m.stats.bytesUp.Load()
			case directionDown:
				v = m.stats.bytesDn.Load()
			}
			writeSample(&b, metricBytes, []labelPair{{"mapping", m.name}, {"direction", dir}}, strconv.FormatInt(v, 10))
		}
	}

	// Only reasons that have actually occurred get a series. Emitting the full
	// cross product of mappings and reasons would multiply the series count by
	// six to say "nothing went wrong", which is what the absence of the series
	// already says.
	writeHeader(&b, metricDialFailures, "counter", "Onward dials that failed, by mapping and reason.")
	for _, m := range all {
		writeReasonSamples(&b, metricDialFailures, m.name, &m.stats.dialFailures)
	}

	writeHeader(&b, metricRejected, "counter", "Sessions refused before any dial, by mapping and reason.")
	for _, m := range all {
		writeReasonSamples(&b, metricRejected, m.name, &m.stats.rejected)
	}

	writeHeader(&b, metricDuration, "summary", "Lifetime of finished sessions in seconds, by mapping.")
	for _, m := range all {
		writeSample(&b, metricDuration+"_sum", mappingLabel(m.name), formatSeconds(m.stats.durNanos.Load()))
		writeSample(&b, metricDuration+"_count", mappingLabel(m.name), strconv.FormatInt(m.stats.durCount.Load(), 10))
	}

	// Last, and omitted entirely on a node with no WireGuard interface, so that
	// the exposition of a tailnet-only node is byte-for-byte what it was before
	// WireGuard existed.
	r.writeWireGuard(&b)

	_, err := w.Write(b.Bytes())
	return err
}

func writeReasonSamples(b *bytes.Buffer, metric, mapping string, counters *[len(reasons)]atomic.Int64) {
	for i, reason := range reasons {
		v := counters[i].Load()
		if v == 0 {
			continue
		}
		writeSample(b, metric, []labelPair{{"mapping", mapping}, {"reason", reason}}, strconv.FormatInt(v, 10))
	}
}

type labelPair struct {
	name  string
	value string
}

func mappingLabel(name string) []labelPair {
	return []labelPair{{"mapping", name}}
}

// writeHeader emits the HELP and TYPE lines for a metric family. Help strings
// are compile-time constants in this package and deliberately contain no
// backslash or newline, the two characters the format would require escaping
// there.
func writeHeader(b *bytes.Buffer, metric, typ, help string) {
	b.WriteString("# HELP ")
	b.WriteString(metric)
	b.WriteByte(' ')
	b.WriteString(help)
	b.WriteString("\n# TYPE ")
	b.WriteString(metric)
	b.WriteByte(' ')
	b.WriteString(typ)
	b.WriteByte('\n')
}

func writeSample(b *bytes.Buffer, metric string, labels []labelPair, value string) {
	b.WriteString(metric)
	if len(labels) > 0 {
		b.WriteByte('{')
		for i, l := range labels {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(l.name)
			b.WriteString(`="`)
			b.WriteString(escapeLabelValue(l.value))
			b.WriteByte('"')
		}
		b.WriteByte('}')
	}
	b.WriteByte(' ')
	b.WriteString(value)
	b.WriteByte('\n')
}

// escapeLabelValue applies the three escapes the text exposition format
// defines for a label value: backslash, double quote and line feed. A mapping
// name reaches this from an environment variable, so it is not trusted to be
// free of them — an unescaped quote would produce a scrape the collector
// rejects wholesale, losing every metric and not just the odd one.
func escapeLabelValue(v string) string {
	if !strings.ContainsAny(v, "\\\"\n") {
		return v
	}
	var b strings.Builder
	b.Grow(len(v) + 8)
	for _, c := range []byte(v) {
		switch c {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// formatSeconds renders accumulated nanoseconds as seconds without an
// exponent, which keeps the golden output readable and is accepted by every
// text-format parser.
func formatSeconds(nanos int64) string {
	return strconv.FormatFloat(float64(nanos)/float64(time.Second), 'f', -1, 64)
}
