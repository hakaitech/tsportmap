package obs

import (
	"bytes"
	"regexp"
	"strconv"
	"sync"
	"testing"
	"time"
)

var activeGaugeSample = regexp.MustCompile(`(?m)^tsportmap_sessions_active\{mapping="[^"]*"\} (-?\d+)$`)

// TestSessionsActiveIsNeverNegativeUnderChurn scrapes while sessions are
// opening and closing.
//
// The active gauge is derived from two independent atomic counters, so a
// scrape that reads them in the wrong order can observe a session's close
// without its open and publish a negative value. Prometheus has no way to
// distinguish that from a real accounting fault, so the exposition must never
// produce one however the two loads interleave with recording.
func TestSessionsActiveIsNeverNegativeUnderChurn(t *testing.T) {
	const (
		writers = 8
		scrapes = 1500
	)

	r := newTestRegistry(t)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				r.SessionOpened("db")
				r.SessionClosed("db", 1, 2, time.Millisecond)
			}
		}()
	}

	var b bytes.Buffer
	for i := 0; i < scrapes; i++ {
		b.Reset()
		if err := r.WritePrometheus(&b); err != nil {
			close(stop)
			wg.Wait()
			t.Fatalf("WritePrometheus: %v", err)
		}
		for _, m := range activeGaugeSample.FindAllStringSubmatch(b.String(), -1) {
			v, err := strconv.ParseInt(m[1], 10, 64)
			if err != nil {
				close(stop)
				wg.Wait()
				t.Fatalf("active gauge %q is not an integer: %v", m[1], err)
			}
			if v < 0 {
				close(stop)
				wg.Wait()
				t.Fatalf("scrape %d published a negative active gauge: %s", i, m[0])
			}
		}
	}

	close(stop)
	wg.Wait()

	// The counters must still balance once everything has stopped, so the
	// ordering above cannot have been bought with a lost increment.
	if got := exposition(t, r); !activeGaugeSample.MatchString(got) {
		t.Fatalf("no active gauge in the final exposition:\n%s", got)
	}
	final := activeGaugeSample.FindStringSubmatch(exposition(t, r))
	if final[1] != "0" {
		t.Errorf("active gauge settled at %s, want 0", final[1])
	}
}
