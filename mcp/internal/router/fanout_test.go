package router

import (
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestFanoutBounded_NeverExceedsLimit — locks down the worker-pool
// guarantee.  Pre-B the fan-out spawned unbounded goroutines, which
// at 1000-host scale opens a thousand outbound mTLS connections
// simultaneously and burns file descriptors.  This test asserts the
// peak concurrent in-flight count stays at or below the configured
// limit regardless of input size.
func TestFanoutBounded_NeverExceedsLimit(t *testing.T) {
	const (
		hostCount = 200
		limit     = 8
	)
	hostnames := make([]string, hostCount)
	for i := range hostnames {
		hostnames[i] = "host-" + strconv.Itoa(i)
	}

	var inFlight, peak atomic.Int32
	work := func(_ string) int {
		cur := inFlight.Add(1)
		// Update peak with a CAS loop so the assertion sees the true
		// high-water mark across goroutines.
		for {
			p := peak.Load()
			if cur <= p || peak.CompareAndSwap(p, cur) {
				break
			}
		}
		// Hold the slot long enough that all parallel work overlaps.
		time.Sleep(5 * time.Millisecond)
		inFlight.Add(-1)
		return 1
	}

	got := fanoutBounded(hostnames, limit, work)

	if len(got) != hostCount {
		t.Fatalf("got %d results, want %d", len(got), hostCount)
	}
	if peak.Load() > limit {
		t.Fatalf("peak in-flight = %d, exceeded limit %d", peak.Load(), limit)
	}
	// Sanity check the cap actually engaged (peak should saturate with
	// hostCount >> limit).  If peak is much less than limit, the test
	// isn't actually exercising the bound.
	if peak.Load() < limit/2 {
		t.Logf("warning: peak in-flight %d well below limit %d — test may not be exercising the bound",
			peak.Load(), limit)
	}
}

// TestFanoutBounded_PreservesOrder — results must come back in the
// same order as inputs even though goroutines complete in arbitrary
// order.  This is the property callers rely on to correlate a host
// in the input slice with its result in the output slice.
func TestFanoutBounded_PreservesOrder(t *testing.T) {
	hostnames := []string{"alpha", "bravo", "charlie", "delta"}
	// Sleep an amount that's inversely related to input position so
	// later inputs finish first — exposes any indexing bug.
	work := func(h string) string {
		var d time.Duration
		switch h {
		case "alpha":
			d = 40 * time.Millisecond
		case "bravo":
			d = 30 * time.Millisecond
		case "charlie":
			d = 20 * time.Millisecond
		case "delta":
			d = 10 * time.Millisecond
		}
		time.Sleep(d)
		return h + ":done"
	}

	got := fanoutBounded(hostnames, 4, work)
	want := []string{"alpha:done", "bravo:done", "charlie:done", "delta:done"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("result[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestFanoutBounded_ZeroLimitFallsBackToUnbounded — guard against a
// caller forgetting to set the limit; we don't want to deadlock.
func TestFanoutBounded_ZeroLimitFallsBackToUnbounded(t *testing.T) {
	hostnames := []string{"a", "b", "c"}
	var counter atomic.Int32
	work := func(_ string) int { counter.Add(1); return 0 }
	got := fanoutBounded(hostnames, 0, work)
	if len(got) != 3 || counter.Load() != 3 {
		t.Fatalf("expected 3 calls, got %d (results=%v)", counter.Load(), got)
	}
}

// TestFanoutBounded_EmptyInput — defensive: empty hostnames should
// return empty results, not panic, and not block on the semaphore.
func TestFanoutBounded_EmptyInput(t *testing.T) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		got := fanoutBounded([]string{}, 8, func(_ string) int {
			t.Errorf("work called on empty input")
			return 0
		})
		if len(got) != 0 {
			t.Errorf("expected 0 results, got %d", len(got))
		}
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("fanoutBounded deadlocked on empty input")
	}
}

// Compile-time assert sync is imported (linter sometimes complains
// otherwise).  Real production callers use this via the worker
// goroutines launched in queryHost.
var _ = sync.WaitGroup{}

// TestFanoutBounded_FleetScaleStress — verify the bound holds at the
// target customer scale (1000 hosts × bound 50).  Runs serially in
// the normal test suite (no -short skip) because it's still fast
// (<1s) and exercises the bound at a realistic operating point that
// might surface a sloppy semaphore implementation we'd never see at
// the 200×8 size of the smaller test.
//
// Asserts: every input is processed exactly once, peak in-flight
// stays at-or-below the configured bound, total time is at least
// (hostCount/limit) × per-call-delay so the bound is actually
// engaging (rather than the timing accidentally letting everything
// finish before the next goroutine starts).
func TestFanoutBounded_FleetScaleStress(t *testing.T) {
	const (
		hostCount    = 1000
		limit        = 50
		perCallDelay = 1 * time.Millisecond
	)
	hostnames := make([]string, hostCount)
	for i := range hostnames {
		hostnames[i] = "h-" + strconv.Itoa(i)
	}

	var inFlight, peak atomic.Int32
	var totalCalls atomic.Int32
	work := func(_ string) int {
		totalCalls.Add(1)
		cur := inFlight.Add(1)
		for {
			p := peak.Load()
			if cur <= p || peak.CompareAndSwap(p, cur) {
				break
			}
		}
		time.Sleep(perCallDelay)
		inFlight.Add(-1)
		return 1
	}

	start := time.Now()
	got := fanoutBounded(hostnames, limit, work)
	elapsed := time.Since(start)

	if len(got) != hostCount {
		t.Fatalf("got %d results, want %d", len(got), hostCount)
	}
	if int(totalCalls.Load()) != hostCount {
		t.Fatalf("got %d work invocations, want %d", totalCalls.Load(), hostCount)
	}
	if peak.Load() > limit {
		t.Fatalf("peak in-flight = %d, exceeded limit %d at fleet scale", peak.Load(), limit)
	}
	// Sanity: with 1000 calls and bound 50, total wall time must be
	// at least (1000/50)=20 × per-call-delay.  If it's much less the
	// bound clearly didn't engage.  Allow generous slack for CI.
	minExpected := time.Duration(hostCount/limit) * perCallDelay
	if elapsed < minExpected/2 {
		t.Errorf("elapsed %v < minExpected/2 %v — bound may not have engaged",
			elapsed, minExpected/2)
	}
}
