package router

import "sync"

// fanoutBounded calls work(input) for each entry in inputs in parallel,
// bounded to `limit` in-flight goroutines at a time.  Returns one
// result per input in input order.
//
// The bound matters at fleet scale: an unbounded fan-out to 1000 hosts
// opens a thousand outbound mTLS connections simultaneously — file
// descriptor and ephemeral-port exhaustion, plus thundering-herd load
// on whatever's at the other end.
//
// Generic over input type so callers can pass either bare hostnames
// (puck_query_fleet — same command to many hosts) or richer per-call
// structs (puck_run_batch — different commands per host).
//
// `limit <= 0` falls back to unbounded (len(inputs)) so a caller who
// forgets to set the limit doesn't deadlock — but production callers
// must always pass a positive limit from Config.
func fanoutBounded[T any, R any](inputs []T, limit int, work func(T) R) []R {
	results := make([]R, len(inputs))
	if limit <= 0 {
		limit = len(inputs)
	}
	if limit == 0 {
		// inputs was also empty — nothing to do.
		return results
	}
	sem := make(chan struct{}, limit)
	var wg sync.WaitGroup
	for i, in := range inputs {
		wg.Add(1)
		sem <- struct{}{} // acquire slot; blocks while limit reached
		go func(idx int, item T) {
			defer wg.Done()
			defer func() { <-sem }() // release slot
			results[idx] = work(item)
		}(i, in)
	}
	wg.Wait()
	return results
}
