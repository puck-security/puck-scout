package agents

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// Sentinel errors returned by Deliver and WaitForResult.
var (
	ErrUnknownCommandID = errors.New("unknown command id")
	ErrHostnameMismatch = errors.New("submitter hostname does not match command's queued hostname")
	ErrTimeout          = errors.New("waiter timeout")
)

// CommandRequest is a command dispatched to an agent.
type CommandRequest struct {
	CommandID       string   `json:"command_id"`
	InvestigationID string   `json:"investigation_id"`
	Command         string   `json:"command"`
	Args            []string `json:"args"`
	TimeoutSeconds  int      `json:"timeout_seconds"`
}

// CommandResult is the result of a command executed by an agent.
type CommandResult struct {
	CommandID  string   `json:"command_id"`
	Command    string   `json:"command"`
	Args       []string `json:"args"`
	Stdout     string   `json:"stdout"`
	Stderr     string   `json:"stderr"`
	ExitCode   int      `json:"exit_code"`
	DurationMs int64    `json:"duration_ms"`
	Error      *string  `json:"error,omitempty"`
}

// ResultSubmission is a batch of results submitted by an agent.
// The Hostname field is intentionally absent: the cert-derived hostname from
// the mTLS connection is the authoritative submitter identity (Vuln 6 closure).
type ResultSubmission struct {
	AgentID         string          `json:"agent_id"`
	InvestigationID string          `json:"investigation_id"`
	Results         []CommandResult `json:"results"`
}

// Waiter records the hostname that owns a queued command's response channel.
// The delivered flag (CAS) prevents double-delivery: a duplicate Deliver call
// for the same commandID returns ErrUnknownCommandID and never reaches the
// channel.  Lifecycle of the waiters-map entry is owned by WaitForResult — it
// deletes on receive or timeout; Deliver only signals.
type Waiter struct {
	Hostname  string
	Ch        chan CommandResult
	delivered atomic.Bool
}

// Queue is a per-agent command queue with result channels.
type Queue struct {
	mu          sync.Mutex
	pending     map[string][]CommandRequest    // hostname -> ordered list of commands
	waiters     map[string]*Waiter             // commandID -> Waiter
	sseChannels map[string]chan CommandRequest  // hostname -> open SSE connection channel
}

// NewQueue creates a new Queue.
func NewQueue() *Queue {
	return &Queue{
		pending:     make(map[string][]CommandRequest),
		waiters:     make(map[string]*Waiter),
		sseChannels: make(map[string]chan CommandRequest),
	}
}

// Enqueue adds a command to the queue for the given hostname, recording
// hostname ownership alongside the result channel so Deliver can enforce
// per-host authz. If an SSE channel is registered for the hostname, the
// command is delivered directly and bypasses the pending queue.
func (q *Queue) Enqueue(hostname string, req CommandRequest) {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.waiters[req.CommandID] = &Waiter{
		Hostname: hostname,
		Ch:       make(chan CommandResult, 1),
	}

	// Fast path: if an SSE channel is open for this hostname, deliver directly.
	if ch, ok := q.sseChannels[hostname]; ok {
		select {
		case ch <- req:
			return
		default:
			// Channel full — fall through to pending queue.
		}
	}
	q.pending[hostname] = append(q.pending[hostname], req)
}

// RegisterSSE registers an SSE connection for the given hostname and returns
// a channel that will receive commands. Any currently-pending commands are
// drained into the channel immediately so no commands are lost on reconnect.
func (q *Queue) RegisterSSE(hostname string) chan CommandRequest {
	ch := make(chan CommandRequest, 128)

	q.mu.Lock()
	q.sseChannels[hostname] = ch
	pending := q.pending[hostname]
	delete(q.pending, hostname)
	q.mu.Unlock()

	// Drain accumulated commands into the channel outside the lock.
	// The channel has capacity 128 and this is a startup operation.
	for _, cmd := range pending {
		ch <- cmd
	}
	return ch
}

// UnregisterSSE removes the SSE channel for the given hostname. Only removes
// if the registered channel matches the provided one (prevents a late-arriving
// unregister from removing a newer reconnect's channel).
func (q *Queue) UnregisterSSE(hostname string, ch chan CommandRequest) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if current, ok := q.sseChannels[hostname]; ok && current == ch {
		delete(q.sseChannels, hostname)
	}
}

// Drain returns and clears all pending commands for the given hostname.
func (q *Queue) Drain(hostname string) []CommandRequest {
	q.mu.Lock()
	defer q.mu.Unlock()

	cmds := q.pending[hostname]
	delete(q.pending, hostname)
	return cmds
}

// Deliver routes a result to the waiting goroutine, verifying that the
// submitter's hostname (derived from the mTLS cert) matches the hostname the
// command was queued to.  Cross-agent injection returns ErrHostnameMismatch.
//
// Double-delivery (a duplicate result for the same commandID) is rejected via
// an atomic compare-and-swap on the waiter's `delivered` flag — only the
// first Deliver succeeds; subsequent calls return ErrUnknownCommandID.  The
// waiters-map entry is owned by WaitForResult, which deletes on receive or
// timeout; Deliver does not touch the map.
func (q *Queue) Deliver(submitterHostname, commandID string, result CommandResult) error {
	q.mu.Lock()
	w, ok := q.waiters[commandID]
	q.mu.Unlock()
	if !ok {
		return ErrUnknownCommandID
	}
	if w.Hostname != submitterHostname {
		return ErrHostnameMismatch
	}
	// CAS guarantees exactly one successful Deliver per waiter.  A losing CAS
	// is semantically "this command no longer has a waiter expecting a result";
	// surface that as ErrUnknownCommandID for the caller (matches the not-in-map
	// path above).
	if !w.delivered.CompareAndSwap(false, true) {
		return ErrUnknownCommandID
	}
	w.Ch <- result
	return nil
}

// WaitForResult blocks until a result is delivered for commandID or the
// timeout elapses — whichever comes first.  Owns the waiters-map entry
// lifecycle: deletes on either branch.
func (q *Queue) WaitForResult(commandID string, timeout time.Duration) (CommandResult, error) {
	q.mu.Lock()
	w, ok := q.waiters[commandID]
	q.mu.Unlock()

	if !ok {
		return CommandResult{}, ErrUnknownCommandID
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case result := <-w.Ch:
		q.mu.Lock()
		delete(q.waiters, commandID)
		q.mu.Unlock()
		return result, nil
	case <-timer.C:
		q.mu.Lock()
		delete(q.waiters, commandID)
		q.mu.Unlock()
		return CommandResult{}, ErrTimeout
	}
}
