package router

import (
	"sync"
	"testing"

	"github.com/puck-security/puck-scout/mcp/internal/agents"
)

// mockAgent simulates an endpoint agent for integration testing.  It
// registers itself in the Registry (so Router.registry.Status returns
// Active), subscribes to its hostname's SSE channel, and routes each
// inbound CommandRequest through a caller-supplied responseFn before
// calling queue.Deliver to satisfy the router's WaitForResult.
//
// Use startMockAgent / stop().  Spawning multiple mockAgents for
// multiple hostnames is the standard pattern for fan-out tests.
type mockAgent struct {
	hostname   string
	queue      *agents.Queue
	responseFn func(agents.CommandRequest) agents.CommandResult
	sseCh      chan agents.CommandRequest
	done       chan struct{}
	wg         sync.WaitGroup
}

// startMockAgent registers `hostname` as Active in the registry and
// spawns a goroutine that responds to each incoming CommandRequest
// via responseFn.  Returns a handle the caller stops via .stop().
func startMockAgent(
	t *testing.T,
	q *agents.Queue,
	r *agents.Registry,
	hostname string,
	responseFn func(agents.CommandRequest) agents.CommandResult,
) *mockAgent {
	t.Helper()
	r.Touch(hostname, hostname+"-agentid")
	m := &mockAgent{
		hostname:   hostname,
		queue:      q,
		responseFn: responseFn,
		sseCh:      q.RegisterSSE(hostname),
		done:       make(chan struct{}),
	}
	m.wg.Add(1)
	go m.run()
	return m
}

func (m *mockAgent) run() {
	defer m.wg.Done()
	for {
		select {
		case req, ok := <-m.sseCh:
			if !ok {
				return
			}
			result := m.responseFn(req)
			result.CommandID = req.CommandID
			result.Command = req.Command
			result.Args = req.Args
			_ = m.queue.Deliver(m.hostname, req.CommandID, result)
		case <-m.done:
			return
		}
	}
}

// stop terminates the mock agent's goroutine.  Tests should defer this
// after startMockAgent to avoid goroutine leaks between tests.
func (m *mockAgent) stop() {
	close(m.done)
	m.queue.UnregisterSSE(m.hostname, m.sseCh)
	m.wg.Wait()
}

// staticResponse returns a responseFn that produces the same
// (stdout, stderr, exit_code) for every command — convenient for
// homogeneous-fleet tests where dedup should collapse everything to
// one group.
func staticResponse(stdout, stderr string, exitCode int) func(agents.CommandRequest) agents.CommandResult {
	return func(_ agents.CommandRequest) agents.CommandResult {
		return agents.CommandResult{
			Stdout:     stdout,
			Stderr:     stderr,
			ExitCode:   exitCode,
			DurationMs: 5,
		}
	}
}
