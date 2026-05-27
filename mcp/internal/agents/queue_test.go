package agents

import (
	"errors"
	"testing"
	"time"
)

func TestQueueEnqueueDrainDeliver(t *testing.T) {
	q := NewQueue()

	req := CommandRequest{
		CommandID:       "cmd-1",
		InvestigationID: "inv-1",
		Command:         "ls",
		Args:            []string{"-la"},
		TimeoutSeconds:  30,
	}

	q.Enqueue("host-a", req)

	// First drain should return the one command.
	cmds := q.Drain("host-a")
	if len(cmds) != 1 {
		t.Fatalf("expected 1 command after drain, got %d", len(cmds))
	}
	if cmds[0].CommandID != "cmd-1" {
		t.Errorf("unexpected command id: %s", cmds[0].CommandID)
	}

	// Second drain should be empty.
	cmds2 := q.Drain("host-a")
	if len(cmds2) != 0 {
		t.Fatalf("expected 0 commands on second drain, got %d", len(cmds2))
	}

	// Deliver a result and read from it via WaitForResult.
	result := CommandResult{
		CommandID: "cmd-1",
		Command:   "ls",
		Args:      []string{"-la"},
		Stdout:    "total 0",
		ExitCode:  0,
	}

	done := make(chan CommandResult, 1)
	go func() {
		res, err := q.WaitForResult("cmd-1", time.Second)
		if err != nil {
			return
		}
		done <- res
	}()

	if err := q.Deliver("host-a", "cmd-1", result); err != nil {
		t.Fatalf("deliver: %v", err)
	}

	select {
	case got := <-done:
		if got.CommandID != "cmd-1" {
			t.Errorf("unexpected result command id: %s", got.CommandID)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for delivered result")
	}
}

func TestQueueWaitForResult(t *testing.T) {
	q := NewQueue()

	req := CommandRequest{
		CommandID: "cmd-2",
		Command:   "whoami",
	}
	q.Enqueue("host-b", req)

	// Deliver the result in a goroutine after 50ms.
	go func() {
		time.Sleep(50 * time.Millisecond)
		_ = q.Deliver("host-b", "cmd-2", CommandResult{
			CommandID: "cmd-2",
			Command:   "whoami",
			Stdout:    "root",
			ExitCode:  0,
		})
	}()

	result, err := q.WaitForResult("cmd-2", time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Stdout != "root" {
		t.Errorf("unexpected stdout: %s", result.Stdout)
	}
}

func TestQueueWaitTimeout(t *testing.T) {
	q := NewQueue()

	req := CommandRequest{
		CommandID: "cmd-3",
		Command:   "sleep",
		Args:      []string{"999"},
	}
	q.Enqueue("host-c", req)

	_, err := q.WaitForResult("cmd-3", 100*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("expected ErrTimeout, got %v", err)
	}
}

func TestQueueWaitForResultUnknownID(t *testing.T) {
	q := NewQueue()

	_, err := q.WaitForResult("nonexistent", time.Second)
	if err == nil {
		t.Fatal("expected error for unknown command id, got nil")
	}
	if !errors.Is(err, ErrUnknownCommandID) {
		t.Fatalf("expected ErrUnknownCommandID, got %v", err)
	}
}

func TestQueue_DeliverMatchingHostname(t *testing.T) {
	q := NewQueue()
	q.Enqueue("host-a", CommandRequest{CommandID: "cmd-1"})
	done := make(chan CommandResult, 1)
	go func() { res, _ := q.WaitForResult("cmd-1", time.Second); done <- res }()
	if err := q.Deliver("host-a", "cmd-1", CommandResult{CommandID: "cmd-1", ExitCode: 0}); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	select {
	case res := <-done:
		if res.CommandID != "cmd-1" {
			t.Fatalf("got %q", res.CommandID)
		}
	case <-time.After(time.Second):
		t.Fatal("waiter did not receive result")
	}
}

func TestQueue_DeliverMismatchedHostname(t *testing.T) {
	q := NewQueue()
	q.Enqueue("host-a", CommandRequest{CommandID: "cmd-1"})
	err := q.Deliver("host-b", "cmd-1", CommandResult{})
	if !errors.Is(err, ErrHostnameMismatch) {
		t.Fatalf("expected ErrHostnameMismatch, got %v", err)
	}
}

func TestQueue_DeliverUnknownCommandID(t *testing.T) {
	q := NewQueue()
	err := q.Deliver("host-a", "never-queued", CommandResult{})
	if !errors.Is(err, ErrUnknownCommandID) {
		t.Fatalf("expected ErrUnknownCommandID, got %v", err)
	}
}

func TestQueue_DuplicateDeliverRejected(t *testing.T) {
	q := NewQueue()
	q.Enqueue("host-a", CommandRequest{CommandID: "cmd-1"})

	// First Deliver must succeed.
	if err := q.Deliver("host-a", "cmd-1", CommandResult{}); err != nil {
		t.Fatalf("first Deliver: %v", err)
	}

	// Second Deliver must get ErrUnknownCommandID — Deliver deleted the waiter
	// atomically after the first send, so the duplicate finds no entry.
	err := q.Deliver("host-a", "cmd-1", CommandResult{})
	if !errors.Is(err, ErrUnknownCommandID) {
		t.Fatalf("duplicate Deliver: expected ErrUnknownCommandID, got %v", err)
	}
}

// TestQueue_SSEDelivery verifies that Enqueue sends directly to a registered
// SSE channel instead of the pending queue.
func TestQueue_SSEDelivery(t *testing.T) {
	q := NewQueue()

	ch := q.RegisterSSE("host-a")
	defer q.UnregisterSSE("host-a", ch)

	req := CommandRequest{CommandID: "cmd-sse-1", Command: "ls"}
	q.Enqueue("host-a", req)

	select {
	case got := <-ch:
		if got.CommandID != "cmd-sse-1" {
			t.Fatalf("expected cmd-sse-1 via SSE channel, got %q", got.CommandID)
		}
	case <-time.After(time.Second):
		t.Fatal("command not delivered to SSE channel within 1s")
	}

	// Pending queue must be empty — command was delivered via SSE.
	if cmds := q.Drain("host-a"); len(cmds) != 0 {
		t.Fatalf("expected empty pending queue after SSE delivery, got %d commands", len(cmds))
	}
}

// TestQueue_SSERegisterDrainsPending verifies that RegisterSSE immediately
// drains any accumulated pending commands into the returned channel.
func TestQueue_SSERegisterDrainsPending(t *testing.T) {
	q := NewQueue()

	// Commands arrive while no SSE connection is open (accumulated in pending).
	q.Enqueue("host-b", CommandRequest{CommandID: "cmd-1", Command: "id"})
	q.Enqueue("host-b", CommandRequest{CommandID: "cmd-2", Command: "whoami"})

	ch := q.RegisterSSE("host-b")
	defer q.UnregisterSSE("host-b", ch)

	// Both commands should be drained into the channel.
	var received []string
	for range 2 {
		select {
		case got := <-ch:
			received = append(received, got.CommandID)
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for drained command")
		}
	}

	if len(received) != 2 {
		t.Fatalf("expected 2 commands from drain, got %d", len(received))
	}

	// Pending queue is empty after RegisterSSE drained it.
	if cmds := q.Drain("host-b"); len(cmds) != 0 {
		t.Fatalf("expected empty pending queue after RegisterSSE, got %d", len(cmds))
	}
}

// TestQueue_SSEUnregisterFallsBackToPending verifies that after UnregisterSSE,
// new Enqueue calls go back to the pending queue.
func TestQueue_SSEUnregisterFallsBackToPending(t *testing.T) {
	q := NewQueue()

	ch := q.RegisterSSE("host-c")
	q.UnregisterSSE("host-c", ch)

	q.Enqueue("host-c", CommandRequest{CommandID: "cmd-fallback", Command: "uname"})

	// Nothing on the SSE channel.
	select {
	case <-ch:
		t.Fatal("expected nothing on unregistered SSE channel")
	default:
	}

	// Command is in the pending queue instead.
	cmds := q.Drain("host-c")
	if len(cmds) != 1 || cmds[0].CommandID != "cmd-fallback" {
		t.Fatalf("expected cmd-fallback in pending queue, got %v", cmds)
	}
}
