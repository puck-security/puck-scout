package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/puck-security/puck-oss/mcp/internal/agents"
)

func testServer(t *testing.T) (*AgentServer, *agents.Registry, *agents.Queue) {
	t.Helper()
	registry := agents.NewRegistry(300)
	queue := agents.NewQueue()
	logger := slog.Default()
	return NewAgentServer(registry, queue, logger, nil, nil), registry, queue
}

// mtlsRequest builds an httptest.Request with a fake TLS peer certificate so
// that requireMTLSIdentity middleware accepts it and plants hostname in context.
func mtlsRequest(method, target, hostname string, body *bytes.Reader) *http.Request {
	cert := &x509.Certificate{
		Subject:  pkix.Name{CommonName: hostname},
		DNSNames: []string{hostname},
	}
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, target, body)
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	return req
}

// TestPollNoCommands verifies that polling with no queued commands returns 204.
// The hostname is now derived from the mTLS client certificate, not from a query param.
func TestPollNoCommands(t *testing.T) {
	srv, _, _ := testServer(t)
	handler := srv.Handler()

	req := mtlsRequest(http.MethodGet, "/v1/poll?agent_id=agent1", "host1", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}
}

// TestPollWithCommands verifies that polling returns 200 with queued commands.
// The hostname is now derived from the mTLS client certificate, not from a query param.
func TestPollWithCommands(t *testing.T) {
	srv, _, queue := testServer(t)
	handler := srv.Handler()

	queue.Enqueue("host1", agents.CommandRequest{
		CommandID: "cmd-001",
		Command:   "ls",
		Args:      []string{"-la"},
	})

	req := mtlsRequest(http.MethodGet, "/v1/poll?agent_id=agent1", "host1", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var body map[string]any
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	cmds, ok := body["commands"].([]any)
	if !ok {
		t.Fatalf("expected commands key with array, got: %v", body["commands"])
	}
	if len(cmds) != 1 {
		t.Fatalf("expected 1 command, got %d", len(cmds))
	}
}

// TestResultSubmission verifies that POSTing results with the correct mTLS
// hostname returns 204 and delivers the result to the waiting goroutine.
func TestResultSubmission(t *testing.T) {
	srv, _, queue := testServer(t)
	handler := srv.Handler()

	// Enqueue a command so there's a waiter.
	queue.Enqueue("host1", agents.CommandRequest{
		CommandID: "cmd-002",
		Command:   "whoami",
	})

	// Collect result in background via WaitForResult.
	resultCh := make(chan agents.CommandResult, 1)
	go func() {
		res, err := queue.WaitForResult("cmd-002", 2*time.Second)
		if err == nil {
			resultCh <- res
		}
	}()

	submission := agents.ResultSubmission{
		AgentID: "agent1",
		Results: []agents.CommandResult{
			{
				CommandID: "cmd-002",
				Command:   "whoami",
				Stdout:    "root",
				ExitCode:  0,
			},
		},
	}

	body, err := json.Marshal(submission)
	if err != nil {
		t.Fatalf("failed to marshal submission: %v", err)
	}

	// Use mTLS identity matching the enqueued hostname.
	req := mtlsRequest(http.MethodPost, "/v1/results", "host1", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", w.Code, w.Body.String())
	}

	select {
	case result := <-resultCh:
		if result.CommandID != "cmd-002" {
			t.Fatalf("expected command_id cmd-002, got %s", result.CommandID)
		}
		if result.Stdout != "root" {
			t.Fatalf("expected stdout 'root', got %s", result.Stdout)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expected result to be delivered to waiter, but timed out")
	}
}

// TestResultSubmission_CrossAgentRejected verifies that an agent trying to
// submit results for a command queued to a different hostname gets 403.
func TestResultSubmission_CrossAgentRejected(t *testing.T) {
	srv, _, queue := testServer(t)
	handler := srv.Handler()

	queue.Enqueue("host-victim", agents.CommandRequest{
		CommandID: "cmd-003",
		Command:   "id",
	})

	submission := agents.ResultSubmission{
		AgentID: "evil-agent",
		Results: []agents.CommandResult{
			{CommandID: "cmd-003", Stdout: "injected"},
		},
	}
	body, _ := json.Marshal(submission)

	// Attacker presents cert for "host-attacker" — not the victim.
	req := mtlsRequest(http.MethodPost, "/v1/results", "host-attacker", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

// TestResultSubmission_UnknownCommandID verifies that submitting results for a
// command that was never queued returns 404.
func TestResultSubmission_UnknownCommandID(t *testing.T) {
	srv, _, _ := testServer(t)
	handler := srv.Handler()

	submission := agents.ResultSubmission{
		Results: []agents.CommandResult{
			{CommandID: "never-queued"},
		},
	}
	body, _ := json.Marshal(submission)

	req := mtlsRequest(http.MethodPost, "/v1/results", "host1", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

// TestResultSubmission_NoCertRejected verifies that /v1/results without a
// client cert is rejected by the requireMTLSIdentity middleware (401).
func TestResultSubmission_NoCertRejected(t *testing.T) {
	srv, _, _ := testServer(t)
	handler := srv.Handler()

	submission := agents.ResultSubmission{
		Results: []agents.CommandResult{{CommandID: "cmd-x"}},
	}
	body, _ := json.Marshal(submission)

	req := httptest.NewRequest(http.MethodPost, "/v1/results", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// No TLS — no cert planted.
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without client cert, got %d", w.Code)
	}
}

// TestPollRegistersAgent verifies that polling registers the agent in the registry.
// The hostname is now derived from the mTLS client certificate, not from a query param.
func TestPollRegistersAgent(t *testing.T) {
	srv, registry, _ := testServer(t)
	handler := srv.Handler()

	req := mtlsRequest(http.MethodGet, "/v1/poll?agent_id=agent2", "host2", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}

	status := registry.Status("host2")
	if status != agents.StatusActive {
		t.Fatalf("expected agent status to be active, got %s", status)
	}
}

// TestPollNoCertRejected verifies that /v1/poll without a client cert is rejected (401).
// Bearer auth on the agent listener is gone; mTLS is the only auth mechanism.
func TestPollNoCertRejected(t *testing.T) {
	srv, _, _ := testServer(t)
	handler := srv.Handler()

	req := httptest.NewRequest(http.MethodGet, "/v1/poll?agent_id=agent1", nil)
	// No TLS state — requireMTLSIdentity must reject this.
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without client cert, got %d", w.Code)
	}
}

// TestEventsNoCertRejected verifies that /v1/events without a client cert
// is rejected by requireMTLSIdentity (401).
func TestEventsNoCertRejected(t *testing.T) {
	srv, _, _ := testServer(t)
	handler := srv.Handler()

	req := httptest.NewRequest(http.MethodGet, "/v1/events?agent_id=agent1", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without client cert, got %d", w.Code)
	}
}

// TestEventsOpensStream verifies that GET /v1/events with a valid cert opens
// an SSE stream (200, correct headers, initial ping event).
func TestEventsOpensStream(t *testing.T) {
	srv, _, _ := testServer(t)
	handler := srv.Handler()

	// Cancel the request after a short time so the handler exits the event loop.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	req := mtlsRequest(http.MethodGet, "/v1/events?agent_id=agent1", "host-sse", nil)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for SSE stream, got %d: %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("expected Content-Type text/event-stream, got %q", ct)
	}
	// Initial ping must be in the body.
	body := w.Body.String()
	if !containsString(body, "event: ping") {
		t.Fatalf("expected initial ping event in body, got: %q", body)
	}
}

// TestEventsDeliversCommand verifies that a command enqueued while an SSE
// stream is open is delivered as a "command" SSE event.
func TestEventsDeliversCommand(t *testing.T) {
	srv, _, queue := testServer(t)
	handler := srv.Handler()

	// Cancel the request after enough time for the command to be delivered.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	req := mtlsRequest(http.MethodGet, "/v1/events?agent_id=agent1", "host-cmd", nil)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	// Enqueue a command in a goroutine shortly after the stream opens.
	go func() {
		time.Sleep(20 * time.Millisecond)
		queue.Enqueue("host-cmd", agents.CommandRequest{
			CommandID: "cmd-via-sse",
			Command:   "uname",
		})
	}()

	handler.ServeHTTP(w, req)

	body := w.Body.String()
	if !containsString(body, "event: command") {
		t.Fatalf("expected command event in SSE body, got: %q", body)
	}
	if !containsString(body, "cmd-via-sse") {
		t.Fatalf("expected command id in SSE body, got: %q", body)
	}
}

func containsString(s, substr string) bool {
	return strings.Contains(s, substr)
}

// TestHealthUnauthenticated verifies that /v1/health is accessible without a
// client cert (so load-balancer probes work without credentials).
func TestHealthUnauthenticated(t *testing.T) {
	srv, _, _ := testServer(t)
	handler := srv.Handler()

	req := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for health without cert, got %d", w.Code)
	}
}

// TestHostnameValidation verifies that path-traversal and malformed hostnames
// embedded in a client cert CN are rejected by requireMTLSIdentity before
// reaching the poll handler.
func TestHostnameValidation(t *testing.T) {
	cases := []struct {
		hostname string
		wantOK   bool
	}{
		{"corp-laptop-47", true},
		{"host.example.com", true},
		{"server_01", true},
		{"../../etc/passwd", false},
		{"../evil", false},
		{"/etc/cron.d/evil", false},
		{"host name", false},
	}

	for _, tc := range cases {
		srv, _, _ := testServer(t)
		handler := srv.Handler()

		// mtlsRequest plants the CN and DNSNames; requireMTLSIdentity validates
		// the hostname regex. For invalid hostnames the CN/SAN pair will also
		// fail the DNSNames == CN check for names containing slashes/spaces,
		// but the hostname regex is the authoritative guard.
		req := mtlsRequest(http.MethodGet, "/v1/poll?agent_id=a1", tc.hostname, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		// Valid hostnames → 204 (no commands). Invalid hostnames → 401 (mTLS rejected).
		gotRejected := w.Code == http.StatusUnauthorized || w.Code == http.StatusBadRequest
		if tc.wantOK && gotRejected {
			t.Errorf("hostname %q: expected to be accepted, got %d", tc.hostname, w.Code)
		}
		if !tc.wantOK && !gotRejected {
			t.Errorf("hostname %q: expected rejection, got %d", tc.hostname, w.Code)
		}
	}
}
