package server

import (
	"bufio"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestMCPServerSSEEndpointEvent verifies that the SSE handler emits an
// endpoint event with a sessionId query parameter — the wiring the SSE
// client needs in order to POST follow-up JSON-RPC messages.
func TestMCPServerSSEEndpointEvent(t *testing.T) {
	s := NewMCPServer(nil, slog.New(slog.NewTextHandler(io.Discard, nil)), "", 0)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/sse")
	if err != nil {
		t.Fatalf("GET /sse: %v", err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get("Content-Type"); got != "text/event-stream" {
		t.Errorf("Content-Type = %q, want text/event-stream", got)
	}

	sessionID := readEndpointSessionID(t, resp.Body)
	if sessionID == "" {
		t.Fatal("endpoint event did not include sessionId")
	}
}

// TestMCPServerInitializeRoundTrip exercises the full SSE transport:
// open /sse, POST an initialize request to /message?sessionId=…, read the
// response off the SSE stream. Older versions returned the response in the
// POST body; this regression test pins the spec-compliant behavior.
func TestMCPServerInitializeRoundTrip(t *testing.T) {
	s := NewMCPServer(nil, slog.New(slog.NewTextHandler(io.Discard, nil)), "", 0)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	sseResp, err := http.Get(ts.URL + "/sse")
	if err != nil {
		t.Fatalf("GET /sse: %v", err)
	}
	defer sseResp.Body.Close()
	br := bufio.NewReader(sseResp.Body)

	sessionID := readEndpointSessionID(t, br)
	if sessionID == "" {
		t.Fatal("missing sessionId in endpoint event")
	}

	// POST initialize.
	body := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	postResp, err := http.Post(ts.URL+"/message?sessionId="+sessionID, "application/json", body)
	if err != nil {
		t.Fatalf("POST /message: %v", err)
	}
	postBody, _ := io.ReadAll(postResp.Body)
	postResp.Body.Close()
	if postResp.StatusCode != http.StatusAccepted {
		t.Errorf("POST status = %d, want 202; body=%s", postResp.StatusCode, postBody)
	}
	// Body of the POST itself must be empty / not the JSON-RPC response —
	// that goes via SSE.
	if strings.Contains(string(postBody), `"jsonrpc"`) {
		t.Errorf("POST body should not contain JSON-RPC response; got: %s", postBody)
	}

	// Read the response off the SSE stream.
	msg := readMessageEvent(t, br, 2*time.Second)
	var resp struct {
		JSONRPC string         `json:"jsonrpc"`
		ID      any            `json:"id"`
		Result  map[string]any `json:"result"`
	}
	if err := json.Unmarshal([]byte(msg), &resp); err != nil {
		t.Fatalf("decode SSE message: %v; raw=%q", err, msg)
	}
	if resp.JSONRPC != "2.0" {
		t.Errorf("jsonrpc = %q, want 2.0", resp.JSONRPC)
	}
	if id, _ := resp.ID.(float64); id != 1 {
		t.Errorf("id = %v, want 1", resp.ID)
	}
	if resp.Result["protocolVersion"] != mcpProtocolVersion {
		t.Errorf("protocolVersion = %v, want %s", resp.Result["protocolVersion"], mcpProtocolVersion)
	}
}

// TestMCPServerMessageRequiresSession verifies POST /message without a
// known session ID returns 4xx instead of trying to dispatch.
func TestMCPServerMessageRequiresSession(t *testing.T) {
	s := NewMCPServer(nil, slog.New(slog.NewTextHandler(io.Discard, nil)), "", 0)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	body := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	resp, err := http.Post(ts.URL+"/message", "application/json", body)
	if err != nil {
		t.Fatalf("POST /message: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("missing sessionId status = %d, want 400", resp.StatusCode)
	}

	body2 := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	resp2, err := http.Post(ts.URL+"/message?sessionId=bogus", "application/json", body2)
	if err != nil {
		t.Fatalf("POST /message?sessionId=bogus: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotFound {
		t.Errorf("unknown sessionId status = %d, want 404", resp2.StatusCode)
	}
}

// readEndpointSessionID consumes lines from r until it finds an SSE
// `endpoint` event, then extracts the sessionId query param from the
// data line. Returns "" if no sessionId is found before EOF.
func readEndpointSessionID(t *testing.T, r io.Reader) string {
	t.Helper()
	br, ok := r.(*bufio.Reader)
	if !ok {
		br = bufio.NewReader(r)
	}
	sawEndpoint := false
	for range 20 {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read SSE: %v", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "event: endpoint" {
			sawEndpoint = true
			continue
		}
		if sawEndpoint && strings.HasPrefix(line, "data: ") {
			data := strings.TrimPrefix(line, "data: ")
			// Expect form: /message?sessionId=<uuid>
			_, sid, ok := strings.Cut(data, "sessionId=")
			if !ok {
				return ""
			}
			return sid
		}
	}
	return ""
}

// readMessageEvent reads SSE lines until it finds a `message` event and
// returns its data line. Fails the test on timeout to keep CI from hanging.
func readMessageEvent(t *testing.T, br *bufio.Reader, timeout time.Duration) string {
	t.Helper()
	type result struct {
		data string
		err  error
	}
	done := make(chan result, 1)
	go func() {
		sawMessage := false
		for range 50 {
			line, err := br.ReadString('\n')
			if err != nil {
				done <- result{err: err}
				return
			}
			line = strings.TrimRight(line, "\r\n")
			if line == "event: message" {
				sawMessage = true
				continue
			}
			if sawMessage && strings.HasPrefix(line, "data: ") {
				done <- result{data: strings.TrimPrefix(line, "data: ")}
				return
			}
		}
		done <- result{err: io.EOF}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("read SSE message event: %v", r.err)
		}
		return r.data
	case <-time.After(timeout):
		t.Fatal("timed out waiting for SSE message event")
		return ""
	}
}
