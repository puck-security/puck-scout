package server

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/google/uuid"

	"github.com/puck-security/puck-scout/mcp/internal/mcp"
	"github.com/puck-security/puck-scout/mcp/internal/router"
)

const mcpMessageMaxBytes = 1 << 20 // 1 MB — sufficient for any JSON-RPC tool call

const (
	mcpProtocolVersion = "2024-11-05"
	mcpServerName      = "puck-mcp"
	mcpServerVersion   = "0.1.0"

	// Per-session response buffer. Most JSON-RPC exchanges are
	// one outstanding request at a time; allow a small burst.
	sessionQueueSize = 16
)

// MCPServer implements the MCP HTTP+SSE transport per spec 2024-11-05:
//
//	GET  /sse           — opens an SSE stream; server emits an `endpoint`
//	                      event whose URL contains a session ID. Responses
//	                      to JSON-RPC requests are delivered as `message`
//	                      events on this stream.
//	POST /message?sessionId=<id>
//	                    — the client posts JSON-RPC requests here. The
//	                      server returns 202 Accepted; the response is
//	                      sent through the corresponding SSE stream.
//
// Earlier versions returned the JSON-RPC response directly in the POST
// body, which is wrong for the HTTP+SSE transport — Claude Code's SSE
// client waits for the response on the SSE stream.
type MCPServer struct {
	router      *router.Router
	logger      *slog.Logger
	token       string
	sseConns    atomic.Int64
	maxSSEConns int64

	// sessions maps sessionID → response delivery channel. The SSE
	// goroutine reads from the channel and writes `message` events;
	// POST handlers look up the channel and queue responses.
	sessions sync.Map // map[string]chan []byte
}

// NewMCPServer creates a new MCP server.
// token is the Bearer token MCP clients must present; empty string disables auth.
// maxSSEConns caps concurrent SSE connections; 0 means no limit.
func NewMCPServer(r *router.Router, logger *slog.Logger, token string, maxSSEConns int) *MCPServer {
	return &MCPServer{router: r, logger: logger, token: token, maxSSEConns: int64(maxSSEConns)}
}

// Handler returns the HTTP mux with MCP endpoints registered.
// /sse and /message require Bearer auth when a token is configured.
// /health and well-known endpoints are excluded from auth.
func (s *MCPServer) Handler() http.Handler {
	auth := requireBearer(s.token)
	mux := http.NewServeMux()
	mux.Handle("GET /sse", auth(http.HandlerFunc(s.handleSSE)))
	mux.Handle("POST /message", auth(http.HandlerFunc(s.handleMessage)))
	mux.HandleFunc("GET /health", s.handleHealth)
	// Return proper JSON 404 for OAuth discovery — tells MCP clients no auth is needed.
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", s.handleNoAuth)
	mux.HandleFunc("GET /.well-known/openid-configuration", s.handleNoAuth)
	// Catch-all: return JSON 404 instead of plain text (prevents SDK parse errors).
	mux.HandleFunc("/", s.handleNotFound)
	return mux
}

// handleNoAuth responds to OAuth discovery with 404 JSON, indicating no auth is required.
func (s *MCPServer) handleNoAuth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	json.NewEncoder(w).Encode(map[string]any{
		"error":             "not_found",
		"error_description": "This server does not require authentication",
	})
}

// handleNotFound returns a JSON 404 for unknown paths.
func (s *MCPServer) handleNotFound(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	json.NewEncoder(w).Encode(map[string]any{
		"error":             "not_found",
		"error_description": "path not found",
	})
}

// handleSSE establishes an SSE connection, allocates a session, and forwards
// queued JSON-RPC responses to the client until disconnect.
func (s *MCPServer) handleSSE(w http.ResponseWriter, r *http.Request) {
	if s.maxSSEConns > 0 && s.sseConns.Load() >= s.maxSSEConns {
		http.Error(w, "too many SSE connections", http.StatusServiceUnavailable)
		return
	}
	s.sseConns.Add(1)
	defer s.sseConns.Add(-1)

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	sessionID := uuid.New().String()
	ch := make(chan []byte, sessionQueueSize)
	s.sessions.Store(sessionID, ch)
	defer s.sessions.Delete(sessionID)

	// Endpoint event: tell the client where to POST and which session to
	// attach to. The sessionId query param is what binds POSTs to this stream.
	fmt.Fprintf(w, "event: endpoint\ndata: /message?sessionId=%s\n\n", sessionID)
	flusher.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case msg := <-ch:
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", msg)
			flusher.Flush()
		}
	}
}

// handleMessage processes incoming JSON-RPC messages and queues the response
// onto the session's SSE channel. The POST itself returns 202 Accepted.
func (s *MCPServer) handleMessage(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("sessionId")
	if sessionID == "" {
		http.Error(w, `{"error":"missing sessionId"}`, http.StatusBadRequest)
		return
	}
	chAny, ok := s.sessions.Load(sessionID)
	if !ok {
		http.Error(w, `{"error":"unknown sessionId"}`, http.StatusNotFound)
		return
	}
	ch := chAny.(chan []byte)

	r.Body = http.MaxBytesReader(w, r.Body, mcpMessageMaxBytes)
	var req mcp.Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Per JSON-RPC, parse errors carry id=null. Send via the session
		// stream regardless so the client surfaces the failure.
		s.queueError(ch, nil, -32700, "parse error: "+err.Error())
		w.WriteHeader(http.StatusAccepted)
		return
	}

	switch req.Method {
	case "initialize":
		s.queueResult(ch, req.ID, mcp.InitializeResult{
			ProtocolVersion: mcpProtocolVersion,
			ServerInfo: mcp.ServerInfo{
				Name:    mcpServerName,
				Version: mcpServerVersion,
			},
			Capabilities: mcp.Capabilities{
				Tools:     &mcp.ToolsCapability{},
				Resources: &mcp.ResourcesCapability{},
			},
		})
	case "notifications/initialized":
		// Notification — no response.
	case "tools/list":
		s.queueResult(ch, req.ID, mcp.ToolsListResult{Tools: s.router.ToolDefinitions()})
	case "tools/call":
		var params mcp.ToolCallParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			s.queueError(ch, req.ID, -32602, "invalid tool call params: "+err.Error())
		} else {
			s.queueResult(ch, req.ID, s.router.HandleToolCall(params))
		}
	case "resources/list":
		s.queueResult(ch, req.ID, mcp.ResourcesListResult{Resources: s.router.ListResources()})
	case "resources/read":
		var params mcp.ResourceReadParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			s.queueError(ch, req.ID, -32602, "invalid resources/read params: "+err.Error())
		} else if body, mime, err := s.router.ReadResource(params.URI); err != nil {
			s.queueError(ch, req.ID, -32602, err.Error())
		} else {
			s.queueResult(ch, req.ID, mcp.ResourceReadResult{
				Contents: []mcp.ResourceContents{{URI: params.URI, MimeType: mime, Text: body}},
			})
		}
	default:
		// Notifications (no id) → silently ignored. Requests (id present)
		// → method-not-found error.
		if req.ID != nil {
			s.queueError(ch, req.ID, -32601, fmt.Sprintf("method not found: %s", req.Method))
		}
	}

	w.WriteHeader(http.StatusAccepted)
}

// handleHealth returns a simple health check response.
func (s *MCPServer) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]any{"status": "ok"}); err != nil {
		s.logger.Error("failed to encode health response", "error", err)
	}
}

// queueResult marshals a JSON-RPC success response and queues it on the
// session's SSE channel. The SSE goroutine picks it up and writes a
// `message` event. A full channel drops the response with a warning log;
// in normal operation the buffer is more than ample for one outstanding
// request.
func (s *MCPServer) queueResult(ch chan<- []byte, id any, result any) {
	body, err := json.Marshal(mcp.Response{JSONRPC: "2.0", ID: id, Result: result})
	if err != nil {
		s.logger.Error("failed to marshal response", "error", err)
		return
	}
	select {
	case ch <- body:
	default:
		s.logger.Warn("session response queue full; dropping response")
	}
}

// queueError is the error-response counterpart of queueResult.
func (s *MCPServer) queueError(ch chan<- []byte, id any, code int, message string) {
	body, err := json.Marshal(mcp.Response{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &mcp.RPCError{Code: code, Message: message},
	})
	if err != nil {
		s.logger.Error("failed to marshal error response", "error", err)
		return
	}
	select {
	case ch <- body:
	default:
		s.logger.Warn("session response queue full; dropping error response")
	}
}
