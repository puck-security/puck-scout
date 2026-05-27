package server

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/puck-security/puck-oss/mcp/internal/mcp"
	"github.com/puck-security/puck-oss/mcp/internal/router"
)

const (
	mcpProtocolVersionStdio = "2024-11-05"
	mcpServerNameStdio      = "puck-mcp"
	mcpServerVersionStdio   = "0.1.0"
)

// StdioServer implements the MCP protocol over stdin/stdout.
// Each line of stdin is a JSON-RPC request; each line of stdout is a response.
type StdioServer struct {
	router *router.Router
	logger *slog.Logger
}

func NewStdioServer(r *router.Router, logger *slog.Logger) *StdioServer {
	return &StdioServer{router: r, logger: logger}
}

// Run reads JSON-RPC messages from stdin and writes responses to stdout.
// Blocks until stdin is closed.
func (s *StdioServer) Run() error {
	scanner := bufio.NewScanner(os.Stdin)
	// Allow large messages (16MB)
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	writer := json.NewEncoder(os.Stdout)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var req mcp.Request
		if err := json.Unmarshal(line, &req); err != nil {
			s.logger.Error("failed to parse request", "error", err)
			resp := mcp.Response{
				JSONRPC: "2.0",
				Error:   &mcp.RPCError{Code: -32700, Message: "parse error: " + err.Error()},
			}
			writer.Encode(resp)
			continue
		}

		s.logger.Debug("received request", "method", req.Method, "id", req.ID)

		resp := s.handleRequest(&req)
		if resp != nil {
			if err := writer.Encode(resp); err != nil {
				s.logger.Error("failed to write response", "error", err)
			}
		}
	}

	if err := scanner.Err(); err != nil && err != io.EOF {
		return fmt.Errorf("stdin read error: %w", err)
	}

	return nil
}

func (s *StdioServer) handleRequest(req *mcp.Request) *mcp.Response {
	switch req.Method {
	case "initialize":
		return &mcp.Response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: mcp.InitializeResult{
				ProtocolVersion: mcpProtocolVersionStdio,
				ServerInfo: mcp.ServerInfo{
					Name:    mcpServerNameStdio,
					Version: mcpServerVersionStdio,
				},
				Capabilities: mcp.Capabilities{
					Tools:     &mcp.ToolsCapability{},
					Resources: &mcp.ResourcesCapability{},
				},
			},
		}

	case "notifications/initialized":
		// No response needed for notifications
		return nil

	case "tools/list":
		return &mcp.Response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  mcp.ToolsListResult{Tools: s.router.ToolDefinitions()},
		}

	case "tools/call":
		var params mcp.ToolCallParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return &mcp.Response{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error:   &mcp.RPCError{Code: -32602, Message: "invalid params: " + err.Error()},
			}
		}
		result := s.router.HandleToolCall(params)
		return &mcp.Response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  result,
		}

	case "resources/list":
		return &mcp.Response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  mcp.ResourcesListResult{Resources: s.router.ListResources()},
		}

	case "resources/read":
		var params mcp.ResourceReadParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return &mcp.Response{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error:   &mcp.RPCError{Code: -32602, Message: "invalid params: " + err.Error()},
			}
		}
		body, mime, err := s.router.ReadResource(params.URI)
		if err != nil {
			return &mcp.Response{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error:   &mcp.RPCError{Code: -32602, Message: err.Error()},
			}
		}
		return &mcp.Response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: mcp.ResourceReadResult{
				Contents: []mcp.ResourceContents{{URI: params.URI, MimeType: mime, Text: body}},
			},
		}

	default:
		return &mcp.Response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &mcp.RPCError{Code: -32601, Message: fmt.Sprintf("method not found: %s", req.Method)},
		}
	}
}
