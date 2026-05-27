package mcp

import "encoding/json"

// Request represents a JSON-RPC 2.0 request message.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// Response represents a JSON-RPC 2.0 response message.
type Response struct {
	JSONRPC string    `json:"jsonrpc"`
	ID      any       `json:"id,omitempty"`
	Result  any       `json:"result,omitempty"`
	Error   *RPCError `json:"error,omitempty"`
}

// RPCError represents a JSON-RPC 2.0 error object.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// InitializeParams holds the parameters for the initialize request.
type InitializeParams struct {
	ProtocolVersion string     `json:"protocolVersion"`
	ClientInfo      ClientInfo `json:"clientInfo"`
}

// ClientInfo identifies the MCP client.
type ClientInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// InitializeResult is the server's response to initialize.
type InitializeResult struct {
	ProtocolVersion string       `json:"protocolVersion"`
	ServerInfo      ServerInfo   `json:"serverInfo"`
	Capabilities    Capabilities `json:"capabilities"`
}

// ServerInfo identifies the MCP server.
type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Capabilities advertises what the server supports.
type Capabilities struct {
	Tools     *ToolsCapability     `json:"tools,omitempty"`
	Resources *ResourcesCapability `json:"resources,omitempty"`
}

// ToolsCapability signals that the server supports tool calls.
type ToolsCapability struct{}

// ResourcesCapability signals that the server supports resources/list
// and resources/read. The optional `subscribe` and `listChanged` fields
// describe additional capabilities (push subscriptions / list-changed
// notifications); puck-mcp does not implement either today, so they
// are omitted.
type ResourcesCapability struct{}

// Resource describes a single addressable resource exposed by the
// server (e.g. a skill's full body). The AI can list resources via
// resources/list and fetch their content via resources/read.
type Resource struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
}

// ResourcesListResult is the response to resources/list.
type ResourcesListResult struct {
	Resources []Resource `json:"resources"`
}

// ResourceReadParams holds the parameters for resources/read.
type ResourceReadParams struct {
	URI string `json:"uri"`
}

// ResourceContents is one chunk of a resources/read response body.
// MCP allows multiple contents per read (e.g. for paginated readers);
// puck-mcp returns a single text content per resource today.
type ResourceContents struct {
	URI      string `json:"uri"`
	MimeType string `json:"mimeType,omitempty"`
	Text     string `json:"text,omitempty"`
}

// ResourceReadResult is the response to resources/read.
type ResourceReadResult struct {
	Contents []ResourceContents `json:"contents"`
}

// ToolsListResult is the response to tools/list.
type ToolsListResult struct {
	Tools []ToolDefinition `json:"tools"`
}

// ToolDefinition describes a single tool exposed by the server.
type ToolDefinition struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

// ToolCallParams holds the parameters for a tools/call request.
type ToolCallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

// ToolCallResult is the response to a tools/call request.
type ToolCallResult struct {
	Content []ContentBlock `json:"content"`
	IsError bool           `json:"isError,omitempty"`
}

// ContentBlock is a single content element in a tool call result.
type ContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// TextResult creates a successful tool result with the given text.
func TextResult(text string) ToolCallResult {
	return ToolCallResult{Content: []ContentBlock{{Type: "text", Text: text}}}
}

// ErrorResult creates a tool result that signals an error.
func ErrorResult(text string) ToolCallResult {
	return ToolCallResult{Content: []ContentBlock{{Type: "text", Text: text}}, IsError: true}
}
