package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/puck-security/puck-scout/mcp/internal/agents"
	"github.com/puck-security/puck-scout/mcp/internal/audit"
	"github.com/puck-security/puck-scout/mcp/internal/pki"
	"github.com/puck-security/puck-scout/mcp/internal/policy"
)

// BuildInfo is set at startup by main.go from -ldflags-injected
// `version` / `commit` / `buildDate` strings.  Surfaced through
// /v1/health so operators can verify the running binary matches what
// they expect post-install (no doctor required).  Empty strings are
// fine — handleHealth still renders.
var BuildInfo struct {
	Version   string
	Commit    string
	BuildDate string
}

// AgentServer handles HTTP communication with endpoint agents.
type AgentServer struct {
	registry *agents.Registry
	queue    *agents.Queue
	logger   *slog.Logger
	audit    *audit.Logger
	// mTLS PKI dependencies (Cluster B)
	ca      *pki.CA
	ledger  *pki.TokenLedger
	certTTL time.Duration
}

// NewAgentServerOpts holds optional PKI dependencies for mTLS enrollment.
// All fields are required for production; nil values disable enrollment routes.
type NewAgentServerOpts struct {
	CA      *pki.CA
	Ledger  *pki.TokenLedger
	CertTTL time.Duration
}

// NewAgentServer creates a new AgentServer with mTLS PKI dependencies.
// auditLog may be nil during tests — Log calls are skipped when it is nil.
// opts may be nil in tests that do not exercise enrollment routes.
func NewAgentServer(registry *agents.Registry, queue *agents.Queue, logger *slog.Logger, auditLog *audit.Logger, opts *NewAgentServerOpts) *AgentServer {
	s := &AgentServer{registry: registry, queue: queue, logger: logger, audit: auditLog}
	if opts != nil {
		s.ca = opts.CA
		s.ledger = opts.Ledger
		s.certTTL = opts.CertTTL
	}
	return s
}

// Handler returns the HTTP mux with all agent endpoints registered.
// All routes that identify the agent (poll, results, renew-cert) require mTLS
// identity via requireMTLSIdentity middleware; hostname is derived from the
// client certificate, not from query parameters.
// /v1/enroll accepts a bootstrap token instead of a client cert (agents do not
// have a cert yet at enrollment time).
// /v1/health is excluded from auth so load-balancer probes work without credentials.
func (s *AgentServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /v1/poll", requireMTLSIdentity(s.handlePoll))
	mux.Handle("GET /v1/events", requireMTLSIdentity(s.handleEvents))
	mux.Handle("POST /v1/results", requireMTLSIdentity(s.handleResults))
	mux.Handle("POST /v1/enroll", http.HandlerFunc((&EnrollHandler{
		CA:      s.ca,
		Ledger:  s.ledger,
		CertTTL: s.certTTL,
		Audit:   s.audit,
	}).ServeHTTP))
	mux.Handle("POST /v1/renew-cert", requireMTLSIdentity((&RenewCertHandler{
		CA:      s.ca,
		CertTTL: s.certTTL,
		Audit:   s.audit,
	}).ServeHTTP))
	mux.HandleFunc("GET /v1/health", s.handleHealth)
	return mux
}

// handlePoll handles GET /v1/poll.
// The agent hostname is derived from the mTLS client certificate planted in
// the request context by requireMTLSIdentity — the query param is ignored.
// agent_id is still accepted as a query param for registry tracking.
// Returns 204 if no commands are pending, 200 with JSON otherwise.
func (s *AgentServer) handlePoll(w http.ResponseWriter, r *http.Request) {
	hostname := HostnameFromContext(r.Context())
	agentID := r.URL.Query().Get("agent_id")

	if agentID == "" {
		http.Error(w, "missing required query param: agent_id", http.StatusBadRequest)
		return
	}

	if first := s.registry.Touch(hostname, agentID); first {
		s.logger.Info("agent registered", "hostname", hostname, "agent_id", agentID)
	} else {
		s.logger.Debug("agent poll", "hostname", hostname)
	}
	s.registry.RecordPolicyDigest(hostname, r.URL.Query().Get("policy_digest"))
	s.registry.RecordOS(hostname, r.URL.Query().Get("os"))

	cmds := s.queue.Drain(hostname)
	if len(cmds) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]any{"commands": cmds}); err != nil {
		s.logger.Error("failed to encode poll response", "error", err)
	}
}

const agentResultsMaxBytes = 10 << 20 // 10 MB — enough for many 1 MB command results

// handleResults handles POST /v1/results.
// The submitter hostname is derived from the mTLS client certificate planted
// in the request context by requireMTLSIdentity — the wire field is ignored.
// Each result is delivered only if the cert hostname matches the hostname the
// command was queued to, preventing cross-agent result injection (Vuln 6).
func (s *AgentServer) handleResults(w http.ResponseWriter, r *http.Request) {
	submitter := HostnameFromContext(r.Context())

	r.Body = http.MaxBytesReader(w, r.Body, agentResultsMaxBytes)
	var submission agents.ResultSubmission
	if err := json.NewDecoder(r.Body).Decode(&submission); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	for _, result := range submission.Results {
		err := s.queue.Deliver(submitter, result.CommandID, result)
		switch {
		case errors.Is(err, agents.ErrHostnameMismatch):
			if s.audit != nil {
				_ = s.audit.Log(audit.Entry{
					EventType: audit.EventCrossAgentResultRejected,
					Hostname:  submitter,
					Reason:    "submitter does not own command " + result.CommandID,
				})
			}
			http.Error(w, "cross-agent result rejected", http.StatusForbidden)
			return
		case errors.Is(err, agents.ErrUnknownCommandID):
			// Unknown command id is a low-signal probe — return 404 without audit.
			http.Error(w, "unknown command id", http.StatusNotFound)
			return
		case err != nil:
			http.Error(w, "deliver failure", http.StatusInternalServerError)
			return
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleHealth handles GET /v1/health.
//
// Returns a JSON object with build + policy identity:
//
//	{
//	  "status": "ok",
//	  "version": "1.2.3",
//	  "commit": "abc1234",
//	  "build_date": "2026-05-27T...",
//	  "policy_digest": "<sha256 hex of embedded policy.toml>",
//	  "policy_version": "<policy.toml's policy_version field>"
//	}
//
// Operators use this as a deploy-time sanity check: curl /v1/health
// after install/upgrade and confirm policy_digest matches
// `shasum -a 256 policy/policy.toml`.  This is the cheapest way to
// rule out "old binary still running" and "embedded policy didn't
// pick up disk edits" without invoking puck-mcp doctor.
//
// All fields are non-secret — version + digest are derivable from the
// published binary, so no auth required (matches the existing
// unauthenticated /v1/health contract used by load-balancer probes).
func (s *AgentServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	body := map[string]any{
		"status":         "ok",
		"version":        BuildInfo.Version,
		"commit":         BuildInfo.Commit,
		"build_date":     BuildInfo.BuildDate,
		"policy_digest":  policy.Digest(),
		"policy_version": policy.Loaded().Version,
	}
	if err := json.NewEncoder(w).Encode(body); err != nil {
		s.logger.Error("failed to encode health response", "error", err)
	}
}

const sseHeartbeatInterval = 25 * time.Second

// handleEvents handles GET /v1/events.
// Opens a persistent Server-Sent Events stream for the connected agent.
// Commands are pushed as "command" events; heartbeat "ping" events are sent
// every 25 seconds to keep the connection alive through NAT and proxies.
// The agent drains any pending commands via GET /v1/poll before opening this
// stream, so RegisterSSE delivers only commands that arrive after connection.
func (s *AgentServer) handleEvents(w http.ResponseWriter, r *http.Request) {
	hostname := HostnameFromContext(r.Context())
	agentID := r.URL.Query().Get("agent_id")
	if agentID == "" {
		http.Error(w, "missing required query param: agent_id", http.StatusBadRequest)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	s.registry.Touch(hostname, agentID)
	s.registry.RecordPolicyDigest(hostname, r.URL.Query().Get("policy_digest"))
	s.registry.RecordOS(hostname, r.URL.Query().Get("os"))
	s.logger.Info("agent SSE connected", "hostname", hostname, "agent_id", agentID)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	// Initial ping confirms the stream is open.
	fmt.Fprintf(w, "event: ping\ndata: \n\n")
	flusher.Flush()

	cmdCh := s.queue.RegisterSSE(hostname)
	defer s.queue.UnregisterSSE(hostname, cmdCh)

	heartbeat := time.NewTicker(sseHeartbeatInterval)
	defer heartbeat.Stop()

	for {
		select {
		case cmd := <-cmdCh:
			data, err := json.Marshal(cmd)
			if err != nil {
				s.logger.Error("failed to marshal SSE command", "hostname", hostname, "error", err)
				continue
			}
			fmt.Fprintf(w, "event: command\ndata: %s\n\n", data)
			flusher.Flush()
		case <-heartbeat.C:
			s.registry.Touch(hostname, agentID)
			fmt.Fprintf(w, "event: ping\ndata: \n\n")
			flusher.Flush()
		case <-r.Context().Done():
			s.logger.Info("agent SSE disconnected", "hostname", hostname)
			return
		}
	}
}
