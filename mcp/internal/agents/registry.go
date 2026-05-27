package agents

import (
	"sync"
	"time"
)

// AgentStatus represents the current status of an agent.
type AgentStatus string

const (
	StatusActive AgentStatus = "active"
	StatusIdle   AgentStatus = "idle"
	StatusStale  AgentStatus = "stale"

	// activeThresholdSecs is the window in which an agent is considered active.
	activeThresholdSecs = 10
)

// Agent holds metadata about a registered agent.
type Agent struct {
	Hostname string
	AgentID  string
	LastSeen time.Time
	Status   AgentStatus
	// PolicyDigest is the hex-encoded sha256 of the policy.toml the
	// agent was compiled with.  Reported by the agent on every poll /
	// SSE-connect via the `policy_digest` query param; "" if the agent
	// predates the field.  Compared to policy.Digest() (server-side) to
	// detect drift.
	PolicyDigest string
	// OS is the canonical OS family the agent reports at poll /
	// SSE-connect time.  Values: "linux", "darwin", "windows", or
	// "" for agents predating the field.  Used by puck_investigate to
	// give the LLM a target_os hint up front so it can skip the
	// uname-discovery turn.
	OS string
}

// Registry is an in-memory registry of known agents.
type Registry struct {
	mu               sync.RWMutex
	agents           map[string]*Agent // keyed by hostname
	staleTimeoutSecs int
}

// NewRegistry creates a new Registry with the given stale timeout in seconds.
func NewRegistry(staleTimeoutSecs int) *Registry {
	return &Registry{
		agents:           make(map[string]*Agent),
		staleTimeoutSecs: staleTimeoutSecs,
	}
}

// Touch registers or updates an agent's last-seen time.
// Returns true the first time this hostname is seen (newly registered).
func (r *Registry) Touch(hostname, agentID string) (firstContact bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	a, ok := r.agents[hostname]
	if !ok {
		a = &Agent{Hostname: hostname, AgentID: agentID}
		r.agents[hostname] = a
		firstContact = true
	}
	a.AgentID = agentID
	a.LastSeen = time.Now()
	a.Status = StatusActive
	return firstContact
}

// RecordPolicyDigest records the agent's reported policy digest.  Called
// from the agent-facing handlers (handlePoll, handleEvents) when the
// agent passes ?policy_digest=<hex>.  No-op if digest is empty (older
// agents that don't report the field) or if the agent is unknown — the
// caller is responsible for Touch'ing first.
func (r *Registry) RecordPolicyDigest(hostname, digest string) {
	if digest == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if a, ok := r.agents[hostname]; ok {
		a.PolicyDigest = digest
	}
}

// PolicyDigest returns the last-reported policy digest for hostname,
// or "" if unknown.  Cheap O(1) read for the rejection-enrichment path.
func (r *Registry) PolicyDigest(hostname string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if a, ok := r.agents[hostname]; ok {
		return a.PolicyDigest
	}
	return ""
}

// RecordOS records the agent's reported OS family.  Called from the
// agent-facing handlers when the agent passes ?os=<value>.  No-op if os
// is empty (older agents) or the agent is unknown — caller Touch's
// first.  Values seen in practice: "linux", "darwin", "windows".
func (r *Registry) RecordOS(hostname, os string) {
	if os == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if a, ok := r.agents[hostname]; ok {
		a.OS = os
	}
}

// OS returns the last-reported OS for hostname, or "" if unknown.
// O(1) read for the puck_investigate hint path.
func (r *Registry) OS(hostname string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if a, ok := r.agents[hostname]; ok {
		return a.OS
	}
	return ""
}

// Status returns the current status of the agent identified by hostname.
// If the hostname is unknown it is considered stale.
func (r *Registry) Status(hostname string) AgentStatus {
	r.mu.RLock()
	defer r.mu.RUnlock()

	a, ok := r.agents[hostname]
	if !ok {
		return StatusStale
	}
	return r.computeStatus(a.LastSeen)
}

// ActiveAgents returns all agents that are not stale (active or idle).
func (r *Registry) ActiveAgents() []Agent {
	r.mu.RLock()
	defer r.mu.RUnlock()

	now := time.Now()
	staleThreshold := time.Duration(r.staleTimeoutSecs) * time.Second

	var result []Agent
	for _, a := range r.agents {
		elapsed := now.Sub(a.LastSeen)
		if elapsed < staleThreshold {
			status := r.computeStatus(a.LastSeen)
			result = append(result, Agent{
				Hostname:     a.Hostname,
				AgentID:      a.AgentID,
				LastSeen:     a.LastSeen,
				Status:       status,
				PolicyDigest: a.PolicyDigest,
				OS:           a.OS,
			})
		}
	}
	return result
}

// computeStatus derives a status from a last-seen time.
// Must be called with at least a read lock held.
func (r *Registry) computeStatus(lastSeen time.Time) AgentStatus {
	elapsed := time.Since(lastSeen)
	if elapsed <= activeThresholdSecs*time.Second {
		return StatusActive
	}
	if elapsed < time.Duration(r.staleTimeoutSecs)*time.Second {
		return StatusIdle
	}
	return StatusStale
}
