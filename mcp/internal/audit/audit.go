package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

type EventType string

const (
	EventCommandQueued      EventType = "command_queued"
	EventCommandResult      EventType = "command_result"
	EventCommandRejected    EventType = "command_rejected"
	EventInvestigationStart EventType = "investigation_start"
	EventInvestigationEnd   EventType = "investigation_end"
	EventCostCapReached     EventType = "cost_cap_reached"
	// EventCrossAgentResultRejected is emitted when an agent attempts to
	// submit results for a command that was queued to a different agent
	// hostname.  This closes Vuln 6 (cross-agent result injection).
	EventCrossAgentResultRejected EventType = "cross_agent_result_rejected"
	// EventCertIssued is emitted after a successful SignAgentCert call in
	// enroll or renew.  Records the agent hostname and cert serial so that
	// PKI events are traceable in the audit log without storing the cert itself.
	EventCertIssued EventType = "cert_issued"
	// EventCertIssuanceFailed is emitted when a bootstrap token was already
	// consumed (atomically validated + spent) but the subsequent SignAgentCert
	// call failed.  The token is lost; the operator must issue a new one.
	// Lets operators correlate "I generated 5 tokens but only 4 certs landed".
	EventCertIssuanceFailed EventType = "cert_issuance_failed"
)

type Entry struct {
	Timestamp        string    `json:"timestamp"`
	EventType        EventType `json:"event_type"`
	InvestigationID  string    `json:"investigation_id"`
	Hostname         string    `json:"hostname,omitempty"`
	Command          string    `json:"command,omitempty"`
	Args             []string  `json:"args,omitempty"`
	RequestingClient string    `json:"requesting_client,omitempty"`
	Status           string    `json:"status,omitempty"`
	Reason           string    `json:"reason,omitempty"`
}

type Logger struct {
	mu     sync.Mutex
	global *os.File
	perInv map[string]*os.File
}

func NewLogger(globalPath string) (*Logger, error) {
	f, err := os.OpenFile(globalPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("open audit log %s: %w", globalPath, err)
	}
	return &Logger{global: f, perInv: make(map[string]*os.File)}, nil
}

func (l *Logger) AddInvestigationLog(investigationID, path string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("open investigation audit log: %w", err)
	}
	l.perInv[investigationID] = f
	return nil
}

func (l *Logger) Log(entry Entry) error {
	if entry.Timestamp == "" {
		entry.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal audit entry: %w", err)
	}
	line := append(data, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()

	if _, err := l.global.Write(line); err != nil {
		return fmt.Errorf("write global audit log: %w", err)
	}
	if f, ok := l.perInv[entry.InvestigationID]; ok {
		if _, err := f.Write(line); err != nil {
			return fmt.Errorf("write investigation audit log: %w", err)
		}
	}
	return nil
}

// CloseInvestigation flushes and closes the per-investigation audit log for the
// given ID. Call this when an investigation completes to release the file descriptor.
func (l *Logger) CloseInvestigation(id string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if f, ok := l.perInv[id]; ok {
		f.Close()
		delete(l.perInv, id)
	}
}

func (l *Logger) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.global.Close()
	for _, f := range l.perInv {
		f.Close()
	}
}
