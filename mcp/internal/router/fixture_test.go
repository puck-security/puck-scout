package router

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/puck-security/puck-scout/mcp/internal/agents"
	"github.com/puck-security/puck-scout/mcp/internal/audit"
	"github.com/puck-security/puck-scout/mcp/internal/config"
	"github.com/puck-security/puck-scout/mcp/internal/investigation"
	"github.com/puck-security/puck-scout/mcp/internal/skills"
)

// testRouterFixture is a fully-wired Router suitable for execution-path
// tests.  Each call to newTestRouter gets its own temp dir, audit log,
// queue, registry, and investigation manager — so parallel tests don't
// share state.
//
// Whitelist is permissive: every binary in `allowedCommands` is
// "unrestricted" (no subcommand or arg restrictions).  Tests that need
// to assert policy rejection pass an `allowedCommands` list that
// deliberately omits the binary they expect to be rejected.
type testRouterFixture struct {
	Router     *Router
	Queue      *agents.Queue
	Registry   *agents.Registry
	InvManager *investigation.Manager
	Audit      *audit.Logger
	AuditPath  string
	Dir        string
}

func newTestRouter(t *testing.T, allowedCommands []string) *testRouterFixture {
	t.Helper()
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	auditLog, err := audit.NewLogger(auditPath)
	if err != nil {
		t.Fatalf("audit.NewLogger: %v", err)
	}
	t.Cleanup(func() { auditLog.Close() })

	registry := agents.NewRegistry(300)
	queue := agents.NewQueue()
	invMgr := investigation.NewManager(filepath.Join(dir, "investigations"), 5, 50, 100)
	cfg := &config.Config{
		MaxFanoutConcurrency: 50,
	}
	_ = allowedCommands // command-validation lives in the embedded policy now; tests can't inject extras

	r := &Router{
		registry:   registry,
		queue:      queue,
		audit:      auditLog,
		invManager: invMgr,
		skills:     map[string]*skills.Skill{},
		cfg:        cfg,
	}
	return &testRouterFixture{
		Router: r, Queue: queue, Registry: registry, InvManager: invMgr,
		Audit: auditLog, AuditPath: auditPath, Dir: dir,
	}
}

// newInvestigation creates a fresh investigation and returns its ID.
func (f *testRouterFixture) newInvestigation(t *testing.T) string {
	t.Helper()
	inv, err := f.InvManager.Create("test", "")
	if err != nil {
		t.Fatalf("create investigation: %v", err)
	}
	return inv.ID
}

// auditEntries reads the audit log and returns all entries.  Useful
// for assertions about per-command granularity, cost-cap events,
// rejection counts, etc.
func (f *testRouterFixture) auditEntries(t *testing.T) []auditEntry {
	t.Helper()
	// Force any buffered audit writes to disk.  The audit.Logger
	// writes synchronously per Log() call so reading the file is
	// sufficient — no flush needed.
	file, err := os.Open(f.AuditPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("open audit: %v", err)
	}
	defer file.Close()

	var entries []auditEntry
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		var e auditEntry
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			continue
		}
		entries = append(entries, e)
	}
	return entries
}

// auditEntry is a minimal struct mirroring the audit.Entry JSON shape.
// We don't import audit.Entry directly because the production type has
// methods + tags we don't need here.
type auditEntry struct {
	EventType       string   `json:"event_type"`
	InvestigationID string   `json:"investigation_id"`
	Hostname        string   `json:"hostname"`
	Command         string   `json:"command"`
	Args            []string `json:"args"`
	Status          string   `json:"status"`
	Reason          string   `json:"reason"`
}

// countAuditEvents returns the number of audit entries matching
// (eventType, hostname).  Hostname "" matches any.
func countAuditEvents(entries []auditEntry, eventType, hostname string) int {
	n := 0
	for _, e := range entries {
		if e.EventType != eventType {
			continue
		}
		if hostname != "" && e.Hostname != hostname {
			continue
		}
		n++
	}
	return n
}
