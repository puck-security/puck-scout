package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLogWritesJSONLines(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	logger, err := NewLogger(logPath)
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer logger.Close()

	err = logger.Log(Entry{
		EventType:       EventCommandQueued,
		InvestigationID: "inv-1",
		Hostname:        "host-01",
		Command:         "ps",
		Args:            []string{"aux"},
	})
	if err != nil {
		t.Fatalf("failed to log: %v", err)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read log: %v", err)
	}

	var entry Entry
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatalf("failed to parse log entry: %v", err)
	}
	if entry.EventType != EventCommandQueued {
		t.Errorf("expected command_queued, got %s", entry.EventType)
	}
	if entry.Hostname != "host-01" {
		t.Errorf("expected host-01, got %s", entry.Hostname)
	}
	if entry.Timestamp == "" {
		t.Error("timestamp should be auto-filled")
	}
}

func TestLogWritesToInvestigationLog(t *testing.T) {
	dir := t.TempDir()
	globalPath := filepath.Join(dir, "audit.jsonl")
	invPath := filepath.Join(dir, "inv-audit.jsonl")
	logger, err := NewLogger(globalPath)
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer logger.Close()

	if err := logger.AddInvestigationLog("inv-1", invPath); err != nil {
		t.Fatalf("failed to add investigation log: %v", err)
	}
	logger.Log(Entry{
		EventType:       EventCommandQueued,
		InvestigationID: "inv-1",
		Command:         "ls",
	})

	for _, path := range []string{globalPath, invPath} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("failed to read %s: %v", path, err)
		}
		if len(data) == 0 {
			t.Errorf("expected data in %s", path)
		}
	}
}
