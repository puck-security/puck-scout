package investigation

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/puck-security/puck-scout/mcp/internal/agents"
)

// containedPath verifies that dest is inside baseDir after path normalization,
// returning an error if it is not. This is a last-resort defense against path
// traversal regardless of how dest was constructed.
func containedPath(baseDir, dest string) error {
	base := filepath.Clean(baseDir) + string(filepath.Separator)
	if !strings.HasPrefix(filepath.Clean(dest)+string(filepath.Separator), base) {
		return fmt.Errorf("destination path escapes base directory")
	}
	return nil
}

// HostResult holds the results collected from a single host during an investigation.
type HostResult struct {
	Hostname        string                 `json:"hostname"`
	InvestigationID string                 `json:"investigation_id"`
	Commands        []agents.CommandResult `json:"commands"`
	CollectedAt     time.Time              `json:"collected_at"`
}

// CreateDirs creates the investigation directory tree: invDir, pathfinder/, fleet/, followup/.
func CreateDirs(invDir string) error {
	for _, sub := range []string{"", "pathfinder", "fleet", "followup"} {
		dir := invDir
		if sub != "" {
			dir = filepath.Join(invDir, sub)
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create dir %q: %w", dir, err)
		}
	}
	return nil
}

// WriteMetadata writes a metadata.json file in invDir containing the query, skill, and any
// additional config values.
func WriteMetadata(invDir, query, skill string, config map[string]any) error {
	meta := map[string]any{
		"query":  query,
		"skill":  skill,
		"config": config,
	}
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}
	dest := filepath.Join(invDir, "metadata.json")
	if err := os.WriteFile(dest, data, 0o600); err != nil {
		return fmt.Errorf("write metadata: %w", err)
	}
	return nil
}

// WriteHostResult writes a {hostname}.json file under invDir/<phase>/ and returns the file path.
func WriteHostResult(invDir string, phase Phase, hostname string, results []agents.CommandResult, investigationID string) (string, error) {
	hr := HostResult{
		Hostname:        hostname,
		InvestigationID: investigationID,
		Commands:        results,
		CollectedAt:     time.Now(),
	}
	data, err := json.MarshalIndent(hr, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal host result: %w", err)
	}
	dest := filepath.Join(invDir, string(phase), hostname+".json")
	if err := containedPath(invDir, dest); err != nil {
		return "", fmt.Errorf("hostname %q: %w", hostname, err)
	}
	if err := os.WriteFile(dest, data, 0o600); err != nil {
		return "", fmt.Errorf("write host result: %w", err)
	}
	return dest, nil
}

// WriteFollowupResult writes a {turn}-{hostname}.json file under invDir/followup/ and returns
// the file path.
func WriteFollowupResult(invDir string, turn int, hostname string, results []agents.CommandResult, investigationID string) (string, error) {
	hr := HostResult{
		Hostname:        hostname,
		InvestigationID: investigationID,
		Commands:        results,
		CollectedAt:     time.Now(),
	}
	data, err := json.MarshalIndent(hr, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal followup result: %w", err)
	}
	filename := fmt.Sprintf("%d-%s.json", turn, hostname)
	dest := filepath.Join(invDir, "followup", filename)
	if err := containedPath(invDir, dest); err != nil {
		return "", fmt.Errorf("hostname %q: %w", hostname, err)
	}
	if err := os.WriteFile(dest, data, 0o600); err != nil {
		return "", fmt.Errorf("write followup result: %w", err)
	}
	return dest, nil
}

// WriteAnalysis writes the analysis content to analysis.md in invDir.
func WriteAnalysis(invDir, content string) error {
	dest := filepath.Join(invDir, "analysis.md")
	if err := os.WriteFile(dest, []byte(content), 0o600); err != nil {
		return fmt.Errorf("write analysis: %w", err)
	}
	return nil
}
