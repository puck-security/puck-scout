package skills

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// SkillStatus captures whether the deployed allowlist covers everything
// the skill declared in `required_commands`. Populated at startup by
// Reconcile; persists for the life of the process (config reloads not
// supported today).
type SkillStatus string

const (
	SkillStatusOK       SkillStatus = "ok"
	SkillStatusDegraded SkillStatus = "degraded"
)

type Skill struct {
	Name             string       `yaml:"name"`
	Version          string       `yaml:"version"`
	Description      string       `yaml:"description"`
	Category         string       `yaml:"category"`
	Guidance         Guidance     `yaml:"guidance"`
	Inputs           []SkillInput `yaml:"inputs"`
	ExpectedDuration string       `yaml:"expected_duration"`
	MaxTurns         int          `yaml:"max_turns"`
	// RequiredCommands lists the MCP-server allowlist patterns this skill
	// expects to invoke. Each entry is either a bare binary name (matching
	// an `unrestricted` entry) or a "<binary> <subcommand prefix>" string
	// matching one of `allowed_subcommands`. Validated at server startup
	// by Reconcile. Optional; older skills without this field reconcile
	// to SkillStatusOK with no missing commands.
	RequiredCommands []string `yaml:"required_commands,omitempty"`

	// Status + MissingCommands are populated by Reconcile after both the
	// skill set and the policy is loaded. Not from YAML.
	Status          SkillStatus `yaml:"-"`
	MissingCommands []string    `yaml:"-"`

	RawYAML string `yaml:"-"`
	README  string `yaml:"-"`
}

type Guidance struct {
	Objective           string `yaml:"objective"`
	PathfinderStrategy  string `yaml:"pathfinder_strategy"`
	FleetStrategy       string `yaml:"fleet_strategy"`
	IterationCriteria   string `yaml:"iteration_criteria"`
	AnalysisTemplate    string `yaml:"analysis_template"`
	RemediationGuidance string `yaml:"remediation_guidance"`
}

type SkillInput struct {
	Name        string `yaml:"name"`
	Type        string `yaml:"type"`
	Description string `yaml:"description"`
	Required    bool   `yaml:"required"`
}

func LoadSkill(dir string) (*Skill, error) {
	yamlPath := filepath.Join(dir, "skill.yaml")
	readmePath := filepath.Join(dir, "README.md")

	yamlData, err := os.ReadFile(yamlPath)
	if err != nil {
		return nil, fmt.Errorf("read skill.yaml: %w", err)
	}

	var skill Skill
	if err := yaml.Unmarshal(yamlData, &skill); err != nil {
		return nil, fmt.Errorf("parse skill.yaml: %w", err)
	}

	skill.RawYAML = string(yamlData)

	readmeData, err := os.ReadFile(readmePath)
	if err != nil {
		skill.README = ""
	} else {
		skill.README = string(readmeData)
	}

	return &skill, nil
}

func LoadAll(skillsDir string) (map[string]*Skill, error) {
	skills := make(map[string]*Skill)
	entries, err := os.ReadDir(skillsDir)
	if err != nil {
		if os.IsNotExist(err) {
			// Missing skills dir is not fatal — server starts with an empty
			// skill map. Investigations can still run; puck_list_skills
			// returns an empty list. The caller logs a warning.
			return skills, nil
		}
		return nil, fmt.Errorf("read skills dir: %w", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dir := filepath.Join(skillsDir, entry.Name())
		yamlPath := filepath.Join(dir, "skill.yaml")
		if _, err := os.Stat(yamlPath); os.IsNotExist(err) {
			continue
		}
		skill, err := LoadSkill(dir)
		if err != nil {
			return nil, fmt.Errorf("load skill %s: %w", entry.Name(), err)
		}
		skills[skill.Name] = skill
	}
	return skills, nil
}

// OverviewContext returns the subset of the skill body the AI needs to
// START the investigation: description, objective, pathfinder strategy,
// iteration criteria, and the analysis-template skeleton. The fleet
// strategy and remediation guidance — which only matter at fan-out and
// report-write time respectively — are intentionally omitted, and the
// AI fetches them on demand via puck_get_skill_section (see ADR-018).
//
// For credential-exposure v1.2.1 this is about 32 KB vs. ~52 KB from
// Context() (post-ADR-017), keeping puck_investigate well below
// typical MCP-client context-limit thresholds across all bundled
// skills.
func (s *Skill) OverviewContext() string {
	return fmt.Sprintf("# Skill: %s (v%s)\n\n%s\n\n## Guidance\n\n### Objective\n%s\n\n### Pathfinder Strategy\n%s\n\n### Iteration Criteria\n%s\n\n### Analysis Template\n%s\n\n---\n\n**Two more guidance sections are available on demand via `puck_get_skill_section(investigation_id, section)`:**\n- `fleet_strategy` — call when you finish the pathfinder phase and are ready to fan out across the fleet.\n- `remediation_guidance` — call when you are about to write the final analysis and need the rotation/containment command templates.\n",
		s.Name, s.Version, s.Description,
		s.Guidance.Objective,
		s.Guidance.PathfinderStrategy,
		s.Guidance.IterationCriteria,
		s.Guidance.AnalysisTemplate,
	)
}

// SectionByName returns the named section of the skill body. Used by
// puck_get_skill_section to deliver the parts of the skill that
// OverviewContext omits. Returns ("", false) for unknown section names
// so callers can return a structured error.
func (s *Skill) SectionByName(name string) (string, bool) {
	switch name {
	case "objective":
		return s.Guidance.Objective, true
	case "pathfinder_strategy":
		return s.Guidance.PathfinderStrategy, true
	case "fleet_strategy":
		return s.Guidance.FleetStrategy, true
	case "iteration_criteria":
		return s.Guidance.IterationCriteria, true
	case "analysis_template":
		return s.Guidance.AnalysisTemplate, true
	case "remediation_guidance":
		return s.Guidance.RemediationGuidance, true
	case "readme":
		return s.README, true
	case "full":
		full := s.Context()
		if s.README != "" {
			full += "\n\n## README\n\n" + s.README
		}
		return full, true
	default:
		return "", false
	}
}

// Context returns the skill body — every guidance section, concatenated
// into a single markdown document. The README is intentionally NOT
// included: it's human-facing documentation, and the AI gets the same
// signal from the description + guidance sections. Including the
// README pushed the response over typical MCP-client context limits
// for large skills (credential-exposure v1.2.1 was ~70 KB with the
// README, ~52 KB without). See ADR-017.
//
// The README remains accessible via the file system and (post-Tier 3)
// via an MCP resource read.
func (s *Skill) Context() string {
	base := fmt.Sprintf("# Skill: %s (v%s)\n\n%s\n\n## Guidance\n\n### Objective\n%s\n\n### Pathfinder Strategy\n%s\n\n### Fleet Strategy\n%s\n\n### Iteration Criteria\n%s\n\n### Analysis Template\n%s",
		s.Name, s.Version, s.Description,
		s.Guidance.Objective,
		s.Guidance.PathfinderStrategy,
		s.Guidance.FleetStrategy,
		s.Guidance.IterationCriteria,
		s.Guidance.AnalysisTemplate,
	)
	if s.Guidance.RemediationGuidance != "" {
		base += "\n\n### Remediation Guidance\n" + s.Guidance.RemediationGuidance
	}
	return base
}
