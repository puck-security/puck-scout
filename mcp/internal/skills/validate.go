package skills

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	reName    = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	reVersion = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

	validCategories = map[string]bool{
		"ir-triage": true, "hunt": true, "compliance": true,
		"inventory": true, "red-team": true,
	}
	validInputTypes = map[string]bool{
		"string": true, "string[]": true, "number": true, "boolean": true,
	}
)

// Validate returns a list of constraint violations for a loaded Skill.
// An empty slice means the skill satisfies the schema in skills/schema/skill-schema.json.
func Validate(s *Skill) []string {
	var errs []string

	if s.Name == "" {
		errs = append(errs, "name: required")
	} else if !reName.MatchString(s.Name) {
		errs = append(errs, fmt.Sprintf("name: must match ^[a-z][a-z0-9-]*$ (got %q)", s.Name))
	}

	if s.Version == "" {
		errs = append(errs, "version: required")
	} else if !reVersion.MatchString(s.Version) {
		errs = append(errs, fmt.Sprintf("version: must be semantic versioning e.g. 1.0.0 (got %q)", s.Version))
	}

	switch l := len(s.Description); {
	case l == 0:
		errs = append(errs, "description: required")
	case l < 10:
		errs = append(errs, fmt.Sprintf("description: too short (%d chars, minimum 10)", l))
	case l > 200:
		errs = append(errs, fmt.Sprintf("description: too long (%d chars, maximum 200)", l))
	}

	if s.Category == "" {
		errs = append(errs, "category: required")
	} else if !validCategories[s.Category] {
		errs = append(errs, fmt.Sprintf("category: invalid value %q; valid: ir-triage, hunt, compliance, inventory, red-team", s.Category))
	}

	if strings.TrimSpace(s.Guidance.Objective) == "" {
		errs = append(errs, "guidance.objective: required, must not be empty")
	}
	if strings.TrimSpace(s.Guidance.PathfinderStrategy) == "" {
		errs = append(errs, "guidance.pathfinder_strategy: required, must not be empty")
	}
	if strings.TrimSpace(s.Guidance.FleetStrategy) == "" {
		errs = append(errs, "guidance.fleet_strategy: required, must not be empty")
	}
	if strings.TrimSpace(s.Guidance.IterationCriteria) == "" {
		errs = append(errs, "guidance.iteration_criteria: required, must not be empty")
	}
	if strings.TrimSpace(s.Guidance.AnalysisTemplate) == "" {
		errs = append(errs, "guidance.analysis_template: required, must not be empty")
	}

	if len(s.Inputs) == 0 {
		errs = append(errs, "inputs: required, must have at least 1 item")
	} else {
		for i, inp := range s.Inputs {
			prefix := fmt.Sprintf("inputs[%d]", i)
			if inp.Name == "" {
				errs = append(errs, prefix+".name: required")
			}
			if inp.Type == "" {
				errs = append(errs, prefix+".type: required")
			} else if !validInputTypes[inp.Type] {
				errs = append(errs, fmt.Sprintf("%s.type: invalid value %q; valid: string, string[], number, boolean", prefix, inp.Type))
			}
			if inp.Description == "" {
				errs = append(errs, prefix+".description: required")
			}
		}
	}

	if strings.TrimSpace(s.ExpectedDuration) == "" {
		errs = append(errs, "expected_duration: required, must not be empty")
	}

	if s.MaxTurns != 0 && (s.MaxTurns < 1 || s.MaxTurns > 20) {
		errs = append(errs, fmt.Sprintf("max_turns: must be between 1 and 20 (got %d)", s.MaxTurns))
	}

	for i, cmd := range s.RequiredCommands {
		if strings.TrimSpace(cmd) == "" {
			errs = append(errs, fmt.Sprintf("required_commands[%d]: must not be empty", i))
		}
	}

	return errs
}
