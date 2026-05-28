package skills

import "github.com/puck-security/puck-scout/mcp/internal/policy"

// Reconcile compares each skill's RequiredCommands against the embedded
// policy grammar (policy/policy.toml) and populates Status +
// MissingCommands.  Skills without a RequiredCommands field reconcile
// to OK.
//
// Called at MCP server startup after the skill set is loaded.  Not
// safe to call concurrently with itself or with readers of
// Status/MissingCommands; serialize at startup before the router begins
// handling requests.
func Reconcile(s *Skill) {
	var missing []string
	for _, pattern := range s.RequiredCommands {
		if !policy.AllowsPattern(pattern) {
			missing = append(missing, pattern)
		}
	}
	if len(missing) > 0 {
		s.Status = SkillStatusDegraded
		s.MissingCommands = missing
	} else {
		s.Status = SkillStatusOK
		s.MissingCommands = nil
	}
}

// ReconcileAll applies Reconcile to every skill in the map.  Convenience
// for the startup path.
func ReconcileAll(skills map[string]*Skill) {
	for _, s := range skills {
		Reconcile(s)
	}
}
