package router

import (
	"fmt"
	"sort"
	"strings"

	"github.com/puck-security/puck-scout/mcp/internal/mcp"
)

// SkillResourceScheme is the URI scheme puck-mcp uses for skill
// resources. Skill bodies are addressable as
// `puck://skill/<name>` (full bundle) or
// `puck://skill/<name>/<section>` (one section).
const SkillResourceScheme = "puck://skill/"

// ListResources returns the catalog of resources the server exposes.
// Today: one "full bundle" resource per loaded skill (the entire
// guidance + README), one per-section resource for each section the
// skill populates, and one per loaded cross-skill reference doc
// (puck://reference/<name>).  AIs can request any of them via
// resources/read without spending a tool-call slot.  See ADR-019.
func (r *Router) ListResources() []mcp.Resource {
	names := make([]string, 0, len(r.skills))
	for name := range r.skills {
		names = append(names, name)
	}
	sort.Strings(names)

	resources := make([]mcp.Resource, 0, len(names)*3+len(r.references))
	for _, name := range names {
		s := r.skills[name]
		resources = append(resources, mcp.Resource{
			URI:         SkillResourceScheme + name,
			Name:        name + " (full)",
			Description: fmt.Sprintf("Complete %s skill body — every guidance section plus README. Use this when the AI wants the entire reference at once.", name),
			MimeType:    "text/markdown",
		})
		for _, section := range []string{
			"pathfinder_strategy",
			"fleet_strategy",
			"iteration_criteria",
			"analysis_template",
			"remediation_guidance",
			"readme",
		} {
			body, ok := s.SectionByName(section)
			if !ok || body == "" {
				continue
			}
			resources = append(resources, mcp.Resource{
				URI:         SkillResourceScheme + name + "/" + section,
				Name:        name + " — " + section,
				Description: fmt.Sprintf("`%s` section of the %s skill. Equivalent to calling puck_get_skill_section but accessible via resources/read.", section, name),
				MimeType:    "text/markdown",
			})
		}
	}

	// Cross-skill reference docs (translation tables, deployment
	// guides, etc.).  Sorted so the listing is stable.
	refNames := make([]string, 0, len(r.references))
	for name := range r.references {
		refNames = append(refNames, name)
	}
	sort.Strings(refNames)
	for _, name := range refNames {
		resources = append(resources, mcp.Resource{
			URI:         ReferenceResourceScheme + name,
			Name:        "reference: " + name,
			Description: fmt.Sprintf("Cross-skill reference doc `%s` — consult when a skill's prose mentions it (e.g. os-adaptation translates Unix tools to Windows native commands).", name),
			MimeType:    "text/markdown",
		})
	}
	return resources
}

// ReadResource resolves a `puck://skill/...` or `puck://reference/...`
// URI to its body. Returns the body text and a MIME type, or an error
// if the URI is malformed or the addressed resource doesn't exist.
// See ADR-019.
func (r *Router) ReadResource(uri string) (string, string, error) {
	// Reference docs (cross-skill markdown — translation tables, guides).
	if rest, ok := strings.CutPrefix(uri, ReferenceResourceScheme); ok {
		if rest == "" {
			return "", "", fmt.Errorf("malformed resource URI %q: missing reference name", uri)
		}
		body, ok := r.references[rest]
		if !ok {
			return "", "", fmt.Errorf("reference %q is not loaded by this server", rest)
		}
		return body, "text/markdown", nil
	}

	rest, ok := strings.CutPrefix(uri, SkillResourceScheme)
	if !ok {
		return "", "", fmt.Errorf("unsupported resource URI %q (this server exposes %s* and %s* resources)", uri, SkillResourceScheme, ReferenceResourceScheme)
	}
	skillName, section, hasSection := strings.Cut(rest, "/")
	if skillName == "" {
		return "", "", fmt.Errorf("malformed resource URI %q: missing skill name", uri)
	}
	s, ok := r.skills[skillName]
	if !ok {
		return "", "", fmt.Errorf("skill %q is not loaded by this server", skillName)
	}
	if !hasSection {
		// Full bundle = Context() + README.
		body := s.Context()
		if s.README != "" {
			body += "\n\n## README\n\n" + s.README
		}
		return body, "text/markdown", nil
	}
	body, ok := s.SectionByName(section)
	if !ok {
		return "", "", fmt.Errorf("unknown section %q on skill %q", section, skillName)
	}
	if body == "" {
		return "", "", fmt.Errorf("section %q on skill %q is empty", section, skillName)
	}
	return body, "text/markdown", nil
}
