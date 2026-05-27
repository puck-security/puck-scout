package router

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ReferenceResourceScheme is the URI prefix for the top-level reference
// documents (cross-skill guides, translation tables) the server
// exposes alongside per-skill resources.  Distinct from
// SkillResourceScheme so clients can tell at a glance which addressable
// content is skill-bound vs. shared.
const ReferenceResourceScheme = "puck://reference/"

// LoadReferenceDir scans `<skillsDir>/_reference/*.md` and returns a map
// of basename-without-extension to file contents.  Used at server
// startup to populate Router.references; missing directory is fine
// (returns empty map, no error).  Failed reads on individual files are
// logged via the returned error slice — partial population is OK.
func LoadReferenceDir(skillsDir string) (map[string]string, error) {
	if skillsDir == "" {
		return map[string]string{}, nil
	}
	root := filepath.Join(skillsDir, "_reference")
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}, nil
		}
		return nil, fmt.Errorf("read reference dir %s: %w", root, err)
	}
	out := make(map[string]string, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".md") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			return nil, fmt.Errorf("read reference %s: %w", name, err)
		}
		key := strings.TrimSuffix(name, ".md")
		out[key] = string(body)
	}
	return out, nil
}

// SetReferences installs the loaded reference docs on the router.  Kept
// as a setter (vs. extending router.New) so existing call sites and
// tests continue to compile unchanged.  Pass nil or empty map to
// disable reference resources.
func (r *Router) SetReferences(refs map[string]string) {
	r.references = refs
}
