package policy

import (
	_ "embed"
	"fmt"
	"sync"

	"github.com/BurntSushi/toml"
)

// policy.toml is the single source of truth for command grammar, shared with
// the Rust agent.  Rust uses `include_str!("../../../../policy/policy.toml")`
// against the repo root directly; Go's `//go:embed` can only reference files
// within the module, so we keep a copy here that is kept in sync from the
// canonical root via `go generate ./internal/policy/`.  CI verifies the two
// don't drift (see .github/workflows/policy-sync.yml).
//
//go:generate sh -c "cp ../../../policy/policy.toml ./policy.toml"
//go:embed policy.toml
var policyTOML []byte

var (
	loadOnce sync.Once
	loaded   *Policy
	loadErr  error
)

// Loaded returns the parsed embedded policy.  Panics if the embedded TOML is
// invalid (build-time error caught by CI).
func Loaded() *Policy {
	loadOnce.Do(func() {
		var p Policy
		if err := toml.Unmarshal(policyTOML, &p); err != nil {
			loadErr = fmt.Errorf("policy.toml parse: %w", err)
			return
		}
		for name, bp := range p.Binaries {
			bp.Name = name
		}
		loaded = &p
	})
	if loadErr != nil {
		panic(loadErr)
	}
	return loaded
}
