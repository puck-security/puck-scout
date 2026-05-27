// Package parsers turns raw stdout from high-volume commands into
// structured aggregations.  Used by the router's resultGroup pipeline
// to compress payloads at fleet scale: instead of returning a 5 KB
// `dpkg -l` listing per host, the registered parser returns a
// structured package list the LLM can reason over directly.
//
// All parsers are best-effort:
//   - Each parser fingerprints its expected output shape (first line,
//     column count, whatever's stable across the supported OS variants).
//   - On fingerprint mismatch the parser returns ok=false and the
//     caller falls back to raw text + dedup.
//   - Parsers MUST NEVER panic.  Adversarial output (intentional or
//     accidental) should yield ok=false, not a crashed handler.
//
// Adding a new parser:
//  1. Create a new file in this package implementing the Parser
//     interface.
//  2. Add a `_ = RegisterDefault(myParser)` line below.
//  3. Add fixture-based tests covering at least one match case and
//     one fingerprint-mismatch fallback case.
package parsers

import "sync"

// Parser turns one host's stdout for a known command into a
// structured form.  Implementations live alongside this file.
type Parser interface {
	// Matches reports whether this parser handles (command, args).
	// Should be fast — called once per resultGroup.
	Matches(command string, args []string) bool

	// Parse processes the stdout of one representative host (after
	// dedup the same stdout describes every host in the group).
	// Returns (structured, true) on success.  Returns (_, false) on
	// fingerprint mismatch; the caller leaves the resultGroup
	// unaggregated.
	Parse(stdout string) (aggregated any, ok bool)

	// Name is for logging / audit.  Should be unique across the
	// registry (registry collision = silent shadowing today; consider
	// adding a check if the registry grows).
	Name() string
}

// Registry holds the active parsers.  In-process state; no
// configuration loaded from disk.  Parsers are added via
// RegisterDefault (init time) or via Register (test / dynamic).
type Registry struct {
	mu      sync.RWMutex
	parsers []Parser
}

// defaultRegistry is the package-level registry the router consults.
// Tests should construct their own Registry rather than mutating this
// one to avoid cross-test pollution.
var defaultRegistry = &Registry{}

// Register adds a parser to a specific registry.
func (r *Registry) Register(p Parser) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.parsers = append(r.parsers, p)
}

// Lookup returns the first parser that Matches the given (command,
// args), or nil if no parser is registered for that shape.  First-
// match-wins ordering means parser specificity matters when multiple
// could match (e.g., "ps" and "ps aux"); register the more specific
// one first.
func (r *Registry) Lookup(command string, args []string) Parser {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, p := range r.parsers {
		if p.Matches(command, args) {
			return p
		}
	}
	return nil
}

// Default returns the package-level registry the router uses.
func Default() *Registry { return defaultRegistry }

// RegisterDefault adds a parser to the package-level registry.
// Returns true so init-time `_ = RegisterDefault(...)` reads cleanly.
func RegisterDefault(p Parser) bool {
	defaultRegistry.Register(p)
	return true
}
