package policy

import (
	"fmt"
)

type Policy struct {
	Version  string                   `toml:"policy_version"`
	Binaries map[string]*BinaryPolicy `toml:"binary"`
}

type BinaryPolicy struct {
	Name               string          `toml:"-"`
	CanonicalPaths     []string        `toml:"canonical_paths"`
	Positional         *PositionalSpec `toml:"positional,omitempty"`
	Flags              []FlagSpec      `toml:"flags"`
	ForbiddenFlags     []string        `toml:"forbidden_flags"`
	SubcommandRequired bool            `toml:"subcommand_required"`
	Subcommands        []string        `toml:"subcommands"`
}

type PositionalSpec struct {
	Kind               ValueKind `toml:"kind"`
	Min                int       `toml:"min"`
	Max                int       `toml:"max"`
	RestrictToPrefixes []string  `toml:"restrict_to_prefixes"`
}

type FlagSpec struct {
	Name  string    `toml:"name"`
	Value ValueKind `toml:"value"`
}

// ValueKind is either a bare-string primitive ("none","string","glob","uint",
// "duration","fs_path") or a tagged variant for enum/structured kinds.
type ValueKind struct {
	Kind     string   // "none" | "string" | "glob" | "uint" | "duration" | "enum" | "fs_path"
	Values   []string // for enum
	Prefixes []string // for fs_path
}

// UnmarshalTOML implements custom decoding so a flag value can be either a bare
// string or a table.  This mirrors the Rust ValueKind::Simple/Tagged shape.
func (v *ValueKind) UnmarshalTOML(raw any) error {
	switch x := raw.(type) {
	case string:
		v.Kind = x
		return nil
	case map[string]any:
		kind, _ := x["kind"].(string)
		v.Kind = kind
		if vs, ok := x["values"].([]any); ok {
			for _, e := range vs {
				if s, ok := e.(string); ok {
					v.Values = append(v.Values, s)
				}
			}
		}
		if ps, ok := x["restrict_to_prefixes"].([]any); ok {
			for _, e := range ps {
				if s, ok := e.(string); ok {
					v.Prefixes = append(v.Prefixes, s)
				}
			}
		}
		return nil
	default:
		return fmt.Errorf("invalid ValueKind shape: %T", raw)
	}
}

// Canonical is the validator's output — the actual command to forward.
type Canonical struct {
	Path string
	Args []string
}
