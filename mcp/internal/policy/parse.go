package policy

import (
	"strings"
	"unicode"
)

// AllowsPattern reports whether the policy admits a `required_commands`
// entry from a skill YAML.  The pattern is either a bare binary name
// (e.g. "whoami", "cat") for binaries that don't require a subcommand,
// or "<binary> <subcommand prefix>" (e.g. "aws iam get-policy",
// "git ls-files") for binaries that do.
//
// Used by skills.Reconcile to flag a skill as degraded when an entry it
// declares isn't covered by the deployed policy.
func AllowsPattern(pattern string) bool {
	parts := strings.Fields(pattern)
	if len(parts) == 0 {
		return false
	}
	bp, err := lookup(parts[0])
	if err != nil {
		return false
	}
	if !bp.SubcommandRequired {
		// Pattern shouldn't include extra tokens when no subcommand is
		// required; if it does, treat as a mismatch rather than silently
		// ignoring the trailing tokens.
		return len(parts) == 1
	}
	if len(parts) < 2 {
		// Subcommand-required binary with no subcommand prefix supplied —
		// no skill should declare a pattern that broad.
		return false
	}
	// Match the subcommand-prefix portion against the declared subcommands.
	subTokens := parts[1:]
	for _, sub := range bp.Subcommands {
		patTokens := strings.Fields(sub)
		if len(patTokens) > len(subTokens) {
			continue
		}
		ok := true
		for i, pat := range patTokens {
			if !tokenMatches(pat, subTokens[i]) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// Validate is the single entry point for the MCP server.  It returns the
// canonical form to forward to the agent, or a typed *PolicyError.
func Validate(command string, args []string) (Canonical, error) {
	bp, err := lookup(command)
	if err != nil {
		return Canonical{}, err
	}
	parsed, err := parseArgs(bp, args)
	if err != nil {
		return Canonical{}, err
	}
	// Server side does not resolve filesystem paths — agent re-validates and
	// resolves.  We forward the first canonical path as a hint; agent ignores.
	canonicalPath := ""
	if len(bp.CanonicalPaths) > 0 {
		canonicalPath = bp.CanonicalPaths[0]
	}
	return Canonical{Path: canonicalPath, Args: parsed.normalisedArgv()}, nil
}

func lookup(command string) (*BinaryPolicy, error) {
	if strings.Contains(command, "/") {
		return nil, &PolicyError{Code: CodePathInCommandName, Binary: command}
	}
	name := strings.ToLower(command)
	if name == "" || !isAllowedName(name) {
		return nil, &PolicyError{Code: CodeInvalidCommandName, Binary: name}
	}
	bp, ok := Loaded().Binaries[name]
	if !ok {
		return nil, &PolicyError{Code: CodeNotInAllowlist, Binary: name}
	}
	return bp, nil
}

func isAllowedName(s string) bool {
	for _, r := range s {
		switch {
		case unicode.IsLower(r) || unicode.IsDigit(r) || r == '_' || r == '-' || r == '+':
			// ok
		default:
			return false
		}
	}
	return true
}

type parsedArgs struct {
	subcommand  []string
	flags       []flagKV
	positionals []string
}

type flagKV struct {
	name     string
	value    string
	hasValue bool
}

func (p parsedArgs) normalisedArgv() []string {
	out := make([]string, 0, len(p.subcommand)+2*len(p.flags)+len(p.positionals))
	out = append(out, p.subcommand...)
	for _, f := range p.flags {
		out = append(out, f.name)
		if f.hasValue {
			out = append(out, f.value)
		}
	}
	out = append(out, p.positionals...)
	return out
}

func parseArgs(p *BinaryPolicy, args []string) (parsedArgs, error) {
	var out parsedArgs
	i := 0
	if p.SubcommandRequired {
		consumed, sc, err := consumeSubcommand(p, args)
		if err != nil {
			return out, err
		}
		out.subcommand = sc
		i = consumed
	}
	for i < len(args) {
		tok := args[i]
		if strings.HasPrefix(tok, "-") {
			for _, f := range p.ForbiddenFlags {
				if f == tok {
					return out, &PolicyError{Code: CodeForbiddenFlag, Binary: p.Name, Detail: tok}
				}
			}
			spec := findFlag(p, tok)
			if spec == nil {
				// Unix combined-short convention: `-XYZ` admits when
				// each of X/Y/Z is a single-char flag with value=none.
				// Mirror of the Rust parse.rs combined_short_admits.
				// Normalised form keeps the combined token (the binary
				// parses combined-shorts natively; no expansion needed
				// and keeping the original aids audit readability).
				if isCombinedShortEligible(tok) && combinedShortAdmits(p, tok) {
					out.flags = append(out.flags, flagKV{name: tok})
					i++
					continue
				}
				return out, &PolicyError{Code: CodeUnknownFlag, Binary: p.Name, Detail: tok}
			}
			if spec.Value.Kind == "none" {
				out.flags = append(out.flags, flagKV{name: tok})
				i++
				continue
			}
			if i+1 >= len(args) {
				return out, &PolicyError{Code: CodeMissingFlagValue, Binary: p.Name, Detail: tok}
			}
			val := args[i+1]
			if err := validateValue(p, spec, val); err != nil {
				return out, err
			}
			out.flags = append(out.flags, flagKV{name: tok, value: val, hasValue: true})
			i += 2
		} else {
			if p.Positional == nil {
				return out, &PolicyError{Code: CodeUnexpectedPositional, Binary: p.Name, Detail: tok}
			}
			if len(out.positionals) >= p.Positional.Max {
				return out, &PolicyError{Code: CodePositionalCountOutOfRange, Binary: p.Name}
			}
			if err := validatePositional(p, p.Positional, tok); err != nil {
				return out, err
			}
			out.positionals = append(out.positionals, tok)
			i++
		}
	}
	if p.Positional != nil && len(out.positionals) < p.Positional.Min {
		return out, &PolicyError{Code: CodePositionalCountOutOfRange, Binary: p.Name}
	}
	return out, nil
}

func findFlag(p *BinaryPolicy, name string) *FlagSpec {
	for i := range p.Flags {
		if p.Flags[i].Name == name {
			return &p.Flags[i]
		}
	}
	return nil
}

// isCombinedShortEligible: a token MIGHT be a combined-short of value-
// less flags if it starts with single `-` (not `--`) and has at least
// two chars after the dash.  `-l` is a regular short; `--list` is a
// long flag; `-la` is what we want to consider for splitting.
func isCombinedShortEligible(tok string) bool {
	return strings.HasPrefix(tok, "-") && !strings.HasPrefix(tok, "--") && len(tok) >= 3
}

// combinedShortAdmits: returns true iff every char after the leading
// `-` is a legitimate value-less flag in p.  Mirror of Rust's
// combined_short_admits.  Standard Unix convention: `ls -la` means
// `ls -l -a`.  Combinations with a value-taking flag (`-n50`) are
// rejected — pass `-n 50` as two separate argv tokens for those.
func combinedShortAdmits(p *BinaryPolicy, tok string) bool {
	rest := tok[1:] // strip leading '-'
	if rest == "" {
		return false
	}
	for _, c := range rest {
		single := "-" + string(c)
		spec := findFlag(p, single)
		if spec == nil {
			return false
		}
		if spec.Value.Kind != "none" {
			return false
		}
	}
	return true
}

func validateValue(p *BinaryPolicy, f *FlagSpec, val string) error {
	return validateByKind(p, f.Name, &f.Value, val)
}

func validatePositional(p *BinaryPolicy, pos *PositionalSpec, val string) error {
	vk := pos.Kind
	if len(pos.RestrictToPrefixes) > 0 && vk.Kind == "fs_path" {
		vk.Prefixes = pos.RestrictToPrefixes
	}
	return validateByKind(p, "<positional>", &vk, val)
}

func validateByKind(p *BinaryPolicy, flagName string, v *ValueKind, val string) error {
	switch v.Kind {
	case "none":
		return nil
	case "string":
		return validateString(p, flagName, val)
	case "glob":
		if err := validateString(p, flagName, val); err != nil {
			return err
		}
		if strings.ContainsAny(val, ";\\$`") {
			return &PolicyError{Code: CodeBadFlagValue, Binary: p.Name, Detail: flagName + ": metacharacter"}
		}
		return nil
	case "uint":
		if val == "" || len(val) > 10 {
			return &PolicyError{Code: CodeBadFlagValue, Binary: p.Name, Detail: flagName + ": not uint"}
		}
		for _, r := range val {
			if r < '0' || r > '9' {
				return &PolicyError{Code: CodeBadFlagValue, Binary: p.Name, Detail: flagName + ": not uint"}
			}
		}
		return nil
	case "duration":
		return validateDuration(p, flagName, val)
	case "enum":
		for _, e := range v.Values {
			if e == val {
				return nil
			}
		}
		return &PolicyError{Code: CodeBadFlagValue, Binary: p.Name, Detail: flagName + ": not in enum"}
	case "fs_path":
		if val == "" || strings.ContainsRune(val, 0) {
			return &PolicyError{Code: CodeBadFlagValue, Binary: p.Name, Detail: flagName + ": empty or NUL"}
		}
		// Reject shell metacharacters in path values.  Mirror of the
		// Rust agent's validate_fs_path.  Same blocklist as
		// tokenMatches: a positional like "C:/Users/foo; rm" would
		// otherwise admit (prefix match passes) but PowerShell's
		// -Command argv-concatenation would then parse the trailing
		// "; rm" as a second statement.  Legitimate paths don't have
		// these chars; spaces ("Program Files") are fine.
		for _, r := range val {
			switch r {
			case ';', '|', '&', '`', '(', ')', '{', '}':
				return &PolicyError{Code: CodeBadFlagValue, Binary: p.Name, Detail: flagName + ": shell metacharacter"}
			}
		}
		if len(v.Prefixes) > 0 {
			ok := false
			for _, pfx := range v.Prefixes {
				if strings.HasPrefix(val, pfx) {
					ok = true
					break
				}
			}
			if !ok {
				return &PolicyError{Code: CodeBadFlagValue, Binary: p.Name, Detail: flagName + ": prefix"}
			}
		}
		return nil
	default:
		return &PolicyError{Code: CodeBadFlagValue, Binary: p.Name, Detail: "unknown kind: " + v.Kind}
	}
}

func validateString(p *BinaryPolicy, flag, val string) error {
	if len(val) > 4096 {
		return &PolicyError{Code: CodeBadFlagValue, Binary: p.Name, Detail: flag + ": too long"}
	}
	for _, r := range val {
		if r == 0 || (unicode.IsControl(r) && r != '\t') {
			return &PolicyError{Code: CodeBadFlagValue, Binary: p.Name, Detail: flag + ": control byte"}
		}
	}
	return nil
}

func validateDuration(p *BinaryPolicy, flag, val string) error {
	i := 0
	if len(val) > 0 && (val[0] == '+' || val[0] == '-') {
		i++
	}
	digits := 0
	for i < len(val) && val[i] >= '0' && val[i] <= '9' {
		i++
		digits++
	}
	if digits == 0 || digits > 10 {
		return &PolicyError{Code: CodeBadFlagValue, Binary: p.Name, Detail: flag + ": duration"}
	}
	if i == len(val) {
		return nil
	}
	if i == len(val)-1 && strings.ContainsRune("smhdwMy", rune(val[i])) {
		return nil
	}
	return &PolicyError{Code: CodeBadFlagValue, Binary: p.Name, Detail: flag + ": duration"}
}

func consumeSubcommand(p *BinaryPolicy, args []string) (int, []string, error) {
	if len(args) == 0 {
		return 0, nil, &PolicyError{Code: CodeSubcommandRequired, Binary: p.Name}
	}
	// Sort entries longest-first by token count.
	entries := make([][]string, len(p.Subcommands))
	for i, s := range p.Subcommands {
		entries[i] = strings.Fields(s)
	}
	for i := 1; i < len(entries); i++ {
		for j := i; j > 0 && len(entries[j]) > len(entries[j-1]); j-- {
			entries[j], entries[j-1] = entries[j-1], entries[j]
		}
	}
	for _, e := range entries {
		if len(e) > len(args) {
			continue
		}
		ok := true
		for k := 0; k < len(e); k++ {
			if !tokenMatches(e[k], args[k]) {
				ok = false
				break
			}
		}
		if ok {
			consumed := append([]string{}, args[:len(e)]...)
			return len(e), consumed, nil
		}
	}
	n := 2
	if n > len(args) {
		n = len(args)
	}
	return 0, nil, &PolicyError{Code: CodeUnknownSubcommand, Binary: p.Name, Detail: strings.Join(args[:n], " ")}
}

func tokenMatches(pattern, input string) bool {
	if strings.HasSuffix(pattern, "*") {
		if !strings.HasPrefix(input, strings.TrimSuffix(pattern, "*")) {
			return false
		}
		// Block characters that would let a multi-statement payload
		// hide inside a single argv token past the prefix check.  See
		// the Rust agent's parse.rs token_matches for the rationale.
		// The two implementations must stay in sync — corpus parity
		// tests will fail if they drift.
		for _, c := range input {
			switch c {
			case ';', '|', '&', '(', ')', '{', '}', '`', ' ', '\t', '\n', '\r':
				return false
			}
		}
		return true
	}
	return pattern == input
}
