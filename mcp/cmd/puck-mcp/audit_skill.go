package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/puck-security/puck-oss/mcp/internal/policy"
	"github.com/puck-security/puck-oss/mcp/internal/skills"
)

// runAuditSkill scans a skill's guidance prose for mentions of policy-known
// binaries and reports any that are not declared in `required_commands`.
//
// Motivation: the reconcile mechanism only checks declared required_commands
// against the policy.  A skill author who writes "use `reg query
// HKLM\\Software\\...`" in pathfinder_strategy but forgets to add `reg query`
// to required_commands gets no warning at startup — the skill reports
// status=ok and then commands silently reject at execution time.  This audit
// closes that loop.
//
// Detection is heuristic: for each binary name in the embedded policy
// grammar, we look for occurrences in the concatenated guidance prose
// using word-boundary regex.  For binaries with subcommand_required, we
// also try to detect the next-token form ("binary subcommand").  False
// positives are possible (e.g. "find" the English verb) but the policy
// grammar is small (~30 binaries) so the noise is bounded.  Exit code 0
// if clean, 1 if any warnings.
func runAuditSkill(args []string) int {
	fs := flag.NewFlagSet("audit-skill", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: puck-mcp audit-skill <path> [<path>...]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Scan each skill's guidance prose for policy-known binary mentions")
		fmt.Fprintln(os.Stderr, "and report any not declared in required_commands.  Catches the")
		fmt.Fprintln(os.Stderr, "common drift where a skill author adds a new command to the prose")
		fmt.Fprintln(os.Stderr, "but forgets to update the required_commands list — that drift would")
		fmt.Fprintln(os.Stderr, "otherwise only surface at investigation time as silent rejection.")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Exit code: 0 = no warnings, 1 = one or more skills have undeclared mentions.")
	}
	_ = fs.Parse(args)

	paths := fs.Args()
	if len(paths) == 0 {
		fs.Usage()
		return 1
	}

	var skillDirs []string
	for _, p := range paths {
		dirs, err := resolveSkillDirs(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
		skillDirs = append(skillDirs, dirs...)
	}

	if len(skillDirs) == 0 {
		fmt.Fprintln(os.Stderr, "no skill directories found in the given paths")
		return 1
	}

	anyWarnings := false
	for _, dir := range skillDirs {
		skill, err := skills.LoadSkill(dir)
		if err != nil {
			fmt.Printf("%s\tLOAD-ERROR: %v\n", filepath.Base(dir), err)
			anyWarnings = true
			continue
		}
		warns := auditSkillProse(skill)
		if len(warns) == 0 {
			fmt.Printf("%s\tOK\n", skill.Name)
			continue
		}
		anyWarnings = true
		fmt.Printf("%s\tUNDECLARED MENTIONS\n", skill.Name)
		for _, w := range warns {
			fmt.Printf("  - %s\n", w)
		}
	}

	if anyWarnings {
		return 1
	}
	return 0
}

// auditSkillProse returns a sorted list of human-readable warnings for any
// policy-known binary that appears in `skill`'s guidance prose but is not
// covered by an entry in skill.RequiredCommands.
//
// `remediation_guidance` is intentionally excluded from the scan: by skill-
// authoring convention that section is operator-facing instructions ("here's
// what you should run to clean up after this finding"), NOT commands the
// skill itself invokes.  Scanning it produced false positives on every
// skill that helpfully showed an `aws iam delete-access-key` remediation
// example.
func auditSkillProse(skill *skills.Skill) []string {
	prose := strings.Join([]string{
		skill.Guidance.Objective,
		skill.Guidance.PathfinderStrategy,
		skill.Guidance.FleetStrategy,
		skill.Guidance.IterationCriteria,
		skill.Guidance.AnalysisTemplate,
	}, "\n")

	declared := map[string]bool{}
	for _, rc := range skill.RequiredCommands {
		declared[rc] = true
	}

	// Index declared entries by their first token (the binary name).  A
	// skill that declares `aws sts get-caller-identity` satisfies any prose
	// mention of `aws` whether or not the subcommand also matches; we
	// flag a finer-grained subcommand mismatch separately.
	declaredBinaries := map[string]bool{}
	for rc := range declared {
		parts := strings.Fields(rc)
		if len(parts) > 0 {
			declaredBinaries[parts[0]] = true
		}
	}

	binaries := policy.Loaded().Binaries
	// Stable order so the output is deterministic for golden-file
	// comparisons in CI.
	names := make([]string, 0, len(binaries))
	for n := range binaries {
		names = append(names, n)
	}
	sort.Strings(names)

	var warns []string
	for _, name := range names {
		bp := binaries[name]
		if !mentionedInProse(prose, name) {
			continue
		}
		if !declaredBinaries[name] {
			warns = append(warns, fmt.Sprintf(
				"prose mentions %q but no required_commands entry covers it; "+
					"add %q to skill.yaml's required_commands (or the relevant subcommand form)",
				name, name,
			))
			continue
		}
		// Binary is declared at the bare-name level.  For subcommand-required
		// binaries, additionally check that each subcommand mentioned in the
		// prose has a corresponding required_commands entry.  This is the
		// stricter check that catches "you declared `aws sts ...` but the
		// prose now also uses `aws iam ...`."
		if bp.SubcommandRequired {
			for _, sub := range subcommandsMentionedInProse(prose, name, bp.Subcommands) {
				wantPattern := name + " " + sub
				if !patternDeclared(declared, name, sub) {
					warns = append(warns, fmt.Sprintf(
						"prose mentions %q but no matching required_commands entry; "+
							"add %q to skill.yaml's required_commands",
						wantPattern, wantPattern,
					))
				}
			}
		}
	}
	return warns
}

// mentionedInProse reports whether `binary` appears in `prose` as an
// actual command invocation rather than the English word of the same
// spelling.  Two high-precision contexts:
//  1. Inside backticks (`find -name foo`)               — the skill-authoring convention
//  2. After a shell-prompt prefix ("$ find ", "# find ") — code-block sentinel
//
// A previous version also matched "binary as first word of a line", but
// that fired on common English-leading-word constructions ("where you
// can:", "find credentials in...", "last login was...") and produced
// more noise than signal.  Skill authors who put their commands in
// backticks (the convention everywhere in the existing skills) get
// caught; the cost is missing un-backticked fenced-block mentions.
func mentionedInProse(prose, binary string) bool {
	quoted := regexp.QuoteMeta(binary)
	// 1. Inside backticks: `binary ...` or `binary` (bare).
	re := regexp.MustCompile("`" + quoted + `(?:[\s` + "`" + `]|$)`)
	if re.MatchString(prose) {
		return true
	}
	// 2. Shell-prompt prefix ("$ binary " or "# binary ") inside prose.
	re = regexp.MustCompile(`[\$#]\s+` + quoted + `\s`)
	return re.MatchString(prose)
}

// subcommandsMentionedInProse returns subcommand patterns from the binary's
// allowlist that appear after the binary name in code-span / code-block
// contexts (same backtick/code-fence/prompt detection as mentionedInProse).
//
// Each subcommand pattern is matched as a full multi-token regex.  For a
// policy entry like "iam list-*", we build a regex that requires every
// fixed token to match literally AND the trailing glob token to match a
// non-empty subcommand suffix.  This avoids the prior over-match where
// "iam list-*" would fire on `aws iam delete-access-key` (the first
// token "iam" appeared, ignoring the rest).
func subcommandsMentionedInProse(prose, binary string, subcommands []string) []string {
	bin := regexp.QuoteMeta(binary)
	seen := map[string]bool{}
	for _, sub := range subcommands {
		tokens := strings.Fields(sub)
		if len(tokens) == 0 {
			continue
		}
		// Build per-token regex fragments.  Fixed tokens match literally;
		// a trailing-glob token (e.g. "list-*") matches as a prefix with
		// at least one trailing word char.  Non-trailing globs would be
		// unusual but handled the same way.
		var fragments []string
		for _, t := range tokens {
			if strings.HasSuffix(t, "*") {
				prefix := regexp.QuoteMeta(strings.TrimSuffix(t, "*"))
				fragments = append(fragments, prefix+`[\w-]+`)
			} else {
				fragments = append(fragments, regexp.QuoteMeta(t))
			}
		}
		subRegex := strings.Join(fragments, `\s+`)
		// Two contexts mirror mentionedInProse — backticks and shell-prompt.
		// Dropped the "line-starts-with" detector; see mentionedInProse for
		// the rationale.
		contexts := []string{
			"`" + bin + `\s+` + subRegex,        // `aws iam list-users ...`
			`[\$#]\s+` + bin + `\s+` + subRegex, // $ aws iam list-users ...
		}
		for _, p := range contexts {
			if regexp.MustCompile(p).MatchString(prose) {
				seen[sub] = true
				break
			}
		}
	}
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// patternDeclared reports whether the declared required_commands set
// covers a `binary subcommand` invocation.  Matches either an exact
// entry or a glob-trailing entry (`aws iam list-*` covers
// `aws iam list-users`).
func patternDeclared(declared map[string]bool, binary, subcommand string) bool {
	want := binary + " " + subcommand
	if declared[want] {
		return true
	}
	for entry := range declared {
		if !strings.HasPrefix(entry, binary+" ") {
			continue
		}
		entrySub := strings.TrimPrefix(entry, binary+" ")
		if !strings.HasSuffix(entrySub, "*") {
			continue
		}
		prefix := strings.TrimSuffix(entrySub, "*")
		if strings.HasPrefix(subcommand, prefix) {
			return true
		}
	}
	return false
}
