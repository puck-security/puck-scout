package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/puck-security/puck-scout/mcp/internal/skills"
)

type validationResult struct {
	Skill  string   `json:"skill"`
	Valid  bool     `json:"valid"`
	Errors []string `json:"errors"`
	Warns  []string `json:"warns,omitempty"`
}

func runValidateSkill(args []string) int {
	fs := flag.NewFlagSet("validate-skill", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "output results as JSON")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: puck-mcp validate-skill [--json] <path> [<path>...]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Validate skill directories against the puck skill schema.")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "  If a path contains skill.yaml it is treated as a single skill directory.")
		fmt.Fprintln(os.Stderr, "  If a path is a directory of subdirectories, each subdir is validated.")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Exit code: 0 = all valid, 1 = one or more invalid.")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Flags:")
		fs.PrintDefaults()
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

	var results []validationResult
	allValid := true

	for _, dir := range skillDirs {
		result := validationResult{
			Skill:  filepath.Base(dir),
			Errors: []string{},
		}

		skill, err := skills.LoadSkill(dir)
		if err != nil {
			result.Valid = false
			result.Errors = append(result.Errors, fmt.Sprintf("load error: %v", err))
			allValid = false
		} else {
			errs := skills.Validate(skill)
			result.Valid = len(errs) == 0
			if len(errs) > 0 {
				result.Errors = errs
			}
			if !result.Valid {
				allValid = false
			}
			if skill.README == "" {
				result.Warns = append(result.Warns, "README.md not found (recommended)")
			}
		}
		results = append(results, result)
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(results)
	} else {
		printValidationResults(results)
	}

	if !allValid {
		return 1
	}
	return 0
}

func printValidationResults(results []validationResult) {
	maxLen := 0
	for _, r := range results {
		if len(r.Skill) > maxLen {
			maxLen = len(r.Skill)
		}
	}
	for _, r := range results {
		pad := strings.Repeat(" ", maxLen-len(r.Skill)+2)
		if r.Valid {
			fmt.Printf("%s%sOK\n", r.Skill, pad)
		} else {
			fmt.Printf("%s%sFAIL\n", r.Skill, pad)
			for _, e := range r.Errors {
				fmt.Printf("  - %s\n", e)
			}
		}
		for _, w := range r.Warns {
			fmt.Printf("  ~ %s\n", w)
		}
	}
}

func resolveSkillDirs(p string) ([]string, error) {
	info, err := os.Stat(p)
	if err != nil {
		return nil, fmt.Errorf("cannot access %s: %w", p, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", p)
	}

	// If the directory directly contains skill.yaml, it's a skill directory.
	if _, err := os.Stat(filepath.Join(p, "skill.yaml")); err == nil {
		return []string{p}, nil
	}

	// Otherwise, each subdirectory containing skill.yaml is a skill.
	entries, err := os.ReadDir(p)
	if err != nil {
		return nil, fmt.Errorf("cannot read directory %s: %w", p, err)
	}
	var dirs []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		subdir := filepath.Join(p, entry.Name())
		if _, err := os.Stat(filepath.Join(subdir, "skill.yaml")); err == nil {
			dirs = append(dirs, subdir)
		}
	}
	return dirs, nil
}
