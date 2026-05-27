package parsers

import (
	"regexp"
	"strings"
)

// rpmParser handles `rpm -qa` (RHEL / Fedora / Amazon Linux package
// listings).
//
// Format: one package per line, NAME-VERSION-RELEASE.ARCH, e.g.
//
//	bash-5.0.17-2.el8.x86_64
//	openssl-libs-1.1.1k-7.el8_6.x86_64
//	systemd-libs-239-58.el8.x86_64
//
// Fingerprint: every non-empty line must match the
// NAME-VERSION-RELEASE.ARCH regex.  Heuristic but robust enough — any
// stdout that's not a list of package strings will have at least one
// non-conforming line and fall back to raw text + dedup.
type rpmParser struct{}

func (p rpmParser) Name() string { return "rpm" }

func (p rpmParser) Matches(command string, args []string) bool {
	if command != "rpm" {
		return false
	}
	// -qa is the package-listing form.  Other rpm subcommands (e.g.
	// rpm -V for verify, rpm -ql for file lists) are out of scope.
	for _, a := range args {
		if a == "-qa" || a == "--all" {
			return true
		}
	}
	return false
}

type rpmPackage struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Release      string `json:"release"`
	Architecture string `json:"architecture"`
}

func (p rpmParser) Parse(stdout string) (any, bool) {
	lines := strings.Split(strings.TrimRight(stdout, "\n"), "\n")
	if len(lines) == 0 || (len(lines) == 1 && lines[0] == "") {
		return nil, false
	}
	packages := make([]rpmPackage, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Last "." separates RELEASE from ARCH.
		dotIdx := strings.LastIndex(line, ".")
		if dotIdx < 1 {
			// Fingerprint mismatch: line doesn't fit name-...-arch.
			return nil, false
		}
		arch := line[dotIdx+1:]
		rest := line[:dotIdx]
		// Last "-" of rest separates VERSION-RELEASE pairs.  Right-
		// most hyphen is RELEASE boundary; the one before that is
		// VERSION boundary.
		relIdx := strings.LastIndex(rest, "-")
		if relIdx < 1 {
			return nil, false
		}
		release := rest[relIdx+1:]
		nameVer := rest[:relIdx]
		verIdx := strings.LastIndex(nameVer, "-")
		if verIdx < 1 {
			return nil, false
		}
		version := nameVer[verIdx+1:]
		name := nameVer[:verIdx]

		// Sanity: arch should be alphanumeric+underscore.
		if !rpmArchRe.MatchString(arch) {
			return nil, false
		}
		packages = append(packages, rpmPackage{
			Name:         name,
			Version:      version,
			Release:      release,
			Architecture: arch,
		})
	}
	if len(packages) == 0 {
		return nil, false
	}
	return map[string]any{
		"parser":   "rpm",
		"packages": packages,
		"count":    len(packages),
	}, true
}

var rpmArchRe = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)

var _ = RegisterDefault(rpmParser{})
