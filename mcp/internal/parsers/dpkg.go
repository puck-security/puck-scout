package parsers

import "strings"

// dpkgParser handles `dpkg -l` output on Debian/Ubuntu hosts.
//
// Format (5 columns after the desired-state column):
//
//	Desired=Unknown/Install/Remove/Purge/Hold
//	| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend
//	|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)
//	||/ Name           Version              Architecture Description
//	+++-==============-====================-============-======================
//	ii  bash           5.0-6ubuntu1.1       amd64        GNU Bourne Again SHell
//
// Fingerprint: header lines starting with "Desired=Unknown/" and
// "||/  Name".  Both must appear; matching on just "ii " would false-
// positive on arbitrary text containing those bytes.
type dpkgParser struct{}

func (p dpkgParser) Name() string { return "dpkg" }

func (p dpkgParser) Matches(command string, args []string) bool {
	if command != "dpkg" {
		return false
	}
	for _, a := range args {
		if a == "-l" || a == "--list" {
			return true
		}
	}
	return false
}

type dpkgPackage struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
	State        string `json:"state"` // ii, rc, etc — desired+status flags
}

func (p dpkgParser) Parse(stdout string) (any, bool) {
	lines := strings.Split(stdout, "\n")
	headerFound := false
	separatorFound := false
	var packages []dpkgPackage
	for _, line := range lines {
		// Fingerprint: the "Desired=" preamble and the "||/" header.
		if strings.HasPrefix(line, "Desired=") {
			headerFound = true
			continue
		}
		if strings.HasPrefix(line, "+++-") {
			separatorFound = true
			continue
		}
		// Skip pre-separator lines and any indented continuation.
		if !separatorFound {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		// State must be the 2-letter flag pair like "ii", "rc", "un",
		// etc.  Anything else suggests we're not actually parsing dpkg.
		state := fields[0]
		if len(state) != 2 {
			continue
		}
		packages = append(packages, dpkgPackage{
			State:        state,
			Name:         fields[1],
			Version:      fields[2],
			Architecture: fields[3],
		})
	}
	if !headerFound || !separatorFound {
		return nil, false
	}
	return map[string]any{
		"parser":   "dpkg",
		"packages": packages,
		"count":    len(packages),
	}, true
}

var _ = RegisterDefault(dpkgParser{})
