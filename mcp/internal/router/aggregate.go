package router

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/puck-security/puck-oss/mcp/internal/parsers"
)

// resultGroup is a set of hosts whose command produced identical output.
// One entry replaces N per-host entries when the output is homogeneous
// — e.g., 800 hosts all reporting "openssl 1.1.1f" condenses to one
// resultGroup with HostCount=800 instead of 800 separate result rows.
//
// On fleet-wide audits this is the difference between an LLM context
// window full of 1000 nearly-identical stdout blocks and a context
// window with 3-5 distinct cohorts.  Dedup is content-only; the audit
// log + on-disk per-host result files still hold the un-collapsed
// material for forensics.
type resultGroup struct {
	HostCount     int      `json:"host_count"`
	Hosts         []string `json:"hosts"`
	Command       string   `json:"command,omitempty"` // populated by run_batch (varies); query_fleet uses single command at top level
	Args          []string `json:"args,omitempty"`
	ExitCode      int      `json:"exit_code"`
	Stdout        string   `json:"stdout"`
	Stderr        string   `json:"stderr"`
	SampleHost    string   `json:"sample_host"`               // first host in the group; pairs with SavedToSample for on-disk navigation
	SavedToSample string   `json:"saved_to_sample,omitempty"` // result file for the sample host (full per-host files exist for every entry in Hosts)

	// Structured carries the parsed-aggregated form of Stdout when a
	// registered parser matched (command, args).  It is omitempty so
	// the LLM only sees it for commands whose output we know how to
	// parse (dpkg -l, ps aux, lsof -i, ...).  When present, the LLM
	// can read this directly instead of re-parsing Stdout.  The raw
	// Stdout is still included as belt-and-suspenders for parsers
	// that didn't capture every detail.
	Structured any `json:"structured,omitempty"`
}

// hostFailure is a per-host failure that couldn't be deduped — agent
// stale, dispatch failure, or anything that prevented the command from
// running.  Kept separate from resultGroup so the LLM can distinguish
// "this host's command produced an output" from "this host's command
// never ran."
type hostFailure struct {
	Hostname string   `json:"hostname"`
	Command  string   `json:"command,omitempty"`
	Args     []string `json:"args,omitempty"`
	Error    string   `json:"error"`
	Rejected bool     `json:"rejected,omitempty"`
}

// dedupHostResults groups the supplied per-host results by content
// (exit_code + stdout + stderr).  Errored entries are split out into
// a separate slice — they don't dedup usefully.  Both slices are
// returned in descending host-count order (largest cohort first) so
// the LLM's eye lands on the dominant cohort first.
//
// Used by puck_query_fleet: every entry has the same (command, args)
// at the top level, so the group's Command/Args fields are left empty
// to keep payloads compact.
//
// command/args are accepted (rather than zeroed) so the parser
// registry can be consulted for the aggregated stdout — if a parser
// matches, the group's Structured field is populated.
func dedupHostResults(in []hostResult, command string, args []string) (groups []resultGroup, failures []hostFailure) {
	idx := make(map[string]int) // content-hash -> groups index
	for _, h := range in {
		if h.Error != "" {
			failures = append(failures, hostFailure{
				Hostname: h.Hostname,
				Error:    h.Error,
			})
			continue
		}
		key := contentHash(h.ExitCode, h.Stdout, h.Stderr)
		if i, ok := idx[key]; ok {
			groups[i].Hosts = append(groups[i].Hosts, h.Hostname)
			groups[i].HostCount++
			continue
		}
		groups = append(groups, resultGroup{
			HostCount:     1,
			Hosts:         []string{h.Hostname},
			ExitCode:      h.ExitCode,
			Stdout:        h.Stdout,
			Stderr:        h.Stderr,
			SampleHost:    h.Hostname,
			SavedToSample: h.SavedTo,
		})
		idx[key] = len(groups) - 1
	}
	sortGroupsByHostCountDesc(groups)
	attachStructured(groups, command, args, true /* sharedCmd */)
	return groups, failures
}

// attachStructured runs the parser registry over each group's stdout.
// `sharedCmd=true` means every group uses the (command, args) supplied
// at the top level (query_fleet).  `sharedCmd=false` means each group
// already carries its own Command/Args (run_batch).
func attachStructured(groups []resultGroup, sharedCommand string, sharedArgs []string, sharedCmd bool) {
	reg := parsers.Default()
	for i := range groups {
		cmd, args := sharedCommand, sharedArgs
		if !sharedCmd {
			cmd, args = groups[i].Command, groups[i].Args
		}
		p := reg.Lookup(cmd, args)
		if p == nil {
			continue
		}
		structured, ok := p.Parse(groups[i].Stdout)
		if !ok {
			continue
		}
		groups[i].Structured = structured
	}
}

// dedupBatchResults is the run_batch counterpart.  Each input entry
// can have a DIFFERENT command/args, so the dedup key includes them
// (otherwise two entries that happened to produce identical output
// across different commands would be falsely grouped — e.g., two
// different commands both printing nothing).  Each group's Command/Args
// fields are populated.
//
// Rejected commands are split out separately; they never reached an
// agent so they don't belong in either the success groups or the
// host-failure list.
func dedupBatchResults(in []batchResult) (groups []resultGroup, failures []hostFailure, rejected []hostFailure) {
	idx := make(map[string]int)
	for _, b := range in {
		if b.Rejected {
			rejected = append(rejected, hostFailure{
				Hostname: b.Hostname,
				Command:  b.Command,
				Args:     b.Args,
				Error:    b.Error,
				Rejected: true,
			})
			continue
		}
		if b.Error != "" {
			failures = append(failures, hostFailure{
				Hostname: b.Hostname,
				Command:  b.Command,
				Args:     b.Args,
				Error:    b.Error,
			})
			continue
		}
		key := batchContentHash(b.Command, b.Args, b.ExitCode, b.Stdout, b.Stderr)
		if i, ok := idx[key]; ok {
			groups[i].Hosts = append(groups[i].Hosts, b.Hostname)
			groups[i].HostCount++
			continue
		}
		groups = append(groups, resultGroup{
			HostCount:     1,
			Hosts:         []string{b.Hostname},
			Command:       b.Command,
			Args:          b.Args,
			ExitCode:      b.ExitCode,
			Stdout:        b.Stdout,
			Stderr:        b.Stderr,
			SampleHost:    b.Hostname,
			SavedToSample: b.SavedTo,
		})
		idx[key] = len(groups) - 1
	}
	sortGroupsByHostCountDesc(groups)
	attachStructured(groups, "", nil, false /* per-group cmd */)
	return groups, failures, rejected
}

// contentHash hashes the parts of a host result that should be
// considered "the same output" — exit code + stdout + stderr.  SHA-256
// is overkill for in-memory comparison but it keys cleanly into a map
// and there's no chance of collision at any realistic fleet size.
func contentHash(exitCode int, stdout, stderr string) string {
	h := sha256.New()
	// Use a separator byte unlikely to appear in real stdout so we
	// can't construct an adversarial pair where (stdout=A+sep, stderr=B)
	// collides with (stdout=A, stderr=sep+B).  0x00 is the choice; the
	// hash is in-memory only so adversarial collision isn't a real
	// concern but the hygiene is free.
	h.Write([]byte{byte(exitCode >> 8), byte(exitCode), 0x00})
	h.Write([]byte(stdout))
	h.Write([]byte{0x00})
	h.Write([]byte(stderr))
	return hex.EncodeToString(h.Sum(nil))
}

// batchContentHash extends contentHash with (command, args) so two
// different commands with happen-to-be-identical output don't collide.
func batchContentHash(command string, args []string, exitCode int, stdout, stderr string) string {
	h := sha256.New()
	h.Write([]byte(command))
	h.Write([]byte{0x00})
	h.Write([]byte(strings.Join(args, "\x00")))
	h.Write([]byte{0x00})
	h.Write([]byte{byte(exitCode >> 8), byte(exitCode), 0x00})
	h.Write([]byte(stdout))
	h.Write([]byte{0x00})
	h.Write([]byte(stderr))
	return hex.EncodeToString(h.Sum(nil))
}

func sortGroupsByHostCountDesc(g []resultGroup) {
	sort.SliceStable(g, func(i, j int) bool {
		if g[i].HostCount != g[j].HostCount {
			return g[i].HostCount > g[j].HostCount
		}
		// Stable tiebreaker by first hostname for deterministic ordering.
		return g[i].SampleHost < g[j].SampleHost
	})
}
