package parsers

import (
	"strconv"
	"strings"
)

// psParser handles `ps aux` output (Linux + macOS, identical first 11
// columns).  The CMD column may contain spaces; we treat everything
// past the 10 fixed columns as one CMD string.
//
// Fingerprint: a header line starting with "USER" and containing
// "PID" + "%CPU" + "COMMAND" (case-sensitive).
type psParser struct{}

func (p psParser) Name() string { return "ps" }

func (p psParser) Matches(command string, args []string) bool {
	if command != "ps" {
		return false
	}
	// aux | -aux | -ef etc are the typical fleet-wide invocations.
	// We match permissively: any args containing "aux" anywhere.
	for _, a := range args {
		if strings.Contains(a, "aux") || strings.Contains(a, "ef") {
			return true
		}
	}
	return false
}

type psEntry struct {
	User    string  `json:"user"`
	PID     int     `json:"pid"`
	CPU     float64 `json:"cpu_pct"`
	Mem     float64 `json:"mem_pct"`
	Command string  `json:"command"`
}

func (p psParser) Parse(stdout string) (any, bool) {
	lines := strings.Split(stdout, "\n")
	headerFound := false
	var processes []psEntry
	for _, line := range lines {
		// Header fingerprint.
		if !headerFound {
			if strings.Contains(line, "USER") &&
				strings.Contains(line, "PID") &&
				strings.Contains(line, "COMMAND") {
				headerFound = true
			}
			continue
		}
		// Parse data rows.  ps aux columns:
		// USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND
		fields := strings.Fields(line)
		if len(fields) < 11 {
			continue
		}
		pid, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}
		cpu, _ := strconv.ParseFloat(fields[2], 64)
		mem, _ := strconv.ParseFloat(fields[3], 64)
		// CMD is everything from field 10 onward (joined with single space).
		cmd := strings.Join(fields[10:], " ")
		processes = append(processes, psEntry{
			User:    fields[0],
			PID:     pid,
			CPU:     cpu,
			Mem:     mem,
			Command: cmd,
		})
	}
	if !headerFound {
		return nil, false
	}
	return map[string]any{
		"parser":    "ps",
		"processes": processes,
		"count":     len(processes),
	}, true
}

var _ = RegisterDefault(psParser{})
