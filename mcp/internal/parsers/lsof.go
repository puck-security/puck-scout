package parsers

import (
	"strconv"
	"strings"
)

// lsofParser handles `lsof -i [-n] [-P]` — the standard "what's
// listening / connected" invocation used across IR triage and
// blast-radius skills.
//
// Format:
//
//	COMMAND   PID    USER   FD   TYPE  DEVICE SIZE/OFF NODE NAME
//	sshd      1234   root   3u   IPv4  ...    0t0      TCP  *:22 (LISTEN)
//
// NAME may contain spaces (the parenthesised state and any IP:port
// fragment).  We treat fields 0-7 as fixed and join 8+ as NAME.
type lsofParser struct{}

func (p lsofParser) Name() string { return "lsof" }

func (p lsofParser) Matches(command string, args []string) bool {
	if command != "lsof" {
		return false
	}
	for _, a := range args {
		// -i (with or without value, e.g., "-i", "-i4", "-iTCP") is
		// the network-listing form we parse.
		if strings.HasPrefix(a, "-i") {
			return true
		}
	}
	return false
}

type lsofEntry struct {
	Command string `json:"command"`
	PID     int    `json:"pid"`
	User    string `json:"user"`
	FD      string `json:"fd"`
	Type    string `json:"type"`
	Name    string `json:"name"`
}

func (p lsofParser) Parse(stdout string) (any, bool) {
	lines := strings.Split(stdout, "\n")
	headerFound := false
	var entries []lsofEntry
	for _, line := range lines {
		if !headerFound {
			if strings.HasPrefix(line, "COMMAND") &&
				strings.Contains(line, "PID") &&
				strings.Contains(line, "NAME") {
				headerFound = true
			}
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 9 {
			continue
		}
		pid, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}
		// NAME column conventionally includes the protocol (TCP/UDP)
		// plus host:port + state.  Operators reading the parsed output
		// want them together — they're inseparable for connection-state
		// interpretation.  We join from field 7 (the NODE column,
		// which holds the protocol) through the end.
		entries = append(entries, lsofEntry{
			Command: fields[0],
			PID:     pid,
			User:    fields[2],
			FD:      fields[3],
			Type:    fields[4],
			Name:    strings.Join(fields[7:], " "),
		})
	}
	if !headerFound {
		return nil, false
	}
	return map[string]any{
		"parser":      "lsof",
		"connections": entries,
		"count":       len(entries),
	}, true
}

var _ = RegisterDefault(lsofParser{})
