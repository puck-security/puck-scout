package server

import (
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"syscall"
)

// BindOrAdvise wraps net.Listen with operator-friendly diagnostics on
// EADDRINUSE: tries lsof / ss to identify the holding process, and suggests
// a free port for the operator's config.
func BindOrAdvise(addr, listenerName string) (net.Listener, error) {
	lst, err := net.Listen("tcp", addr)
	if err == nil {
		return lst, nil
	}
	if !isAddrInUse(err) {
		return nil, err
	}
	port := portOf(addr)
	culprit := whoOwnsPort(port)
	free := suggestFreePort()
	return nil, fmt.Errorf(
		"cannot bind %s listener at %s — port is in use%s.\n"+
			"  Override with `%s: HOST:PORT` in puck-mcp.yaml.\n"+
			"  Suggested free port on this host: %d",
		listenerName, addr, culprit, listenerName, free)
}

func isAddrInUse(err error) bool {
	var sysErr *net.OpError
	if errors.As(err, &sysErr) {
		if sysErr.Err.Error() == "address already in use" {
			return true
		}
		if errno, ok := sysErr.Err.(syscall.Errno); ok && errno == syscall.EADDRINUSE {
			return true
		}
	}
	return false
}

func portOf(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return port
}

func whoOwnsPort(port string) string {
	// Try lsof first (macOS + most Linux)
	if out, err := exec.Command("lsof", "-nP", "-iTCP:"+port, "-sTCP:LISTEN").Output(); err == nil {
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		if len(lines) >= 2 {
			fields := strings.Fields(lines[1])
			if len(fields) >= 2 {
				return fmt.Sprintf(" (held by pid %s: %s)", fields[1], fields[0])
			}
		}
	}
	// Linux fallback: ss -ltnp
	if out, err := exec.Command("ss", "-ltnp", "sport", "= :"+port).Output(); err == nil {
		// Format: LISTEN 0 4096 *:PORT *:* users:(("name",pid=X,fd=Y))
		s := string(out)
		if strings.Contains(s, "pid=") {
			// crude extraction of pid and name
			if idx := strings.Index(s, "users:(("); idx >= 0 {
				rest := s[idx+8:]
				end := strings.Index(rest, "))")
				if end >= 0 {
					return fmt.Sprintf(" (held by %s)", rest[:end])
				}
			}
		}
	}
	return ""
}

func suggestFreePort() int {
	// nosemgrep: go.lang.security.audit.net.bind_all.avoid-bind-to-all-interfaces
	lst, err := net.Listen("tcp", ":0")
	if err != nil {
		return 0
	}
	defer lst.Close()
	return lst.Addr().(*net.TCPAddr).Port
}
