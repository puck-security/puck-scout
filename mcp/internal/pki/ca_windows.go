//go:build windows

package pki

// checkParentDir is a no-op on Windows.  See ca.go for the rationale: Windows
// uses ACLs (not POSIX ownership) and meaningful equivalents would require
// golang.org/x/sys/windows security-descriptor inspection.  puck-mcp on
// Windows is operator-workstation-only (single user); the check has lower
// value there.  Future hardening could add an SDDL-based check.
func checkParentDir(_ string) error {
	return nil
}
