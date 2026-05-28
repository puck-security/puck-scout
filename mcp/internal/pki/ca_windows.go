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

// enforceMode0600 is a no-op on Windows for the same reason: os.Stat reports
// 0666 regardless of the actual ACL.  The owner-only invariant still holds
// via the ACL inherited from the parent dir; a meaningful check would need
// SDDL inspection via golang.org/x/sys/windows.
func enforceMode0600(_ string) error {
	return nil
}
