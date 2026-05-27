//go:build unix

package main

import (
	"os"
	"syscall"
)

// openLogFileNoFollow opens the log file with O_NOFOLLOW so the open fails
// if an attacker planted a symlink at the destination.  We've already moved
// the log out of /tmp (see stdioLogPath) — this is belt-and-suspenders for
// the case where the user's cache dir or our subdirectory inside it has
// somehow been compromised.
func openLogFileNoFollow(path string) (*os.File, error) {
	return os.OpenFile(
		path,
		os.O_APPEND|os.O_CREATE|os.O_WRONLY|syscall.O_NOFOLLOW,
		0o600,
	)
}
