package server

import (
	"fmt"
	"os"
	"strings"

	"github.com/gofrs/flock"
)

// AcquireInstanceLock takes an exclusive non-blocking lock on the pidfile.
// Returns the *flock.Flock the caller is responsible for closing on shutdown
// (Close unlocks AND closes the underlying file).  Returns an error if another
// instance already holds the lock — callers should exit non-zero in that case
// because concurrent daemon instances corrupt the bootstrap-token ledger.
//
// gofrs/flock uses POSIX advisory locks on Unix and Windows LockFileEx on
// Windows; from Go's perspective the API is identical.
func AcquireInstanceLock(pidfilePath string) (*flock.Flock, error) {
	lk := flock.New(pidfilePath)
	locked, err := lk.TryLock()
	if err != nil {
		return nil, fmt.Errorf("acquire pidfile lock %s: %w", pidfilePath, err)
	}
	if !locked {
		existing, _ := os.ReadFile(pidfilePath)
		return nil, fmt.Errorf(
			"another puck-mcp instance holds %s (pid %s). "+
				"Stop that instance first. If it's stale, remove the pidfile.",
			pidfilePath, strings.TrimSpace(string(existing)))
	}
	// Write the PID so `puck-mcp doctor` and operators can see who's holding
	// the lock.  os.WriteFile opens a separate handle to the same path —
	// safe because the lock is on the inode, not the file descriptor.
	if err := os.WriteFile(pidfilePath, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0o644); err != nil {
		_ = lk.Close()
		return nil, err
	}
	return lk, nil
}
