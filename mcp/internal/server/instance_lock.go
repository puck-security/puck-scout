package server

import (
	"fmt"
	"os"
	"strings"

	"github.com/gofrs/flock"
)

// AcquireInstanceLock takes an exclusive non-blocking lock on a sidecar
// `<pidfile>.lock` file (NOT the pidfile itself: gofrs/flock on Windows
// uses LockFileEx which holds an open handle with restrictive share modes,
// blocking the subsequent os.WriteFile of the PID).  Returns the *flock.Flock
// the caller is responsible for closing on shutdown (Close unlocks AND closes
// the underlying file).  Returns an error if another instance already holds
// the lock — callers should exit non-zero in that case because concurrent
// daemon instances corrupt the bootstrap-token ledger.
//
// gofrs/flock uses POSIX advisory locks on Unix and Windows LockFileEx on
// Windows; from Go's perspective the API is identical.
func AcquireInstanceLock(pidfilePath string) (*flock.Flock, error) {
	lockPath := pidfilePath + ".lock"
	lk := flock.New(lockPath)
	locked, err := lk.TryLock()
	if err != nil {
		return nil, fmt.Errorf("acquire pidfile lock %s: %w", lockPath, err)
	}
	if !locked {
		existing, _ := os.ReadFile(pidfilePath)
		return nil, fmt.Errorf(
			"another puck-mcp instance holds %s (pid %s); "+
				"stop that instance first, or remove the pidfile if it is stale",
			pidfilePath, strings.TrimSpace(string(existing)))
	}
	// Write the PID so `puck-mcp doctor` and operators can see who's holding
	// the lock.  Lock lives on the sidecar so this write doesn't fight an
	// open handle on Windows.
	if err := os.WriteFile(pidfilePath, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0o644); err != nil {
		_ = lk.Close()
		return nil, err
	}
	return lk, nil
}
