package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAcquireInstanceLock_HappyPath verifies a single acquire-then-release
// cycle works and writes the PID into the pidfile.
func TestAcquireInstanceLock_HappyPath(t *testing.T) {
	pidfile := filepath.Join(t.TempDir(), "puck-mcp.pid")
	lock, err := AcquireInstanceLock(pidfile)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer lock.Close()

	// PID must be written to the file so doctor / operators can identify
	// the holder.
	data, err := os.ReadFile(pidfile)
	if err != nil {
		t.Fatalf("read pidfile: %v", err)
	}
	pid := strings.TrimSpace(string(data))
	if pid == "" {
		t.Fatalf("pidfile empty after acquire")
	}
	// Sanity: the contents are our own pid.
	if got, want := pid, strings.TrimSpace(itoa(os.Getpid())); got != want {
		t.Fatalf("pidfile pid: got %q, want %q", got, want)
	}
}

// TestAcquireInstanceLock_RejectsConcurrent locks down the gofrs/flock
// migration (W1).  Two concurrent calls on the same pidfile MUST result
// in exactly one success — otherwise two daemons could silently corrupt
// the bootstrap-token ledger.
func TestAcquireInstanceLock_RejectsConcurrent(t *testing.T) {
	pidfile := filepath.Join(t.TempDir(), "puck-mcp.pid")

	first, err := AcquireInstanceLock(pidfile)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	defer first.Close()

	// Second acquire must fail with an error that mentions another
	// instance — operators need to see this in the diagnostic output.
	second, err := AcquireInstanceLock(pidfile)
	if err == nil {
		_ = second.Close()
		t.Fatal("second acquire should have failed; got nil error")
	}
	if !strings.Contains(err.Error(), "another puck-mcp instance") {
		t.Fatalf("error message should mention 'another puck-mcp instance', got: %v", err)
	}
}

// TestAcquireInstanceLock_ReleaseAllowsReacquire verifies that closing
// the lock actually releases it (gofrs/flock's Close unlocks + closes
// the underlying file).  Otherwise restarts of the daemon would block
// indefinitely.
func TestAcquireInstanceLock_ReleaseAllowsReacquire(t *testing.T) {
	pidfile := filepath.Join(t.TempDir(), "puck-mcp.pid")

	first, err := AcquireInstanceLock(pidfile)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close first: %v", err)
	}

	second, err := AcquireInstanceLock(pidfile)
	if err != nil {
		t.Fatalf("second acquire after release: %v", err)
	}
	defer second.Close()
}

// Helper: stdlib has strconv.Itoa but we keep imports minimal.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := false
	if i < 0 {
		neg = true
		i = -i
	}
	var buf [20]byte
	n := len(buf)
	for i > 0 {
		n--
		buf[n] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		n--
		buf[n] = '-'
	}
	return string(buf[n:])
}
