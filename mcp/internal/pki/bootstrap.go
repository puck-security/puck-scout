package pki

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gofrs/flock"
)

const bootstrapTokenPrefix = "puck-bt-"
const bootstrapTokenRandomBytes = 32

// BootstrapToken is the plaintext value plus metadata.  Only returned at
// generation time; the server persists only the SHA-256.
type BootstrapToken struct {
	Plaintext string
	Hostname  string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

type tokenRecord struct {
	TokenSHA256 string     `json:"token_sha256"`
	Hostname    string     `json:"hostname"`
	IssuedAt    time.Time  `json:"issued_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	SpentAt     *time.Time `json:"spent_at,omitempty"`
}

// TokenLedger persists bootstrap-token records as JSONL.  Concurrent calls are
// serialised by an in-memory mutex; durability comes from rename-on-write.
type TokenLedger struct {
	path string
	mu   sync.Mutex
}

func OpenTokenLedger(path string) (*TokenLedger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDONLY, 0o600)
	if err != nil {
		return nil, err
	}
	_ = f.Close()
	// Clean up stale .tmp file from a crashed previous writeAll.
	_ = os.Remove(path + ".tmp")
	return &TokenLedger{path: path}, nil
}

func (l *TokenLedger) Issue(hostname string, ttl time.Duration) (*BootstrapToken, error) {
	raw := make([]byte, bootstrapTokenRandomBytes)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return nil, err
	}
	plaintext := bootstrapTokenPrefix + base64.RawURLEncoding.EncodeToString(raw)
	now := time.Now().UTC()
	rec := tokenRecord{
		TokenSHA256: sha256Hex(plaintext),
		Hostname:    hostname,
		IssuedAt:    now,
		ExpiresAt:   now.Add(ttl),
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.appendRecord(rec); err != nil {
		return nil, err
	}
	return &BootstrapToken{
		Plaintext: plaintext,
		Hostname:  hostname,
		IssuedAt:  rec.IssuedAt,
		ExpiresAt: rec.ExpiresAt,
	}, nil
}

func (l *TokenLedger) Validate(plaintext, requestHostname string) error {
	if !strings.HasPrefix(plaintext, bootstrapTokenPrefix) {
		return ErrTokenMalformed
	}
	hash := sha256Hex(plaintext)
	l.mu.Lock()
	defer l.mu.Unlock()
	records, err := l.readAll()
	if err != nil {
		return err
	}
	for _, rec := range records {
		if rec.TokenSHA256 != hash {
			continue
		}
		if rec.SpentAt != nil {
			return ErrTokenSpent
		}
		if time.Now().After(rec.ExpiresAt) {
			return ErrTokenExpired
		}
		if rec.Hostname != requestHostname {
			return ErrTokenHostMismatch
		}
		return nil
	}
	return ErrTokenUnknown
}

func (l *TokenLedger) Spend(plaintext string) error {
	hash := sha256Hex(plaintext)
	l.mu.Lock()
	defer l.mu.Unlock()
	records, err := l.readAll()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	found := false
	for i := range records {
		if records[i].TokenSHA256 == hash {
			if records[i].SpentAt != nil {
				return ErrTokenSpent
			}
			records[i].SpentAt = &now
			found = true
			break
		}
	}
	if !found {
		return ErrTokenUnknown
	}
	return l.writeAll(records)
}

// ValidateAndSpend atomically validates the token for the given hostname and
// marks it spent in a single critical section.  Use this in the enrollment
// handler instead of separate Validate + Spend calls — separate calls have a
// race window where two concurrent enrollments can both pass Validate and
// both get certs signed.  With ValidateAndSpend, only the first caller
// succeeds; the second receives ErrTokenSpent.
//
// On success, the token is already marked spent on disk before this returns,
// so the caller can proceed to issue a cert.  If cert issuance later fails,
// the token is lost (operator must issue a new one) — that's preferable to
// the alternative where a single token could authorise multiple certs for
// the same hostname.
func (l *TokenLedger) ValidateAndSpend(plaintext, requestHostname string) error {
	if !strings.HasPrefix(plaintext, bootstrapTokenPrefix) {
		return ErrTokenMalformed
	}
	hash := sha256Hex(plaintext)
	l.mu.Lock()
	defer l.mu.Unlock()
	records, err := l.readAll()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	for i, rec := range records {
		if rec.TokenSHA256 != hash {
			continue
		}
		if rec.SpentAt != nil {
			return ErrTokenSpent
		}
		if now.After(rec.ExpiresAt) {
			return ErrTokenExpired
		}
		if rec.Hostname != requestHostname {
			return ErrTokenHostMismatch
		}
		records[i].SpentAt = &now
		return l.writeAll(records)
	}
	return ErrTokenUnknown
}

func (l *TokenLedger) Count() (unspent, spent int, _ error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	records, err := l.readAll()
	if err != nil {
		return 0, 0, err
	}
	for _, r := range records {
		if r.SpentAt == nil {
			unspent++
		} else {
			spent++
		}
	}
	return
}

func (l *TokenLedger) appendRecord(rec tokenRecord) error {
	records, err := l.readAll()
	if err != nil {
		return err
	}
	records = append(records, rec)
	return l.writeAll(records)
}

// readAll reads all records from the ledger file, holding a shared (read) lock
// for the duration.  This prevents reading a partially-written file when a
// concurrent generate-bootstrap-token or daemon Spend is in progress.
// gofrs/flock uses POSIX advisory locks on Unix and LockFileEx on Windows;
// either way the semantics are "blocks only on an exclusive writer".
func (l *TokenLedger) readAll() ([]tokenRecord, error) {
	lk := flock.New(l.path)
	if err := lk.RLock(); err != nil {
		return nil, fmt.Errorf("acquire ledger read lock: %w", err)
	}
	defer func() { _ = lk.Unlock() }()

	liveFile, err := os.OpenFile(l.path, os.O_RDONLY, 0o600)
	if err != nil {
		return nil, err
	}
	defer liveFile.Close()

	data, err := io.ReadAll(liveFile)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}
	var records []tokenRecord
	var corruptLines []string
	for _, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		if line == "" {
			continue
		}
		var r tokenRecord
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			// Don't silently swallow malformed lines: the audit gap is
			// indistinguishable from successful redaction.  Collect them
			// and surface as an error to the caller, who decides whether
			// to fail-closed.  We also stash a backup of the offending line
			// so an operator can inspect what was corrupted.
			log.Printf("pki: malformed ledger line: %v", err)
			corruptLines = append(corruptLines, line)
			continue
		}
		records = append(records, r)
	}
	if len(corruptLines) > 0 {
		// Best-effort: write the corrupt lines to a sidecar file so they're
		// not lost when the next writeAll rewrites the ledger.
		backup := l.path + ".corrupted"
		if f, ferr := os.OpenFile(backup, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); ferr == nil {
			for _, ln := range corruptLines {
				_, _ = f.WriteString(ln + "\n")
			}
			_ = f.Close()
			log.Printf("pki: %d corrupt ledger line(s) moved to %s; investigate then delete", len(corruptLines), backup)
		}
		return records, fmt.Errorf("ledger has %d corrupt line(s) (moved to %s.corrupted); refusing to operate until resolved", len(corruptLines), l.path)
	}
	return records, nil
}

// writeAll serialises records to a tmp file and renames it over the live path.
// An exclusive write lock on the live path is held from before the tmp write
// through to after the rename, providing cross-process serialisation with
// concurrent generate-bootstrap-token runs and daemon Spend calls.
// Lock is blocking-fair via gofrs/flock (POSIX advisory on Unix, LockFileEx
// on Windows).
func (l *TokenLedger) writeAll(records []tokenRecord) error {
	lk := flock.New(l.path)
	if err := lk.Lock(); err != nil {
		return fmt.Errorf("acquire ledger write lock: %w", err)
	}
	defer func() { _ = lk.Unlock() }()

	tmp := l.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, r := range records {
		line, err := json.Marshal(r)
		if err != nil {
			return err
		}
		if _, err := f.Write(append(line, '\n')); err != nil {
			return err
		}
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, l.path)
}

// TokenRecord is the exported view of a single ledger entry.
type TokenRecord struct {
	Hostname  string
	IssuedAt  time.Time
	ExpiresAt time.Time
	SpentAt   *time.Time // nil = unspent (pending enrollment)
}

// ListAll returns every token record in the ledger, oldest first.
func (l *TokenLedger) ListAll() ([]TokenRecord, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	recs, err := l.readAll()
	if err != nil {
		return nil, err
	}
	out := make([]TokenRecord, 0, len(recs))
	for _, r := range recs {
		out = append(out, TokenRecord{
			Hostname:  r.Hostname,
			IssuedAt:  r.IssuedAt,
			ExpiresAt: r.ExpiresAt,
			SpentAt:   r.SpentAt,
		})
	}
	return out, nil
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
