package pki

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func newLedger(t *testing.T) *TokenLedger {
	t.Helper()
	dir := t.TempDir()
	l, err := OpenTokenLedger(filepath.Join(dir, "tokens.jsonl"))
	if err != nil {
		t.Fatalf("open ledger: %v", err)
	}
	return l
}

func TestTokenLifecycle_HappyPath(t *testing.T) {
	l := newLedger(t)
	tok, err := l.Issue("eng-laptop-47", time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if !strings.HasPrefix(tok.Plaintext, "puck-bt-") {
		t.Fatalf("token prefix: %q", tok.Plaintext)
	}
	if err := l.Validate(tok.Plaintext, "eng-laptop-47"); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if err := l.Spend(tok.Plaintext); err != nil {
		t.Fatalf("spend: %v", err)
	}
	if err := l.Validate(tok.Plaintext, "eng-laptop-47"); !errors.Is(err, ErrTokenSpent) {
		t.Fatalf("post-spend validate: want ErrTokenSpent, got %v", err)
	}
}

func TestToken_HostnameBinding(t *testing.T) {
	l := newLedger(t)
	tok, _ := l.Issue("host-a", time.Hour)
	if err := l.Validate(tok.Plaintext, "host-b"); !errors.Is(err, ErrTokenHostMismatch) {
		t.Fatalf("want ErrTokenHostMismatch, got %v", err)
	}
}

// TestToken_HostnameBinding_CaseInsensitive pins that a token's hostname
// binding is canonical (lowercase) and case-folded on validation, so an
// operator who generates a token for "Eng-Laptop-47" and an agent that
// enrolls as "eng-laptop-47" (or vice versa) still match.  Hostname identity
// is case-insensitive everywhere — see server/identity.go.
func TestToken_HostnameBinding_CaseInsensitive(t *testing.T) {
	l := newLedger(t)
	tok, err := l.Issue("Eng-Laptop-47", time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if tok.Hostname != "eng-laptop-47" {
		t.Fatalf("Issue should canonicalise the binding to lowercase; got %q", tok.Hostname)
	}
	if err := l.Validate(tok.Plaintext, "ENG-LAPTOP-47"); err != nil {
		t.Fatalf("case-folded Validate should match: %v", err)
	}
	if err := l.ValidateAndSpend(tok.Plaintext, "eng-laptop-47"); err != nil {
		t.Fatalf("case-folded ValidateAndSpend should match: %v", err)
	}
	// A genuinely different host still mismatches.
	tok2, _ := l.Issue("host-a", time.Hour)
	if err := l.Validate(tok2.Plaintext, "host-b"); !errors.Is(err, ErrTokenHostMismatch) {
		t.Fatalf("want ErrTokenHostMismatch for a different host, got %v", err)
	}
}

func TestToken_Expiry(t *testing.T) {
	l := newLedger(t)
	tok, _ := l.Issue("host-a", -1*time.Second)
	if err := l.Validate(tok.Plaintext, "host-a"); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("want ErrTokenExpired, got %v", err)
	}
}

func TestToken_Malformed(t *testing.T) {
	l := newLedger(t)
	if err := l.Validate("bogus-no-prefix", "host-a"); !errors.Is(err, ErrTokenMalformed) {
		t.Fatalf("want ErrTokenMalformed, got %v", err)
	}
}

func TestToken_SingleUseUnderConcurrentSpend(t *testing.T) {
	l := newLedger(t)
	tok, _ := l.Issue("host-a", time.Hour)
	const n = 100
	var wg sync.WaitGroup
	successes := make(chan struct{}, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := l.Spend(tok.Plaintext); err == nil {
				successes <- struct{}{}
			}
		}()
	}
	wg.Wait()
	close(successes)
	count := 0
	for range successes {
		count++
	}
	if count != 1 {
		t.Fatalf("expected exactly one Spend to succeed; got %d", count)
	}
}

// TestToken_ValidateAndSpend_ConcurrentRace exercises the atomic
// validate+spend path that the enroll handler now uses (C3 of the
// bootstrap review).  Old Validate-then-Spend code had a race where two
// concurrent callers could both pass Validate and both proceed; only one
// won at Spend time, but both might have issued a cert before that.
// ValidateAndSpend closes the race — exactly one caller succeeds.
func TestToken_ValidateAndSpend_ConcurrentRace(t *testing.T) {
	l := newLedger(t)
	tok, _ := l.Issue("host-a", time.Hour)
	const n = 100
	var wg sync.WaitGroup
	results := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- l.ValidateAndSpend(tok.Plaintext, "host-a")
		}()
	}
	wg.Wait()
	close(results)

	var successes, spent, other int
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrTokenSpent):
			spent++
		default:
			other++
			t.Errorf("unexpected error: %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("expected exactly 1 ValidateAndSpend to succeed; got %d (spent=%d, other=%d)",
			successes, spent, other)
	}
	if spent != n-1 {
		t.Fatalf("expected %d ErrTokenSpent failures; got %d", n-1, spent)
	}
}

// TestToken_ValidateAndSpend_RejectsHostnameMismatch verifies that the
// atomic path enforces the hostname-binding check just like separate
// Validate does — a token issued for "host-a" can't be spent against
// "host-b".  The token is NOT marked spent on hostname-mismatch (so the
// real owner can still use it).
func TestToken_ValidateAndSpend_RejectsHostnameMismatch(t *testing.T) {
	l := newLedger(t)
	tok, _ := l.Issue("host-a", time.Hour)

	// First call: wrong hostname.  Must fail without consuming the token.
	if err := l.ValidateAndSpend(tok.Plaintext, "host-b"); !errors.Is(err, ErrTokenHostMismatch) {
		t.Fatalf("expected ErrTokenHostMismatch, got %v", err)
	}

	// Second call: correct hostname.  Must succeed because the token is
	// still unspent — the mismatch must not have marked it consumed.
	if err := l.ValidateAndSpend(tok.Plaintext, "host-a"); err != nil {
		t.Fatalf("expected success after rejecting wrong hostname, got %v", err)
	}
}

// TestToken_ValidateAndSpend_RejectsExpired verifies the atomic path
// also checks expiry (covering the matching check in Validate).
func TestToken_ValidateAndSpend_RejectsExpired(t *testing.T) {
	l := newLedger(t)
	// 1ms TTL — the sleep below ensures we're past expiry.
	tok, _ := l.Issue("host-a", 1*time.Millisecond)
	time.Sleep(10 * time.Millisecond)
	if err := l.ValidateAndSpend(tok.Plaintext, "host-a"); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}
}

// TestLedger_CorruptLineFailsClosed exercises the corrupt-line backup
// path added by D2 of the bootstrap review.  A malformed JSONL line in
// the ledger must:
//  1. Cause readAll to return an error (fail-closed; refuse to operate)
//  2. Move the corrupt line to <ledger>.corrupted (preserved for ops)
//  3. Still return the well-formed records that were already parsed
//
// Without this test, a future "just log and skip" regression would
// silently mask audit-trail corruption.
func TestLedger_CorruptLineFailsClosed(t *testing.T) {
	dir := t.TempDir()
	ledgerPath := filepath.Join(dir, "tokens.jsonl")

	// Issue a token so there's at least one valid record to read back.
	l, err := OpenTokenLedger(ledgerPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := l.Issue("host-a", time.Hour); err != nil {
		t.Fatalf("issue: %v", err)
	}

	// Append a garbage line directly to the JSONL file.  This simulates
	// disk corruption, an interrupted write, or a malicious tamper.
	f, err := os.OpenFile(ledgerPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open ledger for tamper: %v", err)
	}
	if _, err := f.WriteString("this-is-not-valid-json\n"); err != nil {
		t.Fatalf("write tamper: %v", err)
	}
	_ = f.Close()

	// Validate on any token: should fail because the ledger now has a
	// corrupt line.  We don't care which error code — only that it fails.
	tok2, err := l.Issue("host-b", time.Hour) // Issue does readAll first
	if err == nil {
		// If Issue happened to succeed because the corrupt line was
		// appended after a successful read, force another read by
		// calling Validate (which goes through readAll).
		err = l.Validate(tok2.Plaintext, "host-b")
	}
	if err == nil {
		t.Fatal("expected error from corrupt-ledger ops, got nil")
	}
	if !strings.Contains(err.Error(), "corrupt") {
		t.Fatalf("expected 'corrupt' in error message, got: %v", err)
	}

	// Verify the .corrupted sidecar was written with the bad line.
	backupPath := ledgerPath + ".corrupted"
	backup, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatalf("expected backup at %s, got: %v", backupPath, err)
	}
	if !strings.Contains(string(backup), "this-is-not-valid-json") {
		t.Fatalf("backup didn't contain corrupt line; got: %q", backup)
	}
}
