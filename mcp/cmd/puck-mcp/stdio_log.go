package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// stdioLogPath returns the per-user file path the stdio-mode logger should
// write to.  Uses os.UserCacheDir for OS-correctness (XDG_CACHE_HOME on
// Linux, ~/Library/Caches on macOS, %LocalAppData% on Windows).  Creates
// the parent directory mode 0700 if it doesn't exist.
//
// We do NOT write to /tmp anymore: /tmp is world-writable and an attacker
// can pre-create a symlink there to redirect our log writes (e.g., to
// ~/.bashrc).  The user's cache dir is owned by the user and inherits
// 0700 from our MkdirAll.
func stdioLogPath() (string, error) {
	cache, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("UserCacheDir: %w", err)
	}
	dir := filepath.Join(cache, "puck-mcp")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("mkdir %s: %w", dir, err)
	}
	return filepath.Join(dir, "stdio.log"), nil
}
