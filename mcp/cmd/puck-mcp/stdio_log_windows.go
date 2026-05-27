//go:build windows

package main

import "os"

// openLogFileNoFollow on Windows.  Windows doesn't expose O_NOFOLLOW; the
// equivalent FILE_FLAG_OPEN_REPARSE_POINT lives in win32 syscalls and is
// awkward from Go.  However the symlink-redirect attack the Unix variant
// guards against requires a writable shared temp directory (the /tmp
// problem).  On Windows our log lives under %LocalAppData%\puck-mcp\
// which is owned by the current user and not accessible to other local
// users without explicit ACL grants.  Plain OpenFile is acceptable here.
func openLogFileNoFollow(path string) (*os.File, error) {
	return os.OpenFile(
		path,
		os.O_APPEND|os.O_CREATE|os.O_WRONLY,
		0o600,
	)
}
