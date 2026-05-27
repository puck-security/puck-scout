//go:build unix

package pki

import (
	"fmt"
	"os"
	"syscall"
)

func checkParentDir(dir string) error {
	st, err := os.Stat(dir)
	if err != nil {
		return err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return nil // unexpected on a Unix build; best-effort
	}
	euid := uint32(os.Geteuid())
	if euid == 0 {
		if sys.Uid != 0 {
			return fmt.Errorf("%w: %s owned by uid=%d", ErrCAKeyNonRootDir, dir, sys.Uid)
		}
		if st.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%w: %s mode %o group/other-writable",
				ErrCAKeyNonRootDir, dir, st.Mode().Perm())
		}
	} else {
		// non-root dev deploy: owner must be the current user
		if sys.Uid != euid {
			return fmt.Errorf("%w: %s not owned by current uid=%d", ErrCAKeyNonRootDir, dir, euid)
		}
	}
	return nil
}
