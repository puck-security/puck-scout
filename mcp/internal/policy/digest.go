package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
)

// Digest returns the hex-encoded sha256 of the embedded policy.toml.
// This is the server's view of the canonical grammar version; the agent
// reports its own digest on every poll/SSE-connect.  A mismatch means
// the agent's compiled-in policy.toml predates a change to the canonical
// file — the operator needs to rebuild and redeploy puck-agent.
//
// The digest is computed once at first call and cached.  We don't bake
// it into a const at compile time because go:generate produces the file
// on the fly; the runtime hash matches whatever the actual embedded
// bytes are, which is what we want.
func Digest() string {
	digestOnce.Do(func() {
		sum := sha256.Sum256(policyTOML)
		cachedDigest = hex.EncodeToString(sum[:])
	})
	return cachedDigest
}

var (
	digestOnce   sync.Once
	cachedDigest string
)
