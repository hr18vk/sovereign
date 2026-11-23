// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package attribution

import (
	"sync"

	"github.com/cloudflare/circl/sign/ed25519"
	"github.com/hr18vk/sovereign/pkg/identity"
)

// SetVerifyHook installs a test hook in place of identity.VerifyCRDTFrame.
// Open calls it for each outer relay hop, allowing receiver tests to count
// verification calls on acceptance and rejection paths. Production leaves the
// hook nil, so Open calls identity.VerifyCRDTFrame directly.
//
// Tests must call ClearVerifyHook when finished. verifyHookMu protects the
// hook so concurrent Open and HandleFrame callers observe a consistent value.
// The hook is exported for tests in pkg/receive; package-local tests can set
// verifyHook directly.
func SetVerifyHook(hook func(pub ed25519.PublicKey, msg, sig []byte) bool) {
	verifyHookMu.Lock()
	verifyHook = hook
	verifyHookMu.Unlock()
}

// ClearVerifyHook restores Open's direct identity.VerifyCRDTFrame call.
// Tests should defer it after installing a hook so later tests are unaffected.
func ClearVerifyHook() {
	verifyHookMu.Lock()
	verifyHook = nil
	verifyHookMu.Unlock()
}

// VerifyHookCount counts verification calls and delegates each one to
// identity.VerifyCRDTFrame. Install Hook with SetVerifyHook, read the total
// with Load, and call ClearVerifyHook when finished.
//
// Example:
//
//	count := new(VerifyHookCount)
//	attribution.SetVerifyHook(count.Hook)
//	defer attribution.ClearVerifyHook()
//	... run a forged-deep frame through the receiver ...
//	if count.Load() != 0 { t.Fatalf("depth reject must issue zero Verifies") }
type VerifyHookCount struct {
	mu    sync.Mutex
	count int64
}

// Hook increments the counter and delegates to identity.VerifyCRDTFrame.
func (c *VerifyHookCount) Hook(pub ed25519.PublicKey, msg, sig []byte) bool {
	c.mu.Lock()
	c.count++
	c.mu.Unlock()
	return identity.VerifyCRDTFrame(pub, msg, sig)
}

// Load returns the number of Verify calls observed since the hook was set.
func (c *VerifyHookCount) Load() int64 {
	c.mu.Lock()
	n := c.count
	c.mu.Unlock()
	return n
}

// Reset zeroes the counter.
func (c *VerifyHookCount) Reset() {
	c.mu.Lock()
	c.count = 0
	c.mu.Unlock()
}
