package attribution

import (
	"sync"

	"github.com/cloudflare/circl/sign/ed25519"
	"github.com/hr18vk/supremum/pkg/identity"
)

// SetVerifyHook installs a test-only indirection over identity.VerifyCRDTFrame
// for the receiver-composition gate (Track 3.5 G3.5.e). When set, Open calls
// the hook instead of identity.VerifyCRDTFrame on each outer relay hop, so a
// test can count how many Verify calls fire on a cheap-reject path and prove
// the depth/rate/clock reject-before-Verify ordering EXECUTED (not prose-
// asserted, per the F2 lesson). The hook is nil in production (Open calls
// identity.VerifyCRDTFrame directly); tests SetVerifyHook to a counting
// wrapper and MUST ClearVerifyHook when done. It is guarded by verifyHookMu
// (the same mutex the package-level verifyHook var uses), so concurrent
// Open/HandleFrame callers observe a consistent hook.
//
// This is the exported seam the pkg/receive test uses to instrument the
// composed receiver's Verify count; the package-level verifyHook var stays
// unexported (the existing 3.2 tests set it directly within the package).
func SetVerifyHook(hook func(pub ed25519.PublicKey, msg, sig []byte) bool) {
	verifyHookMu.Lock()
	verifyHook = hook
	verifyHookMu.Unlock()
}

// ClearVerifyHook removes the test-only verify hook, restoring Open's direct
// identity.VerifyCRDTFrame call. Tests MUST call this when done (defer it) so
// a leaked hook does not affect later tests.
func ClearVerifyHook() {
	verifyHookMu.Lock()
	verifyHook = nil
	verifyHookMu.Unlock()
}

// VerifyHookCount is a convenience counting hook a test installs via
// SetVerifyHook: it counts every Verify call and delegates to
// identity.VerifyCRDTFrame. The caller reads the count via Load and MUST
// ClearVerifyHook when done.
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

// Hook is the counting indirection: increment the counter, delegate to
// identity.VerifyCRDTFrame.
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
