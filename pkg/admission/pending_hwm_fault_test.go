// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package admission

// This opt-in negative control restores the charge-time watermark write. It
// verifies that the fault injection changes the observed charge, so the test
// can detect a regression in the separation between Accept and CommitHWM.

import (
	"os"
	"testing"
)

// TestPendingHWMFaultControl enables the charge-time watermark write and
// checks that a duplicate is then admitted without another charge. Without
// injection, Accept leaves the watermark pending until CommitHWM, so the same
// unauthenticated counter is charged again rather than becoming a free frame.
func TestPendingHWMFaultControl(t *testing.T) {
	if os.Getenv("SOVEREIGN_TEST_FAULT_SEAMS") != "pendhwm" {
		t.Skip("pending-HWM negative control requires SOVEREIGN_TEST_FAULT_SEAMS=pendhwm")
	}
	b := NewPeerBucket()
	b.disablePendingHWMBugInject.Store(true)
	defer b.disablePendingHWMBugInject.Store(false)
	pub := makePub(1)
	d1, c1 := b.Accept(pubBytes(pub), 100)
	if d1 != Keep || c1 != 100 {
		t.Fatalf("first Accept got %v/%d, want Keep with charge 100", d1, c1)
	}
	d2, c2 := b.Accept(pubBytes(pub), 100)
	if d2 != Keep || c2 != 0 {
		t.Fatalf("fault injection did not restore the charge-time watermark: duplicate Accept got %v/%d, want Keep/0; without injection the duplicate is charged again until CommitHWM", d2, c2)
	}
	t.Logf("charge-time watermark fault restored: duplicate at counter 100 returned Keep with zero charge")
}
