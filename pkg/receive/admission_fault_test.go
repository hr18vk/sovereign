// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package receive

// These tests are negative controls for the admission fault injects. Each
// test arms a test-only fault and asserts that the fix's observable
// effects appear on the system's own counters — an ineffective fix fails its
// control. The test suite never sets the fault environment variable; the
// guard skips each control in every regular test run.

import (
	"os"
	"sync/atomic"
	"testing"

	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// TestAdmissionFault_ClockAdvanceDeferControl exercises the clock-advance
// fault inject. When the deleted pre-apply advance is re-armed, the four
// observables must invert: the clock jumps, NextDot is bricked, the
// recorder fires, and the verdict is Accept.
func TestAdmissionFault_ClockAdvanceDeferControl(t *testing.T) {
	if os.Getenv("SOVEREIGN_TEST_FAULT_RECEIVE_ADMISSION") != "advance" {
		t.Skip("env-gated negative control: SOVEREIGN_TEST_FAULT_RECEIVE_ADMISSION=advance not set")
	}
	const wallBase = int64(1_700_000_000_000_000)
	const budgetNS = int64(1_000_000_000)

	innerWire := buildCRDTDeltaWire(t, rcvEntityID, skewBrickDot)
	env, originPub, _ := relayChain(t, innerWire, 0, wallBase)
	r, _, _, engine := setupAdmissionTestReceiver(t, wallBase, budgetNS, originPub)
	pre := engine.LamportCounter()
	bound := eng.MaxAcceptableDotCounter(engine.LamportSnapshot())
	if skewBrickDot <= bound {
		t.Fatalf("(advance control) premise broken: brick dot %d not over-bound (bound %d)", skewBrickDot, bound)
	}
	advanceCount := new(atomic.Uint64)
	r.onClockAdvance = func(post uint64) error { advanceCount.Add(1); return nil }
	r.advanceDeferFault.Store(true) // arm the fault — the deleted pre-apply advance runs again

	verdict := r.HandleFrame(env.Marshal())

	if post := engine.LamportCounter(); post == pre {
		t.Errorf("clock-advance fault: the brick did not return: the clock stayed at %d — the armed inject did not re-arm the deleted pre-apply advance; the fix is ineffective or the inject is broken", pre)
	}
	if nd := engine.NextDot(); nd.Counter <= bound || nd.Counter == pre+1 {
		t.Errorf("clock-advance fault: NextDot() = %d (bound %d), the bricked mint did not return — the inject is broken", nd.Counter, bound)
	}
	if got := advanceCount.Load(); got == 0 {
		t.Errorf("clock-advance fault: the recorder did not fire — the WAL poison did not return; the inject is broken")
	}
	if verdict.Verdict != Accept {
		t.Errorf("clock-advance fault: verdict = %v, want Accept — reason: %v", verdict.Verdict, verdict.Reason)
	}
}

// TestAdmissionFault_PreVerifyRefundControl exercises the pre-verify refund
// fault inject. When the seven pre-verify refund sites are disabled, the
// burn must return on the bucket's budget counter (floored at 1
// by the boundary law).
func TestAdmissionFault_PreVerifyRefundControl(t *testing.T) {
	if os.Getenv("SOVEREIGN_TEST_FAULT_RECEIVE_ADMISSION") != "refund" {
		t.Skip("env-gated negative control: SOVEREIGN_TEST_FAULT_RECEIVE_ADMISSION=refund not set")
	}
	const wallBase = int64(1_700_000_000_000_000)
	const budgetNS = int64(1_000_000_000)
	const initialBudget = uint64(1) << 20

	originPub, originPriv := genKey(t)
	r, bucket, _, _ := setupAdmissionTestReceiver(t, wallBase, budgetNS, originPub)
	r.disableRefundFault.Store(true) // arm the fault — the refunds no-op

	// The budget burn drive: 31 future-walled frames x delta 32768
	// + one delta-32767 closer = 2^20 - 1 charged, every frame DropClock
	// (pre-Open, unattributed).
	victimPub, victimPriv := genKey(t)
	for i := 1; i <= 31; i++ {
		innerWire := buildCRDTDeltaWire(t, rcvEntityID, uint64(i*32768))
		env := buildOneHopAdmissionEnvelope(t, innerWire, wallBase+10_000_000, originPub, originPriv, victimPub, victimPriv)
		if v := r.HandleFrame(env.Marshal()); v.Verdict != DropClock {
			t.Fatalf("(refund control) premise broken: frame %d got %v (%v), want DropClock", i, v.Verdict, v.Reason)
		}
	}
	bLastEnv := buildOneHopAdmissionEnvelope(t, buildCRDTDeltaWire(t, rcvEntityID, uint64(31*32768+32767)), wallBase+10_000_000, originPub, originPriv, victimPub, victimPriv)
	if v := r.HandleFrame(bLastEnv.Marshal()); v.Verdict != DropClock {
		t.Fatalf("(refund control) premise broken: the closer got %v (%v), want DropClock", v.Verdict, v.Reason)
	}
	if got := bucket.Budget(victimPub[:]); got != 1 {
		t.Errorf("pre-verify refund fault: the burn did not return: after the 31+1 DropClock flood (2^20-1 charged) the victim's budget is %d, want exactly 1 (the boundary-law floor: charges leave budget >= 1) — the refunds fired despite the armed inject; the fix is ineffective or the inject is broken", got)
	}
	ownEnv := buildOneHopAdmissionEnvelope(t, buildCRDTDeltaWire(t, rcvEntityID, uint64(1024*1024)), wallBase, originPub, originPriv, victimPub, victimPriv)
	if v := r.HandleFrame(ownEnv.Marshal()); v.Verdict != DropRate {
		t.Errorf("pre-verify refund fault: the own-frame kill did not return: the victim's own legitimate frame (delta 1 above the HWM) got %v, want DropRate — the burned budget must deny the victim's verifiable traffic", v.Verdict)
	}
}
