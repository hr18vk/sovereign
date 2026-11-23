// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package clock

import (
	"sync"
	"sync/atomic"
	"testing"
)

// recordingAdvancer records the number of AdvanceLamportTo calls and the most
// recent argument. Atomic storage permits concurrent use in the race test.
type recordingAdvancer struct {
	calls atomic.Int64
	last  atomic.Uint64
}

func (r *recordingAdvancer) AdvanceLamportTo(remoteCounter uint64) {
	r.calls.Add(1)
	r.last.Store(remoteCounter)
}

func (r *recordingAdvancer) callCount() int64 { return r.calls.Load() }
func (r *recordingAdvancer) lastArg() uint64  { return r.last.Load() }

// A frame 1500 microseconds in the future is within the drift bound. Admit
// leaves the logical clock unchanged; Advance forwards a counter separately.
func TestAdmit_1500usFutureAccepted(t *testing.T) {
	const t0 int64 = 1_700_000_000_000_000 // local physical time, microseconds
	clock := NewSyntheticClock(t0)
	adv := &recordingAdvancer{}
	cap := NewIngressHLCScalarCap(clock, adv)

	const incomingLogical uint64 = 42
	accepted := cap.Admit(t0 + 1500)

	if !accepted {
		t.Fatalf("frame 1500 microseconds ahead was rejected; want acceptance within the 2000-microsecond bound")
	}
	if got := adv.callCount(); got != 0 {
		t.Fatalf("Admit made %d logical-clock advances; want 0", got)
	}
	cap.Advance(incomingLogical)
	if got := adv.callCount(); got != 1 {
		t.Fatalf("Advance must feed the engine exactly once, got %d", got)
	}
	if got := adv.lastArg(); got != incomingLogical {
		t.Fatalf("Advance must feed incomingLogical=%d, got %d", incomingLogical, got)
	}
}

// A frame 3000 microseconds in the future exceeds the drift bound and is
// rejected without a logical-clock advance.
func TestAdmit_3000usFutureRejected(t *testing.T) {
	const t0 int64 = 1_700_000_000_000_000
	clock := NewSyntheticClock(t0)
	adv := &recordingAdvancer{}
	cap := NewIngressHLCScalarCap(clock, adv)

	accepted := cap.Admit(t0 + 3000)

	if accepted {
		t.Fatalf("frame 3000 microseconds ahead was accepted; want rejection beyond the 2000-microsecond bound")
	}
	if got := adv.callCount(); got != 0 {
		t.Fatalf("rejection made %d logical-clock advances; want 0", got)
	}
}

// A frame 5000 microseconds behind the local clock is accepted as late.
// Physical-time admission does not advance the logical clock.
func TestAdmit_PastPhysicalAccepted(t *testing.T) {
	const t0 int64 = 1_700_000_000_000_000
	clock := NewSyntheticClock(t0)
	adv := &recordingAdvancer{}
	cap := NewIngressHLCScalarCap(clock, adv)

	const incomingLogical uint64 = 7
	accepted := cap.Admit(t0 - 5000)

	if !accepted {
		t.Fatalf("frame 5000 microseconds behind was rejected; want acceptance as a late frame")
	}
	if got := adv.callCount(); got != 0 {
		t.Fatalf("late-frame admission made %d logical-clock advances; want 0", got)
	}
	cap.Advance(incomingLogical)
	if got := adv.lastArg(); got != incomingLogical {
		t.Fatalf("Advance must feed incomingLogical=%d, got %d", incomingLogical, got)
	}
}

// Advance forwards stale logical counters without consulting engine state.
// The real engine ignores them; the recording fake retains them so the test
// can observe the controller's behavior.
func TestAdmit_MonotoneAdvanceByEngine(t *testing.T) {
	const t0 int64 = 1_700_000_000_000_000
	clock := NewSyntheticClock(t0)
	adv := &recordingAdvancer{}
	cap := NewIngressHLCScalarCap(clock, adv)

	// Start with 100 as the fake's previously recorded counter. The controller
	// has no access to an engine's local logical clock.
	adv.last.Store(100)

	const incomingLogical uint64 = 50 // stale relative to engine's 100
	accepted := cap.Admit(t0 + 100)

	if !accepted {
		t.Fatalf("frame within the drift bound was rejected based on logical ordering")
	}
	if got := adv.callCount(); got != 0 {
		t.Fatalf("Admit made %d logical-clock advances; want 0", got)
	}
	cap.Advance(incomingLogical)
	if got := adv.lastArg(); got != incomingLogical {
		t.Fatalf("Advance should forward incomingLogical=%d without pre-filtering; recorded %d", incomingLogical, got)
	}
	// Unlike the recording fake, the real engine's compare-and-swap loop
	// discards a counter that does not exceed its current value.
}

// TestMaxDriftEpsilon_UnitInvariant pins the bound to 2000 microseconds
// (2 milliseconds) and requires an explicit microsecond unit label.
func TestMaxDriftEpsilon_UnitInvariant(t *testing.T) {
	if maxDriftEpsilon != 2000 {
		t.Fatalf("maxDriftEpsilon = %d; want 2000 microseconds (2 milliseconds)", maxDriftEpsilon)
	}
	// 2_000_000 microseconds would widen the bound to 2 seconds.
	if maxDriftEpsilon == 2_000_000 {
		t.Fatalf("maxDriftEpsilon must not be 2_000_000 microseconds (2 seconds)")
	}
	// A value of 2 would enforce 2 microseconds rather than 2 milliseconds.
	if maxDriftEpsilon == 2 {
		t.Fatalf("maxDriftEpsilon must not be 2 microseconds")
	}
	switch maxDriftEpsilonUnit {
	case "microsecond":
		// Required unit label.
	case "":
		t.Fatalf("maxDriftEpsilonUnit is empty; want \"microsecond\"")
	case "millisecond":
		t.Fatalf("maxDriftEpsilonUnit = \"millisecond\" would describe 2000 milliseconds (2 seconds)")
	case "2000 ms":
		t.Fatalf("maxDriftEpsilonUnit = \"2000 ms\" would describe 2 seconds instead of 2 milliseconds")
	default:
		t.Fatalf("maxDriftEpsilonUnit = %q; want \"microsecond\"", maxDriftEpsilonUnit)
	}

	// Both arrays have length zero when maxDriftEpsilon is 2000. Any other
	// constant value makes one array length negative and fails compilation.
	var _ [maxDriftEpsilon - 2000]byte
	var _ [2000 - maxDriftEpsilon]byte
}

// Concurrent Admit and Advance calls share one controller, clock, and
// advancer. Admit contributes no advances, so every expected call comes from
// an explicit Advance call. Run this test with -race to check atomic access.
func TestAdmit_ConcurrentNoRace(t *testing.T) {
	const t0 int64 = 1_700_000_000_000_000
	clock := NewSyntheticClock(t0)
	adv := &recordingAdvancer{}
	cap := NewIngressHLCScalarCap(clock, adv)

	const goroutines = 32
	const iters = 2000

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(seed int) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				// Mix accept and reject paths across goroutines.
				offset := int64((seed + i) % 5000) // 0 to 4999 microseconds ahead
				cap.Admit(t0 + offset)
				cap.Advance(uint64(seed*iters + i))
			}
		}(g)
	}
	wg.Wait()

	if got := adv.callCount(); got != goroutines*iters {
		t.Fatalf("want exactly %d advance calls from explicit Advance calls, with none from Admit; got %d", goroutines*iters, got)
	}
}
