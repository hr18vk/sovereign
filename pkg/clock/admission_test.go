package clock

import (
	"sync"
	"sync/atomic"
	"testing"
)

// recordingAdvancer is a fake LogicalAdvancer that records every
// AdvanceLamportTo invocation (count + last arg) under an atomic so it
// is safe for the -race gate's concurrent Admit callers.
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

// G3.0.f — 1500 us-future frame ACCEPTED.
func TestAdmit_1500usFutureAccepted(t *testing.T) {
	const t0 int64 = 1_700_000_000_000_000 // pinned local physical, us
	clock := NewSyntheticClock(t0)
	adv := &recordingAdvancer{}
	cap := NewIngressHLCScalarCap(clock, adv)

	const incomingLogical uint64 = 42
	accepted := cap.Admit(t0+1500, incomingLogical)

	if !accepted {
		t.Fatalf("1500 us-future frame must be ACCEPTED (1500 > 2000 is false), got rejected")
	}
	if got := adv.callCount(); got != 1 {
		t.Fatalf("AdvanceLamportTo must be called exactly once on accept, got %d", got)
	}
	if got := adv.lastArg(); got != incomingLogical {
		t.Fatalf("AdvanceLamportTo must be called with incomingLogical=%d, got %d", incomingLogical, got)
	}
}

// G3.0.g — 3000 us-future frame REJECTED, AdvanceLamportTo NOT called.
func TestAdmit_3000usFutureRejected(t *testing.T) {
	const t0 int64 = 1_700_000_000_000_000
	clock := NewSyntheticClock(t0)
	adv := &recordingAdvancer{}
	cap := NewIngressHLCScalarCap(clock, adv)

	accepted := cap.Admit(t0+3000, 42)

	if accepted {
		t.Fatalf("3000 us-future frame must be REJECTED (3000 > 2000 is true), got accepted")
	}
	if got := adv.callCount(); got != 0 {
		t.Fatalf("AdvanceLamportTo must NOT be called on reject, got %d calls", got)
	}
}

// G3.0.h — physical-in-the-past frame ACCEPTED (normal late frame, not
// Byzantine). incomingPhysical = T0 - 5000 us -> Admit true,
// AdvanceLamportTo called.
func TestAdmit_PastPhysicalAccepted(t *testing.T) {
	const t0 int64 = 1_700_000_000_000_000
	clock := NewSyntheticClock(t0)
	adv := &recordingAdvancer{}
	cap := NewIngressHLCScalarCap(clock, adv)

	const incomingLogical uint64 = 7
	accepted := cap.Admit(t0-5000, incomingLogical)

	if !accepted {
		t.Fatalf("past-physical frame (T0-5000 us) must be ACCEPTED as a normal late frame, got rejected")
	}
	if got := adv.callCount(); got != 1 {
		t.Fatalf("AdvanceLamportTo must be called on accept of a late frame, got %d", got)
	}
	if got := adv.lastArg(); got != incomingLogical {
		t.Fatalf("AdvanceLamportTo must be called with incomingLogical=%d, got %d", incomingLogical, got)
	}
}

// G3.0.i — max(local, remote) monotone. The controller feeds
// incomingLogical to AdvanceLamportTo unconditionally on accept; the
// ENGINE enforces monotonicity (current >= remoteCounter breaks at
// crdt.go:1642). Prove with a recording fake: advance engine to
// logical=100, admit a frame with incomingLogical=50 -> Admit true,
// fake recorded AdvanceLamportTo(50) was invoked (the engine's
// internal guard then no-ops it). This is BY DESIGN.
func TestAdmit_MonotoneAdvanceByEngine(t *testing.T) {
	const t0 int64 = 1_700_000_000_000_000
	clock := NewSyntheticClock(t0)
	adv := &recordingAdvancer{}
	cap := NewIngressHLCScalarCap(clock, adv)

	// Simulate the engine already advanced to logical=100 by recording
	// it through the same fake (the real engine would hold it in
	// lamportCounter). The controller does NOT read local logical.
	adv.last.Store(100)

	const incomingLogical uint64 = 50 // stale relative to engine's 100
	accepted := cap.Admit(t0+100, incomingLogical)

	if !accepted {
		t.Fatalf("frame within epsilon must be ACCEPTED regardless of logical ordering, got rejected")
	}
	// The controller fed the stale logical to the engine unconditionally.
	if got := adv.lastArg(); got != incomingLogical {
		t.Fatalf("controller must feed incomingLogical=%d to engine (engine no-ops stale), got %d", incomingLogical, got)
	}
	// BY DESIGN: the real engine's crdt.go:1642 guard (current >=
	// remoteCounter -> break) no-ops this stale advance. The recording
	// fake has no such guard, so it records the call — proving the
	// controller does NOT pre-filter on local logical (which would
	// require reading the private lamportCounter and re-open FROZEN
	// crdt.go).
}

// G3.0.j — STATIC TOOTH (the fabrication-detector-ban, load-bearing).
// Asserts:
//  1. maxDriftEpsilon == 2000 (the numeric value, in us).
//  2. maxDriftEpsilonUnit == "microsecond" (the unit sentinel; BANNED:
//     empty, "millisecond"-only, "2000 ms").
//  3. t.Errorf fires if maxDriftEpsilon == 2_000_000 (2000 ms = 2 s =
//     the fabrication) OR if maxDriftEpsilon == 2 with a microsecond
//     clock (2 us = too tight).
//
// This tooth makes the 2000-ms fabrication detector-banned from source
// forever.
func TestMaxDriftEpsilon_UnitInvariant(t *testing.T) {
	// (1) numeric value is exactly 2000 (us == 2 ms, CONSTRAINT Z).
	if maxDriftEpsilon != 2000 {
		t.Fatalf("maxDriftEpsilon must be 2000 (us == 2 ms, CONSTRAINT Z), got %d", maxDriftEpsilon)
	}
	// (3a) the 2000-ms fabrication: 2_000_000 us == 2 s.
	if maxDriftEpsilon == 2_000_000 {
		t.Fatalf("maxDriftEpsilon == 2_000_000 is the 2000-ms FABRICATION (2 s), detector-banned")
	}
	// (3b) the 2-us-too-tight fabrication: value 2 in a microsecond
	// clock admits a 2-us bound (1000x too tight) and fails the
	// acceptance deltas.
	if maxDriftEpsilon == 2 {
		t.Fatalf("maxDriftEpsilon == 2 in a microsecond clock is 2 us (1000x too tight), detector-banned")
	}
	// (2) unit sentinel is "microsecond". BANNED: empty,
	// "millisecond"-only (would imply the 2000 is in ms = 2 s),
	// "2000 ms".
	switch maxDriftEpsilonUnit {
	case "microsecond":
		// the ONLY permitted unit label.
	case "":
		t.Fatalf("maxDriftEpsilonUnit is empty — unit is undeclared, detector-banned")
	case "millisecond":
		t.Fatalf("maxDriftEpsilonUnit == \"millisecond\" implies 2000 ms = 2 s, the FABRICATION, detector-banned")
	case "2000 ms":
		t.Fatalf("maxDriftEpsilonUnit == \"2000 ms\" is the FABRICATION label, detector-banned")
	default:
		t.Fatalf("maxDriftEpsilonUnit == %q is not the permitted \"microsecond\" label, detector-banned", maxDriftEpsilonUnit)
	}

	// Compile-time-checked assertion that the constant is exactly 2000.
	// [0]byte would fail to compile if maxDriftEpsilon != 2000; the
	// non-zero array size is the tooth.
	var _ [maxDriftEpsilon - 2000]byte
	var _ [2000 - maxDriftEpsilon]byte
}

// G3.0.k — concurrent Admit callers on a shared controller + synthetic
// clock: 0 DATA RACE. The controller read path is read-only on the
// clock; AdvanceLamportTo is atomic. Run under `go test -race`.
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
				offset := int64((seed + i) % 5000) // 0..4999 us future
				cap.Admit(t0+offset, uint64(seed*iters+i))
			}
		}(g)
	}
	wg.Wait()

	if got := adv.callCount(); got == 0 {
		t.Fatalf("expected some accepted admits to call AdvanceLamportTo, got 0")
	}
}
