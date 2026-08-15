// Package clock implements the Byzantine-clock admission gate for the
// planetary-fanout CRDT mesh. IngressHLCScalarCap is the FIRST gate an
// inbound frame crosses — it runs BEFORE the ~71.4 us/op Ed25519
// VerifyCRDTFrame gate (Track 1.1, PROVEN commit 6db6132) so that a
// Byzantine-time burst is dropped in sub-us rather than burning 71.4 us
// of signature verification per frame before the drop.
//
// Architectural ordering invariant (load-bearing, tested):
//
//	[wire] -> IngressHLCScalarCap.Admit(...)   // sub-us clock cap, CHEAP
//	       -> if accepted: VerifyCRDTFrame(...) // 71.4 us/op, EXPENSIVE
//	       -> if verify ok: engine.Join(...)    // CRDT merge
//
// pkg/clock imports pkg/sync (read-only) for the LogicalAdvancer seam;
// pkg/sync does NOT import pkg/clock, so there is no import cycle.
package clock

// maxDriftEpsilon is the HLC physical-bound epsilon, CONSTRAINT Z
// (line-locked line 1 of Final_Sovereign_Architecture_Phase3.md).
// Value 2000 MICROSECONDS == 2 milliseconds. This is the ONLY
// unit-correct form of "2000" permitted by CONSTRAINT Z ("2000
// ONLY if the input clock is in microseconds"). The label
// "2000 ms" (= 2 seconds) is a 1000x fabrication that admits 1000x
// the clock-error bound as non-Byzantine and voids the HLC defense;
// it is detector-banned by TestMaxDriftEpsilon_UnitInvariant.
const maxDriftEpsilon int64 = 2000 // microseconds == 2 ms (CONSTRAINT Z)

// maxDriftEpsilonUnit is the unit sentinel read by the static tooth
// (TestMaxDriftEpsilon_UnitInvariant). It MUST stay "microsecond".
// BANNED values: empty, "millisecond"-only (would imply the 2000 is
// in ms = 2 s), "2000 ms".
const maxDriftEpsilonUnit = "microsecond"

// LogicalAdvancer is the wrapper-safe seam into the FROZEN CRDT engine.
// *pkg/sync.DeltaCRDTEngine satisfies this via its existing exported
// method AdvanceLamportTo (crdt.go:1639). The controller does NOT read
// the private lamportCounter field (crdt.go:133) — that would re-open
// FROZEN crdt.go. engine.AdvanceLamportTo already enforces
// max(local, remote) internally (crdt.go:1641-1643: current := Load();
// if current >= remoteCounter { break }; CAS(current, remoteCounter)),
// so the controller feeds incomingLogical unconditionally on accept and
// the engine's own monotone CAS handles the scalar advance.
type LogicalAdvancer interface {
	AdvanceLamportTo(remoteCounter uint64)
}

// WallClock reads the local physical wall time. Production wiring
// (Amazon Time Sync / chrony) lands in Subphase 9.0, NOT this subphase.
// 3.0 ships SyntheticClock for tests and a SystemClock stub
// (time.Now().UnixMicro()); 9.0 replaces SystemClock with the chrony
// reader. Do NOT fabricate a chrony reader this subphase — it is 9.0's
// gate.
type WallClock interface {
	// PhysicalNowUSec returns the local physical wall time in
	// MICROSECONDS since the Unix epoch. The microsecond domain is
	// load-bearing: CONSTRAINT Z resolves the rejection boolean as
	// incomingPhysicalUSec - localPhysicalUSec > maxDriftEpsilon (us).
	PhysicalNowUSec() int64
}

// IngressHLCScalarCap is the Byzantine-clock admission controller. It is
// safe for concurrent use: the Admit read path is read-only on the
// clock, and the engine AdvanceLamportTo is already race-proven in
// Phase 2.5c.2 (atomic CAS, no lock).
type IngressHLCScalarCap struct {
	clock  WallClock
	engine LogicalAdvancer
}

// NewIngressHLCScalarCap binds a wall clock and a logical advancer. The
// controller holds no mutable state of its own.
func NewIngressHLCScalarCap(clock WallClock, engine LogicalAdvancer) *IngressHLCScalarCap {
	return &IngressHLCScalarCap{clock: clock, engine: engine}
}

// Admit applies the HLC physical-bound cap (CONSTRAINT Z) to an inbound
// frame BEFORE the expensive Verify gate. incomingPhysicalUSec is the
// frame's physical wall time in MICROSECONDS; incomingLogical is its
// Lamport/Dot counter.
//
// Rejection boolean (microsecond domain, CONSTRAINT Z):
//
//	if incomingPhysicalUSec - localPhysicalUSec > maxDriftEpsilon {
//	    return false // Byzantine future frame, drop BEFORE Verify
//	}
//
// Verification against the roadmap acceptance deltas:
//
//	1500 us-future -> 1500 > 2000 is FALSE -> ACCEPT (correct)
//	3000 us-future -> 3000 > 2000 is TRUE  -> REJECT (correct)
//
// On accept, the controller feeds incomingLogical to
// engine.AdvanceLamportTo unconditionally; the engine's internal
// max(local, remote) guard (crdt.go:1642) no-ops a stale logical. A
// past-physical frame (incomingPhysicalUSec < local) is a normal late
// frame, not Byzantine, and is accepted.
func (c *IngressHLCScalarCap) Admit(incomingPhysicalUSec int64, incomingLogical uint64) bool {
	localPhysicalUSec := c.clock.PhysicalNowUSec()
	if incomingPhysicalUSec-localPhysicalUSec > maxDriftEpsilon {
		return false
	}
	c.engine.AdvanceLamportTo(incomingLogical)
	return true
}
