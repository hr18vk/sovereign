// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// Package clock implements physical-clock admission for inbound CRDT frames.
// IngressHLCScalarCap rejects timestamps too far ahead of the receiver before
// signature verification, so rejected frames do not incur that cost.
//
// The receive path applies its gates in this order:
//
//	[wire] -> IngressHLCScalarCap.Admit
//	       -> VerifyCRDTFrame
//	       -> DeltaCRDTEngine.Join
//
// LogicalAdvancer lets *sync.DeltaCRDTEngine supply logical-clock updates
// without an import dependency between this package and pkg/sync.
package clock

// maxDriftEpsilon is the maximum accepted future offset for the HLC physical
// clock: 2000 microseconds, or 2 milliseconds. Interpreting the same value as
// milliseconds would widen the bound to 2 seconds.
// TestMaxDriftEpsilon_UnitInvariant checks both the value and its unit label.
const maxDriftEpsilon int64 = 2000 // 2000 microseconds (2 ms)

// maxDriftEpsilonUnit records the time unit used by maxDriftEpsilon.
// TestMaxDriftEpsilon_UnitInvariant requires the exact "microsecond" label so
// the numeric bound cannot silently acquire a different unit.
const maxDriftEpsilonUnit = "microsecond"

// LogicalAdvancer accepts Lamport-clock updates. *sync.DeltaCRDTEngine
// implements it with AdvanceLamportTo. That method uses compare-and-swap to
// install only counters greater than the current value, so callers can forward
// a counter without reading the engine's private state.
type LogicalAdvancer interface {
	AdvanceLamportTo(remoteCounter uint64)
}

// WallClock reads the local physical wall time. SystemClock uses the
// operating system clock; SyntheticClock gives tests fixed or explicitly
// advanced values.
type WallClock interface {
	// PhysicalNowUSec returns the local physical wall time in microseconds
	// since the Unix epoch. Admit uses the same unit for its drift bound.
	PhysicalNowUSec() int64
}

// IngressHLCScalarCap applies the HLC physical-time bound to inbound frames.
// The controller holds no mutable state. Concurrent use is safe when the
// WallClock and LogicalAdvancer implementations support concurrent calls;
// SystemClock, SyntheticClock, and *sync.DeltaCRDTEngine do so.
type IngressHLCScalarCap struct {
	clock  WallClock
	engine LogicalAdvancer
}

// NewIngressHLCScalarCap binds a wall clock and a logical advancer. The
// controller holds no mutable state of its own.
func NewIngressHLCScalarCap(clock WallClock, engine LogicalAdvancer) *IngressHLCScalarCap {
	return &IngressHLCScalarCap{clock: clock, engine: engine}
}

// Admit reports whether a frame's physical timestamp is no more than
// maxDriftEpsilon ahead of the local clock. incomingPhysicalUSec is measured
// in microseconds since the Unix epoch. The rejection condition is:
//
//	if incomingPhysicalUSec-localPhysicalUSec > maxDriftEpsilon {
//		return false
//	}
//
// An offset of 1500 microseconds is accepted; an offset of 3000 is rejected.
// A timestamp behind the local clock is also accepted as a normal late frame.
//
// Admit performs no logical-clock update. Verification and application must
// finish before the caller advances Lamport state for the frame.
func (c *IngressHLCScalarCap) Admit(incomingPhysicalUSec int64) bool {
	localPhysicalUSec := c.clock.PhysicalNowUSec()
	if incomingPhysicalUSec-localPhysicalUSec > maxDriftEpsilon {
		return false
	}
	return true
}

// Advance forwards incomingLogical to the engine's AdvanceLamportTo. The
// engine ignores values that do not exceed its current counter.
//
// Normal receipt processing advances the clock through Join as entries are
// applied. Advance is available for explicit post-apply catch-up. A caller
// must not advance an incoming counter before skew validation: validation
// compares that counter with a local-clock snapshot that must not already
// include the incoming value.
func (c *IngressHLCScalarCap) Advance(incomingLogical uint64) {
	c.engine.AdvanceLamportTo(incomingLogical)
}
