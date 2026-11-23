// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// Package sync bounds inbound DotCounters relative to receiver state in this
// file. Without a bound, a far-future counter passed to Join would advance the
// receiver's Lamport clock and persistence limit, and NextDot would continue
// from that value after a restart.
//
// ReconstructEntryWithSkewBound first applies the stateless digest and
// attribution checks, then compares DotCounter with a bound derived from one
// atomic LamportSnapshot. Rejected values never reach AdvanceLamportTo.
// Incremental counter ratcheting and bursts from multiple identities are not
// prevented by this check.
//
// The default absolute slack is 1000 and the rate horizon is 60 seconds.
// SetLamportAbsoluteSlack and SetLamportHorizonSeconds adjust those limits;
// increasing either accepts a wider range of inbound counters.
package sync

import (
	"math"

	capnp_schema "github.com/hr18vk/sovereign/api/capnp/api/capnp"
)

// LamportSnapshot is a coherent copy of the receiver state used by the skew
// check. ApplyCRDTDeltaEvent and ApplyCRDTDeltaBatch take one snapshot for each
// event or batch. ReconstructEntryWithSkewBound reads only this value, never
// live engine state, so concurrent InsertLocal calls cannot mix values from
// different clock states within one bound calculation.
type LamportSnapshot struct {
	// Lamport is the receiver's Lamport clock at snapshot time and the floor of
	// the bound. It is loaded atomically from e.lamportCounter.
	Lamport uint64
	// ObservedInboundRate is the EWMA of inbound DotCounter advancement updated
	// by AdvanceLamportTo. It raises the bound for faster peers, but a peer can
	// also influence it through accepted counters.
	ObservedInboundRate float64
	// HorizonSeconds sizes the rate-envelope window. Its default is 60 seconds;
	// larger values admit faster counter growth and weaken ratcheting resistance.
	HorizonSeconds float64
	// AbsoluteSlack absorbs reordering and restart skew below the rate envelope.
	// Its default is 1000. Raising it widens the accepted range.
	AbsoluteSlack uint64
}

// MaxAcceptableDotCounter returns snapshot.Lamport plus AbsoluteSlack and
// ceil(ObservedInboundRate * HorizonSeconds). Non-positive rates or horizons
// contribute no rate envelope. The conversion and both additions saturate at
// math.MaxUint64 rather than wrapping to a small bound. A saturated bound no
// longer rejects far-future counters, so the rate, horizon, and slack settings
// must remain within useful ranges.
func MaxAcceptableDotCounter(snapshot LamportSnapshot) uint64 {
	rateEnvelope := 0.0
	if snapshot.ObservedInboundRate > 0 && snapshot.HorizonSeconds > 0 {
		rateEnvelope = math.Ceil(snapshot.ObservedInboundRate * snapshot.HorizonSeconds)
	}
	var envelope uint64
	if rateEnvelope >= float64(math.MaxUint64) {
		envelope = math.MaxUint64
	} else if rateEnvelope > 0 {
		envelope = uint64(rateEnvelope)
	}
	bound := snapshot.Lamport
	if envelope > math.MaxUint64-bound {
		return math.MaxUint64
	}
	bound += envelope
	if snapshot.AbsoluteSlack > math.MaxUint64-bound {
		return math.MaxUint64
	}
	bound += snapshot.AbsoluteSlack
	return bound
}

// ReconstructEntryWithSkewBound validates an inbound CRDTDeltaEvent against
// the wire contract and the receiver's Lamport skew bound. ApplyCRDTDeltaEvent
// and ApplyCRDTDeltaBatch call it before Join.
//
// ReconstructEntry runs first. Its field, attribution, and digest errors are
// returned unchanged, with attribution taking precedence over a digest mismatch.
// Only a valid reconstructed entry is compared with the snapshot-derived bound.
// A counter above the bound returns WireIntegrityLamportSkewPoisoning with the
// received counter, receiver Lamport value, computed bound, rate, horizon, and
// slack. A counter equal to the bound is accepted.
//
// The function does not read live engine state or call Join. The caller owns
// both the atomic snapshot and the subsequent merge.
func ReconstructEntryWithSkewBound(ev capnp_schema.CRDTDeltaEvent, snapshot LamportSnapshot) (ReconstructedEntry, error) {
	// Reuse the field, attribution, and digest checks. The value result needs
	// no pointer allocation here (ADR-0014 §2).
	rec, err := ReconstructEntry(ev)
	if err != nil {
		// Preserve field, attribution, and digest errors without adding skew
		// context that was never evaluated.
		return ReconstructedEntry{}, err
	}

	// Use only the caller's snapshot. The upper bound is inclusive.
	bound := MaxAcceptableDotCounter(snapshot)
	if rec.Entry.DotCounter > bound {
		return ReconstructedEntry{}, &WireIntegrityError{
			EntityID:            rec.EntityID,
			OriginNodeID:        rec.Entry.OriginNodeID,
			DotNodeID:           rec.Entry.DotNodeID,
			InboundDotCounter:   rec.Entry.DotCounter,
			ReceiverLamport:     snapshot.Lamport,
			ComputedBound:       bound,
			ObservedInboundRate: snapshot.ObservedInboundRate,
			HorizonSeconds:      snapshot.HorizonSeconds,
			AbsoluteSlack:       snapshot.AbsoluteSlack,
			Kind:                WireIntegrityLamportSkewPoisoning,
		}
	}

	return rec, nil
}
