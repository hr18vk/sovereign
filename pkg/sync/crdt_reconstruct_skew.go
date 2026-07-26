// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

// The Lamport skew bound (Byzantine far-future-stamp closure at the wire).
//
// Threat model: a malicious peer stamps a far-future DotCounter to brick the
// receiver's Lamport clock via Join's AdvanceLamportTo (crdt.go:
// AdvanceLamportTo fast-forwards e.lamport to max(local, remote) AND bumps the
// on-disk persistence limit). After the brick, the receiver can no longer mint
// a higher dot via NextDot (it Adds-from the poisoned value and returns
// poisoned counters), and the poisoned value SURVIVES a restart. This is the
// far-future-stamp attack — the direct stamp that bricks a receiver in one
// frame.
//
// ReconstructEntry made wire-integrity a PURE-FUNCTION concern of the wire
// frame (digest + attribution, no engine handle). The skew bound is the FIRST
// integrity axis that depends on RECEIVER STATE (the engine's current lamport
// + the observed inbound rate), which forces a new seam shape: a WRAPPING
// seam, ReconstructEntryWithSkewBound, that composes the stateless digest +
// attribution checks (still byte-identical) with a receiver-state-sourced
// bound. The wrapper is still a pure function — the receiver state enters ONLY
// via the LamportSnapshot the caller builds atomically; the wrapper never
// lazily re-reads e.lamport. That contract is the concurrency guard: if the
// wrapper re-read mid-call while a concurrent InsertLocal moves the clock, the
// bound would be incoherent.
//
// THE EIGHT DESIGN CONSTRAINTS:
//
// 1. Byzantine scope honest — closes the far-future-stamp attack fully and
// persistent disk-state poisoning by construction (the poisoned value never
// reaches AdvanceLamportTo so it never persists), and slows
// incremental-ratcheting / Sybil-burst attacks. NO "Byzantine-safe" overclaim.
// 2. Bound shape = receiver.Lamport + ceil(receiver.ObservedInboundRate *
// receiver.HorizonSeconds) + receiver.AbsoluteSlack. NOT a magic constant;
// computed from the receiver's snapshot.
// 3. WRAPPING seam. ReconstructEntry(ev) is byte-identical; the wrapper calls
// it first (digest + attribution checks unchanged), then computes the bound
// and rejects on DotCounter > bound.
// 4. Skew runs AFTER digest + attribution. A triply-corrupt frame reports the
// FIRST detected violation (digest or attribution, per the base seam's
// attribution-before-digest ordering); skew only on a frame clean on the first
// two.
// 5. Diagnostic context preserved: 6 additive WireIntegrityError fields, no
// repurpose.
// 6. Join signature unchanged. AdvanceLamportTo advance semantics unchanged —
// only an EWMA-update line is added (in crdt.go).
// 7. Batch path inherits the check via the wrapper, same atomic snapshot per
// batch (taken ONCE before the loop).
// 8. The atomic snapshot is the CALLER's responsibility — the wrapper never
// reads engine state directly.
//
// The bound-vs-existing-fixture collision is resolved here by config override,
// NOT silent widening: the production defaults remain AbsoluteSlack=1000 /
// HorizonSeconds=60.0 (so the far-future-stamp attack stays closed on the real
// wire), and the engine exposes SetLamportAbsoluteSlack /
// SetLamportHorizonSeconds (matching the existing SetDataDir setter
// convention) so the happy-path wire tests — which mint unrealistically-large
// eyecatch sentinels (0x7f7f7f7f7f7f7f7f etc.) chosen for zero-fill detection,
// NOT as plausible DotCounters — admit their own sentinels WITHOUT widening
// the production bound that closes the attack.
package sync

import (
	"math"

	capnp_schema "github.com/hr18vk/sovereign/api/capnp/api/capnp"
)

// LamportSnapshot is the atomic, receiver-state-sourced input to the skew-bound
// wrapper. The caller (ApplyCRDTDeltaEvent / ApplyCRDTDeltaBatch) builds this
// ONCE, atomically, and passes it to ReconstructEntryWithSkewBound; the wrapper
// is a pure function of (ev, snapshot) and NEVER lazily re-reads e.lamport or
// e.observedInboundRate. This is the concurrency contract that makes the bound
// coherent against concurrent InsertLocal on the same receiver — the first
// receiver-state-dependent integrity check's load-bearing property.
//
// Fields are READ-ONLY inside the seam: the wrapper reads but never mutates
// them. LamportSnapshots are passed by value (they are ~40 bytes) so the caller
// cannot observe wrapper-internal mutation.
type LamportSnapshot struct {
	// Lamport is the receiver's e.lamport at snapshot time — the floor of the
	// bound. Read once, atomically (e.lamportCounter.Load()).
	Lamport uint64
	// ObservedInboundRate is the EWMA of inbound DotCounter advancement the
	// engine maintains (e.observedInboundRate), updated inside AdvanceLamportTo.
	// The rate-envelope term grows the bound with honest peer pace and is
	// attacker-influenceable (a known limitation — incremental-ratcheting).
	ObservedInboundRate float64
	// HorizonSeconds is the policy knob sizing the rate-envelope window
	// (default 60.0; generous to fast honest peers, correspondingly slow
	// against ratcheting attackers). Sourced from the engine's config field
	// (e.lamportSkewHorizonSeconds).
	HorizonSeconds float64
	// AbsoluteSlack is the policy knob floor absorbing reordering/restart skew
	// below the rate envelope (default 1000). Sourced from the engine's config
	// field (e.lamportSkewAbsoluteSlack). Raising it widens the bound; the
	// production default stays small so the far-future-stamp attack stays
	// closed.
	AbsoluteSlack uint64
}

// MaxAcceptableDotCounter computes the Lamport skew bound from a snapshot:
//
//	snapshot.Lamport + ceil(snapshot.ObservedInboundRate * snapshot.HorizonSeconds) + snapshot.AbsoluteSlack
//
// Exported so the test guards and a future operator diagnostic can reconstruct
// the bound from a snapshot without duplicating the formula. The math.Ceil is
// over the float64 product; the cast to uint64 uses math.MaxUint64 saturation so
// a misconfigured/huge EWMA cannot underflow to a small bound via the float→uint
// corner (a defensive floor; incremental ratcheting is the attack that would
// eventually drive the envelope large). The two additions saturate at
// math.MaxUint64 so the bound never wraps to a small value via overflow. A bound
// that has saturated to MaxUint64 is a bound that has lost its guards; the
// operator's recourse is to re-tune the EWMA (per-peer) or the horizon/slack
// knobs — not silent clamp inside the seam.
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

// ReconstructEntryWithSkewBound is the wrapping seam. It is the
// caller-routed entry point for inbound CRDTDeltaEvent frames: every live
// transport path (ApplyCRDTDeltaEvent single-event, ApplyCRDTDeltaBatch
// per-element) routes through THIS wrapper, NOT through ReconstructEntry
// directly. The wrapper:
//
// 1. Calls ReconstructEntry(ev) FIRST. The digest check and the
// dot/origin attribution check run byte-identical to the base seam — every
// existing guard survives unchanged. On error from ReconstructEntry the
// wrapper returns that error UNCHANGED (digest or attribution message
// preserved; no skew context is added because the bound is irrelevant to a
// frame that already failed those checks).
//
// 2. ONLY on success of ReconstructEntry does the wrapper compute the bound
// from the snapshot (NOT from the wire frame, NOT from a hardcoded
// constant) and compare the reconstructed entry's DotCounter to it. A
// DotCounter exceeding the bound returns *WireIntegrityError{Kind:
// WireIntegrityLamportSkewPoisoning} carrying ALL six diagnostic
// fields (InboundDotCounter / ReceiverLamport / ComputedBound /
// ObservedInboundRate / HorizonSeconds / AbsoluteSlack) — the seam's
// diagnostic payoff on the skew axis.
//
// 3. On success: returns rec, nil. The caller then calls Join with rec.Entry;
// Join's signature is unchanged and the only inbound frames that reach Join
// are clean on ALL three wire-contract axes (digest + attribution + skew).
//
// CONTRACT (ordering + atomic snapshot):
//
// - The skew check runs AFTER ReconstructEntry's digest + attribution checks.
// A triply-corrupt frame (digest mismatch + attribution mismatch + skew poison
// on one frame) reports the FIRST detected violation (digest or attribution —
// the existing code reads DotNodeID and runs the attribution check before the
// SHA-256 cross-validation, so attribution fires first on a
// doubly/multiply-corrupt frame). The skew check does NOT run on a frame that
// already failed an earlier axis. Mutation C (re-order the skew check BEFORE
// ReconstructEntry) MUST make the triply-corrupt Case 4 fail red — the
// ordering is a guard, not a stylistic choice.
//
// - The snapshot is READ-ONLY inside this function. The wrapper does not and
// must not lazily re-read e.lamport or e.observedInboundRate; the snapshot
// was built atomically by the caller and is the receiver's coherent view
// of its own clock at the moment of the apply. The concurrency guard (Case
// 5) proves a violating wrapper that re-reads mid-call would let the
// bound's ReceiverLamport field drift from the caller's snapshot — the
// guard asserts ReceiverLamport == the snapshot the caller passed.
//
// Join is NOT called here — the wrapper is structurally separated from the
// merge concern, exactly as ReconstructEntry is, extended to the wrapping form
// for the only axis that needs receiver state.
func ReconstructEntryWithSkewBound(ev capnp_schema.CRDTDeltaEvent, snapshot LamportSnapshot) (ReconstructedEntry, error) {
	// ── ReconstructEntry FIRST — digest + attribution checks byte-identical ──
	// to the base seam. The wrapper composes (does not duplicate) the base
	// seam: a future change to ReconstructEntry flows here for free, and the
	// base guards stay byte-identical because ReconstructEntry's signature and
	// behavior are unchanged. The value-return signature flows through
	// transparently: rec is a stack value here, its fields read by value below
	// — no &rec, no pointer-specific ops (ADR-0014).
	rec, err := ReconstructEntry(ev)
	if err != nil {
		// digest-mismatch / attribution-mismatch / field-unread — return
		// UNCHANGED. The ordering contract: the FIRST detected violation is
		// the one the caller sees; no skew context is synthesized onto a frame
		// that already failed an earlier axis.
		return ReconstructedEntry{}, err
	}

	// ── Skew bound check (only on a frame clean on digest + attribution) ──
	// The bound is computed from the caller's atomic snapshot, NOT re-read off
	// the engine. Reject when the inbound DotCounter STRICTLY exceeds the
	// bound; a frame exactly AT the bound is accepted (the rate envelope's
	// ceiling is "this pace is still plausible for the observed rate within
	// the horizon" — exact-equality frames are the boundary case the envelope
	// was sized to admit).
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
