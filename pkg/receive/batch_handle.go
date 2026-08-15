// Package receive — batch_handle.go is the RECEIVE-side batch path (the Day-5
// arithmetic unlock). It is the batched sibling of HandleFrame (receiver.go:350):
// where HandleFrame parses a RelayEnvelope, runs the cheap gates, verifies ONE
// Ed25519 over ONE inner wire, and ApplyCRDTDeltaEvent-Joins one delta,
// HandleBatchFrame parses a BatchEnvelope, runs the cheap RATE gate ONCE per
// batch, verifies ONE Ed25519 over the marshaled CRDTDeltaBatch wire, and
// ApplyCRDTDeltaBatch-Joins ALL N deltas in one decode + one Join.
//
// THE AMORTIZATION (load-bearing): the ONE Ed25519 verify (60.19us at 32c)
// now covers N deltas — 60.19/N us/delta. The cheap gates run ONCE per batch
// (not N times): the rate gate decrements the per-origin budget ONCE per batch,
// NOT once per delta (the honest amortization of the rate gate, ADR-0010 §2).
//
// THE CLOCK-GATE HONESTY (encode it, do NOT hide it): the per-frame path's
// clock gate (r.cap.Admit on the relay hop's wall timestamp) is RELAY-hop-
// driven. A 0-hop self-originated batch has NO hop walls — so the receiver's
// batch-level cheap gate is RATE ONLY. The per-event clock/depth gates are
// enforced by ApplyCRDTDeltaBatch's ReconstructEntryWithSkewBound-per-element
// (the FROZEN engine path, crdt_apply_batch.go:206 — it checks per-element
// Lamport skew against the once-built snapshot), NOT re-run in the receiver.
// State this honestly: the receiver does NOT re-implement the per-event clock
// gate; it delegates to the FROZEN engine's reconstruct path, which already
// enforces it per element. A batch whose element exceeds the Lamport skew bound
// is rejected by ApplyCRDTDeltaBatch with a *WireIntegrityError (S1a atomic-
// reject: zero joined).
//
// THE S1a ATOMIC-REJECT: on the FIRST *WireIntegrityError from
// ApplyCRDTDeltaBatch (a tampered digest, a dot/origin mismatch, or a Lamport
// skew poisoning on ANY element), the receiver returns DropVerify and ZERO
// deltas are joined (the FROZEN engine's reconstruct-all-then-join-once
// guarantee, crdt_apply_batch.go:149-227). A partial batch is a batch-level
// failure, never a partial apply.
package receive

import (
	"github.com/hr18vk/supremum/pkg/attribution"
)

// BatchAcceptCount returns the number of per-delta Accept increments a
// HandleBatchFrame Accept verdict should record against the per-delta verdict
// counter (sovereign_ingest_verdicts_total). It parses the BatchEnvelope header
// (O(1), no capnp decode) and returns env.BatchCount(); on a malformed header
// it returns 0 (the caller records nothing — the batch was dropped before
// apply). It is the seam the dispatch wrapper (serveConn/readLoop) calls to
// honor the "verdict counter += N on Accept" choice (ADR-0010 §2): the counter
// is PER-DELTA, so a batch of N accepted deltas adds N to the Accept label,
// NOT +1.
//
// This is a SEPARATE header parse from HandleBatchFrame (which parses the
// header inside its own gate stack). The double-parse is O(1) (two header
// reads, no capnp decode) and is the honest cost of keeping the verdict-counter
// increment at the CALLER (the dispatch wrapper owns the Recorder; the Receiver
// does not import pkg/metrics — the same seam discipline as the per-frame path,
// where the caller records RecordIngest and the Receiver returns a Verdict).
func BatchAcceptCount(batchFrameBytes []byte) int {
	env, err := attribution.UnmarshalBatchEnvelope(batchFrameBytes)
	if err != nil {
		return 0
	}
	return int(env.BatchCount())
}

// HybridAcceptCount is the hybrid-frame sibling of BatchAcceptCount: it returns
// the number of per-delta Accept increments a HandleHybridFrame Accept verdict
// should record against sovereign_ingest_verdicts_total. It parses the
// HybridEnvelope header (O(1), no capnp decode — the SAME header parse mold
// BatchAcceptCount uses) and returns env.BatchCount(); on a malformed header it
// returns 0 (the caller records nothing — the batch was dropped before apply).
//
// WHY a SEPARATE FUNCTION (not BatchAcceptCount): the hybrid frame carries the
// WireHybridPQMagic discriminator (NOT the WireV1Magic BatchEnvelope checks), so
// BatchAcceptCount — which calls attribution.UnmarshalBatchEnvelope (the
// WireV1Magic parser) — returns 0 on a hybrid frame (the magic mismatch fails
// the unmarshal). Reusing BatchAcceptCount for the hybrid arm would silently
// record 0 deltas per accepted hybrid batch, undercounting hybrid ingest by Nx
// on the per-delta verdict counter (the throughput signal operators monitor).
// HybridAcceptCount calls attribution.UnmarshalHybridFrame (the WireHybridPQMagic
// parser) + returns env.BatchCount() — the SAME per-delta accounting the v1 batch
// path uses, on the hybrid frame shape. This closes the compound defect the
// /verify audit surfaced: the accept-side dispatch had no IsHybridFrame arm (a
// hybrid frame fell through to HandleFrame → DropMalformed) AND even with the arm
// added, BatchAcceptCount would have undercounted — BOTH halves are fixed here.
func HybridAcceptCount(hybridFrameBytes []byte) int {
	env, err := attribution.UnmarshalHybridFrame(hybridFrameBytes)
	if err != nil {
		return 0
	}
	return int(env.BatchCount())
}
