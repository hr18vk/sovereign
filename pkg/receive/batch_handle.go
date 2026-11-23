// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// Package receive — batch_handle.go is the RECEIVE-side batch path. It is the
// batched sibling of HandleFrame: where HandleFrame parses a RelayEnvelope,
// runs the cheap gates, verifies one Ed25519 signature over one inner wire, and
// ApplyCRDTDeltaEvent joins one delta, HandleBatchFrame parses a BatchEnvelope,
// runs the cheap rate gate once per batch, verifies one Ed25519 signature over
// the marshaled CRDTDeltaBatch wire, and ApplyCRDTDeltaBatch joins all N
// deltas in one decode and one Join.
//
// The amortization (load-bearing): the one Ed25519 verify (60.19 µs at 32c)
// now covers N deltas — 60.19/N µs/delta. The cheap gates run once per batch
// (not N times): the rate gate decrements the per-origin budget once per batch,
// not once per delta (ADR-0010 §2).
//
// The clock gate on the per-frame path (r.cap.Admit on the relay hop's wall
// timestamp) is relay-hop driven. A zero-hop self-originated batch has no hop
// walls, so the receiver's batch-level cheap gate is rate only. The per-event
// clock and depth gates are enforced by ApplyCRDTDeltaBatch's
// ReconstructEntryWithSkewBound per element (the engine batch path checks
// per-element Lamport skew against the once-built snapshot), not re-run in the
// receiver. The receiver does not
// re-implement the per-event clock gate; it delegates to the engine's
// reconstruct path, which already enforces it per element. A batch whose
// element exceeds the Lamport skew bound is held by ApplyCRDTDeltaBatch with a
// *WireIntegrityLamportSkewPoisoning error (the in-window subset still joins).
//
// The batch contract (ADR-0069): a skew-class
// *WireIntegrityLamportSkewPoisoning error holds its element and the loop
// continues (the in-window subset joins, whatever the spike's position).
// Every other *WireIntegrityError (a tampered digest, a dot/origin mismatch,
// a wire-read failure) keeps the whole-batch reject — the first non-skew
// error returns with zero joined (ApplyCRDTDeltaBatch's reject path). An
// integrity-corrupt batch is never partially applied.
package receive
