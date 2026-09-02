// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

// Package receive — bench_alloc_regression_test.go is the
// bench-level regression gate that converts the REPORTED 638→538 alloc/op
// measurement into a PERSISTENT gate. The unit guard
// TestZeroCopyPayloadAllocReduction (pkg/sync) pins the value-return change at the ReconstructEntry granularity
// (2 allocs/op < 4 baseline). This guard pins the alloc-hardening pair at the FULL integrated
// ingest-path granularity: a real signed CRDTDeltaBatch through
// Receiver.HandleBatchFrame → ApplyCRDTDeltaBatch → ReconstructEntryWithSkewBound
// → ReconstructEntry → Join, with the capnp decode + the Seq closure + the
// per-shard CAS — the WHOLE path a production node runs on the peer wire.
//
// A unit guard cannot catch a subtler regression: a future commit that adds a
// new capnp accessor returning a string copy (re-introducing the
// string(b)/[]byte(string) round-trip the zero-copy read removed), or a new
// allocation inside the batch accumulator that the unit-level
// ReconstructEntry(ReconstructedEntry) guard bypasses, would slip past the unit guard
// but fail this integrated-path guard. This is the bench→test conversion: the bench REPORTS; the
// test ENFORCES, so a silent regression fails the gate instead of silently
// inflating the wall [a review identified the bench→test gap;
// this guard closes it].
//
// The ceiling is calibrated with measured headroom: the alloc-hardening pair = 538 allocs/op
// at N=100 (reproduced -cpu=1 and -cpu=4). The gate asserts
// allocs/delta <= 5.8 (580/batch) — a ~8% headroom so allocator jitter does
// not flake the gate, but a revert of the value-return change (back to *ReconstructedEntry, the
// 638 baseline = 6.38/delta) FAILS loudly. testing.AllocsPerRun is
// DETERMINISTIC for a fixed call sequence (the allocator path is a pure
// function of the live code), so 5.8 is a real bound, not a probabilistic one.
package receive

import (
	"crypto/sha256"
	"fmt"
	"testing"

	capnp "capnproto.org/go/capnp/v3"
	"github.com/cloudflare/circl/sign/ed25519"
	capnp_schema "github.com/hr18vk/sovereign/api/capnp/api/capnp"
	"github.com/hr18vk/sovereign/pkg/admission"
	"github.com/hr18vk/sovereign/pkg/attribution"
	"github.com/hr18vk/sovereign/pkg/clock"
	"github.com/hr18vk/sovereign/pkg/identity"
	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// buildAllocBenchBatchWire builds a signed CRDTDeltaBatch of n distinct self-originated
// deltas against rcvOriginNodeID — a self-contained mirror of buildBenchBatchWire
// (batch_bench_test.go:62) that accepts testing.TB so it runs in a *testing.T
// (the bench helper hardcodes *testing.B). The wire is byte-faithful: a real
// origin frame the receiver's Dir resolves (newBenchReceiver registers
// rcvOriginNodeID) and ReconstructEntry accepts (DotNodeID == OriginNodeID, the
// attribution check; PayloadDigest == SHA-256(Payload), the the zero-copy-read SHA catch).
func buildAllocBenchBatchWire(tb testing.TB, n int, baseDot uint64) []byte {
	tb.Helper()
	msg, seg, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		tb.Fatalf("capnp.NewMessage: %v", err)
	}
	batch, err := capnp_schema.NewRootCRDTDeltaBatch(seg)
	if err != nil {
		tb.Fatalf("NewRootCRDTDeltaBatch: %v", err)
	}
	events, err := batch.NewEvents(int32(n))
	if err != nil {
		tb.Fatalf("NewEvents: %v", err)
	}
	for i := 0; i < n; i++ {
		ev := events.At(i)
		ev.SetVersion(eng.CRDTDeltaEventWireVersion)
		payload := fmt.Sprintf("allocbench-payload-%d", i)
		dgst := sha256.Sum256([]byte(payload))
		if err := ev.SetPayloadDigest(dgst[:]); err != nil {
			tb.Fatalf("SetPayloadDigest %d: %v", i, err)
		}
		if err := ev.SetOriginNodeID(rcvOriginNodeID[:]); err != nil {
			tb.Fatalf("SetOriginNodeID %d: %v", i, err)
		}
		if err := ev.SetDotNodeID(rcvOriginNodeID[:]); err != nil {
			tb.Fatalf("SetDotNodeID %d: %v", i, err)
		}
		ev.SetDotCounter(baseDot + uint64(i))
		ev.SetH3Index(0x8928308280fffff)
		ev.SetSystemTime(0x1111111111111111)
		ev.SetValidTimeStart(0x2222222222222222)
		ev.SetValidTimeEnd(0x3333333333333333)
		ev.SetAssertionTime(0x4444444444444444)
		ev.SetDecisionTime(0x5555555555555555)
		eid := fmt.Sprintf("allocbench-entity-%d-%d", i, baseDot)
		if err := ev.SetEntityId(eid); err != nil {
			tb.Fatalf("SetEntityId %d: %v", i, err)
		}
		if err := ev.SetPayload(payload); err != nil {
			tb.Fatalf("SetPayload %d: %v", i, err)
		}
	}
	data, err := msg.Marshal()
	if err != nil {
		tb.Fatalf("msg.Marshal: %v", err)
	}
	return data
}

// buildAllocBenchSignedFrame mints ONE signed BatchEnvelope (the amortization target:
// one Ed25519 over the whole batch wire) and applies it once to warm the
// engine (the timed loop re-Joins idempotently — the CRDT dedupes, so the
// measured op is a no-op apply + a FULL every-op verify, mirroring the bench's
// honest lower-bound construction exactly).
func buildAllocBenchSignedFrame(t *testing.T, recv *Receiver, originSeed []byte, n int) []byte {
	t.Helper()
	batchWire := buildAllocBenchBatchWire(t, n, 1)
	sig, err := identity.SignCRDTFrame(originSeed, batchWire)
	if err != nil {
		t.Fatalf("SignCRDTFrame: %v", err)
	}
	var sigArr [attribution.OriginSigSize]byte
	copy(sigArr[:], sig)
	frame := attribution.MarshalBatchEnvelope(rcvOriginNodeID, sigArr, 1, uint16(n), batchWire)
	// Warm ONCE: a real apply so the timed loop's re-Join is idempotent (the
	// engine bounds to N entries — no arena exhaustion across the AllocsPerRun
	// loop; the verify runs FULLY every op, the same honest lower bound the
	// bench enforces).
	warm := recv.HandleBatchFrame(frame)
	if warm.Verdict != Accept {
		t.Fatalf("warm-up frame: verdict=%s want Accept (reason: %v) — the frame failed the gate (the guard is invalid)", warm.Verdict, warm.Reason)
	}
	return frame
}

// TestBenchAllocNoRegression drives the FULL integrated ingest path (the
// same one BenchmarkBatchedVerifyParallel/shared/N=100 measures) and asserts
// the per-delta alloc count does not regress past the the alloc-hardening pair headroom. It is
// the bench→test conversion: the unit guard pins ReconstructEntry; this guard pins
// the integrated path (HandleBatchFrame → ApplyCRDTDeltaBatch →
// ReconstructEntry → Join, including the capnp decode + Seq closure +
// per-shard CAS — the allocations that live OUTSIDE the unit guard's reach).
//
// RED-verified on a revert to *ReconstructedEntry (the value-return change undone): the
// integrated per-delta count inflates 5.38 → 6.38, failing the 5.8 ceiling.
// A new string-copy path on the capnp seam (a the zero-copy-read regression) that the unit
// guard bypasses would also inflate past the headroom.
func TestBenchAllocNoRegression(t *testing.T) {
	originPub, originPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	originSeed := originPriv.Seed()
	// Build a fresh engine + receiver + Directory (the same construction
	// newBenchReceiver uses in bench_silicon_test.go:91 — origin pub
	// registered so Dir.Lookup resolves it). The bench helper hardcodes
	// *testing.B, so this guard builds an identical receiver from a *testing.T.
	engine, err := eng.NewDeltaCRDTEngine(rcvOriginNodeID, 0, 64*1024*1024)
	if err != nil {
		t.Fatalf("NewDeltaCRDTEngine: %v", err)
	}
	defer engine.Close()
	engine.SetDataDir(t.TempDir())
	dir := identity.NewDirectory()
	if err := dir.Register(rcvOriginNodeID, originPub); err != nil {
		t.Fatalf("Directory.Register: %v", err)
	}
	bucket := admission.NewPeerBucket()
	sc := clock.NewSyntheticClock(1_700_000_000_000_000)
	capGate := clock.NewIngressHLCScalarCap(sc, engine)
	recv := NewReceiver(bucket, capGate, sc, dir, engine, 50_000_000)

	const N = 100
	frame := buildAllocBenchSignedFrame(t, recv, originSeed, N)

	// ~8% headroom over the measured 5.38 allocs/delta (538/batch at N=100 on
	// -cpu=1 and -cpu=4). A the value-return revert to 638 = 6.38/delta fails.
	// testing.AllocsPerRun is deterministic for a fixed call sequence — 5.8 is
	// a real bound, not a probabilistic flake ceiling.
	const allocsPerDeltaCeiling = 5.8

	allocsPerBatch := testing.AllocsPerRun(30, func() {
		v := recv.HandleBatchFrame(frame)
		if v.Verdict != Accept {
			t.Fatalf("integrated-alloc-guard: HandleBatchFrame verdict = %s, want Accept (reason: %v) — a timed frame failed the gate (the guard is invalid)", v.Verdict, v.Reason)
		}
	})
	allocsPerDelta := allocsPerBatch / float64(N)

	if allocsPerDelta > allocsPerDeltaCeiling {
		t.Fatalf("integrated ingest-path allocs/delta = %.3f (> %.3f ceiling; %.0f/batch at N=%d). "+
			"A the value-return revert (back to *ReconstructedEntry, the 638 baseline = 6.38/delta) OR a NEW string/allocation path "+
			"on the capnp decode → ReconstructEntry → Join seam regressed past the headroom. "+
			"Re-run BenchmarkBatchedVerifyParallel/shared/N=100 to confirm; if the bench still shows ~538 the guard mis-calibrated (raise the ceiling), "+
			"if the bench shows >580 the regression is REAL — bisect to find the new alloc site.",
			allocsPerDelta, allocsPerDeltaCeiling, allocsPerBatch, N)
	}
	t.Logf("integrated ingest path (HandleBatchFrame → ApplyCRDTDeltaBatch → ReconstructEntry → Join) = %.3f allocs/delta (%.0f/batch at N=%d) <= %.1f ceiling — the alloc-hardening pair hold at the integrated granularity (the unit guard holds ReconstructEntry; this guard holds the path)", allocsPerDelta, allocsPerBatch, N, allocsPerDeltaCeiling)
}
