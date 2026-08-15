// Package receive — g09e_bench_alloc_regression_test.go is the Day-9.5
// bench-level regression gate that converts the REPORTED 638→538 alloc/op
// measurement (commit 2b42ed9) into a PERSISTENT gate. The unit tooth
// TestG09b (pkg/sync) pins FIX C at the ReconstructEntry granularity
// (2 allocs/op < 4 baseline). This tooth pins FIX A+C at the FULL integrated
// ingest-path granularity: a real signed CRDTDeltaBatch through
// Receiver.HandleBatchFrame → ApplyCRDTDeltaBatch → ReconstructEntryWithSkewBound
// → ReconstructEntry → Join, with the capnp decode + the Seq closure + the
// per-shard CAS — the WHOLE path a production node runs on the peer wire.
//
// A unit tooth cannot catch a subtler regression: a future commit that adds a
// new capnp accessor returning a string copy (re-introducing the
// string(b)/[]byte(string) round-trip Day 9's FIX A removed), or a new
// allocation inside the batch accumulator that the unit-level
// ReconstructEntry(ReconstructedEntry) tooth bypasses, would slip past G09b
// but fail G09e. This is the bench→test conversion: the bench REPORTS; the
// test ENFORCES, so a silent regression fails the gate instead of silently
// inflating the wall [the Day-9 audit verdict identified the bench→test gap;
// this tooth closes it].
//
// The ceiling is calibrated with measured headroom: FIX A+C = 538 allocs/op
// at N=100 (reproduced -cpu=1 and -cpu=4 on 2b42ed9). The gate asserts
// allocs/delta <= 5.8 (580/batch) — a ~8% headroom so allocator jitter does
// not flake the gate, but a revert of FIX C (back to *ReconstructedEntry, the
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
	capnp_schema "github.com/hr18vk/supremum/api/capnp/api/capnp"
	"github.com/hr18vk/supremum/pkg/admission"
	"github.com/hr18vk/supremum/pkg/attribution"
	"github.com/hr18vk/supremum/pkg/clock"
	"github.com/hr18vk/supremum/pkg/identity"
	eng "github.com/hr18vk/supremum/pkg/sync"
)

// g09eBuildBatchWire builds a signed CRDTDeltaBatch of n distinct self-originated
// deltas against rcvOriginNodeID — a self-contained mirror of buildBenchBatchWire
// (batch_bench_test.go:62) that accepts testing.TB so it runs in a *testing.T
// (the bench helper hardcodes *testing.B). The wire is byte-faithful: a real
// origin frame the receiver's Dir resolves (newBenchReceiver registers
// rcvOriginNodeID) and ReconstructEntry accepts (DotNodeID == OriginNodeID, the
// attribution check; PayloadDigest == SHA-256(Payload), the FIX-A SHA catch).
func g09eBuildBatchWire(tb testing.TB, n int, baseDot uint64) []byte {
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
		payload := fmt.Sprintf("g09e-payload-%d", i)
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
		eid := fmt.Sprintf("g09e-entity-%d-%d", i, baseDot)
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

// g09eBuildSignedFrame mints ONE signed BatchEnvelope (the amortization target:
// one Ed25519 over the whole batch wire) and applies it once to warm the
// engine (the timed loop re-Joins idempotently — the CRDT dedupes, so the
// measured op is a no-op apply + a FULL every-op verify, mirroring the bench's
// honest lower-bound construction exactly).
func g09eBuildSignedFrame(t *testing.T, recv *Receiver, originSeed []byte, n int) []byte {
	t.Helper()
	batchWire := g09eBuildBatchWire(t, n, 1)
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
		t.Fatalf("g09e warm: verdict=%s want Accept (reason: %v) — the frame failed the gate (the tooth is invalid)", warm.Verdict, warm.Reason)
	}
	return frame
}

// TestG09e_BenchAllocNoRegression drives the FULL integrated ingest path (the
// same one BenchmarkBatchedVerifyParallel/shared/N=100 measures) and asserts
// the per-delta alloc count does not regress past the FIX A+C headroom. It is
// the bench→test conversion: G09.b pins the unit ReconstructEntry; G09.e pins
// the integrated path (HandleBatchFrame → ApplyCRDTDeltaBatch →
// ReconstructEntry → Join, including the capnp decode + Seq closure +
// per-shard CAS — the allocations that live OUTSIDE the unit tooth's reach).
//
// RED-verified on a revert to *ReconstructedEntry (FIX C undone): the
// integrated per-delta count inflates 5.38 → 6.38, failing the 5.8 ceiling.
// A new string-copy path on the capnp seam (a FIX-A regression) that the unit
// tooth bypasses would also inflate past the headroom.
func TestG09e_BenchAllocNoRegression(t *testing.T) {
	originPub, originPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	originSeed := originPriv.Seed()
	// Build a fresh engine + receiver + Directory (the same construction
	// newBenchReceiver uses in bench_silicon_test.go:91 — origin pub
	// registered so Dir.Lookup resolves it). The bench helper hardcodes
	// *testing.B, so this tooth builds an identical receiver from a *testing.T.
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
	frame := g09eBuildSignedFrame(t, recv, originSeed, N)

	// ~8% headroom over the measured 5.38 allocs/delta (538/batch at N=100 on
	// 2b42ed9 -cpu=1 and -cpu=4). A FIX-C revert to 638 = 6.38/delta fails.
	// testing.AllocsPerRun is deterministic for a fixed call sequence — 5.8 is
	// a real bound, not a probabilistic flake ceiling.
	const allocsPerDeltaCeiling = 5.8

	allocsPerBatch := testing.AllocsPerRun(30, func() {
		v := recv.HandleBatchFrame(frame)
		if v.Verdict != Accept {
			t.Fatalf("G09.e: HandleBatchFrame verdict = %s, want Accept (reason: %v) — a timed frame failed the gate (the tooth is invalid)", v.Verdict, v.Reason)
		}
	})
	allocsPerDelta := allocsPerBatch / float64(N)

	if allocsPerDelta > allocsPerDeltaCeiling {
		t.Fatalf("G09.e FAILED: integrated ingest-path allocs/delta = %.3f (> %.3f ceiling; %.0f/batch at N=%d). "+
			"A Day-9 FIX-C revert (back to *ReconstructedEntry, the 638 baseline = 6.38/delta) OR a NEW string/allocation path "+
			"on the capnp decode → ReconstructEntry → Join seam regressed past the headroom. "+
			"Re-run BenchmarkBatchedVerifyParallel/shared/N=100 to confirm; if the bench still shows ~538 the tooth mis-calibrated (raise the ceiling), "+
			"if the bench shows >580 the regression is REAL — bisect to find the new alloc site.",
			allocsPerDelta, allocsPerDeltaCeiling, allocsPerBatch, N)
	}
	t.Logf("G09.e PASS: integrated ingest path (HandleBatchFrame → ApplyCRDTDeltaBatch → ReconstructEntry → Join) = %.3f allocs/delta (%.0f/batch at N=%d) <= %.1f ceiling — FIX A+C hold at the integrated granularity (G09.b holds the unit; G09.e holds the path)", allocsPerDelta, allocsPerBatch, N, allocsPerDeltaCeiling)
}
