// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

import (
	"fmt"
	"hash/maphash"
	"sync/atomic"
	"testing"
	"time"

	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// TestIBLTVersionLockstep checks the mesh's scheme mirror and response gates.
// The engine scheme is process-global, so separate pkg/sync tests cover wire
// rejection in both directions: a v1 process rejects 'IBL2' and a v2 process
// rejects 'IBL1'. This test instead varies the mesh mirrors within one process.
//
// With gA enabled and gB disabled, gA sends 0x11 requests and gB sends 0x01
// requests. Neither may build an O(S) response for the other's role: digest.go
// rejects 0x01 at an enabled mirror, and the role and enabled-only branches
// reject 0x11 at a disabled mirror. The pair must still converge without a
// wrong diff. Cross-process mixed schemes instead lose the routed request at
// the parse layer and use the fallback; that behavior belongs to the pkg/sync
// tests rather than this in-process harness.
//
// With both mirrors enabled, the test drives the complete v2 exchange over
// loopback TLS: a 0x11 request, a response at the requested size, subtraction,
// and a clean peel for 25 differences per direction. At 1,024 buckets the
// tables have ample capacity (1024 >> 1.295*25), so convergence must require no
// peel oversends or fallbacks. Removing either response gate provides a
// negative control by making digestRespondSent advance.
func TestIBLTVersionLockstep(t *testing.T) {
	t.Cleanup(func() { eng.SetIBLTSchemeV2(false) })

	// First exercise a homogeneous v2 pair.
	eng.SetIBLTSchemeV2(true)
	hB := newStratifiedHarness(t, true)
	hB.gA.SetIBLTV2(true)
	hB.gB.SetIBLTV2(true)
	hB.gA.SetDigestWaitTimeout(2 * time.Second)
	hB.gB.SetDigestWaitTimeout(2 * time.Second)
	hB.insertEvents(t, 50)
	roundsB, convergedB, raB, rbB := hB.sweepUntilConverged(t, 20, 20*time.Millisecond)
	if !convergedB {
		hB.close()
		t.Fatalf("arm B: the homogeneous v2 pair did not converge in %d rounds (rootA=%x rootB=%x) — the v2 exchange is broken end-to-end", roundsB, raB, rbB)
	}
	if ovs := hB.gA.digestPeelOversends.Load() + hB.gB.digestPeelOversends.Load(); ovs != 0 {
		hB.close()
		t.Fatalf("arm B: the homogeneous v2 pair took %d peel-oversends at D=25/direction — the v2 exchange did not prune; the pair converged only via oversend", ovs)
	}
	if fa, fb := atomic.LoadInt32(&hB.fallbackA), atomic.LoadInt32(&hB.fallbackB); fa != 0 || fb != 0 {
		hB.close()
		t.Fatalf("arm B: fallbacks fired on a healthy homogeneous v2 pair (A=%d B=%d) — the 0x11→peek→response exchange failed before the peel", fa, fb)
	}
	t.Logf("homogeneous v2 cluster converged in %d rounds, zero peel oversends, zero fallbacks — the v2 exchange prunes end-to-end over TLS", roundsB)
	hB.close()

	// Then verify that mixed mirror settings build no responses on either side.
	hA := newStratifiedHarness(t, true)
	hA.gA.SetIBLTV2(true) // armed requester (0x11); gB deliberately unarmed
	hA.gA.SetDigestWaitTimeout(100 * time.Millisecond)
	hA.gB.SetDigestWaitTimeout(100 * time.Millisecond)
	hA.insertEvents(t, 50)
	sentA0 := hA.gA.digestRespondSent.Load()
	sentB0 := hA.gB.digestRespondSent.Load()
	roundsA, convergedA, raA, rbA := hA.sweepUntilConverged(t, 60, 20*time.Millisecond)
	if !convergedA {
		hA.close()
		t.Fatalf("arm A: the mixed pair did not converge in %d rounds (rootA=%x rootB=%x) — convergence was lost (a wrong diff shipped)", roundsA, raA, rbA)
	}
	if got := hA.gB.digestRespondSent.Load(); got != sentB0 {
		hA.close()
		t.Fatalf("arm A: the unarmed mirror built and sent a response (digestRespondSent %d → %d) — a v1 mirror answered a request it must never answer (the 0x11 gate is missing)", sentB0, got)
	}
	if got := hA.gA.digestRespondSent.Load(); got != sentA0 {
		hA.close()
		t.Fatalf("arm A: the armed node built and sent a response to a 0x01 request (digestRespondSent %d → %d) — the !ibltV2 answer gate is missing: an armed node must never burn an O(S) response on a v1 request", sentA0, got)
	}
	t.Logf("mixed mirror pair converged in %d rounds with zero response builds on either side (armed A never answers 0x01, unarmed B never answers 0x11) — the exchange rode the routed request bodies; the fleet-level mixed degradation is the parse-layer lockstep (pkg/sync negative-control arm c)", roundsA)
	hA.close()
}

// TestIBLTSizeAdopt checks digestRequestBuckets, the eight-byte header read
// that lets a responder adopt the requester's bucket count. It accepts a
// 2,048-bucket v2 body, rejects a v1 'IBL1' body even under role 0x11, and
// rejects a truncated body. A frame with a legacy strata-estimator section
// verifies that digestFrameSplit locates the IBLT header after that section.
//
// End-to-end size adoption has two further checks. The pkg/sync independent
// floor test shows 900 differences failing at 1,024 buckets and peeling at
// 2,048. Round two of TestIBLTAdaptiveLadder exercises the mesh path: either a
// response-size or local-build mismatch would produce DiffNil rather than a
// clean 900-key peel. Reading the frame header instead of the split IBLT body,
// or omitting the magic check, makes the corresponding case fail.
func TestIBLTSizeAdopt(t *testing.T) {
	t.Cleanup(func() { eng.SetIBLTSchemeV2(false) })
	seed := maphash.MakeSeed()
	nodeID := [16]byte{0xF3, 0x35}

	// (a) a v2 request with a 2048-bucket body.
	eng.SetIBLTSchemeV2(true)
	v2Table := eng.NewIBLTWithSeed(2048, 4, seed)
	v2Wire, err := eng.MarshalIBLT(v2Table)
	v2Table.Release()
	if err != nil {
		t.Fatalf("(a) MarshalIBLT(v2 2048): %v", err)
	}
	frame := buildDigestFrame(digestRoleRequestV2, nodeID, seed, nil, v2Wire)
	n, ok := digestRequestBuckets(frame)
	if !ok || n != 2048 {
		t.Fatalf("(a) digestRequestBuckets = (%d, %v), want (2048, true) — the peek mis-reads the v2 body", n, ok)
	}

	// (b) role 0x11 but a v1-magic body — the peek must reject on magic.
	eng.SetIBLTSchemeV2(false)
	v1Table := eng.NewIBLTWithSeed(1024, 4, seed)
	v1Wire, err := eng.MarshalIBLT(v1Table)
	v1Table.Release()
	if err != nil {
		t.Fatalf("(b) MarshalIBLT(v1 1024): %v", err)
	}
	if _, ok := digestRequestBuckets(buildDigestFrame(digestRoleRequestV2, nodeID, seed, nil, v1Wire)); ok {
		t.Fatalf("(b) the peek accepted a v1-magic ('IBL1') body under a 0x11 role — the gate verifies the role byte, not the body magic: an adversarial frame would size the responder's build from unverified bytes")
	}

	// (c) truncated body (< 8 bytes).
	if _, ok := digestRequestBuckets(buildDigestFrame(digestRoleRequestV2, nodeID, seed, nil, v1Wire[:5])); ok {
		t.Fatalf("(c) the peek accepted a truncated IBLT body — the length guard is missing")
	}

	// (d) a legacy SE-carrying frame: the SE rides before the IBLT; the peek
	// must split, not assume offset 0.
	eng.SetIBLTSchemeV2(true)
	seBody := []byte{0x01, 0x02, 0x03, 0x04, 0x05} // a nonzero opaque SE (the digestLegacySE shape)
	n, ok = digestRequestBuckets(buildDigestFrame(digestRoleRequestV2, nodeID, seed, seBody, v2Wire))
	if !ok || n != 2048 {
		t.Fatalf("(d) digestRequestBuckets behind a 5-byte SE = (%d, %v), want (2048, true) — digestFrameSplit's offset contract broke: the peek read the SE bytes as the IBLT header", n, ok)
	}
	eng.SetIBLTSchemeV2(false)
	t.Logf("the peek adopts (2048,true) from a v2 body, rejects v1-magic + truncated bodies, and offsets past a legacy SE")
}

// TestIBLTAdaptiveLadder drives the sizing lifecycle with 900 differences,
// above the approximately 790-entry v2 capacity at 1,024 buckets but within the
// capacity at 2,048. It calls generateSweepDelta directly and releases every
// delta without applying it, preserving the difference across rounds instead of
// letting a handler-disabled oversend resynchronize the peer. The harness runs
// no background sweeps, so this test goroutine is the ladder map's only writer
// and the production counters remain valid observations.
//
// The expected trajectory is:
//
//	r1 at 1024: PeelErr increments digestPeelOversends and escalates the peer
//	            to 2048 buckets.
//	r2-r5 at 2048: each peel sends exactly the 900 A-only keys. The fourth
//	            clean peel increments digestLadderDecays and returns to 1024.
//	r6 at 1024: the peel fails again and escalates a second time, demonstrating
//	            the cost of hysteresis near the capacity boundary.
//
// Round two also checks both size adoptions. A 1,024-bucket response to a
// 2,048-bucket request, or a local build that ignores the response size, would
// produce a configuration-mismatch DiffNil rather than a clean 900-key peel.
// Removing ladderEscalate leaves round two too small to peel; removing
// ladderCleanPeel prevents the expected decay.
func TestIBLTAdaptiveLadder(t *testing.T) {
	t.Cleanup(func() { eng.SetIBLTSchemeV2(false) })
	eng.SetIBLTSchemeV2(true)
	h := newStratifiedHarness(t, true)
	defer h.close()
	h.gA.SetIBLTV2(true)
	h.gB.SetIBLTV2(true)
	h.gA.SetDigestWaitTimeout(2 * time.Second)
	h.gB.SetDigestWaitTimeout(2 * time.Second)

	// 900 A-only keys: D=900 > 790 at B=1024; 1.295*900 = 1166 < 2048.
	for i := 0; i < 900; i++ {
		h.gA.InsertLocalEvents(fmt.Sprintf("iblt-ladder-%d", i), fmt.Sprintf("v-%d", i), eng.CRDTEntry{
			SystemTime: int64(1_800_000_000 + i),
			H3Index:    uint64(i),
		})
	}
	time.Sleep(100 * time.Millisecond) // let local inserts settle before reconciliation
	peer := h.identB.NodeID

	// r1 @1024 — the observed premise: the peel fails, the ladder escalates.
	esc0 := h.gA.digestLadderEscalations.Load()
	ovs0 := h.gA.digestPeelOversends.Load()
	d1 := h.gA.generateSweepDelta(h.ctx, peer)
	var pe1 error
	var dn1 bool
	if d1 != nil {
		pe1 = d1.PeelErr()
		dn1 = d1.DiffNil()
		d1.Release()
	}
	if pe1 == nil {
		t.Fatalf("r1: the D=900 exchange at B=1024 did not fail its peel (PeelErr=%v, DiffNil=%v) — the negative control's premise is wrong; D must exceed the v2 ceiling at 1024", pe1, dn1)
	}
	if ovs := h.gA.digestPeelOversends.Load(); ovs != ovs0+1 {
		t.Fatalf("r1: digestPeelOversends %d → %d, want +1 — the peel failure was not counted (the observable the ladder keys on is broken)", ovs0, ovs)
	}
	if esc := h.gA.digestLadderEscalations.Load(); esc != esc0+1 {
		t.Fatalf("r1: the observed PeelErr did not escalate the ladder (escalations %d → %d, want +1) — the ladder hook is not wired to the peel-failure branch", esc0, esc)
	}
	if b := h.gA.digestBucketsFor(peer); b != 2048 {
		t.Fatalf("r1: post-escalation digestBucketsFor=%d, want 2048 (1024 ×2, under the 21845 ceiling)", b)
	}

	// r2-r5 @2048 — clean 900-peels; r5's streak decays the ladder.
	for r := 2; r <= 5; r++ {
		d := h.gA.generateSweepDelta(h.ctx, peer)
		if d == nil {
			t.Fatalf("r%d: generateSweepDelta returned nil at B=2048", r)
		}
		if d.PeelErr() != nil || d.DiffNil() {
			pe, dn := d.PeelErr(), d.DiffNil()
			d.Release()
			t.Fatalf("r%d: the peel at B=2048 still failed (PeelErr=%v DiffNil=%v) — the ×2 escalation did not reach a peelable size (c_4*900=1166 < 2048 must peel)", r, pe, dn)
		}
		if got := d.SendKeyCount(); got != 900 {
			d.Release()
			t.Fatalf("r%d: clean peel shipped %d keys, want exactly the 900 A-only (a wrong-diff peel is the forbidden state)", r, got)
		}
		d.Release()
	}
	if dec := h.gA.digestLadderDecays.Load(); dec != 1 {
		t.Fatalf("the 4-consecutive-clean-streak did not decay the ladder (digestLadderDecays=%d, want 1) — the hysteresis hook is not wired to the clean-peel branch", dec)
	}
	if b := h.gA.digestBucketsFor(peer); b != 1024 {
		t.Fatalf("post-decay digestBucketsFor=%d, want 1024 (2048 ×½, floor at the legacy default)", b)
	}

	// r6 @1024 — the disclosed hysteresis cost: fail + re-escalate.
	escBefore := h.gA.digestLadderEscalations.Load()
	d6 := h.gA.generateSweepDelta(h.ctx, peer)
	if d6 == nil || d6.PeelErr() == nil {
		if d6 != nil {
			d6.Release()
		}
		t.Fatalf("r6: the peel at the decayed 1024 must fail again at D=900 — it did not; the decayed size is somehow peelable (the hysteresis premise is wrong)")
	}
	d6.Release()
	if esc := h.gA.digestLadderEscalations.Load(); esc != escBefore+1 {
		t.Fatalf("r6: the post-decay PeelErr did not re-escalate (escalations %d → %d, want +1)", escBefore, esc)
	}
	t.Logf("r1 fail@1024→escalate, r2-r5 clean 900-peels@2048 (the transitive size-adoption proof), streak-4 decay, r6 re-fail@1024→re-escalate (the disclosed hysteresis cost)")
}

// TestIBLTSweepSuffixObservability checks the sweep line's v2 tokens by exact
// equality and verifies that every disabled combination returns an empty
// suffix. Stratified mode alone must not emit tokens, and v2 without stratified
// mode has no digest exchange to describe. With both enabled, the expected
// snapshot count comes from its process-global getter to avoid a fixed-value
// race with other tests.
//
// The final case enables v2 without stratified mode on a real harness. One
// AntiEntropySweep must set the inert-configuration warning while still
// completing, and a second sweep must leave the CompareAndSwap-controlled flag
// set. Removing either the suffix guard or the warning update makes the relevant
// case fail.
func TestIBLTSweepSuffixObservability(t *testing.T) {
	t.Cleanup(func() { eng.SetIBLTSchemeV2(false) })

	// (a) stratified off + unarmed.
	ga := &Gossiper{}
	if s := ga.iblt2SweepSuffix(); s != "" {
		t.Fatalf("(a) a bare gossiper emitted %q — the off sweep line must stay byte-identical (empty suffix)", s)
	}

	// (b) stratified on + unarmed.
	gb := &Gossiper{}
	gb.SetStratifiedAntiEntropy(true)
	if s := gb.iblt2SweepSuffix(); s != "" {
		t.Fatalf("(b) an unarmed gossiper with stratified on emitted %q — stratified alone must not emit v2 tokens", s)
	}

	// (c) armed + stratified off.
	gc := &Gossiper{}
	gc.SetIBLTV2(true)
	if s := gc.iblt2SweepSuffix(); s != "" {
		t.Fatalf("(c) an armed-but-not-stratified gossiper emitted %q — the suffix is inert without a digest exchange (the orphan-config class)", s)
	}

	// (d) armed + stratified on: the exact format at the ladder floor.
	gd := &Gossiper{}
	gd.SetStratifiedAntiEntropy(true)
	gd.SetIBLTV2(true)
	want := fmt.Sprintf(" iblt2_b=%d/%d iblt2_esc=%d iblt2_dec=%d iblt2_snap=%d",
		eng.IBLTDigestDefaultBuckets, eng.IBLTDigestDefaultBuckets,
		0, 0, eng.DigestSnapshotRestarts())
	if s := gd.iblt2SweepSuffix(); s != want {
		t.Fatalf("(d) armed suffix = %q, want exact format %q; the observability tokens changed", s, want)
	}

	// (e) the orphan warn on a harness (stratified off, mirror armed).
	h := newStratifiedHarness(t, false)
	defer h.close()
	h.gA.SetIBLTV2(true)
	h.gA.AntiEntropySweep(h.ctx)
	if !h.gA.ibltV2OrphanWarn.Load() {
		t.Fatalf("(e) the orphan config (iblt-v2 armed, stratified off) did not flip the warn-once flag — the inert-config disclosure is not wired")
	}
	h.gA.AntiEntropySweep(h.ctx)
	if !h.gA.ibltV2OrphanWarn.Load() {
		t.Fatalf("(e) the second sweep unset the warn flag — impossible under CompareAndSwap(false, true); the once-only property broke")
	}
	t.Logf("all disabled combinations emit an empty suffix; the enabled line has the exact format and the inert-configuration warning stays set")
}
