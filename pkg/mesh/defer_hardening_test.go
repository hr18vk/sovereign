// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

// These regression tests exercise the defer handler's received-entry budget
// (ADR-0062/0063). Fault-injection controls make each guard fail when its
// protection is removed.
//
//   TestDeferHardenOffBatch checks that disabled mode re-publishes every
//   retained foreign batch, while enabled mode bounds the same shape.
//   TestDeferHardenByteCap places more than 608 foreign elements in one
//   window and checks that the budget both holds and engages.
//   TestDeferHardenCombined charges self entries and retained foreign
//   elements against one budget at batch sizes 100 and 1.
//   TestDeferHardenTrueCount charges the retained decoded count rather than
//   the untrusted header and skips an individually oversized entry without
//   stalling ring rotation.
//
// All figures are from an in-process two-node loopback mesh.
// Both nodes install WireRelayHooks exactly as cmd/sovereign-node/main.go does,
// so foreign entries resolve to retained batches and can be re-published.
//
// foreignEnvelopes and foreignReceived directly observe publishes and decoded
// element counts. Envelope counts cannot substitute for element counts: mixed
// HAMT iteration flushes partial self batches at self/foreign boundaries. In
// one measured shape, 200 self entries produced 165–179 envelopes. On the
// per-frame path, shippedEntries is the combined received count because each
// published frame carries one entry.

import (
	"testing"
	"time"

	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// buildDeferHardeningMesh installs relay retention on both nodes. Without
// WireRelayHooks, RetainForeign and RetainForeignBatch never run, so every
// foreign entry would be a relay miss and the budget assertions would not
// exercise a real publish.
//
// Unbounded Lamport slack models warm peers. A cold receiver starts near zero
// while these fixtures use dot counters above 1,000; batch admission previously
// stalled at 1,630 of 10,000 entries in this shape. The knob keeps the test
// focused on defer budgets rather than cold-peer admission.
func buildDeferHardeningMesh(t *testing.T, opts DeferOpts) *DeferMesh {
	t.Helper()
	m := buildDeferMesh(t, opts)
	m.gA.WireRelayHooks(m.recvA)
	m.gB.WireRelayHooks(m.recvB)
	m.engineA.SetLamportAbsoluteSlack(eng.LamportSkewAbsoluteSlackUnbounded)
	m.engineB.SetLamportAbsoluteSlack(eng.LamportSkewAbsoluteSlackUnbounded)
	return m
}

// deferHardeningPropagate drives synchronized rounds until e holds all n keys,
// then returns the rounds used. Presence uses exact State().Get lookups. B's
// self ship path sends payloadCache entries in batchSize batches, so A joins
// the keys and retains their envelopes as foreign relay state.
func deferHardeningPropagate(t *testing.T, m *DeferMesh, e *eng.DeltaCRDTEngine, fmtName string, first, n, maxRounds int) int {
	t.Helper()
	for r := 1; r <= maxRounds; r++ {
		if got := deferCountPresent(t, e, fmtName, first, n); got == n {
			return r - 1
		}
		deferSweepRound(t, m)
	}
	if got := deferCountPresent(t, e, fmtName, first, n); got != n {
		t.Fatalf("deferHardeningPropagate: %s holds %d/%d keys after %d rounds; B->A propagation did not converge", fmtName, got, n, maxRounds)
	}
	return maxRounds
}

// deferHardeningEscalationRound runs one A-only sweep and returns its state
// and the increase in digestDeferEscalations. Sharing this helper keeps every
// budget assertion tied to the actual armed-round signal.
func deferHardeningEscalationRound(t *testing.T, m *DeferMesh) (st sweepState, escDelta int64) {
	t.Helper()
	before := m.gA.digestDeferEscalations.Load()
	st = deferSweepAOnly(t, m)
	escDelta = m.gA.digestDeferEscalations.Load() - before
	return st, escDelta
}

// TestDeferHardenOffBatch compares disabled and enabled handling on one relay
// shape. B inserts 1,000 keys that reach A in ten 100-element batches, then A
// inserts 200 keys and B stops answering. A's digest waits expire and trigger
// the defer path on every A-only sweep.
//
// Disabled mode must re-publish every retained envelope, touch no defer state,
// and retain the original stratified fallback report. Enabled mode must charge
// self and foreign received entries against one budget. Reintroducing the old
// unconditional 608-element cap in disabled mode produces six envelopes rather
// than ten and fails the test.
func TestDeferHardenOffBatch(t *testing.T) {
	const (
		hardeningForeignKeys    = 1000 // B's keyset, relayed by A in 10 exact-100 batches
		hardeningDivergenceKeys = 200  // A's post-propagation divergence wave (keeps the gate firing)
		hardeningBatchSize      = 100
	)
	// Disabled mode retains the original uncapped batch path.
	m := buildDeferHardeningMesh(t, DeferOpts{deferHandler: false, stratified: true, batchSize: hardeningBatchSize, digestWait: 250 * time.Millisecond})
	deferInsert(t, m.gB, "defer-hardening-relay-%d", 0, hardeningForeignKeys)
	deferHardeningPropagate(t, m, m.engineA, "defer-hardening-relay-%d", 0, hardeningForeignKeys, 20)
	deferInsert(t, m.gA, "defer-hardening-divergence-%d", 0, hardeningDivergenceKeys)
	m.gB.disableDigestRespond.Store(true) // A sweeps alone and its digest request receives no response
	stA := deferSweepAOnly(t, m)
	if stA.shippedEntries != hardeningDivergenceKeys {
		t.Fatalf("disabled off-batch: trigger round published %d self entries, want %d without a cap", stA.shippedEntries, hardeningDivergenceKeys)
	}
	// Compare against the relay cache's forward-map cardinality rather than a
	// fixed envelope count. Propagation produced 10 envelopes without the race
	// detector and 11 with it when B re-shipped a residual partial batch. Every
	// forward entry has a dot in batchReverse and represents a retained foreign
	// entry in A's delta, so the uncapped round must publish all of them.
	fwd, rev := m.gA.relay.batchLenForTest()
	_ = rev
	if stA.foreignEnvelopes != fwd {
		t.Fatalf("disabled off-batch: re-published %d foreign envelopes, want all %d retained envelopes; no cap applies (envelopes=%d entries=%d relay_misses=%d)", stA.foreignEnvelopes, fwd, stA.shippedEnvelopes, stA.shippedEntries, stA.relayMisses)
	}
	if stA.relayMisses != 0 {
		t.Fatalf("disabled off-batch: %d relay misses on a wired retention seam — every foreign entry must resolve to its retained batch (a miss here is a harness premise failure, not the cap)", stA.relayMisses)
	}
	if m.fallbackA.Load() == 0 {
		t.Fatalf("disabled off-batch: fallback reporter stayed silent (defers=%d escalations=%d), want the original report and no defer activity", m.gA.digestDefers.Load(), m.gA.digestDeferEscalations.Load())
	}
	if m.gA.digestDefers.Load() != 0 || m.gA.digestDeferEscalations.Load() != 0 || m.gA.deferState != nil {
		t.Fatalf("disabled off-batch: touched defer state (defers=%d escalations=%d map=%v), want none", m.gA.digestDefers.Load(), m.gA.digestDeferEscalations.Load(), m.gA.deferState != nil)
	}
	t.Logf("disabled off-batch: re-published %d foreign envelopes and %d self entries with %d fallback reports and no defer state", stA.foreignEnvelopes, stA.shippedEntries, m.fallbackA.Load())
	// Enabled mode uses the same shape. Rounds 1–2 defer, round 3 counts the
	// keyset without shipping, and later rounds ship bounded windows. The first
	// ship round must engage the budget: about 78 self entries are in window,
	// leaving room for five 100-element batches but not a sixth. Publishing all
	// available batches would mean the window, not the budget, limited the round.
	m2 := buildDeferHardeningMesh(t, DeferOpts{deferHandler: true, stratified: true, batchSize: hardeningBatchSize, digestWait: 250 * time.Millisecond})
	deferInsert(t, m2.gB, "defer-hardening-relay-%d", 0, hardeningForeignKeys)
	deferHardeningPropagate(t, m2, m2.engineA, "defer-hardening-relay-%d", 0, hardeningForeignKeys, 20)
	deferInsert(t, m2.gA, "defer-hardening-divergence-%d", 0, hardeningDivergenceKeys)
	m2.gB.disableDigestRespond.Store(true)
	fwd2, _ := m2.gA.relay.batchLenForTest() // the distinct available envelopes (fixed post-propagation: A receives nothing new in the A-only rounds)
	shipRounds := 0
	for r := 1; r <= 10; r++ {
		st, escDelta := deferHardeningEscalationRound(t, m2)
		if escDelta == 0 {
			continue // a non-escalation round (defer or gate-skip): nothing armed, nothing to bound
		}
		comb := st.shippedEntries + st.foreignReceived
		if comb > deferSliceMaxEntries {
			t.Fatalf("enabled off-batch: round %d shipped combined %d received entries (self=%d foreign=%d envelopes=%d), above the single %d-entry budget", r, comb, st.shippedEntries, st.foreignReceived, st.foreignEnvelopes, deferSliceMaxEntries)
		}
		if st.relayMisses != 0 {
			t.Fatalf("enabled off-batch: escalation round %d saw %d relay misses on a wired retention seam — the engagement reasoning (a round that publishes fewer than all available envelopes was stopped by the budget) requires zero misses (a miss is a non-budget stopper)", r, st.relayMisses)
		}
		if st.shippedEntries > 0 || st.foreignEnvelopes > 0 {
			shipRounds++
		}
		if shipRounds == 1 && st.foreignEnvelopes >= fwd2 {
			t.Fatalf("enabled off-batch: first ship round re-published %d of %d available foreign envelopes; the budget did not engage (combined=%d entries=%d)", st.foreignEnvelopes, fwd2, comb, st.shippedEntries)
		}
	}
	if shipRounds < 2 {
		t.Fatalf("enabled off-batch: only %d escalation ship rounds in 10 (defers=%d esc=%d) — the escalation must ship its bounded slices across rounds (the count round + >= 2 ship rounds are the N=3 ladder)", shipRounds, m2.gA.digestDefers.Load(), m2.gA.digestDeferEscalations.Load())
	}
	if m2.fallbackA.Load() != 0 {
		t.Fatalf("enabled off-batch: fallback reporter fired %d times on deferred rounds, want zero oversend reports", m2.fallbackA.Load())
	}
	t.Logf("off-batch: disabled mode shipped all %d batches; enabled mode held combined received entries at <=%d (escalations=%d ship_rounds=%d)", hardeningForeignKeys/hardeningBatchSize, deferSliceMaxEntries, m2.gA.digestDeferEscalations.Load(), shipRounds)
}

// TestDeferHardenByteCap places ten hash-scattered 100-element batches in each
// approximately 39% window. A batch missing that window has probability
// 0.61^100, about 1e-22, so the window offers more than 608 foreign elements.
// The test asserts foreignReceived rather than deriving elements from envelope
// counts, and requires at least one available envelope to be refused. Removing
// the walk's cost pre-check publishes all ten envelopes and fails the test.
func TestDeferHardenByteCap(t *testing.T) {
	const (
		hardeningForeignKeys    = 1000
		hardeningDivergenceKeys = 40 // the minimal gate-fire divergence (self keys at A; B never announces again, so the stale recorded root keeps A's gate firing)
		hardeningBatchSize      = 100
	)
	m := buildDeferHardeningMesh(t, DeferOpts{deferHandler: true, stratified: true, batchSize: hardeningBatchSize, digestWait: 250 * time.Millisecond})
	deferInsert(t, m.gB, "defer-hardening-cap-%d", 0, hardeningForeignKeys)
	deferHardeningPropagate(t, m, m.engineA, "defer-hardening-cap-%d", 0, hardeningForeignKeys, 20)
	deferInsert(t, m.gA, "defer-hardening-divergence-%d", 0, hardeningDivergenceKeys)
	m.gB.disableDigestRespond.Store(true)
	fwd, _ := m.gA.relay.batchLenForTest() // the distinct available envelopes (fixed post-propagation; the div wave is self keys — never retained)
	engaged := false
	shipRounds := 0
	for r := 1; r <= 10; r++ {
		st, escDelta := deferHardeningEscalationRound(t, m)
		if escDelta == 0 {
			continue // defer / count round: nothing shipped this round
		}
		if st.foreignReceived > deferSliceMaxEntries {
			t.Fatalf("byte cap: escalation round %d charged %d foreign elements in %d envelopes, want at most %d", r, st.foreignReceived, st.foreignEnvelopes, deferSliceMaxEntries)
		}
		if st.relayMisses != 0 {
			t.Fatalf("byte cap: escalation round %d had %d relay misses, want 0 with retained batches", r, st.relayMisses)
		}
		if st.foreignEnvelopes > 0 {
			shipRounds++
			if st.foreignEnvelopes < fwd {
				engaged = true // with every batch in window and no misses, the budget refused an envelope
			}
		}
	}
	if !engaged {
		t.Fatalf("byte cap: every ship round published all %d available envelopes (ship_rounds=%d defers=%d escalations=%d); the budget never engaged", fwd, shipRounds, m.gA.digestDefers.Load(), m.gA.digestDeferEscalations.Load())
	}
	t.Logf("byte cap: %d escalation ship rounds; foreign received stayed <= %d with at least one of %d envelopes refused", shipRounds, deferSliceMaxEntries, fwd)
}

// TestDeferHardenCombined charges self entries and decoded foreign batch
// elements against one deferSliceMaxEntries budget at batch sizes 100 and 1.
// Independent 608-entry walk and foreign-publish caps could permit about 1,216
// combined entries; the mixed-window case fails if those caps return.
func TestDeferHardenCombined(t *testing.T) {
	const (
		hardeningForeignKeys = 1000
		hardeningSelfKeys    = 700 // the divergence wave: big enough that every escalation window mixes self and foreign
		hardeningBatchSize   = 100
	)
	// At batch size 100, A holds 1,000 foreign entries in ten batches and 700
	// self entries. An approximately 38.9% window offers about 266 self entries
	// plus elements from every hash-scattered foreign batch, roughly 1,266
	// received entries without the shared budget.
	m := buildDeferHardeningMesh(t, DeferOpts{deferHandler: true, stratified: true, batchSize: hardeningBatchSize, digestWait: 250 * time.Millisecond})
	deferInsert(t, m.gB, "defer-hardening-mixed-foreign-%d", 0, hardeningForeignKeys)
	deferHardeningPropagate(t, m, m.engineA, "defer-hardening-mixed-foreign-%d", 0, hardeningForeignKeys, 20)
	deferInsert(t, m.gA, "defer-hardening-mixed-self-%d", 0, hardeningSelfKeys)
	m.gB.disableDigestRespond.Store(true)
	shipRounds100 := 0
	for r := 1; r <= 10; r++ {
		st, escDelta := deferHardeningEscalationRound(t, m)
		if escDelta == 0 {
			continue // defer / count round: nothing armed to bound
		}
		comb := st.shippedEntries + st.foreignReceived
		if comb > deferSliceMaxEntries {
			t.Fatalf("combined budget (batch100): round %d shipped %d received entries (self=%d foreign=%d envelopes=%d), above the single %d budget", r, comb, st.shippedEntries, st.foreignReceived, st.foreignEnvelopes, deferSliceMaxEntries)
		}
		if comb > 0 {
			shipRounds100++
		}
	}
	if shipRounds100 < 2 {
		t.Fatalf("TestDeferHardenCombined(batch100): only %d escalation ship rounds in 10 (defers=%d esc=%d) — the ladder (2 defers + count + >= 2 ships) did not complete", shipRounds100, m.gA.digestDefers.Load(), m.gA.digestDeferEscalations.Load())
	}
	t.Logf("TestDeferHardenCombined(batch100): %d mixed escalation rounds, combined received <= %d each — one budget", shipRounds100, deferSliceMaxEntries)
	// At batch size 1, costOf is nil and shippedEntries counts self and foreign
	// frames at cost 1. A propagation-phase timeout can arm the ladder before
	// this loop, so the test observes the escalation counter rather than assuming
	// a round index. It first establishes sEst=500 and a whole-ring window, then
	// adds 400 self entries. The next armed round offers about 900 entries through
	// that stale window, and only the budget prevents a full-keyset dump. Removing
	// the walk cap publishes all 900 and fails the negative control.
	m2 := buildDeferHardeningMesh(t, DeferOpts{deferHandler: true, stratified: true, batchSize: 1, digestWait: 250 * time.Millisecond})
	deferInsert(t, m2.gB, "defer-hardening-per-frame-%d", 0, 400) // B's per-frame keyset: A joins and retains 400 relay frames (the per-frame retention seam)
	// Allow 250 propagation rounds for serialized per-frame Ed25519 verification.
	// A four-core race-detector run verified about 12–14 frames/s, so 400 frames
	// need about 30 seconds while a converged gate-skip round takes about 0.1s.
	// The loop exits as soon as all keys are present; the cap only bounds waiting.
	deferHardeningPropagate(t, m2, m2.engineA, "defer-hardening-per-frame-%d", 0, 400, 250)
	deferInsert(t, m2.gA, "defer-hardening-per-frame-self-%d", 0, 100) // A's self keyset: state 500 <= 608 — every pre-wave walk adopts sEst <= 608, keeping the window whole-ring-eligible
	m2.gB.disableDigestRespond.Store(true)
	// Wait for the first armed round. From scratch it counts sEst=500 without
	// shipping; an earlier timeout may instead have shipped the 500-entry set.
	// Either way the window is whole-ring and no walk occurs before the growth
	// wave. Twelve rounds are twice the worst observed ladder.
	armed := false
	for r := 1; r <= 12 && !armed; r++ {
		st, escDelta := deferHardeningEscalationRound(t, m2)
		if st.shippedEntries > deferSliceMaxEntries {
			t.Fatalf("TestDeferHardenCombined(batch1): pre-wave round %d published %d frames > the %d budget", r, st.shippedEntries, deferSliceMaxEntries)
		}
		armed = escDelta > 0
	}
	if !armed {
		t.Fatalf("TestDeferHardenCombined(batch1): the ladder never armed within 12 rounds (defers=%d esc=%d) — 3 consecutive triggers must arm the window", m2.gA.digestDefers.Load(), m2.gA.digestDeferEscalations.Load())
	}
	// Grow beyond the budget while sEst still describes the 500-entry set. The
	// next armed round offers about 900 frames through the stale whole-ring
	// window, so only the received-cost budget prevents a full-keyset dump.
	deferInsert(t, m2.gA, "defer-hardening-per-frame-self-%d", 100, 400)
	shipRounds1 := 0
	engaged1 := false
	for r := 1; r <= 10; r++ {
		st, escDelta := deferHardeningEscalationRound(t, m2)
		t.Logf("TestDeferHardenCombined(batch1): post-wave round %d escDelta=%d shipped=%d foreignRecv=%d (defers=%d esc_total=%d)", r, escDelta, st.shippedEntries, st.foreignReceived, m2.gA.digestDefers.Load(), m2.gA.digestDeferEscalations.Load())
		if escDelta == 0 {
			continue // defer round: nothing armed
		}
		if st.shippedEntries > deferSliceMaxEntries {
			t.Fatalf("TestDeferHardenCombined(batch1): escalation round %d published %d frames (self+foreign combined) > the %d budget — the per-frame path's combined bound breached (a full-keyset dump through the whole-ring window)", r, st.shippedEntries, deferSliceMaxEntries)
		}
		if st.shippedEntries > 0 {
			shipRounds1++
		}
		if st.shippedEntries >= deferSliceMaxEntries-100 {
			engaged1 = true // the budget is the binding constraint: ~608 of the ~900 available frames published in one round
		}
	}
	if !engaged1 {
		t.Fatalf("TestDeferHardenCombined(batch1): the budget never engaged (ship_rounds=%d; state ~900 > budget %d with the window whole-ring from the stale pre-wave sEst — some armed round must publish ~%d of the ~900 offered frames; without the cap the whole-ring round would publish all 900)", shipRounds1, deferSliceMaxEntries, deferSliceMaxEntries)
	}
	t.Logf("TestDeferHardenCombined: batch100 mixed rounds held combined <= %d; batch1 post-wave armed rounds held entries <= %d with the budget engaged (the whole-ring round cut at the budget) — one budget, both configs", deferSliceMaxEntries, deferSliceMaxEntries)
}

// TestDeferHardenTrueCount checks two received-cost invariants.
//
// On the mesh, a retained batch declares one element in its unsigned envelope
// header but has a decoded count of two. That header is outside the signed
// batchWire and is not cross-validated on input; a hybrid envelope parses as
// zero. The ship round must report foreignReceived=2 from the retained decoded
// count, not the header's one or zero.
//
// The direct walk gives one foreign entry cost 700. It must skip that entry,
// offer every other entry, retain a complete walkedCount, and advance nextOffset
// to the window end. Offering it would cap or park the ring permanently.
func TestDeferHardenTrueCount(t *testing.T) {
	const hardeningSelfKeys = 40 // A's self wave: small, whole-ring at the count round
	m := buildDeferHardeningMesh(t, DeferOpts{deferHandler: true, stratified: true, batchSize: 100, digestWait: 250 * time.Millisecond})
	deferInsert(t, m.gB, "defer-hardening-true-count-%d", 0, 1) // B's single key: a 1-element trailing batch (header count 1)
	deferHardeningPropagate(t, m, m.engineA, "defer-hardening-true-count-%d", 0, 1, 20)
	// Find A's joined foreign entry's dot, then fetch its retained frame.
	var realDot uint64
	found := false
	d := m.gA.engine.GenerateDelta(eng.NewIBLT(1, 4))
	d.Entries(func(entityID string, entry eng.CRDTEntry) bool {
		if entry.OriginNodeID == m.identB.NodeID {
			realDot, found = entry.DotCounter, true
		}
		return true
	})
	d.Release()
	if !found {
		t.Fatalf("TestDeferHardenTrueCount: A never joined B's key (the propagate premise failed)")
	}
	frame, seq, _, ok := m.gA.relay.lookupBatchCounted(m.identB.NodeID, realDot)
	if !ok {
		t.Fatalf("TestDeferHardenTrueCount: no retained batch for B's dot %d (the relay-retention premise failed)", realDot)
	}
	// Re-retain the same bytes with a decoded count of two while the unsigned
	// header still says one. This models an origin that under-reports its signed
	// batchWire and a hybrid envelope whose header parses as zero through
	// UnmarshalBatchEnvelope.
	m.gA.relay.retainBatch(m.identB.NodeID, seq, []uint64{realDot, realDot + 1_000_000}, frame)
	deferInsert(t, m.gA, "defer-hardening-true-count-self-%d", 0, hardeningSelfKeys)
	m.gB.disableDigestRespond.Store(true)
	armed := false
	for r := 1; r <= 12 && !armed; r++ {
		_, escDelta := deferHardeningEscalationRound(t, m)
		armed = escDelta > 0
	}
	if !armed {
		t.Fatalf("TestDeferHardenTrueCount: the ladder never armed within 12 rounds (defers=%d esc=%d)", m.gA.digestDefers.Load(), m.gA.digestDeferEscalations.Load())
	}
	// The first armed ship round (the count round ships nothing).
	shipped := false
	for r := 1; r <= 6 && !shipped; r++ {
		st, escDelta := deferHardeningEscalationRound(t, m)
		if escDelta == 0 || st.shippedEntries == 0 {
			continue
		}
		shipped = true
		if st.relayMisses != 0 {
			t.Fatalf("TestDeferHardenTrueCount: %d relay misses on a wired retention seam — the charge assert needs the batch to resolve", st.relayMisses)
		}
		if st.foreignEnvelopes != 1 {
			t.Fatalf("TestDeferHardenTrueCount: the ship round re-published %d foreign envelopes, want exactly 1 (the single retained batch)", st.foreignEnvelopes)
		}
		if st.foreignReceived != 2 {
			t.Fatalf("true count: charged %d foreign elements, want the retained decoded count 2 rather than the unsigned envelope header", st.foreignReceived)
		}
		if st.shippedEntries != hardeningSelfKeys {
			t.Fatalf("TestDeferHardenTrueCount: the ship round published %d self entries, want exactly %d", st.shippedEntries, hardeningSelfKeys)
		}
	}
	if !shipped {
		t.Fatalf("TestDeferHardenTrueCount: no armed ship round within 6 rounds of the arm (defers=%d esc=%d)", m.gA.digestDefers.Load(), m.gA.digestDeferEscalations.Load())
	}
	t.Logf("TestDeferHardenTrueCount (mesh arm): the armed ship round charged the retained-decoded count (2 elements for a header that says 1) — the charge source is the decoded truth, not the header")
	// For the direct walk, arm fresh defer state and charge the foreign entry
	// 700 through costOf. The oversized entry must never reach fn or consume
	// budget, and the ring must advance.
	peer := m.identB.NodeID
	m.gA.deferState[peer] = peerDeferState{consecutive: deferEscalationRounds, shipWindow: true, sEst: 500}
	d2 := m.gA.engine.GenerateDelta(eng.NewIBLT(1, 4))
	defer d2.Release()
	var offeredForeign, offeredSelf int
	costOf := func(entityID string, entry eng.CRDTEntry) int {
		if entry.OriginNodeID == m.identB.NodeID {
			return 700 // a retained batch larger than the 608-entry budget
		}
		return 1
	}
	fn := func(entityID string, entry eng.CRDTEntry) bool {
		if entry.OriginNodeID == m.identB.NodeID {
			offeredForeign++
		} else {
			offeredSelf++
		}
		return true
	}
	m.gA.walkDeferWindow(peer, d2, costOf, fn)
	ds := m.gA.deferState[peer]
	if offeredForeign != 0 {
		t.Fatalf("TestDeferHardenTrueCount (unit arm): the walk offered the 700-cost oversized entry to the ship path — an entry that can never fit any round's budget must be skipped, not offered (offered_self=%d)", offeredSelf)
	}
	if offeredSelf != hardeningSelfKeys {
		t.Fatalf("true count unit: offered %d of %d self entries; the oversized entry must not stop the round", offeredSelf, hardeningSelfKeys)
	}
	if ds.walkedCount != 1+hardeningSelfKeys {
		t.Fatalf("TestDeferHardenTrueCount (unit arm): walkedCount=%d, want the complete count %d — a skip is count-only; the sEst update must stay exact", ds.walkedCount, 1+hardeningSelfKeys)
	}
	if ds.nextOffset != ^uint64(0) {
		t.Fatalf("true count unit: nextOffset=%d, want window end %d; the oversized entry must not park the ring", ds.nextOffset, ^uint64(0))
	}
	t.Logf("TestDeferHardenTrueCount: the oversized entry was skipped (never offered), every self entry offered, the count complete, and the ring advanced to the window end — no park")
}
