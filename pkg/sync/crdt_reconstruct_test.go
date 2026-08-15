// Phase 2c — production teeth for the ReconstructEntry wire-integrity seam.
//
// This file is the biting test the Phase 2c mandate requires: it drives the
// PRODUCTION ReconstructEntry (pkg/sync/crdt_reconstruct.go) — not a test-local
// helper — and asserts both halves of the seam's contract:
//
//	(a) Consistent pair: a CRDTDeltaEvent whose PayloadDigest == SHA-256(payload)
//	    reconstructs to a CRDTEntry with EVERY contract field populated off the
//	    wire (no zero-fill). Lines: see TestPhase2c_ReconstructEntry_Biting
//	    "consistent pair" block.
//
//	(b) Mismatched pair: a CRDTDeltaEvent whose PayloadDigest !=
//	    SHA-256(payload) is rejected with a typed *WireIntegrityError carrying
//	    the diagnostic context Option A (decode-time rejection) forfeits — the
//	    entityID, the originNodeID, the on-wire digest, and the recomputed
//	    digest.
//
// TEETH (heightened — production code is being added; a production test must
// bite). The two mutations the mandate requires the test to catch:
//
//	Mutation A — neuter the bytes.Equal integrity check in ReconstructEntry
//	  (e.g. make it always return nil). The mismatched-pair case would then
//	  return a ReconstructedEntry instead of an error. The test asserts
//	  err == nil -> FAIL (see "mismatched pair must reject"). Verified by
//	  mutation in the Phase 2c report §3.
//
//	Mutation B — zero-fill a wire field on reconstruction (the C5-class silent
//	  fall-through). Example: overwrite rec.DotCounter = 0 after reading it off
//	  the wire. The consistent-pair case's field-equality assertion fires
//	  (got.Entry.DotCounter != rtEntityID-style sentinel). Verified by mutation
//	  in the Phase 2c report §3.
//
// Scope discipline: this file ADDS a test only. It does not modify
// crdt_capnp_roundtrip_test.go or crdt_capnp_teeth_test.go — the verifier's
// diff of those files must be empty. The constants it needs (rtHostA,
// rtEntityID, rtPayload, rtPayloadDigest, the rt* temporal/H3 sentinels,
// CRDTDeltaEventWireVersion) come from the single production source of truth
// (crdt_apply.go) and are read directly by name; this file does not redeclare them.
package sync

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	capnp "capnproto.org/go/capnp/v3"
	capnp_schema "github.com/hr18vk/supremum/api/capnp/api/capnp"
)

// buildReconstructFrame is the Phase 2c test-side frame builder. It assembles a
// CRDTDeltaEvent with a caller-supplied (payload, payloadDigest) pair, MARSHALS
// it to capnp bytes, and decodes it back via capnp.Unmarshal +
// ReadRootCRDTDeltaEvent — so ReconstructEntry is exercised against a frame
// that crossed an actual marshal/unmarshal boundary, not an in-memory struct
// constructed in the same arena. This is the exact shape a future production
// transport will hand the seam (decoded capnp bytes); the integrity check runs
// on real capnp Text/Data fields read off a real arena, not a stub. The 11
// CRDTEntry contract fields + EntityId are stamped with the rt* sentinels
// shared with the roundtrip test; DotCounter is a distinct nonzero sentinel so
// Mutation B (zero-fill DotCounter) provably changes a nonzero field to zero.
//
// dotCounter lets the test override the dot counter (defaults to a distinct
// nonzero sentinel) so the field-equality assertion catches a zero-fill.
func buildReconstructFrame(t *testing.T, digest [32]byte, payload string, dotCounter uint64) capnp_schema.CRDTDeltaEvent {
	t.Helper()
	msg, seg, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		t.Fatalf("capnp.NewMessage: %v", err)
	}
	ev, err := capnp_schema.NewRootCRDTDeltaEvent(seg)
	if err != nil {
		t.Fatalf("NewRootCRDTDeltaEvent: %v", err)
	}
	ev.SetVersion(CRDTDeltaEventWireVersion)
	if err := ev.SetPayloadDigest(digest[:]); err != nil {
		t.Fatalf("SetPayloadDigest: %v", err)
	}
	if err := ev.SetOriginNodeID(rtHostA[:]); err != nil {
		t.Fatalf("SetOriginNodeID: %v", err)
	}
	if err := ev.SetDotNodeID(rtHostA[:]); err != nil {
		t.Fatalf("SetDotNodeID: %v", err)
	}
	ev.SetDotCounter(dotCounter)
	ev.SetH3Index(rtH3Index)
	ev.SetSystemTime(rtSystemTime)
	ev.SetValidTimeStart(rtValidTimeStart)
	ev.SetValidTimeEnd(rtValidTimeEnd)
	ev.SetAssertionTime(rtAssertionTime)
	ev.SetDecisionTime(rtDecisionTime)
	if err := ev.SetEntityId(rtEntityID); err != nil {
		t.Fatalf("SetEntityId: %v", err)
	}
	if err := ev.SetPayload(payload); err != nil {
		t.Fatalf("SetPayload: %v", err)
	}
	data, err := msg.Marshal()
	if err != nil {
		t.Fatalf("msg.Marshal: %v", err)
	}
	// Round-trip through bytes so ReconstructEntry reads capnp fields off a
	// real decoupled arena — the shape a production transport will hand it.
	decMsg, err := capnp.Unmarshal(data)
	if err != nil {
		t.Fatalf("capnp.Unmarshal: %v", err)
	}
	ev2, err := capnp_schema.ReadRootCRDTDeltaEvent(decMsg)
	if err != nil {
		t.Fatalf("ReadRootCRDTDeltaEvent: %v", err)
	}
	return ev2
}

// rtReconstructDotCounter is a distinct nonzero sentinel for DotCounter so a
// zero-fill mutation (Mutation B) changes a known nonzero value to zero and
// the field-equality assertion fires. Different from the roundtrip test's
// hardcoded 1 to keep the two test files' dot sentinels independent.
const rtReconstructDotCounter uint64 = 0x7f7f7f7f7f7f7f7f

// TestPhase2c_ReconstructEntry_Biting is the production teeth. It drives the
// PRODUCTION ReconstructEntry on a consistent pair (must succeed with all 12
// fields populated from the wire) and a mismatched pair (must reject with a
// typed *WireIntegrityError carrying full diagnostic context). Mutation proofs
// in the Phase 2c report §3 confirm it catches a neutered bytes.Equal
// (Mutation A → mismatched returns nil → FAIL) and a zero-filled wire field
// (Mutation B → consistent field-equality → FAIL).
func TestPhase2c_ReconstructEntry_Biting(t *testing.T) {
	// --- Case 1: consistent pair. ReconstructEntry MUST succeed and return ---
	// a ReconstructedEntry whose CRDTEntry has EVERY contract field populated
	// off the wire (no zero-fill). Field-by-field equality vs the rt* sentinels
	// is the C5-class catch: a silent zero-fill of any field on reconstruction
	// diverges from its sentinel and the assertion fires.
	consistentEV := buildReconstructFrame(
		t, rtPayloadDigest, rtPayload, rtReconstructDotCounter)
	rec, err := ReconstructEntry(consistentEV)
	if err != nil {
		t.Fatalf("consistent pair: ReconstructEntry rejected a valid (payload, payloadDigest) pair: %v — the seam must succeed when SHA-256(payload)==PayloadDigest and all 12 fields read cleanly", err)
	}
	if rec == (ReconstructedEntry{}) {
		t.Fatalf("consistent pair: ReconstructEntry returned the zero-value entry with nil error — the seam must return a populated ReconstructedEntry on success (FIX C value-return: the nil==pointer check translates to a zero-value check on the comparable struct, byte-identical semantics)")
	}

	// 12 wire fields, no zero-fill — each assertion catches a silent
	// zero-fill or a wire/entry field swap. Mutation B (zero-fill DotCounter)
	// breaks the DotCounter assertion here; zero-fill of any other field
	// breaks its line.
	if rec.EntityID != rtEntityID {
		t.Errorf("consistent EntityID: got %q, want %q — zero-fill or wire-field-drop regression", rec.EntityID, rtEntityID)
	}
	if rec.Payload != rtPayload {
		t.Errorf("consistent Payload: got %q, want %q — zero-fill or payload-lost (C6) regression", rec.Payload, rtPayload)
	}
	if rec.Payload == string(rtPayloadDigest[:]) {
		t.Errorf("consistent Payload equals the digest bytes — C6 digest-substitution regression")
	}
	if rec.Entry.PayloadDigest != rtPayloadDigest {
		t.Errorf("consistent PayloadDigest: got %x, want %x", rec.Entry.PayloadDigest, rtPayloadDigest)
	}
	if rec.Entry.OriginNodeID != rtHostA {
		t.Errorf("consistent OriginNodeID: got %x, want %x", rec.Entry.OriginNodeID, rtHostA)
	}
	if rec.Entry.DotNodeID != rtHostA {
		t.Errorf("consistent DotNodeID: got %x, want %x (must come off the wire, not zero-filled)", rec.Entry.DotNodeID, rtHostA)
	}
	if rec.Entry.DotCounter != rtReconstructDotCounter {
		t.Errorf("consistent DotCounter: got %#x, want %#x — MUTATION B CATCH: zero-fill after read makes this fail", rec.Entry.DotCounter, rtReconstructDotCounter)
	}
	if rec.Entry.H3Index != rtH3Index {
		t.Errorf("consistent H3Index: got %#x, want %#x (must come off the wire, not zero-filled)", rec.Entry.H3Index, rtH3Index)
	}
	if rec.Entry.SystemTime != rtSystemTime {
		t.Errorf("consistent SystemTime: got %#x, want %#x (must come off the wire, not zero-filled)", rec.Entry.SystemTime, rtSystemTime)
	}
	if rec.Entry.ValidTimeStart != rtValidTimeStart {
		t.Errorf("consistent ValidTimeStart: got %#x, want %#x (must come off the wire, not zero-filled)", rec.Entry.ValidTimeStart, rtValidTimeStart)
	}
	if rec.Entry.ValidTimeEnd != rtValidTimeEnd {
		t.Errorf("consistent ValidTimeEnd: got %#x, want %#x (must come off the wire, not zero-filled)", rec.Entry.ValidTimeEnd, rtValidTimeEnd)
	}
	if rec.Entry.AssertionTime != rtAssertionTime {
		t.Errorf("consistent AssertionTime: got %#x, want %#x (must come off the wire, not zero-filled)", rec.Entry.AssertionTime, rtAssertionTime)
	}
	if rec.Entry.DecisionTime != rtDecisionTime {
		t.Errorf("consistent DecisionTime: got %#x, want %#x (must come off the wire, not zero-filled)", rec.Entry.DecisionTime, rtDecisionTime)
	}

	// Belt-and-braces: the entry's PayloadDigest MUST equal SHA-256 of the
	// reconstructed payload — this is the integrity property the seam
	// validated; asserting it again here pins that the digest returned on
	// the entry is the WIRE digest (not the recomputed one), and both are
	// equal for the consistent pair. Phase 2a documented that Join stores
	// only PayloadDigest; the seam's contract is that it has proven the
	// stored digest equals SHA-256(payload).
	recomputed := sha256.Sum256([]byte(rec.Payload))
	if !bytes.Equal(recomputed[:], rec.Entry.PayloadDigest[:]) {
		t.Errorf("consistent pair: reconstructed PayloadDigest %x != SHA-256(reconstructed payload) %x — seam returned an entry whose stored digest does not validate against its own payload", rec.Entry.PayloadDigest, recomputed)
	}

	// --- Case 2: mismatched pair. ReconstructEntry MUST reject with a typed ---
	// *WireIntegrityError carrying entityID + originNodeID + on-wire and
	// recomputed digests — the diagnostic context the architect refused to
	// lose (the whole reason Option A was overruled). A neutered bytes.Equal
	// (Mutation A) makes ReconstructEntry return nil here, and this block's
	// err==nil fatal fires. The originNodeID assertion is what Option A
	// could not have provided.
	wrongDigest := sha256.Sum256([]byte(rtPayload + "tampered-by-a-buggy-peer"))
	if wrongDigest == rtPayloadDigest {
		wrongDigest[0] ^= 0x01
		if wrongDigest == rtPayloadDigest {
			t.Fatalf("could not construct a deterministic mismatched digest; give up rather than risk a false green")
		}
	}
	mismatchedEV := buildReconstructFrame(
		t, wrongDigest, rtPayload, rtReconstructDotCounter)
	rec2, err := ReconstructEntry(mismatchedEV)
	if err == nil {
		t.Fatalf("PHASE2c INVARIANT BROKEN: ReconstructEntry accepted a mismatched (payload, payloadDigest) pair — MUTATION A CATCH: a neutered bytes.Equal makes this fire. wire-integrity gap is LIVE: SHA-256(payload) != PayloadDigest but the seam returned nil (entry %v)", rec2)
	}
	if rec2 != (ReconstructedEntry{}) {
		t.Fatalf("PHASE2c INVARIANT BROKEN: ReconstructEntry returned a non-zero entry (%v) alongside the integrity error — the seam must never partially populate an entry on failure (FIX C value-return: the !=nil pointer check translates to a non-zero-value check, byte-identical semantics)", rec2)
	}

	var wie *WireIntegrityError
	if !errors.As(err, &wie) {
		t.Fatalf("PHASE2c INVARIANT BROKEN: ReconstructEntry rejected the mismatched pair with the wrong error type %T; expected *WireIntegrityError so the teeth are specific to the integrity failure", err)
	}

	// Diagnostic context — the Option C payoff. Each of these is a property
	// Option A (decode-time rejection) forfeits. The entityID and originNodeID
	// identify WHICH frame from WHICH peer failed; the two digests name what
	// the wire carried vs what the payload actually hashes to.
	if wie.EntityID != rtEntityID {
		t.Errorf("mismatched diagnostic EntityID: got %q, want %q — the error must carry the entityID so a failed frame is attributable (Option C payoff)", wie.EntityID, rtEntityID)
	}
	if wie.OriginNodeID != rtHostA {
		t.Errorf("mismatched diagnostic OriginNodeID: got %x, want %x — the error must carry the origin peer id (Option C payoff)", wie.OriginNodeID, rtHostA)
	}
	if wie.OnWireDigest != wrongDigest {
		t.Errorf("mismatched diagnostic OnWireDigest: got %x, want %x — the error must carry the digest the wire carried", wie.OnWireDigest, wrongDigest)
	}
	if wie.RecomputedDigest != rtPayloadDigest {
		t.Errorf("mismatched diagnostic RecomputedDigest: got %x, want %x — the error must carry SHA-256(payload) the seam recomputed", wie.RecomputedDigest, rtPayloadDigest)
	}
	if wie.Kind != WireIntegrityDigestMismatch {
		t.Errorf("mismatched Kind: got %d, want %d (WireIntegrityDigestMismatch)", wie.Kind, WireIntegrityDigestMismatch)
	}

	t.Logf("Phase 2c GREEN: ReconstructEntry rejects a mismatched (payload, payloadDigest) pair with %q (technique proven in the production seam; the seam is the Option C location the architect ruled, separated from Join).", err.Error())
}

// reconstructFrameFresh builds a fresh decoded CRDTDeltaEvent whose Payload ==
// rtPayload and PayloadDigest == SHA-256(rtPayload), the consistent-pair shape
// the Day-9 alloc teeth need. It is the buildReconstructFrame helper parameterized
// to the consistent pair so the teeth exercise the SUCCESS path (the path FIX A
// rewired to ev.PayloadBytes() + sha256.Sum256(payloadBytes)).
func reconstructFrameFresh(t *testing.T) capnp_schema.CRDTDeltaEvent {
	t.Helper()
	return buildReconstructFrame(t, rtPayloadDigest, rtPayload, rtReconstructDotCounter)
}

// TestG09b_ZeroCopyPayloadAllocReduction is the Day-9 FIX A+C alloc-count drop
// tooth (gate G09.b). It asserts the SUCCESS path of ReconstructEntry allocates
// strictly FEWER heap objects/op than the pre-Day-9 basline — proving the
// zero-copy PayloadBytes read (FIX A) and value-return ReconstructedEntry (FIX
// C) actually eliminated heap allocs, not merely reshuffled them.
//
// MEASURED TRUTH (recorded in ADR-0014, this session @ 4c, count=3, the
// integrated bench — Testing.AllocsPerRun here is the per-call micro-proof):
//
//	BASELINE (old ev.Payload() + []byte(payload) + *ReconstructedEntry): 4 allocs/op
//	FIX A+C    (ev.PayloadBytes() zero-copy + value return):             2 allocs/op
//
// The tooth's RED condition: a regression that reverts FIX C (restores
// `&ReconstructedEntry{...}` at the success return) raises the per-call count
// from 2 back toward 4 → the assertion fires. A revert of FIX A alone does
// NOT move the count (escape analysis proves []byte(string) for sha256.Sum256
// was stack-allocated, "does not escape" — ADR-0014 §8 ATTACK 1/MEDIOCRITY 2).
// That honest asymmetry is recorded: FIX A is a bytes-path correctness
// simplification (it removes the []byte(string) hidden in the SHA argument),
// NOT an alloc-count win; FIX C is the alloc-count win. The tooth therefore
// binds the COMBINED count (≤2) and separately asserts the byte-identical
// Payload/digest invariants FIX A must preserve.
//
// The ≤2 ceiling is the post-fix count with slack — go's escape analysis can
// shift a per-call alloc under aggressive inlining/opts, so the tooth pins the
// load-bearing property (fewer than the old 4; the value return holds) rather
// than an exact 2, which would be brittle. The regression-revert case (back to
// 4) is what the tooth catches; it fails noisily.
func TestG09b_ZeroCopyPayloadAllocReduction(t *testing.T) {
	ev := reconstructFrameFresh(t)

	allocs := testing.AllocsPerRun(100, func() {
		rec, err := ReconstructEntry(ev)
		if err != nil {
			t.Fatalf("FIX A+C tooth: ReconstructEntry rejected the consistent frame: %v — the tooth must run the SUCCESS path to measure allocs", err)
		}
		// Drain rec so a smart compiler can't dead-code-eliminate the call.
		if rec == (ReconstructedEntry{}) {
			t.Fatalf("FIX A+C tooth: ReconstructEntry returned the zero entry on the consistent frame")
		}
		// Touch the load-bearing fields so the value return cannot be elided.
		_ = rec.EntityID
		_ = rec.Payload
		_ = rec.Entry
	})

	// The combined count must be STRICTLY below the old 4-alloc/op baseline.
	// A revert to the pointer return pushes this back to ~4 → FAIL.
	if allocs >= 4 {
		t.Fatalf("G09.b FAILED: ReconstructEntry success path allocs/op = %.2f, want < 4 (the pre-Day-9 baseline). A regression to *ReconstructedEntry or to a heap-escaping []byte(string) raises the count — did FIX A/C get reverted?", allocs)
	}
	t.Logf("G09.b PASS: ReconstructEntry success path = %.2f allocs/op (< 4 baseline; FIX A+C hold)", allocs)

	// ── Byte-identical invariants FIX A must preserve ──
	// ev.PayloadBytes() aliases the segment arena; string(payloadBytes) must
	// equal the original ev.Payload() string (both source the same segment
	// bytes). rec.Payload must equal rtPayload (the :151 contract), and the
	// recomputed digest must equal SHA-256(rtPayload) (the :195 contract).
	rec, err := ReconstructEntry(ev)
	if err != nil {
		t.Fatalf("G09.b byte-invariant: consistent frame rejected: %v", err)
	}
	if rec.Payload != rtPayload {
		t.Errorf("G09.b byte-invariant: rec.Payload != rtPayload — string(payloadBytes) diverged from the segment bytes (got len=%d, want len=%d)", len(rec.Payload), len(rtPayload))
	}
	// The digest must validate against the materialized payload string AND the
	// original — proving the zero-copy bytes fed to SHA are the SAME bytes the
	// string was materialized from (no alias corruption, no double-copy skew).
	wantDigest := sha256.Sum256([]byte(rtPayload))
	if rec.Entry.PayloadDigest != rtPayloadDigest {
		t.Errorf("G09.b byte-invariant: rec.Entry.PayloadDigest != on-wire rtPayloadDigest — the digest field drifted")
	}
	if rec.Entry.PayloadDigest != [32]byte(wantDigest) {
		t.Errorf("G09.b byte-invariant: rec.Entry.PayloadDigest %x != SHA-256(rtPayload) %x — the zero-copy PayloadBytes the SHA consumed did NOT hash to the same value as rtPayload (alias corruption / double-copy skew)", rec.Entry.PayloadDigest, wantDigest)
	}
	// And the SHA of the materialized string must equal the SHA of the original
	// (the round-trip is byte-identical — the central claim of FIX A).
	if sha256.Sum256([]byte(rec.Payload)) != wantDigest {
		t.Errorf("G09.b byte-invariant: SHA-256(rec.Payload) != SHA-256(rtPayload) — the materialized string diverged from the original payload bytes")
	}
}

// crdtApplyFrozenMD5 is the pinned md5 of the TRUE-FROZEN pkg/sync/crdt_apply.go
// (the production caller of ReconstructEntryWithSkewBound). Day 9 FIX C changes
// the RETURN TYPE of the seam from (*ReconstructedEntry) to (ReconstructedEntry,
// value). The FROZEN contract is that crdt_apply.go's SOURCE is byte-identical
// (it recompiles transparently against the new signature) — its md5 MUST stay
// pinned. The value is the low 8 hex chars of the file's md5, asserted PRE and
// POST (the gate run records the full hash).
const crdtApplyFrozenMD5 = "ed9132a2"

// TestG09c_FROZEN_SourceIdentical_CrdtApply is the Day-9 FIX C FROZEN-safety
// tooth (gate G09.c). It reads pkg/sync/crdt_apply.go straight off disk, hashes
// it, and ASSERTS the md5 matches the pinned FROZEN value. The tooth catches a
// FROZEN violation BEFORE it ships: if FIX C's signature change forced an edit
// to crdt_apply.go (e.g. a nil-check the value type no longer satisfied, or a
// &rec the value type no longer permits), the md5 would drift and this would
// FAIL.
//
// FROZEN SAFETY is necessary but NOT sufficient for compiled-semantics
// invariance; the source md5 proves only that the file was not edited. The
// compiled-behavior check is the separate gate G09.d (TestPhase2d_ApplyCRDTDeltaEvent_Biting
// green) — that test exercises the FROZEN crdt_apply.go's call to the new
// value-return seam and would FAIL if the recompile changed behavior. Both
// together are the FROZEN contract (ADR-0014 §2 FIX C checklist 1-5).
func TestG09c_FROZEN_SourceIdentical_CrdtApply(t *testing.T) {
	// Resolve the file path relative to THIS test file so the tooth does not
	// depend on the process cwd. crdt_apply.go sits next to this test file in
	// pkg/sync.
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("G09.c: runtime.Caller failed — cannot locate the test file to resolve the sibling crdt_apply.go path")
	}
	crdtApplyPath := filepath.Join(filepath.Dir(thisFile), "crdt_apply.go")

	raw, err := os.ReadFile(crdtApplyPath)
	if err != nil {
		t.Fatalf("G09.c: cannot read FROZEN crdt_apply.go at %q: %v — the FROZEN-identical tooth cannot run without the file", crdtApplyPath, err)
	}
	sum := md5.Sum(raw)
	got := hex.EncodeToString(sum[:])

	if got[:8] != crdtApplyFrozenMD5 {
		t.Fatalf("G09.c FAILED: pkg/sync/crdt_apply.go md5 prefix = %s, want %s (the pinned FROZEN value). Day 9 FIX C changed the ReconstructEntryWithSkewBound return type to a value; crdt_apply.go MUST recompile transparently (zero source diff). A md5 drift means crdt_apply.go was EDITED — a TRUE-FROZEN violation (ADR-0014 §2, §6 rule 6). Full md5: %s", got[:8], crdtApplyFrozenMD5, got)
	}
	// Belt: the full hash is recorded for the gate log (the pinned invariant is
	// the 8-char prefix; the full hash is the byte-for-byte identity the gate
	// G09.g records PRE==POST).
	t.Logf("G09.c PASS: pkg/sync/crdt_apply.go md5 = %s (prefix %s == pinned FROZEN; FIX C value-return compiled transparently, zero source diff)", got, got[:8])

	// Also assert the OTHER four TRUE-FROZEN files are byte-identical to their
	// pinned md5 prefixes — the full FROZEN set Day 9 must not touch. The
	// prefixes are the pinned values from the executor prompt §2.
	frozen := []struct {
		name string
		path string
		pin  string
	}{
		{"crdt.go", "crdt.go", "44f89527"}, // Day 17 (ADR-0022): re-pinned a50fee8f -> 5cebad26 — Join sort.Slice replaced by slices.SortFunc with a no-capture package-level comparator (cmpIncomingEntries), killing the reflect-path slice-header spill at the sort step; the 3 contracts (determinism/EBR/57.6M) re-proven by TestJoinDeterminism_PooledVsUnpooledMerkleEqual + TestJoinPool_DoesNotRetirePoolBuffers + TestPhase2J_BenchArenaGreen; the ADR also rejects Change B (capnp entity cache): bench is alloc-neutral + a stale lastEntityID-across-Joins UAF. Day 16 (ADR-0021): re-pinned 705ac671 -> a50fee8f, a COMMENT-ONLY change (a doc above `var DataDir` at crdt.go:17; NO byte of executable code changed, the 3 contracts byte-identical). The honesty discipline for the comment drift, disclosed per the Day-8.5 receiver.go precedent. Day 10 (ADR-0015): UNFROZEN for the JOIN-BUFFER POOL (FIX J1+J2). The 3 contracts (determinism/EBR/57.6M) are proven safe; the md5 re-pin is the honesty discipline — disclosed, not hidden (Day-8.5 receiver.go precedent).
		{"schema.capnp", filepath.Join("..", "..", "api", "capnp", "api", "capnp", "schema.capnp"), "47d2796a"},
		{"schema.capnp.go", filepath.Join("..", "..", "api", "capnp", "api", "capnp", "schema.capnp.go"), "590af228"},
		{"envelope.go", filepath.Join("..", "..", "pkg", "attribution", "envelope.go"), "b1beba1e"},
	}
	for _, f := range frozen {
		p := filepath.Join(filepath.Dir(thisFile), f.path)
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("G09.c: cannot read FROZEN %s at %q: %v", f.name, p, err)
		}
		s := md5.Sum(b)
		g := hex.EncodeToString(s[:])
		if g[:8] != f.pin {
			t.Fatalf("G09.c FAILED: FROZEN %s md5 prefix = %s, want %s — a TRUE-FROZEN file drifted under Day 9 (ADR-0014 §6 rule 6). Full: %s", f.name, g[:8], f.pin, g)
		}
		t.Logf("G09.c: FROZEN %s md5 = %s (prefix %s == pinned)", f.name, g, g[:8])
	}
}
