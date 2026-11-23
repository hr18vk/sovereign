// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package receive

// The admission trust test file (ADR-0069). These tests verify the admission and
// budget hardening behavior: the durable clock-brick, subset admission, the re-key
// (ADR-0070), the pre-verify bucket burn, and the answer budget.
//
// The tests:
//   TestClockBrick_BoundedAdvance              — the clock-brick negative control
//   TestSubsetAdmission_AdversarialBatch       — the subset-admission negative control (head and middle spike)
//   TestSubsetAdmission_NonSkewDigestPreserved — the digest-preserved control
//   TestPreVerifyRateBudget_RefundPerFrame     — the per-frame refund negative control
//   TestPreVerifyRateBudget_RefundBatch        — the batch-family refund negative control
//   TestPreVerifyRateBudget_AcceptedChargeStands — the accepted charge control

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
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

// skewBrickDot is the Q1 brick value: 2^62 [derive: expr: 2^62 => 4611686018427387904] — far beyond the fresh-engine
// bound (local + ceil(rate*horizon) + slack = 0+0+1000 = 1000 at genesis,
// derived at runtime via the exported bound API) yet a value a 0-hop
// frame carries past every cheap gate initially (0-hop skips the rate gate;
// the clock gate reads the local wall on 0-hop; Open, Directory, and verify
// all pass for a registered origin; the 8b cross-check passes by builder
// construction) — so the only thing standing between it and the mint is the
// pinned apply bound, which the deleted pre-apply advance fed an
// already-bricked clock. The tautology, one frame.
const skewBrickDot uint64 = 1 << 62

// admissionBatchSpec is the per-element spec for buildAdmissionBatchWire: the
// (entityID, payload, payloadDigest, dotCounter) are caller-supplied so a
// spike (an over-bound dot with a correct digest — the skew class) or a
// digest corruption (the non-skew control) can be planted at any index.
type admissionBatchSpec struct {
	entityID      string
	payload       string
	payloadDigest [32]byte
	dotCounter    uint64
}

// admissionTestEntityID derives a distinct per-element entityID from the
// shared rcvEntityID sentinel so PointGet (the observed per-element join
// observable) distinguishes each element's join without a merged-view loop.
func admissionTestEntityID(prefix string, i int) string {
	return fmt.Sprintf("%s;%s=%03d", rcvEntityID, prefix, i)
}

// buildAdmissionBatchWire assembles a CRDTDeltaBatch capnp wire over specs —
// the test-side mirror of buildBatchWireFrame (pkg/sync) re-derived here
// with the rcv* sentinels so pkg/receive does not reach into pkg/sync test
// internals. Every element carries OriginNodeID == DotNodeID ==
// rcvOriginNodeID (the attribution check) and the rcv temporal sentinels
// buildCRDTDeltaWire stamps (the values the engine's reconstruct accepts).
func buildAdmissionBatchWire(t testing.TB, specs []admissionBatchSpec) []byte {
	t.Helper()
	msg, seg, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		t.Fatalf("capnp.NewMessage: %v", err)
	}
	batch, err := capnp_schema.NewRootCRDTDeltaBatch(seg)
	if err != nil {
		t.Fatalf("NewRootCRDTDeltaBatch: %v", err)
	}
	if len(specs) == 0 {
		t.Fatalf("buildAdmissionBatchWire: empty batch is not a valid shape")
	}
	events, err := batch.NewEvents(int32(len(specs)))
	if err != nil {
		t.Fatalf("batch.NewEvents: %v", err)
	}
	for i, sp := range specs {
		ev := events.At(i)
		ev.SetVersion(eng.CRDTDeltaEventWireVersion)
		if err := ev.SetPayloadDigest(sp.payloadDigest[:]); err != nil {
			t.Fatalf("event %d SetPayloadDigest: %v", i, err)
		}
		if err := ev.SetOriginNodeID(rcvOriginNodeID[:]); err != nil {
			t.Fatalf("event %d SetOriginNodeID: %v", i, err)
		}
		if err := ev.SetDotNodeID(rcvOriginNodeID[:]); err != nil {
			t.Fatalf("event %d SetDotNodeID: %v", i, err)
		}
		ev.SetDotCounter(sp.dotCounter)
		ev.SetH3Index(0x8928308280fffff)
		ev.SetSystemTime(0x1111111111111111)
		ev.SetValidTimeStart(0x2222222222222222)
		ev.SetValidTimeEnd(0x3333333333333333)
		ev.SetAssertionTime(0x4444444444444444)
		ev.SetDecisionTime(0x5555555555555555)
		if err := ev.SetEntityId(sp.entityID); err != nil {
			t.Fatalf("event %d SetEntityId: %v", i, err)
		}
		if err := ev.SetPayload(sp.payload); err != nil {
			t.Fatalf("event %d SetPayload: %v", i, err)
		}
	}
	data, err := msg.Marshal()
	if err != nil {
		t.Fatalf("msg.Marshal: %v", err)
	}
	return data
}

// setupAdmissionTestReceiver mirrors setupReceiver (receiver_test.go) but
// provides the PeerBucket and Directory handles: the Q4 tests observe the
// bucket directly (Budget per key — the observed drain, never an indexed
// premise), and the Q2 batch tests register the origin-side keypair the
// batch envelope's signature must verify against. Construction identical to
// setupReceiver: fresh bucket, SyntheticClock pinned at clockBaseUSec,
// IngressHLCScalarCap over it, Directory with originPub registered under
// rcvOriginNodeID, fresh engine (isolated per-test DataDir).
func setupAdmissionTestReceiver(t testing.TB, clockBaseUSec int64, budgetNS int64, originPub ed25519.PublicKey) (*Receiver, *admission.PeerBucket, *identity.Directory, *eng.DeltaCRDTEngine) {
	t.Helper()
	bucket := admission.NewPeerBucket()
	engine := setupEngine(t)
	sc := clock.NewSyntheticClock(clockBaseUSec)
	capc := clock.NewIngressHLCScalarCap(sc, engine)
	dir := identity.NewDirectory()
	if originPub != nil {
		if err := dir.Register(rcvOriginNodeID, originPub); err != nil {
			t.Fatalf("Directory.Register: %v", err)
		}
	}
	r := NewReceiver(bucket, capc, sc, dir, engine, budgetNS)
	return r, bucket, dir, engine
}

// buildOneHopAdmissionEnvelope builds one origin-signed, single-relay envelope
// with injected keys — the impostor drive relayChain cannot express (it mints
// its own fresh keys): the hop stamps relayPub as its relay identity but is
// signed by relaySignerPriv. A relay passes relaySignerPriv == the
// key matching relayPub (env.Open's hop verify passes); the impostor passes
// a different key — the victim's pub stamped, the attacker's sig — so the
// frame dies at env.Open (the per-frame refund site at DropVerify). wall is
// the hop's physical timestamp (the clock gate's operand).
func buildOneHopAdmissionEnvelope(t testing.TB, innerWire []byte, wall int64, originPub ed25519.PublicKey, originPriv ed25519.PrivateKey, relayPub ed25519.PublicKey, relaySignerPriv ed25519.PrivateKey) *attribution.RelayEnvelope {
	t.Helper()
	originSig := ed25519.Sign(originPriv, innerWire)
	hop := attribution.SignHop(relaySignerPriv, pubArray(relayPub), innerWire, nil, 0, wall)
	dotCounter, originNodeID := decodeGateFields(t, innerWire)
	return attribution.NewSignedRelayEnvelopeV3(innerWire, sigArray(originSig), dotCounter, originNodeID, []attribution.Hop{hop})
}

// buildDeepAdmissionEnvelope builds an origin-signed nHops chain whose last
// hop stamps lastHopPub (the rate gate's charge key) with in-window walls —
// the DropDepth drive: with MaxHopsForBudget below the chain depth, env.Open
// returns ErrHopBoundExceeded before any verify (the depth refund site; the
// depth check is the O(1) gate, zero Verify calls —
// TestReceiver_RejectBeforeVerify_Depth's proven shape). Intermediate hops
// use fresh keys: well-formed by construction, their sigs never run.
func buildDeepAdmissionEnvelope(t testing.TB, innerWire []byte, nHops int, wallBase int64, originPub ed25519.PublicKey, originPriv ed25519.PrivateKey, lastHopPub ed25519.PublicKey, lastHopPriv ed25519.PrivateKey) *attribution.RelayEnvelope {
	t.Helper()
	originSig := ed25519.Sign(originPriv, innerWire)
	hops := make([]attribution.Hop, nHops)
	var preceding []byte
	for i := 0; i < nHops; i++ {
		wall := wallBase + int64(i*1000)
		var hp ed25519.PublicKey
		var hs ed25519.PrivateKey
		if i == nHops-1 {
			hp, hs = lastHopPub, lastHopPriv
		} else {
			hp, hs = genKey(t)
		}
		hops[i] = attribution.SignHop(hs, pubArray(hp), innerWire, preceding, uint16(i), wall)
		preceding = attribution.SignedMaterial(innerWire, preceding, uint16(i), wall)
	}
	dotCounter, originNodeID := decodeGateFields(t, innerWire)
	return attribution.NewSignedRelayEnvelopeV3(innerWire, sigArray(originSig), dotCounter, originNodeID, hops)
}

// TestClockBrick_BoundedAdvance — the clock-brick negative control
// (ADR-0069): a Directory-registered origin signs one 0-hop frame with
// dotCounter 2^62. Expected behavior: the frame passes every gate (0-hop
// skips the rate gate; the clock gate reads the local synthetic wall; Open,
// Directory, the inner verify and the 8b cross-check all pass by
// construction), the deleted pre-apply advance then advances the
// clock to the attacker's own dot before the pinned apply reads it — the
// bound can never fire against a clock already advanced to the value under
// test — so the frame joins and the mint is bricked durably (AdvanceLamportTo's
// disk-bump). Green under fix (b): the 8c advance is deleted, the apply's
// own bound reads the true clock and refuses (verdict DropVerify, Kind
// WireIntegrityLamportSkewPoisoning), the clock never moves, NextDot() stays
// in-window, the recorder never fires.
func TestClockBrick_BoundedAdvance(t *testing.T) {
	const wallBase = int64(1_700_000_000_000_000)
	const budgetNS = int64(1_000_000_000) // 1ms -> MaxHopsForBudget=15; a 0-hop frame needs none

	innerWire := buildCRDTDeltaWire(t, rcvEntityID, skewBrickDot)
	env, originPub, _ := relayChain(t, innerWire, 0, wallBase) // the 0-hop substrate
	r, _, _, engine := setupAdmissionTestReceiver(t, wallBase, budgetNS, originPub)

	pre := engine.LamportCounter()
	bound := eng.MaxAcceptableDotCounter(engine.LamportSnapshot())
	if skewBrickDot <= bound {
		t.Fatalf("Q1 premise broken: brick dot %d is not over-bound (bound %d) — the negative control proves nothing", skewBrickDot, bound)
	}
	advanceCount := new(atomic.Uint64)
	r.onClockAdvance = func(post uint64) error { advanceCount.Add(1); return nil }

	verdict := r.HandleFrame(env.Marshal())

	post := engine.LamportCounter()
	if post != pre {
		t.Errorf("clock advance: the brick: V.clock jumped %d -> %d on one verified 0-hop frame (dot %d, bound %d) — the deleted pre-apply advance fed the pinned apply route a clock already advanced to the attacker's own dot, so the skew bound can never fire: the mint is bricked durably (AdvanceLamportTo's disk-bump)", pre, post, skewBrickDot, bound)
	}
	nd := engine.NextDot()
	if nd.Counter > bound {
		t.Errorf("clock advance: NextDot() = %d, want <= bound %d — the bricked mint emits dots no peer will accept (each peer's bound is its-local+ceil(rate*horizon)+slack); a registered-but-compromised origin displaced the mint with one frame", nd.Counter, bound)
	}
	if nd.Counter != pre+1 {
		t.Errorf("clock advance: NextDot() = %d, want exactly pre+1 = %d — a refused frame must advance the mint by nothing but its own step", nd.Counter, pre+1)
	}
	if got := advanceCount.Load(); got != 0 {
		t.Errorf("clock advance: the onClockAdvance recorder fired %d time(s) (post=%d > pre=%d) — the durable WAL clock-advance record carries the poison; recovery replays the bricked high-water", got, post, pre)
	}
	if verdict.Verdict != DropVerify {
		t.Errorf("clock advance: verdict = %v, want DropVerify — the pinned apply bound must refuse a verified-but-over-bound dot; got reason: %v", verdict.Verdict, verdict.Reason)
	} else {
		var wie *eng.WireIntegrityError
		if !errors.As(verdict.Reason, &wie) || wie.Kind != eng.WireIntegrityLamportSkewPoisoning {
			t.Errorf("clock advance: the refusal's Kind must be WireIntegrityLamportSkewPoisoning (got %v) — the I-2 subset admission keys on exactly this Kind", verdict.Reason)
		}
	}
}

// TestSubsetAdmission_AdversarialBatch — the subset-admission negative control
// (ADR-0069): an origin-signed 100-element batch whose spike element
// (position 0, then position 50 — the adversarial unsorted shape; a
// prefix-stop would join zero) carries dot 2^62 with a correct digest (the
// skew class, never the digest class) while the other 99 elements are
// in-window (dots 2..101 <= the fresh bound). Expected behavior: atomic batch processing
// whole-batch atomicity rejects the entire
// batch on the first over-bound element — zero of the 99 in-window
// elements join, and the sender's re-ship re-wedges forever. Green: elements
// join in any position (joined 99, held 1), the verdict is Accept, the
// spike itself never enters state.
func TestSubsetAdmission_AdversarialBatch(t *testing.T) {
	const wallBase = int64(1_700_000_000_000_000)
	const budgetNS = int64(1_000_000_000)
	const n = 100
	for _, leg := range []struct {
		spikeAt int
		prefix  string
	}{{0, "head-spike"}, {50, "mid-spike"}} {
		originPub, originPriv := genKey(t)
		r, _, _, engine := setupAdmissionTestReceiver(t, wallBase, budgetNS, originPub)
		bound := eng.MaxAcceptableDotCounter(engine.LamportSnapshot())

		specs := make([]admissionBatchSpec, n)
		for j := 0; j < n; j++ {
			payload := fmt.Sprintf("subset-%s-%03d", leg.prefix, j)
			d := sha256.Sum256([]byte(payload))
			dot := uint64(j + 2) // in-window: 2..101 <= fresh bound (0+0+1000)
			if j == leg.spikeAt {
				dot = skewBrickDot // the spike: over-bound, digest CORRECT
			}
			specs[j] = admissionBatchSpec{entityID: admissionTestEntityID(leg.prefix, j), payload: payload, payloadDigest: d, dotCounter: dot}
		}
		batchWire := buildAdmissionBatchWire(t, specs)
		sig := ed25519.Sign(originPriv, batchWire)
		frame := attribution.MarshalBatchEnvelope(rcvOriginNodeID, sigArray(sig), 1, uint16(n), batchWire)

		verdict := r.HandleBatchFrame(frame)

		joined := 0
		for j := 0; j < n; j++ {
			if j == leg.spikeAt {
				continue
			}
			if got := engine.PointGet(admissionTestEntityID(leg.prefix, j)); len(got) > 0 {
				joined++
			}
		}
		if joined != n-1 {
			t.Errorf("spike@%d: the wedge: A holds %d of the %d in-window elements — whole-batch atomicity lets one over-bound element (dot %d > bound %d) wedge the entire %d-element heal; the sender re-ships and re-wedges forever", leg.spikeAt, joined, n-1, skewBrickDot, bound, n)
		}
		if verdict.Verdict != Accept {
			t.Errorf("spike@%d: verdict = %v, want Accept (the in-window subset applies; the held tail is loud, never a whole-batch refusal) — reason: %v", leg.spikeAt, verdict.Verdict, verdict.Reason)
		}
		if got := r.batchSkewHeldTail.Load(); got != 1 {
			t.Errorf("spike@%d: batchSkewHeldTail = %d, want exactly 1 — the loud held-tail counter names the spike; a silent skip or a miscount fails here (the counter must exist)", leg.spikeAt, got)
		}
		if got := engine.PointGet(admissionTestEntityID(leg.prefix, leg.spikeAt)); len(got) != 0 {
			t.Errorf("spike@%d: the over-bound spike element joined (%d entries) — the held tail must never enter state", leg.spikeAt, len(got))
		}
		for _, j := range []int{(leg.spikeAt + 1) % n, n / 2, n - 1} {
			if j == leg.spikeAt {
				continue
			}
			entries := engine.PointGet(admissionTestEntityID(leg.prefix, j))
			wantDot := uint64(j + 2)
			if len(entries) == 0 || entries[0].DotCounter != wantDot {
				t.Errorf("spike@%d: element %d joined wrong dot: got %v, want DotCounter %d", leg.spikeAt, j, entries, wantDot)
			}
		}
	}
}

// TestSubsetAdmission_NonSkewDigestPreserved — the digest-preserved control
// (ADR-0069): a mid-batch digest corruption (element 50's
// payloadDigest mismatches its payload — the non-skew WireIntegrity class)
// keeps the whole-batch reject across both regression cases:
// zero joined, zero side effects, the verdict a DropVerify carrying the
// digest Kind. The I-2 subset admission must fire on exactly the skew Kind
// — this control is the negative control that
// confirms that partial joins are restricted strictly to skew recovery
// while non-skew corruption triggers whole-batch rejection.
func TestSubsetAdmission_NonSkewDigestPreserved(t *testing.T) {
	const wallBase = int64(1_700_000_000_000_000)
	const budgetNS = int64(1_000_000_000)
	const n = 100
	const corruptAt = 50
	originPub, originPriv := genKey(t)
	r, _, _, engine := setupAdmissionTestReceiver(t, wallBase, budgetNS, originPub)
	pre := engine.LamportCounter()

	specs := make([]admissionBatchSpec, n)
	for j := 0; j < n; j++ {
		payload := fmt.Sprintf("nonskew-%03d", j)
		d := sha256.Sum256([]byte(payload))
		if j == corruptAt {
			d = sha256.Sum256([]byte("corrupt-payload-digest")) // the corruption: digest != payload, dot in-window
		}
		specs[j] = admissionBatchSpec{entityID: admissionTestEntityID("nonskew", j), payload: payload, payloadDigest: d, dotCounter: uint64(j + 2)}
	}
	batchWire := buildAdmissionBatchWire(t, specs)
	sig := ed25519.Sign(originPriv, batchWire)
	frame := attribution.MarshalBatchEnvelope(rcvOriginNodeID, sigArray(sig), 1, uint16(n), batchWire)

	verdict := r.HandleBatchFrame(frame)

	joined := 0
	for j := 0; j < n; j++ {
		if got := engine.PointGet(admissionTestEntityID("nonskew", j)); len(got) > 0 {
			joined++
		}
	}
	if joined != 0 {
		t.Errorf("digest corruption: %d elements joined from a batch carrying a digest corruption at element %d — whole-batch atomicity is load-bearing for every non-skew class (the C5/C6 Mutation-B/C contract); the subset admission must fire on exactly the skew Kind", joined, corruptAt)
	}
	if verdict.Verdict != DropVerify {
		t.Errorf("digest corruption: verdict = %v, want DropVerify (the digest class keeps the whole-batch refusal at both trees)", verdict.Verdict)
	} else {
		var wie *eng.WireIntegrityError
		if !errors.As(verdict.Reason, &wie) || wie.Kind != eng.WireIntegrityDigestMismatch {
			t.Errorf("digest corruption: the refusal's Kind must be WireIntegrityDigestMismatch (got %v) — the discriminator proving this batch died as digest class, never skew (which subset-admits under test)", verdict.Reason)
		}
	}
	if post := engine.LamportCounter(); post != pre {
		t.Errorf("digest corruption: the clock moved %d -> %d on a whole-batch digest reject — zero side effects is the S1a contract", pre, post)
	}
}

// TestPreVerifyRateBudget_RefundPerFrame — the per-frame refund negative control
// (ADR-0069): an impostor forges 1-hop frames stamping the victim
// relay's pub as lastHop with the attacker's hop sig (env.Open fails per
// frame) and monotonically rising dotCounters — each delta small enough to
// keep and charge (the sizing law: one delta >= budget drops uncharged at
// its first admit; the drain is cumulative). The drive:
// 1024 frames x delta 1024 [derive: expr: 1048576/1024 => 1024] drain the
// fresh 2^20 budget to exactly 0 at base, and the victim's own next frame
// (delta 1 above the HWM) returns DropRate — the permanent burn (no refill
// exists). Green: every pre-verify drop refunds the charge this frame made;
// the budget survives the flood; the victim's own frame passes the rate
// gate (it then dies at the skew bound — the refusal). Sections B and C
// drive the other two per-frame refund sites: DropClock and DropDepth.
func TestPreVerifyRateBudget_RefundPerFrame(t *testing.T) {
	const wallBase = int64(1_700_000_000_000_000)
	const budgetNS = int64(1_000_000_000) // 1ms: admits the 1-hop drives
	const initialBudget = uint64(1) << 20 // 1048576, the ewma initialBudget

	originPub, originPriv := genKey(t)
	r, bucket, _, _ := setupAdmissionTestReceiver(t, wallBase, budgetNS, originPub)

	// Section A: the Open-fail drain
	victimPub, victimPriv := genKey(t)
	_, attackerPriv := genKey(t) // stamps the victim's pub, signs with its own key
	if got := bucket.Budget(victimPub[:]); got != 0 {
		t.Fatalf("premise: a never-charged key's budget must read 0 (the no-entry state), got %d", got)
	}
	// The drain honors the sizing law's boundary: Accept drops a delta >=
	// remaining budget uncharged, so a charge can never
	// take the budget to 0 (admit requires delta < remaining, so the floor
	// is 1): the reachable floor is exactly 1
	// (1023 x 1024 + one closer x 1023 = 2^20 - 1 charged), and the
	// own-frame kill needs remaining < own-delta = 1 — i.e. remaining == 1.
	for i := 1; i <= 1023; i++ {
		innerWire := buildCRDTDeltaWire(t, rcvEntityID, uint64(i*1024))
		env := buildOneHopAdmissionEnvelope(t, innerWire, wallBase, originPub, originPriv, victimPub, attackerPriv)
		if v := r.HandleFrame(env.Marshal()); v.Verdict != DropVerify {
			t.Fatalf("Q4 section A premise broken: forged-relay frame %d got %v (%v), want DropVerify at env.Open — the drain arithmetic depends on every frame dying pre-verify", i, v.Verdict, v.Reason)
		}
	}
	lastWire := buildCRDTDeltaWire(t, rcvEntityID, uint64(1023*1024+1023))
	lastEnv := buildOneHopAdmissionEnvelope(t, lastWire, wallBase, originPub, originPriv, victimPub, attackerPriv)
	if v := r.HandleFrame(lastEnv.Marshal()); v.Verdict != DropVerify {
		t.Fatalf("Q4 section A premise broken: the delta-1023 closer got %v (%v), want DropVerify at env.Open", v.Verdict, v.Reason)
	}
	if got := bucket.Budget(victimPub[:]); got != initialBudget {
		t.Errorf("budget Open-fail: the burn: after 1023+1 forged 1-hop frames stamping the victim's relayPub (1023 x delta 1024 + one delta-1023 closer = 2^20 - 1 charged, every frame dying at env.Open), the victim's budget is %d, want %d — the rate gate charged a key that was never cryptographically attributed (the pre-verify burn); at base the drain is permanent (no refill exists): the victim identity is deny-of-serviced at this receiver", got, initialBudget)
	}
	// The N1 re-key (ADR-0070): the probe dot re-keys from 2^20 (delta 1 above
	// the pre-ADR-0070 HWM the flood's charges advanced) to 2^20-1 — the
	// pending-HWM never commits the refunded Open-fail deaths, so at the
	// ADR-0070 tree the HWM reads 0 and the old probe's delta would be 2^20
	// >= the restored budget 2^20: a DropRate that would read as a
	// refund-surface defect but is the new watermark economy. At 2^20-1:
	// the pre-ADR-0070 tree reads delta-0 (the free duplicate Keep); the
	// ADR-0070 tree charges 2^20-1 < 2^20 (the victim's first attributed
	// frame pays its full first-seen counter). Both trees pass the rate
	// gate and die at the skew bound (the refusal).
	ownInner := buildCRDTDeltaWire(t, rcvEntityID, uint64(1023*1024+1023))
	ownEnv := buildOneHopAdmissionEnvelope(t, ownInner, wallBase, originPub, originPriv, victimPub, victimPriv)
	if v := r.HandleFrame(ownEnv.Marshal()); v.Verdict == DropRate {
		t.Errorf("budget Open-fail: the own-frame kill: the victim's own next frame returned DropRate — the rate gate denies the victim's verifiable traffic at both trees (the pre-ADR-0070 HWM grants the probe a free duplicate Keep; the ADR-0070 pending-HWM charges it as the first-seen counter, in-budget); the frame must pass the rate gate and die at the skew bound instead")
	}

	// Section B: the DropClock refund site
	v2Pub, v2Priv := genKey(t)
	for i := 1; i <= 31; i++ {
		innerWire := buildCRDTDeltaWire(t, rcvEntityID, uint64(i*32768))
		env := buildOneHopAdmissionEnvelope(t, innerWire, wallBase+10_000_000, originPub, originPriv, v2Pub, v2Priv)
		if v := r.HandleFrame(env.Marshal()); v.Verdict != DropClock {
			t.Fatalf("Q4 section B premise broken: frame %d got %v (%v), want DropClock — the 10ms-future wall must trip the drift gate", i, v.Verdict, v.Reason)
		}
	}
	bLast := buildCRDTDeltaWire(t, rcvEntityID, uint64(31*32768+32767)) // the >= boundary closer: 31x32768 + 32767 = 2^20 - 1
	bLastEnv := buildOneHopAdmissionEnvelope(t, bLast, wallBase+10_000_000, originPub, originPriv, v2Pub, v2Priv)
	if v := r.HandleFrame(bLastEnv.Marshal()); v.Verdict != DropClock {
		t.Fatalf("Q4 section B premise broken: the closer got %v (%v), want DropClock", v.Verdict, v.Reason)
	}
	if got := bucket.Budget(v2Pub[:]); got != initialBudget {
		t.Errorf("budget Verify-fail: the burn (DropClock): 31+1 future-walled frames (31 x delta 32768 + one delta-32767 closer = 2^20 - 1, the >= boundary floor) drained relayPub %x to %d, want %d — the clock-gate drop is pre-Open (the relay never attributed); it refunds under test", pubShort(v2Pub), got, initialBudget)
	}

	// Section C: the DropDepth refund site
	r2, bucket2, _, _ := setupAdmissionTestReceiver(t, wallBase, int64(30*1000), originPub) // 30us: MaxHopsForBudget=0
	v3Pub, v3Priv := genKey(t)
	for i := 1; i <= 31; i++ {
		innerWire := buildCRDTDeltaWire(t, rcvEntityID, uint64(i*32768))
		env := buildDeepAdmissionEnvelope(t, innerWire, 3, wallBase, originPub, originPriv, v3Pub, v3Priv)
		if v := r2.HandleFrame(env.Marshal()); v.Verdict != DropDepth {
			t.Fatalf("Q4 section C premise broken: 3-hop frame %d got %v (%v), want DropDepth on the 30us receiver (the depth check fires before any Verify)", i, v.Verdict, v.Reason)
		}
	}
	cLast := buildCRDTDeltaWire(t, rcvEntityID, uint64(31*32768+32767)) // the >= boundary closer
	cLastEnv := buildDeepAdmissionEnvelope(t, cLast, 3, wallBase, originPub, originPriv, v3Pub, v3Priv)
	if v := r2.HandleFrame(cLastEnv.Marshal()); v.Verdict != DropDepth {
		t.Fatalf("Q4 section C premise broken: the closer got %v (%v), want DropDepth", v.Verdict, v.Reason)
	}
	if got := bucket2.Budget(v3Pub[:]); got != initialBudget {
		t.Errorf("budget Apply-fail: the burn (DropDepth): 31+1 over-deep frames (31 x delta 32768 + one delta-32767 closer = 2^20 - 1, the >= boundary floor) drained relayPub %x to %d, want %d — the depth drop is pre-verify by construction (TestReceiver_RejectBeforeVerify_Depth's zero-Verify shape); it refunds under test", pubShort(v3Pub), got, initialBudget)
	}

	// Post-Open drops keep the charge (the refund principle's other
	// half, a control observed at both trees): a frame whose relay chain
	// verifies (env.Open passes) but whose origin is unknown burns the
	// relay's budget — the attributed relay paid for its own forwarding;
	// refunding post-Open drops would let a verified relay flood
	// unverifiable-origin frames at zero cost (the expensive-path burn the
	// gate exists to bound).
	rDir, bucketDir, _, _ := setupAdmissionTestReceiver(t, wallBase, budgetNS, nil) // no origin registered: the Directory-miss shape
	v4Pub, v4Priv := genKey(t)
	env4 := buildOneHopAdmissionEnvelope(t, buildCRDTDeltaWire(t, rcvEntityID, 3), wallBase, originPub, originPriv, v4Pub, v4Priv)
	if v := rDir.HandleFrame(env4.Marshal()); v.Verdict != DropVerify {
		t.Fatalf("Q4 keep-leg premise broken: got %v (%v), want DropVerify at the Directory miss (the origin is unregistered on rDir)", v.Verdict, v.Reason)
	}
	if got := bucketDir.Budget(v4Pub[:]); got != initialBudget-3 {
		t.Errorf("budget keep: the Directory-miss drop refunded the relay's charge (budget %d, want %d = 2^20 - delta 3): a post-Open drop keeps the charge — the relay chain verified, so the charged identity was attributed; a refund here re-opens the expensive-path burn the rate gate exists to bound", got, initialBudget-3)
	}
}

// pubShort renders a 4-byte hex prefix of an Ed25519 pubkey for the
// burn-leg fail lines (an identity is named, never buried in 32 hex bytes
// — the X1c rateDropReason discipline).
func pubShort(pub ed25519.PublicKey) string {
	return fmt.Sprintf("%x", pub[:4])
}

// admissionTestDigest is the payload digest helper (SHA-256 of the payload
// — the digest ReconstructEntry cross-validates).
func admissionTestDigest(s string) [32]byte {
	return sha256.Sum256([]byte(s))
}

// TestPreVerifyRateBudget_RefundBatch — the batch-family refund negative control
// (ADR-0069): the same drain through the distinct 16-byte origin key
// space (the batch originNodeID is zero-extended to the
// 32-byte rate key — a space no real 32-byte relay pubkey occupies). The
// batch twin: an impostor stamps the victim origin's nodeID on 1024 batch
// envelopes with garbage sigs (OriginSeq rising by 1024 — each Keep
// charged); the victim is registered here, so every frame dies at the one
// batch verify (the sig-fail refund site) after the
// charge. The hybrid twin (below): the same shape on HandleHybridFrame with
// the victim unregistered — every frame dies at the LookupBoth miss
// (the LookupBoth-miss refund site). Predicted at base:
// both victims drain to 0 and the victim's own next batch returns DropRate.
// Green: both refunds fire; the own batch accepts. The apply-rejection
// keep-leg (a verified origin's digest-corrupt batch) keeps the charge at
// both trees — the origin authenticated at the one verify; its own bad
// wire is its own budget.
func TestPreVerifyRateBudget_RefundBatch(t *testing.T) {
	const wallBase = int64(1_700_000_000_000_000)
	const budgetNS = int64(1_000_000_000)
	const initialBudget = uint64(1) << 20

	// The batch twin (the sig-fail site): the victim origin registered
	var victimOrigin [16]byte
	for i := range victimOrigin {
		victimOrigin[i] = byte(0x40 + i)
	}
	vOPub, vOPriv := genKey(t)
	r, bucket, dir, _ := setupAdmissionTestReceiver(t, wallBase, budgetNS, nil)
	if err := dir.Register(victimOrigin, vOPub); err != nil {
		t.Fatalf("Register victim origin: %v", err)
	}
	var rateKey [32]byte
	copy(rateKey[:16], victimOrigin[:]) // the zero-extension
	if got := bucket.Budget(rateKey[:]); got != 0 {
		t.Fatalf("batch premise: a never-charged origin key's budget must read 0 (the no-entry state), got %d", got)
	}
	twinWire := buildAdmissionBatchWire(t, []admissionBatchSpec{
		{entityID: admissionTestEntityID("refund", 0), payload: "refund-0", payloadDigest: admissionTestDigest("refund-0"), dotCounter: 2},
		{entityID: admissionTestEntityID("refund", 1), payload: "refund-1", payloadDigest: admissionTestDigest("refund-1"), dotCounter: 3},
	})
	var gs [attribution.OriginSigSize]byte
	for i := range gs {
		gs[i] = 0xAA // nonzero garbage: a zero sig dies as ErrBatchUnsigned at the unmarshal, pre-charge — no burn
	}
	// The same >= boundary law as leg A: 1023 x 1024 + one closer x 1023 =
	// 2^20 - 1 charged; the reachable drain floor is 1, never 0.
	for i := 1; i <= 1023; i++ {
		frame := attribution.MarshalBatchEnvelope(victimOrigin, gs, uint64(i*1024), 2, twinWire)
		if v := r.HandleBatchFrame(frame); v.Verdict != DropVerify {
			t.Fatalf("Q4 batch premise broken: garbage-sig batch %d got %v (%v), want DropVerify at the one batch verify", i, v.Verdict, v.Reason)
		}
	}
	if v := r.HandleBatchFrame(attribution.MarshalBatchEnvelope(victimOrigin, gs, uint64(1023*1024+1023), 2, twinWire)); v.Verdict != DropVerify {
		t.Fatalf("Q4 batch premise broken: the delta-1023 closer got %v (%v), want DropVerify at the one batch verify", v.Verdict, v.Reason)
	}
	if got := bucket.Budget(rateKey[:]); got != initialBudget {
		t.Errorf("budget batch: the burn: 1023+1 garbage-sig batches stamping the victim origin's nodeID (1023 x delta 1024 + one delta-1023 closer = 2^20 - 1 charged, every frame dying at the one batch verify after the charge) drained its batch budget to %d, want %d — the 16-byte origin key space is attacker-stampable pre-verify; at base the burn is permanent (no refill exists)", got, initialBudget)
	}
	sig := ed25519.Sign(vOPriv, twinWire)
	var sigArr [attribution.OriginSigSize]byte
	copy(sigArr[:], sig)
	// N1 re-key (ADR-0070): the probe seq re-keys from 2^20 (delta 1 above
	// the pre-ADR-0070 HWM the flood's charges advanced) to 2^20-1 — the
	// pending-HWM never commits the refunded flood deaths, so at the
	// ADR-0070 tree the HWM reads 0 and the old probe's delta would be 2^20 >= the
	// restored budget 2^20: a drop that would read as a refund-surface
	// defect but is the new watermark economy. At 2^20-1: the pre-ADR-0070 tree
	// reads delta-0 (the free duplicate keep — still an accept); the ADR-0070
	// tree charges 2^20-1 < 2^20 (the victim's first batch pays its
	// full first-seen seq — the documented fresh-peer economy). Both trees
	// accept.
	own := attribution.MarshalBatchEnvelope(victimOrigin, sigArr, uint64(1023*1024+1023), 2, twinWire)
	if v := r.HandleBatchFrame(own); v.Verdict != Accept {
		t.Errorf("budget batch: the victim origin's own next batch got %v (%v) — the budget survived the refunded impostor flood at both trees (the pre-ADR-0070 HWM at 2^20-1 grants the probe a free duplicate keep; the ADR-0070 pending-HWM charges it as the first-seen seq, in-budget); the dots are in-window", v.Verdict, v.Reason)
	}

	// The hybrid twin (the LookupBoth-miss site): victim unregistered
	var hybOrigin [16]byte
	for i := range hybOrigin {
		hybOrigin[i] = byte(0x60 + i)
	}
	var hybKey [32]byte
	copy(hybKey[:16], hybOrigin[:])
	rh, bucketH, _, _ := setupAdmissionTestReceiver(t, wallBase, budgetNS, nil)
	rh.SetHybridVerify(true)
	var edG [attribution.OriginSigSize]byte
	var pqG [attribution.PQSignatureSize]byte
	for i := range edG {
		edG[i] = 0xAA // nonzero: a zero sig dies as ErrHybridUnsigned pre-charge
	}
	for i := range pqG {
		pqG[i] = 0xBB
	}
	for i := 1; i <= 1023; i++ {
		frame := attribution.MarshalHybridFrame(hybOrigin, edG, pqG, uint64(i*1024), 2, twinWire)
		if v := rh.HandleHybridFrame(frame); v.Verdict != DropVerify {
			t.Fatalf("Q4 hybrid premise broken: frame %d got %v (%v), want DropVerify at the LookupBoth miss (the origin is unregistered on rh)", i, v.Verdict, v.Reason)
		}
	}
	if v := rh.HandleHybridFrame(attribution.MarshalHybridFrame(hybOrigin, edG, pqG, uint64(1023*1024+1023), 2, twinWire)); v.Verdict != DropVerify {
		t.Fatalf("Q4 hybrid premise broken: the delta-1023 closer got %v (%v), want DropVerify at the LookupBoth miss", v.Verdict, v.Reason)
	}
	if got := bucketH.Budget(hybKey[:]); got != initialBudget {
		t.Errorf("budget hybrid: the burn: 1023+1 hybrid frames stamping the unregistered victim origin's nodeID (1023 x delta 1024 + one delta-1023 closer = 2^20 - 1 charged, every frame dying at the LookupBoth miss after the charge) drained its hybrid-batch budget to %d, want %d — the hybrid twin charge site is the same attacker-stampable seam", got, initialBudget)
	}

	// The apply-rejection keep-leg (a control at both trees): a verified
	// origin's digest-corrupt batch keeps the charge — the origin
	// authenticated at the one verify; its own bad wire is
	// its own budget (the keep site).
	var keepOrigin [16]byte
	for i := range keepOrigin {
		keepOrigin[i] = byte(0x80 + i)
	}
	kPub, kPriv := genKey(t)
	rk, bucketK, dirK, _ := setupAdmissionTestReceiver(t, wallBase, budgetNS, nil)
	if err := dirK.Register(keepOrigin, kPub); err != nil {
		t.Fatalf("Register keep-origin: %v", err)
	}
	corruptWire := buildAdmissionBatchWire(t, []admissionBatchSpec{
		{entityID: admissionTestEntityID("keep", 0), payload: "keep-0", payloadDigest: admissionTestDigest("keep-0"), dotCounter: 2},
		{entityID: admissionTestEntityID("keep", 1), payload: "keep-1", payloadDigest: admissionTestDigest("corrupt-digest"), dotCounter: 3},
	})
	ksig := ed25519.Sign(kPriv, corruptWire)
	var ksigArr [attribution.OriginSigSize]byte
	copy(ksigArr[:], ksig)
	kv := rk.HandleBatchFrame(attribution.MarshalBatchEnvelope(keepOrigin, ksigArr, 1, 2, corruptWire))
	if kv.Verdict != DropVerify {
		t.Fatalf("Q4 keep-leg premise broken: got %v (%v), want DropVerify at the S1a apply reject", kv.Verdict, kv.Reason)
	}
	var kwie *eng.WireIntegrityError
	if !errors.As(kv.Reason, &kwie) || kwie.Kind != eng.WireIntegrityDigestMismatch {
		t.Errorf("budget keep: the refusal's Kind must be WireIntegrityDigestMismatch (got %v) — the discriminator proving the charge kept at the apply site, never the verify", kv.Reason)
	}
	var keepKey [32]byte
	copy(keepKey[:16], keepOrigin[:])
	if got := bucketK.Budget(keepKey[:]); got != initialBudget-1 {
		t.Errorf("budget keep: the apply-rejected batch's charge was refunded (budget %d, want %d = 2^20 - the delta-1 charge): the origin verified at the one batch verify — the apply rejection keeps the charge; a refund here would bill verified origins nothing for their own bad wire", got, initialBudget-1)
	}
}

// TestPreVerifyRateBudget_AcceptedChargeStands — the accepted charge control
// (ADR-0069): a real relay's verifiable per-frame traffic still
// charges its bucket and is not refunded, and a real origin's batch
// still charges its batch budget. This control passes at both trees by
// design — it exists to convict a refund-everything fix (a fix that
// refunds accepted frames' charges would re-open the Sybil-burst
// isolation the rate gate exists to enforce, and this negative control would fail).
func TestPreVerifyRateBudget_AcceptedChargeStands(t *testing.T) {
	const wallBase = int64(1_700_000_000_000_000)
	const budgetNS = int64(1_000_000_000)
	const initialBudget = uint64(1) << 20

	// The per-frame leg: an accepted frame charges
	originPub, originPriv := genKey(t)
	r, bucket, _, _ := setupAdmissionTestReceiver(t, wallBase, budgetNS, originPub)
	relayPub, relayPriv := genKey(t)
	inner := buildCRDTDeltaWire(t, rcvEntityID, 5) // dot 5: in-window (fresh bound 1000), delta 5 on a fresh key
	env := buildOneHopAdmissionEnvelope(t, inner, wallBase, originPub, originPriv, relayPub, relayPriv)
	if v := r.HandleFrame(env.Marshal()); v.Verdict != Accept {
		t.Fatalf("Q4 premise broken: the 1-hop frame got %v (%v), want Accept", v.Verdict, v.Reason)
	}
	if got := bucket.Budget(relayPub[:]); got != initialBudget-5 {
		t.Errorf("budget per-frame: the accepted frame's charge was refunded (budget %d, want %d = 2^20 - delta 5): a verified relay's own verifiable traffic must pay for itself — the refund is drop-path-only (the unattributed-identity principle); refunding accepted traffic re-opens the Sybil-burst isolation the rate gate enforces", got, initialBudget-5)
	}

	// The batch leg: an accepted batch charges
	var oOrigin [16]byte
	for i := range oOrigin {
		oOrigin[i] = byte(0x90 + i)
	}
	oPub, oPriv := genKey(t)
	rb, bucketB, dirB, _ := setupAdmissionTestReceiver(t, wallBase, budgetNS, nil)
	if err := dirB.Register(oOrigin, oPub); err != nil {
		t.Fatalf("Register origin: %v", err)
	}
	wire := buildAdmissionBatchWire(t, []admissionBatchSpec{
		{entityID: admissionTestEntityID("valid", 0), payload: "valid-0", payloadDigest: admissionTestDigest("valid-0"), dotCounter: 2},
		{entityID: admissionTestEntityID("valid", 1), payload: "valid-1", payloadDigest: admissionTestDigest("valid-1"), dotCounter: 3},
	})
	hs := ed25519.Sign(oPriv, wire)
	var hArr [attribution.OriginSigSize]byte
	copy(hArr[:], hs)
	if v := rb.HandleBatchFrame(attribution.MarshalBatchEnvelope(oOrigin, hArr, 2, 2, wire)); v.Verdict != Accept {
		t.Fatalf("Q4 batch premise broken: got %v (%v), want Accept", v.Verdict, v.Reason)
	}
	var okKey [32]byte
	copy(okKey[:16], oOrigin[:])
	if got := bucketB.Budget(okKey[:]); got != initialBudget-2 {
		t.Errorf("budget batch: the accepted batch's charge was refunded (budget %d, want %d = 2^20 - the delta-2 OriginSeq charge): an accepted origin pays for its own burst — same principle, same family", got, initialBudget-2)
	}
}

// TestSubsetAdmission_PureHoldReturnsDropVerify — the pure-hold coverage negative control
// (the branch carried no fixed-tree negative controls). Green at the current tree;
// its value is the guard, never a claimed defect.
func TestSubsetAdmission_PureHoldReturnsDropVerify(t *testing.T) {
	const wallBase = int64(1_700_000_000_000_000)
	const budgetNS = int64(1_000_000_000)
	const n = 3
	originPub, originPriv := genKey(t)
	r, _, _, engine := setupAdmissionTestReceiver(t, wallBase, budgetNS, originPub)
	specs := make([]admissionBatchSpec, n)
	for j := 0; j < n; j++ {
		payload := fmt.Sprintf("purehold-%03d", j)
		d := sha256.Sum256([]byte(payload))
		specs[j] = admissionBatchSpec{entityID: admissionTestEntityID("purehold", j), payload: payload, payloadDigest: d, dotCounter: skewBrickDot}
	}
	batchWire := buildAdmissionBatchWire(t, specs)
	sig := ed25519.Sign(originPriv, batchWire)
	frame := attribution.MarshalBatchEnvelope(rcvOriginNodeID, sigArray(sig), 1, uint16(n), batchWire)
	preSnap := engine.LamportSnapshot()
	verdict := r.HandleBatchFrame(frame)
	if verdict.Verdict != DropVerify {
		t.Errorf("subset pure-hold: verdict = %v, want DropVerify — the whole-batch-over-skew refusal is loud, never a silent no-op Accept", verdict.Verdict)
	}
	if verdict.Reason == nil || !strings.Contains(verdict.Reason.Error(), "held IN FULL") {
		t.Errorf("subset pure-hold: the refusal must name the held tail (expecting \"held IN FULL\"); got reason: %v", verdict.Reason)
	}
	if got := r.batchSkewHeldTail.Load(); got != n {
		t.Errorf("subset pure-hold: batchSkewHeldTail = %d, want %d", got, n)
	}
	for j := 0; j < n; j++ {
		if got := engine.PointGet(admissionTestEntityID("purehold", j)); len(got) != 0 {
			t.Errorf("subset pure-hold: element %d entered state (%d entries) — a held batch joins nothing", j, len(got))
		}
	}
	if post := engine.LamportSnapshot(); post != preSnap {
		t.Errorf("subset pure-hold: the Lamport snapshot moved %v -> %v — a held batch advances nothing (the rate EWMA included)", preSnap, post)
	}
}

// TestSubsetAdmission_HeldTailSuppressesSideEffects — the held-element side-effects control:
// the held element must ghost neither the secondary-index feed nor the batch relay
// retention — both downstream layers see the joined set alone.
func TestSubsetAdmission_HeldTailSuppressesSideEffects(t *testing.T) {
	const wallBase = int64(1_700_000_000_000_000)
	const budgetNS = int64(1_000_000_000)
	const n = 3
	const spikeAt = 1
	originPub, originPriv := genKey(t)
	r, _, _, engine := setupAdmissionTestReceiver(t, wallBase, budgetNS, originPub)
	var fed []string
	r.onIndexFeed = func(entityID string, h3 uint64, systemTime int64) { fed = append(fed, entityID) }
	var retainedDots []uint64
	r.onAcceptRelayBatch = func(origin [16]byte, seq uint64, dots []uint64, frame []byte) {
		retainedDots = append(retainedDots, dots...)
	}
	specs := make([]admissionBatchSpec, n)
	for j := 0; j < n; j++ {
		payload := fmt.Sprintf("nonskew-%03d", j)
		d := sha256.Sum256([]byte(payload))
		dot := uint64(j + 2)
		if j == spikeAt {
			dot = skewBrickDot
		}
		specs[j] = admissionBatchSpec{entityID: admissionTestEntityID("nonskew", j), payload: payload, payloadDigest: d, dotCounter: dot}
	}
	batchWire := buildAdmissionBatchWire(t, specs)
	sig := ed25519.Sign(originPriv, batchWire)
	frame := attribution.MarshalBatchEnvelope(rcvOriginNodeID, sigArray(sig), 1, uint16(n), batchWire)
	verdict := r.HandleBatchFrame(frame)
	if verdict.Verdict != Accept {
		t.Fatalf("subset nonskew: verdict = %v, want Accept (2 of 3 joined; the held tail never refuses the whole batch) — reason: %v", verdict.Verdict, verdict.Reason)
	}
	if got := r.batchSkewHeldTail.Load(); got != 1 {
		t.Fatalf("subset nonskew: batchSkewHeldTail = %d, want 1", got)
	}
	if len(fed) != n-1 {
		t.Errorf("subset nonskew: the index feed received %d elements, want %d (the joined set — the held element must not ghost the secondary index): fed=%v", len(fed), n-1, fed)
	}
	for _, id := range fed {
		if id == admissionTestEntityID("nonskew", spikeAt) {
			t.Errorf("subset nonskew: the held element's entity %s reached the index feed — a delta never in state ghosted the index", id)
		}
	}
	// N3 re-key (ADR-0070): the (a') fix
	// skips the retention on a held>0 partial entirely (the retained
	// object is the full origin-signed frame; it can never heal the tail,
	// and a relayer cannot re-sign a sub-frame), so the pin count is 0.
	if len(retainedDots) != 0 {
		t.Errorf("held partial: the held>0 partial pinned %d dots (%v), want 0 — the retention is skipped on a held partial: the full origin-signed frame can never heal the tail, so the pin is pure memory + a free-riding frame", len(retainedDots), retainedDots)
	}
	if joined := len(engine.PointGet(admissionTestEntityID("nonskew", 0))) + len(engine.PointGet(admissionTestEntityID("nonskew", 2))); joined != 2 {
		t.Errorf("subset nonskew: the drive's sanity: joined=%d, want 2 in-window elements in state", joined)
	}
}

// TestAcceptVerdict_AcceptedCountsJoined — the Accept verdict counter control:
// The mid-batch-skew Accept verdict counts its joined elements, never the
// wire header's batch count (which counts the held element too).
func TestAcceptVerdict_AcceptedCountsJoined(t *testing.T) {
	const wallBase = int64(1_700_000_000_000_000)
	const budgetNS = int64(1_000_000_000)
	const n = 3
	const spikeAt = 1
	originPub, originPriv := genKey(t)
	r, _, _, engine := setupAdmissionTestReceiver(t, wallBase, budgetNS, originPub)
	specs := make([]admissionBatchSpec, n)
	for j := 0; j < n; j++ {
		payload := fmt.Sprintf("accepted-%03d", j)
		d := sha256.Sum256([]byte(payload))
		dot := uint64(j + 2)
		if j == spikeAt {
			dot = skewBrickDot
		}
		specs[j] = admissionBatchSpec{entityID: admissionTestEntityID("accepted", j), payload: payload, payloadDigest: d, dotCounter: dot}
	}
	batchWire := buildAdmissionBatchWire(t, specs)
	sig := ed25519.Sign(originPriv, batchWire)
	frame := attribution.MarshalBatchEnvelope(rcvOriginNodeID, sigArray(sig), 1, uint16(n), batchWire)
	verdict := r.HandleBatchFrame(frame)
	if verdict.Verdict != Accept {
		t.Fatalf("accepted counts: verdict = %v, want Accept — reason: %v", verdict.Verdict, verdict.Reason)
	}
	if verdict.Accepted != n-1 {
		t.Errorf("accepted counts: verdict.Accepted = %d, want %d — the Accept verdict counts its joined elements; the wire header's %d counts the held element too (the per-delta counter must never over-count a delta that never entered state)", verdict.Accepted, n-1, n)
	}
	if got := r.batchSkewHeldTail.Load(); got != 1 {
		t.Errorf("accepted counts: batchSkewHeldTail = %d, want 1", got)
	}
	if joined := len(engine.PointGet(admissionTestEntityID("accepted", 0))) + len(engine.PointGet(admissionTestEntityID("accepted", 2))); joined != 2 {
		t.Errorf("accepted counts: the drive's sanity: joined=%d, want 2 in-window elements in state", joined)
	}
}
