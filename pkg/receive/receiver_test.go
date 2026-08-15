package receive

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"os"
	"strings"
	"sync"
	"testing"

	capnp "capnproto.org/go/capnp/v3"
	"github.com/cloudflare/circl/sign/ed25519"
	capnp_schema "github.com/hr18vk/supremum/api/capnp/api/capnp"
	"github.com/hr18vk/supremum/pkg/admission"
	"github.com/hr18vk/supremum/pkg/attribution"
	"github.com/hr18vk/supremum/pkg/clock"
	"github.com/hr18vk/supremum/pkg/identity"
	eng "github.com/hr18vk/supremum/pkg/sync"
	"golang.org/x/sys/unix"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// rcvEntityID is a deterministic 40-char entityID (mirrors the rtEntityID
// sentinel in pkg/sync/crdt_capnp_roundtrip_test.go so the capnp frame is a
// faithful CRDTDeltaEvent the engine accepts).
const rcvEntityID = "tenant=acme;ledger=txn;id=0a1b2c3d4e5f60718293a4b5c6d7e8f9"

// rcvPayload is the recoverable wire payload (NOT byte-equal to its digest).
const rcvPayload = "this-is-recoverable-payload-bytes-NOT-its-digest"

// rcvOriginNodeID is the origin's 16-byte nodeID (the Directory key).
var rcvOriginNodeID = [16]byte{
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
}

// rcvPayloadDigest is SHA-256(rcvPayload), the PayloadDigest the capnp frame
// carries (ApplyCRDTDeltaEvent's ReconstructEntry cross-validates it).
var rcvPayloadDigest [32]byte

func init() {
	d := sha256.Sum256([]byte(rcvPayload))
	copy(rcvPayloadDigest[:], d[:])
}

// genKey generates a fresh Ed25519 keypair.
func genKey(t testing.TB) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return pub, priv
}

// pubArray copies a 32-byte pubkey into [32]byte.
func pubArray(pub ed25519.PublicKey) [32]byte {
	var a [32]byte
	copy(a[:], pub)
	return a
}

// sigArray copies a 64-byte signature into [64]byte.
func sigArray(sig []byte) [64]byte {
	var a [64]byte
	copy(a[:], sig)
	return a
}

// buildCRDTDeltaWire marshals a single CRDTDeltaEvent capnp frame the engine's
// ApplyCRDTDeltaEvent accepts: DotNodeID == OriginNodeID (the attribution
// check), PayloadDigest == SHA-256(payload) (the digest check), and the
// compiled wire version. dotCounter is the frame's DotCounter (the cheap
// gates read it; the engine's skew bound admits it when within the bound).
// It mirrors encodeEntryToCRDTDeltaEvent in pkg/sync/crdt_capnp_roundtrip_
// test.go (re-derived here, not imported, so pkg/receive does not reach into
// pkg/sync test internals).
func buildCRDTDeltaWire(t testing.TB, entityID string, dotCounter uint64) []byte {
	t.Helper()
	msg, seg, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		t.Fatalf("capnp.NewMessage: %v", err)
	}
	ev, err := capnp_schema.NewRootCRDTDeltaEvent(seg)
	if err != nil {
		t.Fatalf("NewRootCRDTDeltaEvent: %v", err)
	}
	ev.SetVersion(eng.CRDTDeltaEventWireVersion)
	if err := ev.SetPayloadDigest(rcvPayloadDigest[:]); err != nil {
		t.Fatalf("SetPayloadDigest: %v", err)
	}
	if err := ev.SetOriginNodeID(rcvOriginNodeID[:]); err != nil {
		t.Fatalf("SetOriginNodeID: %v", err)
	}
	// DotNodeID == OriginNodeID (the attribution check in ReconstructEntry).
	if err := ev.SetDotNodeID(rcvOriginNodeID[:]); err != nil {
		t.Fatalf("SetDotNodeID: %v", err)
	}
	ev.SetDotCounter(dotCounter)
	// Distinct nonzero temporal sentinels (mirrors the rt sentinels).
	ev.SetH3Index(0x8928308280fffff)
	ev.SetSystemTime(0x1111111111111111)
	ev.SetValidTimeStart(0x2222222222222222)
	ev.SetValidTimeEnd(0x3333333333333333)
	ev.SetAssertionTime(0x4444444444444444)
	ev.SetDecisionTime(0x5555555555555555)
	if err := ev.SetEntityId(entityID); err != nil {
		t.Fatalf("SetEntityId: %v", err)
	}
	if err := ev.SetPayload(rcvPayload); err != nil {
		t.Fatalf("SetPayload: %v", err)
	}
	data, err := msg.Marshal()
	if err != nil {
		t.Fatalf("msg.Marshal: %v", err)
	}
	return data
}

// setupEngine builds a fresh DeltaCRDTEngine with an isolated on-disk Lamport
// dir and the production-default skew bound (AbsoluteSlack=1000), so a small
// honest DotCounter (e.g. 7) is admitted by the skew bound. Cleanup is wired.
func setupEngine(t testing.TB) *eng.DeltaCRDTEngine {
	t.Helper()
	// Isolate DataDir per test (mirrors setupRTEngine in pkg/sync).
	oldDataDir := eng.DataDir
	eng.DataDir = t.TempDir()
	t.Cleanup(func() { eng.DataDir = oldDataDir })
	e, err := eng.NewDeltaCRDTEngine(rcvOriginNodeID, 0, 64*1024*1024)
	if err != nil {
		t.Fatalf("NewDeltaCRDTEngine: %v", err)
	}
	t.Cleanup(func() {
		if cerr := e.Close(); cerr != nil {
			t.Logf("engine.Close: %v", cerr)
		}
	})
	return e
}

// relayChain builds a signed relay chain over an inner wire: the origin signs
// the inner wire (originSig rides the envelope), then nHops relays each sign
// the chain-of-custody material and append their Hop. Returns the signed
// envelope, the origin's pubkey (for the Directory), and the relay pubkeys.
// wallBase is the first relay's physical timestamp (microseconds); each
// subsequent relay is +1000us (within the 2ms clock drift epsilon so the
// clock gate admits them when the local clock is pinned near wallBase).
func relayChain(t testing.TB, innerWire []byte, nHops int, wallBase int64) (*attribution.RelayEnvelope, ed25519.PublicKey, []ed25519.PublicKey) {
	t.Helper()
	originPub, originPriv := genKey(t)
	originSig := ed25519.Sign(originPriv, innerWire)

	relayPubs := make([]ed25519.PublicKey, nHops)
	relayPrivs := make([]ed25519.PrivateKey, nHops)
	for i := 0; i < nHops; i++ {
		relayPubs[i], relayPrivs[i] = genKey(t)
	}
	hops := make([]attribution.Hop, nHops)
	var preceding []byte
	for i := 0; i < nHops; i++ {
		wall := wallBase + int64(i*1000)
		hops[i] = attribution.SignHop(relayPrivs[i], pubArray(relayPubs[i]), innerWire, preceding, uint16(i), wall)
		// Thread the signed-material accumulator exactly as Open does.
		preceding = attribution.SignedMaterial(innerWire, preceding, uint16(i), wall)
	}
	// v3 (Track 3.6): the envelope header mirrors the inner capnp gate fields
	// (dotCounter, originNodeID) so the receiver's cheap gates read them O(1).
	// The test helper decodes them off the inner wire it is given (it already
	// has the inner wire) and binds them into the v3 header via the v3 builder,
	// so the receiver's cross-check (header == inner) passes and the cheap
	// gates see the real values. This mirrors what the production origin does
	// (it knows dotCounter/originNodeID when it builds the inner capnp).
	dotCounter, originNodeID := decodeGateFields(t, innerWire)
	return attribution.NewSignedRelayEnvelopeV3(innerWire, sigArray(originSig), dotCounter, originNodeID, hops), originPub, relayPubs
}

// decodeGateFields decodes the dotCounter and originNodeID off an inner capnp
// CRDTDeltaEvent wire — the values the v3 header mirrors. It is the test-side
// inverse of the receiver's readGateFieldsFromCapnp: the build helper uses it
// to populate the v3 header mirrors from the inner wire it constructed, so the
// receiver's cross-check (header == inner) passes. It is a test helper (the
// production origin knows these values without decoding — it set them).
func decodeGateFields(t testing.TB, innerWire []byte) (dotCounter uint64, originNodeID [16]byte) {
	t.Helper()
	msg, err := capnp.Unmarshal(innerWire)
	if err != nil {
		t.Fatalf("decodeGateFields: capnp unmarshal: %v", err)
	}
	defer msg.Release()
	ev, err := capnp_schema.ReadRootCRDTDeltaEvent(msg)
	if err != nil {
		t.Fatalf("decodeGateFields: read root: %v", err)
	}
	originBytes, err := ev.OriginNodeID()
	if err != nil {
		t.Fatalf("decodeGateFields: read originNodeID: %v", err)
	}
	if len(originBytes) != 16 {
		t.Fatalf("decodeGateFields: originNodeID len %d != 16", len(originBytes))
	}
	copy(originNodeID[:], originBytes)
	return ev.DotCounter(), originNodeID
}

// setupReceiver builds a fully-wired Receiver: a fresh PeerBucket, a
// SyntheticClock pinned at clockBaseUSec, an IngressHLCScalarCap over it, a
// Directory with the origin registered, and a fresh engine. budgetNS is the
// 3.2 admission budget (nanoseconds). Returns the receiver, the synthetic
// clock (so tests can advance it), the directory, and the engine.
func setupReceiver(t testing.TB, clockBaseUSec int64, budgetNS int64, originPub ed25519.PublicKey) (*Receiver, *clock.SyntheticClock, *identity.Directory, *eng.DeltaCRDTEngine) {
	t.Helper()
	bucket := admission.NewPeerBucket()
	engine := setupEngine(t)
	sc := clock.NewSyntheticClock(clockBaseUSec)
	cap := clock.NewIngressHLCScalarCap(sc, engine)
	dir := identity.NewDirectory()
	if originPub != nil {
		if err := dir.Register(rcvOriginNodeID, originPub); err != nil {
			t.Fatalf("Directory.Register: %v", err)
		}
	}
	r := NewReceiver(bucket, cap, sc, dir, engine, budgetNS)
	return r, sc, dir, engine
}

// ---------------------------------------------------------------------------
// G3.5.f — COMPOSITION acceptance over a real AF_UNIX socketpair
// ---------------------------------------------------------------------------

// TestReceiver_CompositionOverSocketpair is the ACCEPTANCE gate: one side
// builds a signed relay-chain envelope (origin signs inner; one relay signs a
// hop), length-prefixes it, writes it over a real AF_UNIX socketpair; the
// receiver reassembles via FrameReader, runs the full §3 ordering, and the
// engine's LamportCounter advances to the frame's DotCounter (the Join/
// AdvanceLamportTo seam bites) — the first production caller of
// ApplyCRDTDeltaEvent wired to real data over metal.
func TestReceiver_CompositionOverSocketpair(t *testing.T) {
	const dotCounter = uint64(7)
	const wallBase = int64(1_700_000_000_000_000)
	const budgetNS = int64(1_000_000_000) // 1ms -> MaxHopsForBudget=15, admits 1 hop

	innerWire := buildCRDTDeltaWire(t, rcvEntityID, dotCounter)
	env, originPub, _ := relayChain(t, innerWire, 1, wallBase)

	r, sc, _, engine := setupReceiver(t, wallBase, budgetNS, originPub)
	_ = sc

	// Marshal + length-prefix the envelope (the GAP-2 wire shape).
	prefixed := LengthPrefixFrame(env.Marshal())

	// Real AF_UNIX socketpair: write the prefixed frame on one end, reassemble
	// on the other via FrameReader, run HandleFrame.
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	sendFd, recvFd := fds[0], fds[1]

	// Write the prefixed frame (best-effort single write; the frame is small).
	if _, err := unix.Write(sendFd, prefixed); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Reassemble on the recv end via FrameReader over an *os.File.
	recvFile := os.NewFile(uintptr(recvFd), "recv")
	fr := NewFrameReader(recvFile)
	frameBytes, err := fr.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	// The reassembled frame MUST equal the Marshal'd envelope (prefix stripped).
	if !bytes.Equal(frameBytes, env.Marshal()) {
		t.Fatalf("reassembled frame != Marshal'd envelope (len got=%d want=%d)", len(frameBytes), len(env.Marshal()))
	}

	// Run the full gate-stack composition.
	verdict := r.HandleFrame(frameBytes)
	if verdict.Verdict != Accept {
		t.Fatalf("composition must Accept over a real socketpair, got %v: %v", verdict.Verdict, verdict.Reason)
	}

	// The Join/AdvanceLamportTo seam MUST bite: the engine's LamportCounter
	// advances to the frame's DotCounter (the first production caller of
	// ApplyCRDTDeltaEvent wired to real data over metal).
	if got := engine.LamportCounter(); got != dotCounter {
		t.Fatalf("engine.LamportCounter = %d, want %d (Join/Advance seam must advance to the frame's DotCounter)", got, dotCounter)
	}
}

// ---------------------------------------------------------------------------
// G3.5.e — EXECUTED reject-before-Verify instrumentation (F2: RUN, not prose)
// ---------------------------------------------------------------------------

// TestReceiver_RejectBeforeVerify_Depth proves a >maxHops deep envelope is
// dropped at the 3.2 depth check with ZERO Verify calls (the O(1) depth
// reject-before-Verify defense). It instruments Verify via the verifyHook seam
// and asserts the hook counter == 0 on the depth-reject path.
func TestReceiver_RejectBeforeVerify_Depth(t *testing.T) {
	const dotCounter = uint64(7)
	const wallBase = int64(1_700_000_000_000_000)
	// Budget sized so MaxHopsForBudget admits only a few hops; build a chain
	// deeper than the bound. 30us budget -> MaxHopsForBudget=0 (below one
	// Verify), so ANY relayed frame (>=1 hop) is depth-dropped.
	const budgetNS = int64(30 * 1_000) // 30us -> MaxHopsForBudget=0

	innerWire := buildCRDTDeltaWire(t, rcvEntityID, dotCounter)
	// 3-hop chain, bound 0 -> depth exceed.
	env, originPub, _ := relayChain(t, innerWire, 3, wallBase)

	r, _, _, _ := setupReceiver(t, wallBase, budgetNS, originPub)

	count := new(attribution.VerifyHookCount)
	attribution.SetVerifyHook(count.Hook)
	defer attribution.ClearVerifyHook()

	verdict := r.HandleFrame(env.Marshal())
	if verdict.Verdict != DropDepth {
		t.Fatalf("deep envelope must DropDepth, got %v: %v", verdict.Verdict, verdict.Reason)
	}
	if got := count.Load(); got != 0 {
		t.Fatalf("depth reject must issue ZERO Verify calls, got %d", got)
	}
}

// TestReceiver_RejectBeforeVerify_Rate proves a MaxUint64 dotCounter frame is
// dropped at the 3.1 rate gate with ZERO Open Verifies (the 5.0 A2 ratchet
// against the COMPOSED receiver, not just PeerBucket in isolation). The rate
// gate runs BEFORE Open, so the depth/verify gates never fire.
func TestReceiver_RejectBeforeVerify_Rate(t *testing.T) {
	const dotCounter = MaxUint64DotCounter
	const wallBase = int64(1_700_000_000_000_000)
	const budgetNS = int64(1_000_000_000) // 1ms -> MaxHopsForBudget=15 (would admit 1 hop)

	innerWire := buildCRDTDeltaWire(t, rcvEntityID, dotCounter)
	env, originPub, _ := relayChain(t, innerWire, 1, wallBase)

	r, _, _, _ := setupReceiver(t, wallBase, budgetNS, originPub)

	count := new(attribution.VerifyHookCount)
	attribution.SetVerifyHook(count.Hook)
	defer attribution.ClearVerifyHook()

	verdict := r.HandleFrame(env.Marshal())
	if verdict.Verdict != DropRate {
		t.Fatalf("MaxUint64 dotCounter frame must DropRate, got %v: %v", verdict.Verdict, verdict.Reason)
	}
	if got := count.Load(); got != 0 {
		t.Fatalf("rate reject must issue ZERO Open Verifies, got %d", got)
	}
}

// TestReceiver_RejectBeforeVerify_Clock proves a 3ms-future physical frame is
// dropped at the 3.0 clock gate with ZERO Open Verifies (the clock reject-
// before-Verify defense). The clock gate runs BEFORE Open.
func TestReceiver_RejectBeforeVerify_Clock(t *testing.T) {
	const dotCounter = uint64(7)
	const wallBase = int64(1_700_000_000_000_000)
	const budgetNS = int64(1_000_000_000) // 1ms -> MaxHopsForBudget=15

	innerWire := buildCRDTDeltaWire(t, rcvEntityID, dotCounter)
	// The relay's wall timestamp is wallBase; pin the local clock 3ms in the
	// PAST so the frame's physical time is 3ms-future (3000us > 2000us epsilon
	// -> clock reject). The last hop's WallUSec is wallBase (1 hop).
	env, originPub, _ := relayChain(t, innerWire, 1, wallBase)

	// Local clock 3ms BEFORE the frame's physical time.
	r, _, _, _ := setupReceiver(t, wallBase-3000, budgetNS, originPub)

	count := new(attribution.VerifyHookCount)
	attribution.SetVerifyHook(count.Hook)
	defer attribution.ClearVerifyHook()

	verdict := r.HandleFrame(env.Marshal())
	if verdict.Verdict != DropClock {
		t.Fatalf("3ms-future physical frame must DropClock, got %v: %v", verdict.Verdict, verdict.Reason)
	}
	if got := count.Load(); got != 0 {
		t.Fatalf("clock reject must issue ZERO Open Verifies, got %d", got)
	}
}

// ---------------------------------------------------------------------------
// G3.5.a — originSig absent from the wire -> DropVerify (the probe cheat
// cannot ship as production)
// ---------------------------------------------------------------------------

// TestReceiver_ZeroOriginSigDropped proves a version-1 envelope (all-zero
// originSig, the probe-cheat shape) is DropVerify'd at the 1.1 inner origin
// verify: the production receiver never admits an unsigned origin. This is
// the HC1 contract — the live receiver resolves originSig from the wire, not
// from a test-computed cheat.
func TestReceiver_ZeroOriginSigDropped(t *testing.T) {
	const dotCounter = uint64(7)
	const wallBase = int64(1_700_000_000_000_000)
	const budgetNS = int64(1_000_000_000)

	innerWire := buildCRDTDeltaWire(t, rcvEntityID, dotCounter)
	// Build a version-1 envelope (NewRelayEnvelope, all-zero originSig).
	relayPubs := make([]ed25519.PublicKey, 1)
	relayPrivs := make([]ed25519.PrivateKey, 1)
	relayPubs[0], relayPrivs[0] = genKey(t)
	hops := make([]attribution.Hop, 1)
	hops[0] = attribution.SignHop(relayPrivs[0], pubArray(relayPubs[0]), innerWire, nil, 0, wallBase)
	env := attribution.NewRelayEnvelope(innerWire, hops) // zero originSig

	// Register a throwaway origin pub (the Directory resolves it, but the zero
	// sig fails VerifyCRDTFrame).
	originPub, _ := genKey(t)
	r, _, _, _ := setupReceiver(t, wallBase, budgetNS, originPub)

	verdict := r.HandleFrame(env.Marshal())
	if verdict.Verdict != DropVerify {
		t.Fatalf("zero originSig (probe cheat) must DropVerify, got %v: %v", verdict.Verdict, verdict.Reason)
	}
}

// TestReceiver_UnknownOriginDropped proves a frame whose originNodeID is not
// in the Directory is DropVerify'd (GAP-3: the receiver cannot verify an
// unknown origin).
func TestReceiver_UnknownOriginDropped(t *testing.T) {
	const dotCounter = uint64(7)
	const wallBase = int64(1_700_000_000_000_000)
	const budgetNS = int64(1_000_000_000)

	innerWire := buildCRDTDeltaWire(t, rcvEntityID, dotCounter)
	env, originPub, _ := relayChain(t, innerWire, 1, wallBase)

	// Register a DIFFERENT origin (so the frame's originNodeID is a miss).
	otherPub, _ := genKey(t)
	r, _, _, _ := setupReceiver(t, wallBase, budgetNS, otherPub)
	_ = originPub // intentionally NOT registered

	verdict := r.HandleFrame(env.Marshal())
	if verdict.Verdict != DropVerify {
		t.Fatalf("unknown origin must DropVerify, got %v: %v", verdict.Verdict, verdict.Reason)
	}
}

// TestReceiver_ForgedOriginSigDropped proves a forged originSig (signed by a
// different key) is DropVerify'd at the 1.1 inner origin verify.
func TestReceiver_ForgedOriginSigDropped(t *testing.T) {
	const dotCounter = uint64(7)
	const wallBase = int64(1_700_000_000_000_000)
	const budgetNS = int64(1_000_000_000)

	innerWire := buildCRDTDeltaWire(t, rcvEntityID, dotCounter)
	env, originPub, _ := relayChain(t, innerWire, 1, wallBase)

	// Attacker signs the inner wire with a different key; overwrite originSig.
	_, attackerPriv := genKey(t)
	forgedSig := ed25519.Sign(attackerPriv, innerWire)
	// Rebuild the envelope with the forged originSig. The v3 header mirrors
	// (dotCounter, originNodeID) are preserved from the original env so the
	// frame reaches the 1.1 inner origin verify (the gate this test exercises)
	// rather than dropping earlier at the Directory lookup on a zeroed mirror.
	mirrorDot, mirrorOrigin := decodeGateFields(t, innerWire)
	env2 := attribution.NewSignedRelayEnvelopeV3(innerWire, sigArray(forgedSig), mirrorDot, mirrorOrigin, env.Hops())

	r, _, _, _ := setupReceiver(t, wallBase, budgetNS, originPub)

	verdict := r.HandleFrame(env2.Marshal())
	if verdict.Verdict != DropVerify {
		t.Fatalf("forged originSig must DropVerify, got %v: %v", verdict.Verdict, verdict.Reason)
	}
}

// TestReceiver_MalformedDropped proves a malformed frame (not a relay
// envelope) is DropMalformed'd without a panic.
func TestReceiver_MalformedDropped(t *testing.T) {
	const wallBase = int64(1_700_000_000_000_000)
	const budgetNS = int64(1_000_000_000)
	originPub, _ := genKey(t)
	r, _, _, _ := setupReceiver(t, wallBase, budgetNS, originPub)

	cases := [][]byte{
		nil,
		make([]byte, 4),
		{1, 0, 0, 0, 0, 0, 0, 0}, // wrong version
	}
	for i, w := range cases {
		verdict := r.HandleFrame(w)
		if verdict.Verdict != DropMalformed {
			t.Fatalf("malformed case %d must DropMalformed, got %v: %v", i, verdict.Verdict, verdict.Reason)
		}
	}
}

// TestReceiver_NoPanicOnAdversarialInput proves the receiver NEVER panics on
// adversarial input (a forged frame is a Verdict, never a crash). It feeds
// random bytes of varying lengths through HandleFrame.
func TestReceiver_NoPanicOnAdversarialInput(t *testing.T) {
	const wallBase = int64(1_700_000_000_000_000)
	const budgetNS = int64(1_000_000_000)
	originPub, _ := genKey(t)
	r, _, _, _ := setupReceiver(t, wallBase, budgetNS, originPub)

	for _, n := range []int{0, 1, 7, 8, 71, 72, 73, 200, 1000} {
		w := make([]byte, n)
		_, _ = rand.Read(w)
		// Must not panic; any verdict is acceptable.
		_ = r.HandleFrame(w)
	}
}

// ---------------------------------------------------------------------------
// G3.5.g — relay A->B->C->D over the composed receiver (multi-hop chain)
// ---------------------------------------------------------------------------

// TestReceiver_RelayChainABCD proves a 3-hop relay chain A->B->C->D reaches
// the receiver (D) and verifies all outer hops in Open THEN the inner origin.
// It exercises the full composition over a multi-hop chain.
func TestReceiver_RelayChainABCD(t *testing.T) {
	const dotCounter = uint64(7)
	const wallBase = int64(1_700_000_000_000_000)
	const budgetNS = int64(1_000_000_000) // 1ms -> MaxHopsForBudget=15, admits 3 hops

	innerWire := buildCRDTDeltaWire(t, rcvEntityID, dotCounter)
	// 3-hop chain B->C->D over A's signed inner frame.
	env, originPub, _ := relayChain(t, innerWire, 3, wallBase)

	r, _, _, engine := setupReceiver(t, wallBase, budgetNS, originPub)

	verdict := r.HandleFrame(env.Marshal())
	if verdict.Verdict != Accept {
		t.Fatalf("3-hop relay chain must Accept, got %v: %v", verdict.Verdict, verdict.Reason)
	}
	if got := engine.LamportCounter(); got != dotCounter {
		t.Fatalf("engine.LamportCounter = %d, want %d after 3-hop relay Join", got, dotCounter)
	}
}

// TestReceiver_RelayForwardEgress proves the relay-forward egress (2.0 tie):
// a relay appends a new hop, Marshals, length-prefixes, and sends via
// TransmitHeapBufferSend over a real AF_UNIX socketpair; the receiver
// reassembles and accepts the forwarded frame. This proves the egress (2.0
// TransmitHeapBuffer) and the ingress (3.5 receiver) compose for relay.
func TestReceiver_RelayForwardEgress(t *testing.T) {
	const dotCounter = uint64(7)
	const wallBase = int64(1_700_000_000_000_000)
	const budgetNS = int64(1_000_000_000)

	innerWire := buildCRDTDeltaWire(t, rcvEntityID, dotCounter)
	// Origin A signs; relay B signs one hop.
	env, originPub, relayPubs := relayChain(t, innerWire, 1, wallBase)
	originSig := env.OriginSig()
	existingHops := env.Hops()

	// Relay C forwards one more hop: append C's hop, Marshal, length-prefix,
	// send via TransmitHeapBufferSend over a socketpair.
	relayCPub, relayCPriv := genKey(t)
	newHopWall := wallBase + 2000 // C's physical timestamp (within 2ms of the local clock)

	// Socketpair for the egress -> ingress composition.
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	sendFd, recvFd := fds[0], fds[1]
	// Arm SO_ZEROCOPY best-effort (the 2.0 conditional; EOPNOTSUPP tolerated).
	_ = unix.SetsockoptInt(sendFd, unix.SOL_SOCKET, unix.SO_ZEROCOPY, 1)

	// Forward: C signs hop index 1 (existingHops has 1 hop at index 0). The
	// v3 header mirrors (dotCounter, originNodeID) are copied off the verified
	// incoming env unchanged — relays attest custody, they do not alter the
	// origin's gate fields (Track 3.6).
	sent, err := ForwardEnvelope(relayCPriv, pubArray(relayCPub), innerWire, originSig, env.DotCounter(), env.OriginNodeID(), existingHops, 1, newHopWall, sendFd, nil)
	if err != nil {
		t.Fatalf("ForwardEnvelope: %v", err)
	}
	// sent is the prefixed-frame length (the 2.0 egress boundary sendmsg'd
	// the full prefixed frame). Assert it is positive (the send carried the
	// data over the socketpair).
	if sent <= 0 {
		t.Fatalf("ForwardEnvelope sent = %d, want > 0 (the egress must carry the prefixed frame)", sent)
	}
	_ = relayPubs

	// Receiver: reassemble via FrameReader and run the composition. The local
	// clock is pinned at wallBase so C's newHopWall (wallBase+2000) is within
	// the 2ms clock drift epsilon (2000us <= 2000us epsilon -> accept; the
	// bound is > epsilon rejects, == epsilon accepts).
	r, _, _, engine := setupReceiver(t, wallBase, budgetNS, originPub)
	recvFile := os.NewFile(uintptr(recvFd), "recv")
	fr := NewFrameReader(recvFile)
	frameBytes, err := fr.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	verdict := r.HandleFrame(frameBytes)
	if verdict.Verdict != Accept {
		t.Fatalf("forwarded 2-hop frame must Accept, got %v: %v", verdict.Verdict, verdict.Reason)
	}
	if got := engine.LamportCounter(); got != dotCounter {
		t.Fatalf("engine.LamportCounter = %d, want %d after forwarded relay Join", got, dotCounter)
	}
}

// ---------------------------------------------------------------------------
// G3.5.h — -race over 32 concurrent receiver handles
// ---------------------------------------------------------------------------

// TestReceiver_ConcurrentHandlesNoRace runs 32 goroutines, each building its
// own signed relay-chain frame and running it through a SHARED receiver, with
// zero races (the -race gate). The shared receiver's gates are all
// concurrency-safe (PeerBucket sharded-mutex, IngressHLCScalarCap read-only,
// Open immutable-envelope, Directory RWMutex, ApplyCRDTDeltaEvent race-proven).
func TestReceiver_ConcurrentHandlesNoRace(t *testing.T) {
	const goroutines = 32
	const dotCounter = uint64(7)
	const wallBase = int64(1_700_000_000_000_000)
	const budgetNS = int64(1_000_000_000)

	innerWire := buildCRDTDeltaWire(t, rcvEntityID, dotCounter)
	env, originPub, _ := relayChain(t, innerWire, 1, wallBase)
	frame := env.Marshal()

	r, _, _, engine := setupReceiver(t, wallBase, budgetNS, originPub)

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				v := r.HandleFrame(frame)
				if v.Verdict != Accept {
					t.Errorf("goroutine %d iter %d: want Accept, got %v: %v", id, i, v.Verdict, v.Reason)
					return
				}
			}
		}(g)
	}
	wg.Wait()
	// The engine's LamportCounter advanced to dotCounter (concurrent Joins
	// all advance to the same value; the CAS is race-proven).
	if got := engine.LamportCounter(); got != dotCounter {
		t.Fatalf("engine.LamportCounter = %d, want %d after concurrent Joins", got, dotCounter)
	}
}

// ---------------------------------------------------------------------------
// G3.5 (frame reader) — length-prefix reassembler teeth
// ---------------------------------------------------------------------------

// TestFrameReader_RoundTrip proves FrameReader reassembles a length-prefixed
// frame byte-identical to the envelope (prefix stripped), over a pipe that
// delivers the bytes in arbitrary-sized chunks.
func TestFrameReader_RoundTrip(t *testing.T) {
	innerWire := buildCRDTDeltaWire(t, rcvEntityID, 7)
	env, _, _ := relayChain(t, innerWire, 2, 1_700_000_000_000_000)
	prefixed := LengthPrefixFrame(env.Marshal())

	// Use a pipe so the bytes arrive in arbitrary-sized reads.
	pr, pw := io.Pipe()
	go func() {
		// Write in small chunks to exercise the reassembly loop.
		for i := 0; i < len(prefixed); i += 7 {
			end := i + 7
			if end > len(prefixed) {
				end = len(prefixed)
			}
			if _, err := pw.Write(prefixed[i:end]); err != nil {
				_ = pw.CloseWithError(err)
				return
			}
		}
		_ = pw.Close()
	}()
	fr := NewFrameReader(pr)
	frameBytes, err := fr.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if !bytes.Equal(frameBytes, env.Marshal()) {
		t.Fatalf("reassembled frame != Marshal'd envelope (len got=%d want=%d)", len(frameBytes), len(env.Marshal()))
	}
}

// TestFrameReader_MultipleFrames proves the reassembler handles back-to-back
// frames (trailing bytes from one frame are kept for the next).
func TestFrameReader_MultipleFrames(t *testing.T) {
	innerWire := buildCRDTDeltaWire(t, rcvEntityID, 7)
	env, _, _ := relayChain(t, innerWire, 1, 1_700_000_000_000_000)
	one := LengthPrefixFrame(env.Marshal())
	// Two frames concatenated in one buffer.
	combined := append(append([]byte{}, one...), one...)

	pr, pw := io.Pipe()
	go func() {
		_, _ = pw.Write(combined)
		_ = pw.Close()
	}()
	fr := NewFrameReader(pr)
	for i := 0; i < 2; i++ {
		frameBytes, err := fr.ReadFrame()
		if err != nil {
			t.Fatalf("ReadFrame %d: %v", i, err)
		}
		if !bytes.Equal(frameBytes, env.Marshal()) {
			t.Fatalf("frame %d reassembled != Marshal'd envelope", i)
		}
	}
}

// TestFrameReader_TooLarge proves a forged length prefix exceeding maxFrameSize
// is rejected with ErrFrameTooLarge (the reassembly buffer cannot grow
// unbounded).
func TestFrameReader_TooLarge(t *testing.T) {
	pr, pw := io.Pipe()
	go func() {
		// A 4-byte BE prefix claiming a frame larger than maxFrameSize.
		var prefix [4]byte
		binary.BigEndian.PutUint32(prefix[:], uint32(maxFrameSize+1))
		_, _ = pw.Write(prefix[:])
		_ = pw.Close()
	}()
	fr := NewFrameReader(pr)
	_, err := fr.ReadFrame()
	if err != ErrFrameTooLarge {
		t.Fatalf("forged length prefix must ErrFrameTooLarge, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// G3.5.l — source guard: no unsafe, no internal imports (static tooth)
// ---------------------------------------------------------------------------

// TestReceiver_SourceGuard greps pkg/receive non-test Go source for the
// forbidden imports/constructs: no `unsafe` import, no import of
// internal/transport, internal/chaos, internal/network, internal/database
// (receive is a leaf over the gate packages), and no runtime.Pin / unix.Mmap
// (the 2.0-tied forward path uses TransmitHeapBuffer, which is already
// guarded; pkg/receive source does NOT Pin any mmap/C region).
func TestReceiver_SourceGuard(t *testing.T) {
	dir := "."
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir pkg/receive: %v", err)
	}
	forbiddenImports := []string{
		"\"unsafe\"",
		"\"github.com/hr18vk/supremum/internal/transport\"",
		"\"github.com/hr18vk/supremum/internal/chaos\"",
		"\"github.com/hr18vk/supremum/internal/network\"",
		"\"github.com/hr18vk/supremum/internal/database\"",
	}
	forbiddenCalls := []string{
		"runtime.Pin",    // pkg/receive must NOT Pin directly (2.0 forward path owns the Pin)
		"unix.Mmap",      // no mmap in pkg/receive
		"unix.Munmap",    // no munmap in pkg/receive
		"runtime.Pinner", // no direct Pinner use (TransmitHeapBuffer owns it)
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		src := string(b)
		for _, imp := range forbiddenImports {
			if strings.Contains(src, imp) {
				t.Errorf("G3.5.l: forbidden import %s in %s (pkg/receive is a leaf over the gate packages; no unsafe, no internal/*)", imp, name)
			}
		}
		for _, call := range forbiddenCalls {
			if strings.Contains(src, call) {
				t.Errorf("G3.5.l: forbidden call %s in %s (pkg/receive must NOT Pin/mmap directly; the 2.0 forward path owns the Pin via TransmitHeapBuffer)", call, name)
			}
		}

		// Desync tooth (mandatory, Track 3.5 pre-commit action): the envelope
		// byte-offset layout MUST be sourced from attribution.HeaderLen /
		// HopSize / PubSize / SigSize, NEVER re-derived as literals in
		// pkg/receive. A prior Track 3.5 draft hardcoded `const hdrLen =
		// 2 + 2 + 4 + 64` and `const hopSz = 32 + 64 + 8` here; when
		// envelope.go's WallSize drifted (8 -> 16), the receiver kept the
		// stale 104-byte hop size while Marshal wrote 112-byte hops, so the
		// wall-timestamp read drifted into the next hop's relayPub bytes ->
		// a far-future physical timestamp -> an honest-but-false 3.0 clock-
		// cap reject that named the WRONG cause (silent misattribution, the
		// exact class verified live by the Architect this track). Sourcing
		// the consts from the single truth in pkg/attribution kills the drift
		// at the source: a layout change propagates by const-reference, so the
		// receiver and the encoder can never disagree. This tooth ensures the
		// offset literals never creep back into pkg/receive.
		forbiddenOffsets := []string{
			"2 + 2 + 4 + 64",
			"2+2+4+64",
			"32 + 64 + 8",
			"32+64+8",
		}
		for _, off := range forbiddenOffsets {
			if strings.Contains(src, off) {
				t.Errorf("G3.5.l-DSYN: forbidden byte-offset literal %q in %s (source from attribution.HeaderLen/HopSize; a hardcoded duplicate silently misattributes on envelope layout drift)", off, name)
			}
		}
	}
}
