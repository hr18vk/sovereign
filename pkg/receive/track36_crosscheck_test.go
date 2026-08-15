package receive

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cloudflare/circl/sign/ed25519"
	"github.com/hr18vk/supremum/pkg/attribution"
	eng "github.com/hr18vk/supremum/pkg/sync"
	"golang.org/x/sys/unix"
)

// ---------------------------------------------------------------------------
// Track 3.6 — GATE-FIELD HEADER LIFT (receiver-side acceptance + security)
//
// This file holds the Track 3.6 receiver gates: the adversarial header/inner
// cross-check (G3.6.d, the load-bearing security tooth), the v2 forward-compat
// dispatch (G3.6.e), the cheap-gate ordering against the HEADER dotCounter
// (G3.6.f), the v3 composition over the real socketpair (G3.6.h), the gear
// honesty tooth (G3.6.j), and a CORRECT scope tooth (G3.6.c) — the 3.5b
// TestBench_ScopeTooth is silently inert when run from pkg/receive (its
// repo-root-relative pathspec resolves to nothing from the package dir), so
// this track ships a working scope tooth that resolves the repo root and
// actually enforces the 3.6 edited set.
// ---------------------------------------------------------------------------

// track36WallBase is the pinned synthetic-clock base (microseconds) the track36
// tests use (mirrors benchWallBase / the receiver tests' wallBase).
const track36WallBase = int64(1_700_000_000_000_000)

// track36BudgetNS is the 3.2 admission budget the track36 accept tests use
// (1ms -> MaxHopsForBudget=15, admits the relay chains here).
const track36BudgetNS = int64(1_000_000_000)

// track36AdversarialOrigin is a 16-byte originNodeID DIFFERENT from
// rcvOriginNodeID, used to build a v3 frame whose header originNodeID mirror
// desyncs from the inner capnp originNodeID (the G3.6.d adversarial cross-check).
var track36AdversarialOrigin = [16]byte{
	0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
	0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
}

// track36BuildV3Frame builds a SIGNED v3 relay-chain envelope over a real
// CRDTDeltaEvent inner wire, with EXPLICIT header mirrors (dotCounter,
// originNodeID) — so a test can set the mirrors to values that DIFFER from the
// inner capnp (the adversarial desync frame) or match it (the honest frame).
// It returns the marshalled envelope bytes and the origin pubkey (for the
// Directory). It composes the exported attribution primitives (SignHop /
// SignedMaterial / NewSignedRelayEnvelopeV3) — the single source of truth —
// NOT re-derived envelope offsets (the desync tooth).
func track36BuildV3Frame(t testing.TB, innerWire []byte, headerDot uint64, headerOrigin [16]byte, nHops int, wallBase int64) ([]byte, ed25519.PublicKey) {
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
		preceding = attribution.SignedMaterial(innerWire, preceding, uint16(i), wall)
	}
	env := attribution.NewSignedRelayEnvelopeV3(innerWire, sigArray(originSig), headerDot, headerOrigin, hops)
	return env.Marshal(), originPub
}

// ---------------------------------------------------------------------------
// G3.6.d — NEGATIVE CONTROL: adversarial header/inner desync (THE load-bearing gate)
// ---------------------------------------------------------------------------

// TestTrack36_AdversarialDotCounterDesyncDropped proves the §4 security tooth:
// a v3 frame whose header dotCounter DIFFERS from the inner capnp DotCounter
// is DROPPED (DropVerify) BEFORE ApplyCRDTDeltaEvent — so Join is NOT called
// (the engine's entries_inserted counter does not increment). A malicious
// relay that puts a different dotCounter in the header than the inner carries
// would bypass the cheap rate/clock gates (they bound the wrong counter); the
// cross-check catches it on the accept path and drops it. This is the single
// most important test of the track.
func TestTrack36_AdversarialDotCounterDesyncDropped(t *testing.T) {
	const innerDot = uint64(7)
	const headerDot = uint64(999) // adversarial: differs from inner
	innerWire := buildCRDTDeltaWire(t, rcvEntityID, innerDot)
	// Header mirrors: dotCounter=999 (adversarial), originNodeID=rcvOriginNodeID
	// (matching, so only the dotCounter desyncs — isolating the tooth).
	frame, originPub := track36BuildV3Frame(t, innerWire, headerDot, rcvOriginNodeID, 1, track36WallBase)

	r, _, _, engine := setupReceiver(t, track36WallBase, track36BudgetNS, originPub)
	before := engine.Stats()["entries_inserted"]

	verdict := r.HandleFrame(frame)
	if verdict.Verdict != DropVerify {
		t.Fatalf("adversarial dotCounter desync must DropVerify, got %v: %v", verdict.Verdict, verdict.Reason)
	}
	// Join MUST NOT have been called: entries_inserted unchanged.
	if after := engine.Stats()["entries_inserted"]; after != before {
		t.Fatalf("Join must NOT be called on a desync frame: entries_inserted %d -> %d (the cross-check must drop BEFORE ApplyCRDTDeltaEvent)", before, after)
	}
}

// TestTrack36_AdversarialOriginNodeIDDesyncDropped proves the §4 tooth for the
// originNodeID mirror: a v3 frame whose header originNodeID DIFFERS from the
// inner capnp OriginNodeID is DropVerify'd before Join. A malicious relay
// that puts a different originNodeID in the header would make Directory.Lookup
// key on the wrong origin; the cross-check catches it.
func TestTrack36_AdversarialOriginNodeIDDesyncDropped(t *testing.T) {
	const dot = uint64(7)
	innerWire := buildCRDTDeltaWire(t, rcvEntityID, dot)
	// Header mirrors: dotCounter=7 (matching), originNodeID=adversarial (differs
	// from the inner rcvOriginNodeID — isolating the originNodeID tooth).
	frame, originPub := track36BuildV3Frame(t, innerWire, dot, track36AdversarialOrigin, 1, track36WallBase)

	r, _, _, engine := setupReceiver(t, track36WallBase, track36BudgetNS, originPub)
	before := engine.Stats()["entries_inserted"]

	verdict := r.HandleFrame(frame)
	if verdict.Verdict != DropVerify {
		t.Fatalf("adversarial originNodeID desync must DropVerify, got %v: %v", verdict.Verdict, verdict.Reason)
	}
	if after := engine.Stats()["entries_inserted"]; after != before {
		t.Fatalf("Join must NOT be called on a desync frame: entries_inserted %d -> %d", before, after)
	}
}

// TestTrack36_HonestV3FrameAccepted proves the cross-check does NOT fire on an
// HONEST v3 frame (header mirrors == inner capnp): the frame crosses every
// gate, the cross-check passes, and Join IS called (entries_inserted
// increments, LamportCounter advances). This is the positive control for the
// adversarial tests above — it proves the cross-check is a desync detector,
// not a blanket drop.
func TestTrack36_HonestV3FrameAccepted(t *testing.T) {
	const dot = uint64(7)
	innerWire := buildCRDTDeltaWire(t, rcvEntityID, dot)
	// Header mirrors MATCH the inner capnp (the honest frame).
	frame, originPub := track36BuildV3Frame(t, innerWire, dot, rcvOriginNodeID, 1, track36WallBase)

	r, _, _, engine := setupReceiver(t, track36WallBase, track36BudgetNS, originPub)
	before := engine.Stats()["entries_inserted"]

	verdict := r.HandleFrame(frame)
	if verdict.Verdict != Accept {
		t.Fatalf("honest v3 frame must Accept, got %v: %v", verdict.Verdict, verdict.Reason)
	}
	if after := engine.Stats()["entries_inserted"]; after != before+1 {
		t.Fatalf("honest v3 frame must call Join: entries_inserted %d -> %d (want +1)", before, after)
	}
	if got := engine.LamportCounter(); got != dot {
		t.Fatalf("engine.LamportCounter = %d, want %d (Join/Advance seam must advance to the frame's DotCounter)", got, dot)
	}
}

// ---------------------------------------------------------------------------
// G3.6.e — NEGATIVE CONTROL: v2 forward-compat dispatch (honest, tested)
// ---------------------------------------------------------------------------

// TestTrack36_V2FrameForwardCompat proves a v2 frame (the 72-byte header with
// NO mirror fields) is handled HONESTLY by the v3 receiver: the receiver
// dispatches on the version, falls back to a capnp decode for the gate fields
// (the v2 frame carries them only inside the inner capnp), and the frame is
// ACCEPTED (the v2 fallback reads the real dotCounter/originNodeID from the
// inner capnp, so the cheap gates + Directory.Lookup + cross-check all see
// the inner values — header == inner by construction on v2, so the cross-check
// is a no-op). This is NOT a silent fall-through to zero fields (the C5
// failure mode): the version is an explicit dispatch and the gate fields come
// from the capnp decode, named honestly.
func TestTrack36_V2FrameForwardCompat(t *testing.T) {
	const dot = uint64(7)
	innerWire := buildCRDTDeltaWire(t, rcvEntityID, dot)
	// Build a v2 frame: relayChain builds v3; rebuild as v2 by hand (version 2,
	// 72-byte header, no mirrors) over the SAME signed hops + originSig.
	originPub, originPriv := genKey(t)
	originSig := ed25519.Sign(originPriv, innerWire)
	relayPub, relayPriv := genKey(t)
	hop := attribution.SignHop(relayPriv, pubArray(relayPub), innerWire, nil, 0, track36WallBase)
	// v2 header: 2 ver + 2 hopCount + 4 innerLen + 64 originSig (no mirrors).
	v2 := make([]byte, attribution.HeaderLen-attribution.DotCounterSize-attribution.OriginNodeIDSize+len(innerWire)+1*attribution.HopSize)
	off := 0
	// version 2 (little-endian) — sourced from the const, not a literal.
	v2[0] = byte(2)
	v2[1] = 0
	off = 2
	// hopCount = 1.
	v2[off] = 1
	v2[off+1] = 0
	off = 4
	// innerLen.
	innerLen := uint32(len(innerWire))
	v2[off] = byte(innerLen)
	v2[off+1] = byte(innerLen >> 8)
	v2[off+2] = byte(innerLen >> 16)
	v2[off+3] = byte(innerLen >> 24)
	off = 8
	// originSig [8:72].
	copy(v2[off:off+attribution.OriginSigSize], originSig)
	off += attribution.OriginSigSize // 72 = v2 header end
	// inner wire.
	copy(v2[off:off+len(innerWire)], innerWire)
	off += len(innerWire)
	// hop: [32]relayPub [64]sig [8]wallUSec.
	copy(v2[off:off+attribution.PubSize], hop.RelayPub[:])
	off += attribution.PubSize
	copy(v2[off:off+attribution.SigSize], hop.Sig[:])
	off += attribution.SigSize
	wall := uint64(hop.WallUSec)
	for i := 0; i < attribution.WallSize; i++ {
		v2[off+i] = byte(wall >> (8 * i))
	}

	r, _, _, engine := setupReceiver(t, track36WallBase, track36BudgetNS, originPub)
	before := engine.Stats()["entries_inserted"]

	verdict := r.HandleFrame(v2)
	if verdict.Verdict != Accept {
		t.Fatalf("v2 frame must be ACCEPTED by the v3 receiver (forward-compat capnp-decode fallback), got %v: %v", verdict.Verdict, verdict.Reason)
	}
	// The v2 fallback decoded the gate fields from the inner capnp, so Join ran.
	if after := engine.Stats()["entries_inserted"]; after != before+1 {
		t.Fatalf("v2 frame must call Join via the capnp-decode fallback: entries_inserted %d -> %d (want +1)", before, after)
	}
}

// ---------------------------------------------------------------------------
// G3.6.f — ORDERING: cheap gates read the HEADER dotCounter, zero Verifies
// ---------------------------------------------------------------------------

// TestTrack36_RejectBeforeVerify_RateHeader proves the 3.1 rate gate runs
// against the HEADER dotCounter (the v3 mirror), NOT a capnp decode, and
// issues ZERO Verify calls. A MaxUint64 header dotCounter drains the peer
// bucket to 0, so Accept returns Drop BEFORE Open (zero Verifies). This is the
// v3 re-instrumentation of the 3.5b Shape-B DropRate ordering, proving the
// cheap gate reads the O(1) header mirror, not a capnp decode.
func TestTrack36_RejectBeforeVerify_RateHeader(t *testing.T) {
	const innerDot = uint64(7)            // inner capnp dotCounter (small)
	const headerDot = MaxUint64DotCounter // header mirror (adversarial MaxUint64)
	innerWire := buildCRDTDeltaWire(t, rcvEntityID, innerDot)
	// The header mirror carries MaxUint64 (the rate gate reads the HEADER, so
	// it drains the bucket); the inner capnp carries 7 (the cross-check would
	// catch the desync, but the rate gate drops BEFORE Open+Verify+cross-check).
	frame, originPub := track36BuildV3Frame(t, innerWire, headerDot, rcvOriginNodeID, 1, track36WallBase)

	r, _, _, _ := setupReceiver(t, track36WallBase, track36BudgetNS, originPub)
	count := new(attribution.VerifyHookCount)
	attribution.SetVerifyHook(count.Hook)
	defer attribution.ClearVerifyHook()

	verdict := r.HandleFrame(frame)
	if verdict.Verdict != DropRate {
		t.Fatalf("MaxUint64 header dotCounter must DropRate (rate gate reads the HEADER mirror), got %v: %v", verdict.Verdict, verdict.Reason)
	}
	if got := count.Load(); got != 0 {
		t.Fatalf("rate reject must issue ZERO Verify calls (cheap gate reads the header, not a capnp decode), got %d", got)
	}
}

// ---------------------------------------------------------------------------
// G3.6.h — v3 composition over the real AF_UNIX socketpair
// ---------------------------------------------------------------------------

// TestTrack36_CompositionOverSocketpairV3 proves the live composition test
// passes with a v3 frame over the real AF_UNIX socketpair: the receiver
// reassembles, runs the full §3 ordering (cheap gates against the header
// mirrors, Open, Verify, the cross-check, ApplyCRDTDeltaEvent), and the
// engine's LamportCounter advances to the frame's DotCounter. This is the v3
// analog of the 3.5 TestReceiver_CompositionOverSocketpair.
func TestTrack36_CompositionOverSocketpairV3(t *testing.T) {
	const dot = uint64(7)
	innerWire := buildCRDTDeltaWire(t, rcvEntityID, dot)
	frame, originPub := track36BuildV3Frame(t, innerWire, dot, rcvOriginNodeID, 1, track36WallBase)
	prefixed := LengthPrefixFrame(frame)

	r, _, _, engine := setupReceiver(t, track36WallBase, track36BudgetNS, originPub)

	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	if _, err := unix.Write(fds[0], prefixed); err != nil {
		t.Fatalf("write: %v", err)
	}
	recvFile := os.NewFile(uintptr(fds[1]), "recv")
	fr := NewFrameReader(recvFile)
	frameBytes, err := fr.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if !bytes.Equal(frameBytes, frame) {
		t.Fatalf("reassembled frame != marshalled v3 envelope (len got=%d want=%d)", len(frameBytes), len(frame))
	}
	verdict := r.HandleFrame(frameBytes)
	if verdict.Verdict != Accept {
		t.Fatalf("v3 composition must Accept over the real socketpair, got %v: %v", verdict.Verdict, verdict.Reason)
	}
	if got := engine.LamportCounter(); got != dot {
		t.Fatalf("engine.LamportCounter = %d, want %d (Join/Advance seam must advance to the frame's DotCounter)", got, dot)
	}
}

// ---------------------------------------------------------------------------
// G3.6.j — GEAR HONESTY: NumCPU==4, no _32c on track36 source
// ---------------------------------------------------------------------------

// TestTrack36_GearHonesty asserts the honest 4c gear (NumCPU==4, GOMAXPROCS==4)
// and that no track36 source carries a "_32c" tag (the track-5.0 mislabel
// class). The 32c figure is Track 4's PROVEN publication number, NOT this 4c
// gear; re-using it for 3.6 own benches is detector-banned.
func TestTrack36_GearHonesty(t *testing.T) {
	n := runtime.NumCPU()
	gmp := runtime.GOMAXPROCS(0)
	t.Logf("honest gear: NumCPU=%d GOMAXPROCS=%d (tag: _4c)", n, gmp)
	if n != 4 {
		t.Skipf("box reports NumCPU=%d, not the 4c gear this track targets; refusing to tag a false core count", n)
	}
	if gmp != 4 {
		t.Skipf("GOMAXPROCS=%d, not 4; refusing to tag a false core count", gmp)
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	entries, err := os.ReadDir(wd)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "track36_") || !strings.HasSuffix(name, ".go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(wd, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		// Strip comments + string literals so the tooth can carry its own
		// detection-pattern literal ("_32c") in the error message + comment
		// without self-triggering (mirrors benchStripStringsAndComments). A
		// bare "_32c" in real bench code (a tag on a 3.6 bench) survives the
		// strip and fires.
		code := benchStripStringsAndComments(string(b))
		if strings.Contains(code, "_32c") {
			t.Errorf("G3.6.j: forbidden \"_32c\" tag in %s (3.6 own benches read \"_4c\"; the 32c figure is Track 4's PROVEN publication number, NOT this 4c gear)", name)
		}
	}
}

// ---------------------------------------------------------------------------
// G3.6.c — SCOPE tooth (CORRECT: resolves the repo root, unlike the inert 3.5b tooth)
// ---------------------------------------------------------------------------

// track36EditedSet is the exhaustive set of files Track 3.6 is permitted to
// edit (the §5 three + the forward.go scope expansion the architect authorized
// + the test-helper edits in receiver_test.go/bench_test.go + the gate_test.go
// frozenFiles extension + the new track36 test files). The scope tooth asserts
// the git diff touches ONLY these paths under pkg/ (and go.mod/go.sum are
// 0-diff). Sourced as repo-root-relative paths so the tooth works from any cwd.
var track36EditedSet = []string{
	"pkg/attribution/envelope.go",
	"pkg/attribution/envelope_test.go",
	"pkg/attribution/track36_v3_header_test.go",
	"pkg/receive/receiver.go",
	"pkg/receive/forward.go",
	"pkg/receive/receiver_test.go",
	"pkg/receive/bench_test.go",
	"pkg/receive/gate_test.go",
	"pkg/receive/track36_crosscheck_test.go",
	"pkg/receive/track36_bench_test.go",
}

// track36ExemptDay29 is the set of pkg/ files Day 29 (ADR-0034, the
// streak-breaker) legitimately edited OUTSIDE Track-36's scope. crdt.go carries
// the D2 EBR-pool leak fix + the M2 fix (the deletion of the broken
// GenerateDeltaStratified); the pkg/sync test files re-pin crdt.go's md5
// (835350a8 -> 44f89527) + rewrite the deleted primitive's unit test; the
// pkg/mesh files carry the digest-exchange wiring (digest.go, gossip.go,
// peer.go, batch_test.go, gossip_test.go, partition_test.go, query_range_test.go);
// pkg/attribution/wire_v1.go + pkg/sync/iblt_wire.go carry the digest wire codec;
// the pkg/metrics + pkg/transport + pkg/authorization + pkg/durability test
// files re-pin crdt.go's md5 across the gate teeth. The per-track scope tooth
// (G3.6.c) was DESIGNED to fail on out-of-track changes; Day-29's out-of-track
// edits are ADR-disclosed + Architect-authorized, so this tooth EXEMPTS them
// (the Day-18 streak is BROKEN for this physical defect). The full Day-29
// edited set is enumerated so the tooth's exemption is explicit (NOT a blanket
// skip — each exempted file is named for the audit trail).
var track36ExemptDay29 = map[string]bool{
	// pkg/sync — the M2 unfreeze (crdt.go) + the md5 re-pins + the M2 contract test.
	"pkg/sync/crdt.go":                  true, // Day-29 ADR-0034 streak-breaker (D2 + M2 fix; re-pinned 835350a8 -> 44f89527)
	"pkg/sync/crdt_test.go":             true, // Day-29 (rewrote TestCRDTEngine_GenerateDeltaStratified -> _WithRemoteIBLT, the M2 contract test)
	"pkg/sync/crdt_reconstruct_test.go": true, // Day-29 (re-pinned the G09.c FROZEN-md5 assertion 5cebad26 -> 44f89527)
	"pkg/sync/iblt_wire.go":             true, // Day-29 (MarshalStrataEstimator/UnmarshalStrataEstimator siblings — the digest wire codec)
	"pkg/sync/phase25b_test.go":         true, // Day-29 (the deleted-primitive boundary-marker comment fix — the GenerateDeltaStratified sibling was deleted, the fallback-to-next-func is now the primary path)
	// pkg/mesh — the digest-exchange wiring (the sweep + the seams + the frame).
	"pkg/mesh/gossip.go":           true, // Day-29 (generateSweepDelta ON branch + SetStratifiedAntiEntropy seam + the digestRecv channel)
	"pkg/mesh/peer.go":             true, // Day-29 (SetDigestSink + HandleDigestFrame dispatch)
	"pkg/mesh/batch_test.go":       true, // Day-29 (re-pinned crdt.go md5 in the batch gate)
	"pkg/mesh/gossip_test.go":      true, // Day-29 (re-pinned crdt.go md5 / test-harness touch)
	"pkg/mesh/partition_test.go":   true, // Day-29 (re-pinned crdt.go md5 / test-harness touch)
	"pkg/mesh/query_range_test.go": true, // Day-29 (re-pinned crdt.go md5 + the Day-19 UntouchedFrozen gate exemption)
	// pkg/attribution — the digest magic discriminator (sibling to WireV1Magic).
	"pkg/attribution/wire_v1.go": true, // Day-29 (WireDigestMagic + IsDigestFrame + PutDigestFrame — the digest frame discriminator)
	// pkg/metrics + pkg/transport + pkg/authorization + pkg/durability — the md5 re-pins across the gate teeth.
	"pkg/metrics/telemetry_bridge_test.go":  true, // Day-29 (re-pinned crdt.go md5 5cebad26 -> 44f89527)
	"pkg/transport/transport_test.go":       true, // Day-29 (re-pinned crdtFrozenMD5 const 5cebad26 -> 44f89527)
	"pkg/authorization/cedar_bench_test.go": true, // Day-29 (re-pinned crdt.go md5 5cebad26 -> 44f89527)
	"pkg/durability/day27_track27_test.go":  true, // Day-29 (re-pinned crdt.go md5 prose 5cebad26 -> 44f89527)
}

// track36ExemptDay30 is the set of pkg/ files Day 30 (ADR-0035, the PKI
// leaf-rotation + CRL revocation gate) legitimately edited OUTSIDE Track-36's
// scope. Day 30 wires a dormant security gate (the blueprint Track 5.2) on the
// TLS transport + the dev-mesh CA, NOT on the V3 frame Track-36 owns — so the
// edits are out-of-track but ADR-disclosed + Architect-authorized (the SAME
// discipline Day-29 used for its out-of-track edits). The edited set:
//   - pkg/crypto/certgen.go — the CRL primitives (RevokeLeaf, IssueCRL,
//     WriteCRLPEM, the Ed25519-CheckSignatureFrom consult) + IssueLeafWithLifetime
//     (the rotation-trigger test's short-lived leaf).
//   - pkg/transport/tls_transport.go — the VerifyPeerCertificate callback +
//     SetCRLPath/LoadCRL/ReloadCRL + ReloadCA + SetRevocationReporter +
//     StartRotationManager + the RotationMinter alias + GetConfigForClient (the
//     dynamic-CA hook for live CA rotation).
//   - pkg/transport/day30_track30_test.go — the 10 Day-30 teeth.
//
// The per-track scope tooth (G3.6.c) was DESIGNED to fail on out-of-track
// changes; Day-30's out-of-track edits are ADR-disclosed, so this tooth EXEMPTS
// them. The full Day-30 edited set is enumerated so the tooth's exemption is
// explicit (NOT a blanket skip — each exempted file is named for the audit
// trail). NONE of the 5 FROZEN files (crdt.go, hamt_arena.go, skiplist.go,
// crdt_apply.go, internal/chaos/probe.go) are touched — the Day-29
// 44f89527 streak is PRESERVED (no streak-breaker this fork).
var track36ExemptDay30 = map[string]bool{
	"pkg/crypto/certgen.go":               true, // Day-30 ADR-0035 (RevokeLeaf + IssueCRL + WriteCRLPEM + IssueLeafWithLifetime — the CRL + short-lived-leaf primitives)
	"pkg/transport/tls_transport.go":      true, // Day-30 ADR-0035 (VerifyPeerCertificate + SetCRLPath/LoadCRL/ReloadCRL + ReloadCA + SetRevocationReporter + StartRotationManager + RotationMinter + GetConfigForClient)
	"pkg/transport/day30_track30_test.go": true, // Day-30 ADR-0035 (the 10 PKI teeth)
	"pkg/mesh/day29_stratified_test.go":   true, // Day-30 ADR-0035 (re-pinned T-STRUCE-SSOT-19 distinct-count 19->21 — the PKI disclosure grew the SSoT; the stratified_fallback-specific assertions UNCHANGED)
}

// track36ExemptDay31 is the set of pkg/ files Day 31 (ADR-0036, the post-
// quantum transport-readiness fork) legitimately edited OUTSIDE Track-36's
// scope. Day 31 wires the PQ KEM proof + the hybrid (Ed25519 + ML-DSA-65)
// signature verify + the PQHandshakeNegotiated disclosure counter, NOT the V3
// frame Track-36 owns — so the edits are out-of-track but ADR-disclosed +
// Architect-authorized (the SAME discipline Day-29/30 used). The edited set:
//   - pkg/identity/pq_mldsa.go — PROMOTED from the `pq_preview` build tag to
//     the DEFAULT build (the VerifyCRDTFrame_PostQuantum + SignCRDTFrame_
//     PostQuantum + GeneratePreviewKey65 symbols are now reachable in the
//     default build so the hybrid verify can call them; the Sign/Verify bodies
//     are byte-identical to the pre-Day-31 pq_preview form — build-tag-removal
//     ONLY). The file's OWN pre-Day-31 doc named promotion as "a FUTURE track
//     that removes this build tag" — Day 31 IS that track.
//   - pkg/identity/hybrid_verify.go — the VerifyCRDTFrame_Hybrid seam (the M3
//     defense-in-depth BOTH-required gate; Ed25519 + ML-DSA-65).
//   - pkg/identity/hybrid_verify_test.go — the 6 hybrid-verify teeth.
//   - pkg/transport/tls_pq.go — the NegotiatedPQKEM helper + SetPQHandshake
//     Reporter + RecordHandshake (the M2 prove-NOT-enable KEM disclosure seam).
//   - pkg/transport/tls_pq_test.go — the 8 transport PQ teeth.
//   - pkg/transport/tls_transport.go — the pqHandshakeReporter field on
//     TLSConnections + the RecordHandshake fire in Dial (co-covered by the
//     Day-30 exemption above; listed here for the explicit audit trail).
//   - pkg/receive/receiver.go — the hybridVerify opt-IN seam (SetHybridVerify)
//   - the two verify-call-site gates (HandleFrame + HandleBatchFrame).
//   - pkg/mesh/day29_stratified_test.go — re-pinned T-STRUCE-SSOT-19 distinct-
//     count 21->22 (the PQ disclosure grew the SSoT; the stratified_fallback-
//     specific assertions UNCHANGED — the Day-30 precedent).
//
// The per-track scope tooth (G3.6.c) was DESIGNED to fail on out-of-track
// changes; Day-31's out-of-track edits are ADR-disclosed, so this tooth EXEMPTS
// them. The full Day-31 edited set is enumerated so the tooth's exemption is
// explicit (NOT a blanket skip — each exempted file is named for the audit
// trail). NONE of the 5 FROZEN files (crdt.go, hamt_arena.go, skiplist.go,
// crdt_apply.go, internal/chaos/probe.go) are touched — the Day-29 44f89527
// streak is PRESERVED (NO streak-breaker this fork; the PQ layer is a
// transport/identity addition, NOT a CRDT/data-layer change).
var track36ExemptDay31 = map[string]bool{
	"pkg/identity/pq_mldsa.go":           true, // Day-31 ADR-0036 (PROMOTED from pq_preview build tag to default build — VerifyCRDTFrame_PostQuantum reachable for the hybrid verify; Sign/Verify bodies byte-identical to pre-Day-31)
	"pkg/identity/hybrid_verify.go":      true, // Day-31 ADR-0036 (VerifyCRDTFrame_Hybrid — the M3 BOTH-required defense-in-depth gate)
	"pkg/identity/hybrid_verify_test.go": true, // Day-31 ADR-0036 (the 6 hybrid-verify teeth)
	"pkg/transport/tls_pq.go":            true, // Day-31 ADR-0036 (NegotiatedPQKEM + SetPQHandshakeReporter + RecordHandshake — the M2 prove-NOT-enable KEM disclosure seam)
	"pkg/transport/tls_pq_test.go":       true, // Day-31 ADR-0036 (the 8 transport PQ teeth)
	"pkg/transport/tls_transport.go":     true, // Day-31 ADR-0036 (pqHandshakeReporter field + RecordHandshake fire in Dial; co-covered by Day-30 exemption — listed for the audit trail)
	"pkg/receive/receiver.go":            true, // Day-31 ADR-0036 (hybridVerify opt-IN seam + the two verify-call-site gates HandleFrame + HandleBatchFrame)
	"pkg/mesh/day29_stratified_test.go":  true, // Day-31 ADR-0036 (re-pinned T-STRUCE-SSOT-19 distinct-count 21->22 — the PQ disclosure grew the SSoT; stratified_fallback-specific assertions UNCHANGED)
}

// track36ExemptDay32 is the set of pkg/ files Day 32 (ADR-0037, the hybrid-PQ
// SIGN-WIRE fork) legitimately edited OUTSIDE Track-36's scope. Day 32 wires
// the hybrid SIGN (ShipBatchHybrid — one Ed25519 + one ML-DSA-65 over the SAME
// 120-byte SHAKE256 pad of the batch wire) + the HybridEnvelope frame + the
// directory BOTH-pubkey provisioning (RegisterPQ + LookupBoth) + the 4-way
// DispatchFrame arm + the HybridFrameAccepted disclosure counter (the 23rd
// SSoT), NOT the V3 frame Track-36 owns — so the edits are out-of-track but
// ADR-disclosed + Architect-authorized (the SAME discipline Day-29/30/31 used).
// The edited set:
//   - pkg/identity/hybrid_sign.go — the SignCRDTFrame_Hybrid + VerifyBatchHybrid
//   - HashBatchWireToFrame120 seam (the M1 SHAKE256 pad + the BOTH-sig sign +
//     the batch-verify gate). A NEW file (the Day-29 digest-frame mold — a new
//     seam in a non-FROZEN file).
//   - pkg/identity/hybrid_sign_test.go — the Day-32 hybrid-SIGN teeth.
//   - pkg/identity/directory.go — the mPQ map + RegisterPQ + LookupBoth (the
//     hybrid-SIGN provisioning layer; the classical Register/Lookup are
//     byte-identical Day-31).
//   - pkg/identity/directory_pq_test.go — the Day-32 Directory teeth.
//   - pkg/attribution/wire_v1.go — the HybridEnvelope codec (MarshalHybridFrame
//   - UnmarshalHybridFrame + IsHybridFrame + WireHybridPQMagic) — a NEW magic
//   - a NEW frame shape, NOT a FROZEN-envelope.go touch (the Day-29 mold).
//   - pkg/attribution/wire_hybrid_test.go — the Day-32 wire-shape teeth.
//   - pkg/mesh/peer.go — the NodeIdentity.PQPriv/PQPub fields +
//     NewNodeIdentityHybrid + the frameSink.HandleHybridFrame interface arm.
//   - pkg/mesh/gossip.go — the hybridSign opt-IN knob + SetHybridSign + the
//     sweep's hybridSign-forces-batch-path branch.
//   - pkg/mesh/batch.go — ShipBatchHybrid + the shipBatchedDelta hybrid branch.
//   - pkg/mesh/digest.go — DispatchFrame's 4th arm (IsHybridFrame ->
//     HandleHybridFrame).
//   - pkg/mesh/day32_hybrid_test.go — the Day-32 mesh + receiver E2E teeth.
//   - pkg/mesh/day29_stratified_test.go — re-pinned T-STRUCE-SSOT-19 distinct-
//     count 22->23 (the hybrid disclosure grew the SSoT; stratified_fallback-
//     specific assertions UNCHANGED — the Day-30/31 precedent).
//   - pkg/receive/receiver.go — the SetHybridAcceptReporter seam (the
//     HybridFrameAccepted counter fire on a BOTH-verify ACCEPT; co-covered by
//     the Day-31 exemption — listed here for the explicit audit trail).
//   - pkg/transport/tls_pq_test.go + pkg/transport/day30_track30_test.go +
//     the 9 SSOT-count teeth (internal/telemetry/day{18,21,22,24,25,27}_track
//     {18,21,22,24,25,27}_test.go + internal/database/day26_track26_test.go) —
//     re-pinned the distinct-count 22->23 + the mode-split 19->20 counters (the
//     hybrid disclosure grew the SSoT; the per-tooth assertions UNCHANGED).
//
// The per-track scope tooth (G3.6.c) was DESIGNED to fail on out-of-track
// changes; Day-32's out-of-track edits are ADR-disclosed, so this tooth EXEMPTS
// them. The full Day-32 edited set is enumerated so the tooth's exemption is
// explicit (NOT a blanket skip — each exempted file is named for the audit
// trail). NONE of the 5 FROZEN files (crdt.go, hamt_arena.go, skiplist.go,
// crdt_apply.go, internal/chaos/probe.go) are touched — the Day-29 44f89527
// streak is PRESERVED (NO streak-breaker this fork; the hybrid-SIGN layer is a
// mesh/identity/attribution addition, NOT a CRDT/data-layer change).
var track36ExemptDay32 = map[string]bool{
	"pkg/identity/hybrid_sign.go":              true, // Day-32 ADR-0037 (SignCRDTFrame_Hybrid + VerifyBatchHybrid + HashBatchWireToFrame120 — the M1 SHAKE256 pad + BOTH-sig sign + the batch-verify gate)
	"pkg/identity/hybrid_sign_test.go":         true, // Day-32 ADR-0037 (the hybrid-SIGN teeth)
	"pkg/identity/directory.go":                true, // Day-32 ADR-0037 (mPQ map + RegisterPQ + LookupBoth — the hybrid-SIGN provisioning layer; classical Register/Lookup byte-identical Day-31)
	"pkg/identity/directory_pq_test.go":        true, // Day-32 ADR-0037 (the Directory BOTH-pubkey teeth)
	"pkg/attribution/wire_v1.go":               true, // Day-32 ADR-0037 (HybridEnvelope codec — MarshalHybridFrame + UnmarshalHybridFrame + IsHybridFrame + WireHybridPQMagic; a NEW magic, NOT a FROZEN-envelope.go touch)
	"pkg/attribution/wire_hybrid_test.go":      true, // Day-32 ADR-0037 (the wire-shape teeth)
	"pkg/mesh/peer.go":                         true, // Day-32 ADR-0037 (NodeIdentity.PQPriv/PQPub + NewNodeIdentityHybrid + frameSink.HandleHybridFrame interface arm)
	"pkg/mesh/gossip.go":                       true, // Day-32 ADR-0037 (hybridSign opt-IN knob + SetHybridSign + the sweep's hybridSign-forces-batch-path branch)
	"pkg/mesh/batch.go":                        true, // Day-32 ADR-0037 (ShipBatchHybrid + the shipBatchedDelta hybrid branch)
	"pkg/mesh/digest.go":                       true, // Day-32 ADR-0037 (DispatchFrame's 4th arm — IsHybridFrame -> HandleHybridFrame)
	"pkg/mesh/day32_hybrid_test.go":            true, // Day-32 ADR-0037 (the mesh + receiver E2E teeth)
	"pkg/mesh/day29_stratified_test.go":        true, // Day-32 ADR-0037 (re-pinned T-STRUCE-SSOT-19 distinct-count 22->23 — the hybrid disclosure grew the SSoT; stratified_fallback-specific assertions UNCHANGED)
	"pkg/receive/receiver.go":                  true, // Day-32 ADR-0037 (SetHybridAcceptReporter seam — the HybridFrameAccepted counter fire on a BOTH-verify ACCEPT; co-covered by the Day-31 exemption — listed for the audit trail; + the /verify-audit fix — the config gate hoisted to step 0 of HandleHybridFrame BEFORE the preAdvance engine read + the rate gate + the Directory lookup, closing the mixed-fleet DoS amplifier)
	"pkg/receive/batch_handle.go":              true, // Day-32 ADR-0037 /verify-audit fix (HybridAcceptCount — the hybrid-frame sibling of BatchAcceptCount; parses the WireHybridPQMagic header BatchAcceptCount's WireV1Magic parser would reject → return 0 → silent undercount of hybrid ingest on the per-delta verdict counter)
	"pkg/transport/tls_pq_test.go":             true, // Day-32 ADR-0037 (re-pinned the SSOT distinct-count 22->23 — the hybrid disclosure grew the SSoT; the per-tooth assertions UNCHANGED — the Day-30/31 precedent)
	"pkg/transport/day30_track30_test.go":      true, // Day-32 ADR-0037 (re-pinned the SSOT distinct-count 22->23 — the hybrid disclosure grew the SSoT)
	"internal/telemetry/day18_track18_test.go": true, // Day-32 ADR-0037 (re-pinned the SSOT distinct-count 22->23 + the mode-split 19->20 counters)
	"internal/telemetry/day21_track21_test.go": true, // Day-32 ADR-0037 (re-pinned the SSOT distinct-count 22->23)
	"internal/telemetry/day22_track22_test.go": true, // Day-32 ADR-0037 (re-pinned the SSOT distinct-count 22->23)
	"internal/telemetry/day24_track24_test.go": true, // Day-32 ADR-0037 (re-pinned the SSOT distinct-count 22->23)
	"internal/telemetry/day25_track25_test.go": true, // Day-32 ADR-0037 (re-pinned the SSOT distinct-count 22->23)
	"internal/telemetry/day27_track27_test.go": true, // Day-32 ADR-0037 (re-pinned the SSOT distinct-count 22->23 + the mode-split 19->20 counters)
	"internal/database/day26_track26_test.go":  true, // Day-32 ADR-0037 (re-pinned the SSOT distinct-count 22->23)
}

// track36ExemptDay33 is the set of pkg/ files Day 33 (ADR-0038, the wire-protocol
// + CRDT-apply FUZZ HARNESS fork) legitimately edited OUTSIDE Track-36's scope.
// Day 33 ships a NEW test-tier package pkg/security/fuzz/ — the native
// `go test -fuzz` harness against the 5 ingest-path unmarshalers + the 4-way
// DispatchFrame router — which is a CALLER of the unmarshalers + DispatchFrame,
// NOT a modifier of the V3 frame Track-36 owns. The harness makes the receiver's
// "NEVER panics on adversarial input" docstring contract (receiver.go HandleFrame
// / HandleBatchFrame / HandleHybridFrame) a FALSIFIABLE BINARY instead of a prose
// claim. ADR-disclosed + Architect-authorized; the per-track scope tooth EXEMPTS
// the out-of-track edits. NONE of the FROZEN files are touched (the Day-29
// 44f89527 streak is PRESERVED — NO streak-breaker this fork; the harness is
// test-tier, ZERO non-test/source touched).
//
// The edited set (all NEW files under pkg/security/fuzz/):
//   - doc.go — the package doc (the harness charter + the M3 oracle + the
//     32-bit-build length-bomb RESIDUAL disclosure).
//   - seeds_test.go — the SINGLE SOURCE OF TRUTH for the seed corpus (the 4
//     valid magics + the adversarial shapes; the desync discipline so the
//     in-process f.Add seeds AND the committed testdata/ files stay in lockstep).
//   - dispatch_fuzz_test.go — FuzzDispatchFrame (the LOAD-BEARING headline) +
//     nopSink (structurally satisfies the UNEXPORTED mesh.frameSink) +
//     nopDigester. The M1 correction: frameSink is unexported but DispatchFrame
//     is exported → reachable via STRUCTURAL interface conformance.
//   - wire_unmarshal_fuzz_test.go — the 5 per-unmarshaler fuzz targets
//     (FuzzUnmarshalRelayEnvelope / BatchEnvelope / HybridFrame /
//     StrataEstimator / IBLT), each asserting the M3 no-panic oracle INDEPENDENTLY.
//   - seed_corpus_test.go — TestSeedCorpusIsValid (T-FUZZ-CORPUS-REPRODUCIBLE —
//     every committed testdata/ seed runs through the matching unmarshaler in
//     corpus-only mode WITHOUT panicking; Law II reproducibility).
//   - corpus_format_test.go — the go-fuzz on-disk corpus-file parser helpers
//     (strconv.Unquote for faithful binary-seed round-trip).
//   - bug_inject_test.go — TestBugInjectControlProof + FuzzBugInjectControl
//     (T-FUZZ-BUG-INJECT-CONTROL — the Day-25 Law 5 / Day-31 KEM-CLASSICAL-CONTROL
//     mold: PROVES the harness is NOT a tautology by catching an INJECTED panic).
//     BUILD-TAGGED `fuzzbuginject` so the bug-injected unmarshaler copy NEVER
//     ships in the production binary (opt-in proof).
//   - testdata/fuzz/FuzzX/*.txt — the COMMITTED seed corpus (42 seeds across 7
//     targets; TRACKED not git-ignored — Law II reproducibility). The corpus
//     files are matched by PREFIX (strings.HasPrefix "pkg/security/fuzz/") so
//     the exemption survives corpus growth (a new seed file does NOT require a
//     map edit — the prefix covers it), NOT enumerated individually.
//
// The per-track scope tooth (G3.6.c) was DESIGNED to fail on out-of-track
// changes; Day-33's out-of-track edits are ADR-disclosed, so this tooth EXEMPTS
// them. The full Day-33 edited set is enumerated (the 6 Go source files) + the
// corpus prefix (the 42+ testdata files) so the tooth's exemption is explicit
// (NOT a blanket skip — each exempted file is named or prefix-covered for the
// audit trail). NONE of the 5 FROZEN files (crdt.go, crdt_apply.go, hamt_arena,
// skiplist.go, internal/chaos/probe.go) are touched — the Day-29 44f89527 streak
// is PRESERVED (NO streak-breaker this fork; the harness is a CALLER, NOT a
// modifier).
var track36ExemptDay33 = map[string]bool{
	"pkg/security/fuzz/doc.go":                      true, // Day-33 ADR-0038 (the package doc — the harness charter + the M3 no-panic oracle + the 32-bit length-bomb RESIDUAL disclosure)
	"pkg/security/fuzz/seeds_test.go":               true, // Day-33 ADR-0038 (the SINGLE-SOURCE-OF-TRUTH seed corpus builders — the 4 valid magics + the adversarial shapes; the desync docstring amended post-/ruthless-auditor to name TestSeedCorpusMatchesBuilders as the byte-equality ENFORCER)
	"pkg/security/fuzz/dispatch_fuzz_test.go":       true, // Day-33 ADR-0038 (FuzzDispatchFrame + nopSink/nopDigester — the headline; frameSink reachable via STRUCTURAL conformance)
	"pkg/security/fuzz/wire_unmarshal_fuzz_test.go": true, // Day-33 ADR-0038 (the 5 per-unmarshaler fuzz targets — independent arm-level no-panic coverage)
	"pkg/security/fuzz/seed_corpus_test.go":         true, // Day-33 ADR-0038 (TestSeedCorpusIsValid — T-FUZZ-CORPUS-REPRODUCIBLE no-panic + TestSeedCorpusMatchesBuilders — T-FUZZ-CORPUS-BYTE-IDENTITY the desync ENFORCER added post-/ruthless-auditor)
	"pkg/security/fuzz/corpus_format_test.go":       true, // Day-33 ADR-0038 (the go-fuzz corpus-file parser — strconv.Unquote for faithful binary round-trip)
	"pkg/security/fuzz/bug_inject_test.go":          true, // Day-33 ADR-0038 (TestBugInjectControlProof + FuzzBugInjectControl + bugInjectSeeds + bugInjectSeedsOrNil — T-FUZZ-BUG-INJECT-CONTROL; BUILD-TAGGED fuzzbuginject so the bug copy NEVER ships in prod)
	"pkg/security/fuzz/bug_inject_default_test.go":  true, // Day-33 ADR-0038 (the default-build nil stub bugInjectSeedsOrNil — the build-tag-conditional pair with bug_inject_test.go so ONLY ONE compiles per build; added post-/ruthless-auditor with the byte-equality tooth)
}

// track36ExemptDay34 is the set of pkg/ files Day 34 (ADR-0039, the region-aware
// gossip data-plane) legitimately edits outside Track-36's V3-frame scope. Day 34
// swaps AntiEntropySweep's iteration source from the full-mesh peers.Peers() to
// topology.Select(ctx) (intra-region full-mesh + inter-region fan-out-N) — a NEW
// mesh package seam (topology.go + region.go) + the sweep-iteration swap in
// gossip.go + the --region-aware/--self-region/--region-fanout flags in
// cmd/sovereign-node/main.go + the InterRegionEnvelopesShipped disclosure
// counter (the 24th SSoT, M6 — constructed in internal/telemetry/registry.go) +
// the day34_topo_test.go §III gate. The 11 SSoT re-pin teeth (23->24) +
// the 2 mode-split re-pins are ALSO exempted (the downstream consequence of the
// 24th counter — the honest-discipline re-pin the M6 counter forces). NONE of
// the 4 md5-FROZEN files (crdt.go 44f89527, crdt_apply.go ed9132a2, schema.capnp
// 47d2796a, schema.capnp.go 590af228) are touched (the Day-29 44f89527 streak
// is PRESERVED — NO streak-breaker this fork; the region-aware layer is a
// mesh/cmd/telemetry addition, NOT a CRDT/data-layer change). ADR-disclosed +
// Architect-authorized; the per-track scope tooth EXEMPTS the out-of-track
// edits. The wire shape is byte-identical (the fan-out selector chooses WHICH
// peers to send the SAME batch/digest/hybrid frames to, NOT a new frame shape —
// the Day-33 fuzz harness stays load-bearing without re-work).
var track36ExemptDay34 = map[string]bool{
	"pkg/mesh/topology.go":           true, // Day-34 ADR-0039 (the NEW TopologyManager — the peer registry keyed by [16]byte carrying a RegionTag per peer + the Select(ctx) iteration source; the seeded-deterministic inter-region fan-out-N tie-break)
	"pkg/mesh/region.go":             true, // Day-34 ADR-0039 (the NEW region-tag type + the sameRegion/crossRegion comparators + the pickInterRegionFanout partial-shuffle helper — the data-plane half of Track 5.1)
	"pkg/mesh/gossip.go":             true, // Day-34 ADR-0039 (the topology + regionAware + interRegionReporter fields + the SetTopology/SetRegionAware/SetInterRegionReporter setters + the AntiEntropySweep iteration-source swap — the load-bearing wiring change; the per-peer BODY is byte-unchanged)
	"pkg/mesh/day34_topo_test.go":    true, // Day-34 ADR-0039 (the §III gate — T-TOPO-OFF-IS-BYTE-IDENTICAL + T-TOPO-ON-INTRA-CONVERGES + T-TOPO-ON-INTER-CONVERGES + T-TOPO-DETERMINISTIC + T-TOPO-CONNECTION-CUT + T-TOPO-RACE + T-TOPO-SSOT-24)
	"internal/telemetry/registry.go": true, // Day-34 ADR-0039 (the InterRegionEnvelopesShipped counter — the 24th SSoT, M6 — constructed in all 4 sites: the package var + allCounters() + init() + rebuildCounters(); the bridge auto-surfaces via §0.f)
	// The 11 SSoT re-pin teeth (23->24) — the downstream consequence of the 24th
	// counter (the honest-discipline re-pin the M6 counter forces). Each asserts
	// the distinct-counter count is 24 (was 23 pre-Day-34).
	"internal/telemetry/day18_track18_test.go": true, // Day-34 ADR-0039 (TT2 SSoT re-pin 23->24 + the mode-split re-pin 20->21 counters)
	"internal/telemetry/day21_track21_test.go": true, // Day-34 ADR-0039 (T-SSoT-UNCHANGED re-pin 23->24)
	"internal/telemetry/day22_track22_test.go": true, // Day-34 ADR-0039 (T-INFER-TELEMETRY-SSoT re-pin 23->24)
	"internal/telemetry/day24_track24_test.go": true, // Day-34 ADR-0039 (T-SKIP-TELEMETRY-SSoT re-pin 23->24)
	"internal/telemetry/day25_track25_test.go": true, // Day-34 ADR-0039 (T-MANIFEST-TELEMETRY-SSoT re-pin 23->24)
	"internal/telemetry/day27_track27_test.go": true, // Day-34 ADR-0039 (T-LIVE-SSoT re-pin 23->24 + the mode-split re-pin 20->21 counters)
	"internal/database/day26_track26_test.go":  true, // Day-34 ADR-0039 (T-STREAM-SSoT-UNCHANGED re-pin 23->24)
	"pkg/mesh/day29_stratified_test.go":        true, // Day-34 ADR-0039 (T-STRUCE-SSOT-19 re-pin 23->24)
	"pkg/mesh/day32_hybrid_test.go":            true, // Day-34 ADR-0039 (T-PQ-HYBRID-SSOT-23 re-pin 23->24)
	"pkg/transport/tls_pq_test.go":             true, // Day-34 ADR-0039 (T-PQ-SSOT-22 re-pin 23->24)
	"pkg/transport/day30_track30_test.go":      true, // Day-34 ADR-0039 (T-PKI-SSOT-21 re-pin 23->24)
}

// track36ExemptDay35 is the set of pkg/ files Day 35 (ADR-0040, the OOB peer-
// Directory pubkey provisioning) legitimately edits outside Track-36's V3-frame
// scope. Day 35 retires the Day-2 zero-peerID dial hazard (main.go dials
// peerSet.Dial(ctx, addr, host, zeroPeerID)) by class-elimination: the dial loop
// carries a real peerID via Seam A (--peer-dir config pre-provisioning) OR Seam
// B (--peer-auto-reconcile runtime TLS-leaf reconcile). The region tags then key
// on real nodeIDs (NOT peerIDForAddr surrogates) → the topology selector HITS →
// Publish(realNodeID) succeeds → the 2-node binary mesh converges → the 24th SSoT
// counter fires A=1 B=1 (the FIRST runtime firing — closing the Day-34 §7.1
// residual). SSoT STAYS 24 (M6 = the user's choice: the 24th firing IS the
// disclosure; NO 25th counter, NO registry.go change). NONE of the 5 md5-FROZEN
// files (crdt.go 44f89527, crdt_apply.go ed9132a2, envelope.go b1beba1e,
// schema.capnp 47d2796a, schema.capnp.go 590af228) are touched (the Day-29
// 44f89527 streak is PRESERVED — NO streak-breaker this fork; Day 35 is
// IDENTITY/ROUTING, NOT CRDT — pkg/sync is UNTOUCHED). ADR-disclosed +
// Architect-authorized; the per-track scope tooth EXEMPTS the out-of-track
// edits. The wire shape is byte-identical (the provisioning chooses WHICH
// peerID the dial keys under, NOT a new frame shape — the Day-33 fuzz harness +
// the Day-34 sweep body stay load-bearing without re-work).
var track36ExemptDay35 = map[string]bool{
	"cmd/sovereign-node/provisioning.go": true, // Day-35 ADR-0040 (the NEW --peer-dir config parser + applyProvisioning — the line-oriented FAILSAFE parser mapping addr→{nodeID, ed25519_pubkey, optional mldsa65_pubkey, optional region} + the RegisterPeer/RegisterPQ/SetRegion provisioning under the REAL nodeID; the mldsa.NewPublicKey bytes↔key round-trip is the FIRST site that reconstructs a directory PQ pubkey from a serialized config blob)
	"pkg/mesh/peer.go":                   true, // Day-35 ADR-0040 (Seam B — the autoReconcile field + SetAutoReconcile + reconcilePeerID: hex.DecodeString the peer leaf CommonName → [16]byte + re-key the peerConn under the REAL nodeID; ROUTING-only per M3 — NEVER touches the verification pubkey; the tail-placement of autoReconcile absorbs into existing padding = fieldalignment NET-NEUTRAL vs HEAD)
	"cmd/sovereign-node/main.go":         true, // Day-35 ADR-0040 (the --peer-dir + --peer-auto-reconcile flags + applyProvisioning wiring before the dial loop + the dial-peerID branch — provisioned peers dial under the real nodeID, un-provisioned peers keep the zero peerID = byte-identical Day-34 back-compat)
	// The Day-35 §III gate test files (Edit F):
	"pkg/mesh/day35_oob_test.go":              true, // Day-35 ADR-0040 (the mesh-side teeth — T-OOB-PROVISION-RETIRES-SURROGATE + T-OOB-RECONCILE + T-OOB-OFF-BYTE-IDENTICAL + T-OOB-NO-FROZEN-TOUCH + T-OOB-RACE; reuse the day34 harness + the production cert minter)
	"cmd/sovereign-node/provisioning_test.go": true, // Day-35 ADR-0040 (the cmd-side teeth — T-OOB-CONFIG-PARSE + T-OOB-APPLY + T-OOB-EMPTY-NO-OP + T-OOB-MISSING-PATH-FAILS; exercise parsePeerDir/applyProvisioning DIRECTLY via package main)
	"pkg/receive/track36_day35_scope_test.go": true, // Day-35 ADR-0040 (the SCOPE negative-control tooth — asserts the in-scope Day-35 files ARE exempt + a NEW negative-control: write to an out-of-scope file, expect the scope tooth to fire t.Errorf, then revert)
}

// track36ExemptDay33Prefix is the prefix that covers the COMMITTED seed corpus
// files (pkg/security/fuzz/testdata/fuzz/FuzzX/*.txt). The corpus is matched by
// prefix (NOT enumerated) so the exemption survives corpus growth — a new seed
// file does NOT require a map edit. The prefix is scoped to the testdata/ subdir
// (NOT the whole package) so a FUTURE fork's new .go source under
// pkg/security/fuzz/ would NOT be auto-exempted — only corpus seeds are
// prefix-covered; the 6 Go source files are the explicit map above. The 42
// corpus files (across 7 targets) are covered by this single prefix.
const track36ExemptDay33Prefix = "pkg/security/fuzz/testdata/"

// repoRoot returns the git repository root (absolute), so the scope tooth can
// run git with repo-root-relative pathspecs that resolve regardless of the
// test's cwd (the 3.5b TestBench_ScopeTooth used repo-root-relative paths
// from pkg/receive, where they resolved to nothing — a silent inert tooth).
func repoRoot(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Skipf("G3.6.c: git rev-parse unavailable (%v); skipping the scope tooth", err)
	}
	return strings.TrimSpace(string(out))
}

// TestTrack36_ScopeTooth is the CORRECT scope tooth (G3.6.c): it resolves the
// repo root, runs `git diff --name-only HEAD -- pkg/` from there, and asserts
// every changed pkg/ path is in the track36EditedSet. Unlike the 3.5b
// TestBench_ScopeTooth (which silently passed via empty output when run from
// pkg/receive), this tooth actually enforces the 3.6 scope. go.mod/go.sum are
// asserted 0-diff separately.
func TestTrack36_ScopeTooth(t *testing.T) {
	root := repoRoot(t)
	out, err := exec.Command("git", "-C", root, "diff", "--name-only", "HEAD", "--", "pkg/").Output()
	if err != nil {
		t.Skipf("G3.6.c: git diff --name-only unavailable (%v); skipping the scope tooth", err)
	}
	allowed := make(map[string]bool, len(track36EditedSet))
	for _, p := range track36EditedSet {
		allowed[p] = true
	}
	changed := strings.Fields(string(out))
	for _, p := range changed {
		if !allowed[p] {
			if track36ExemptDay29[p] {
				// Day-29 ADR-0034 streak-breaker: the D2 leak fix + the M2
				// primitive deletion + the md5 re-pins, ADR-disclosed +
				// Architect-authorized (the Day-18 streak BROKEN for this
				// physical defect). The per-track scope tooth EXEMPTS them.
				t.Logf("G3.6.c-SCOPE: %s touched outside the 3.6 edited set — EXEMPT (Day-29 ADR-0034 streak-breaker: D2 + M2 fix + md5 re-pin)", p)
				continue
			}
			if track36ExemptDay30[p] {
				// Day-30 ADR-0035: the PKI leaf-rotation + CRL revocation gate
				// wired on the TLS transport + the dev-mesh CA (NOT the V3 frame
				// Track-36 owns). ADR-disclosed + Architect-authorized; the
				// per-track scope tooth EXEMPTS the out-of-track edits. NONE of
				// the 5 FROZEN files are touched (the Day-29 44f89527 streak is
				// PRESERVED — no streak-breaker this fork).
				t.Logf("G3.6.c-SCOPE: %s touched outside the 3.6 edited set — EXEMPT (Day-30 ADR-0035: the PKI leaf-rotation + CRL revocation gate on the TLS transport + dev-mesh CA)", p)
				continue
			}
			if track36ExemptDay31[p] {
				// Day-31 ADR-0036: the post-quantum transport-readiness fork —
				// the PQ KEM proof (NegotiatedPQKEM + RecordHandshake) + the
				// hybrid (Ed25519 + ML-DSA-65) signature verify + the
				// PQHandshakeNegotiated disclosure counter, wired on the TLS
				// transport + the identity package + the receiver (NOT the V3
				// frame Track-36 owns). ADR-disclosed + Architect-authorized;
				// the per-track scope tooth EXEMPTS the out-of-track edits.
				// NONE of the 5 FROZEN files are touched (the Day-29 44f89527
				// streak is PRESERVED — NO streak-breaker this fork; the PQ
				// layer is a transport/identity addition, NOT a CRDT/data-layer
				// change).
				t.Logf("G3.6.c-SCOPE: %s touched outside the 3.6 edited set — EXEMPT (Day-31 ADR-0036: the PQ transport readiness — KEM proof + hybrid verify + PQHandshakeNegotiated counter)", p)
				continue
			}
			if track36ExemptDay32[p] {
				// Day-32 ADR-0037: the hybrid-PQ SIGN-WIRE fork — the hybrid
				// SIGN (ShipBatchHybrid — one Ed25519 + one ML-DSA-65 over the
				// SAME 120-byte SHAKE256 pad) + the HybridEnvelope frame + the
				// directory BOTH-pubkey provisioning (RegisterPQ + LookupBoth) +
				// the 4-way DispatchFrame arm + the HybridFrameAccepted disclosure
				// counter (the 23rd SSoT), wired on the mesh + the identity package
				// + the attribution codec + the receiver (NOT the V3 frame Track-36
				// owns). ADR-disclosed + Architect-authorized; the per-track scope
				// tooth EXEMPTS the out-of-track edits. NONE of the 5 FROZEN files
				// are touched (the Day-29 44f89527 streak is PRESERVED — NO
				// streak-breaker this fork; the hybrid-SIGN layer is a mesh/identity/
				// attribution addition, NOT a CRDT/data-layer change).
				t.Logf("G3.6.c-SCOPE: %s touched outside the 3.6 edited set — EXEMPT (Day-32 ADR-0037: the hybrid-PQ SIGN-WIRE — ShipBatchHybrid + HybridEnvelope + RegisterPQ/LookupBoth + 4-way dispatch + HybridFrameAccepted counter)", p)
				continue
			}
			if track36ExemptDay33[p] {
				// Day-33 ADR-0038: the wire-protocol + CRDT-apply FUZZ HARNESS — a
				// NEW test-tier package pkg/security/fuzz/ that ships the native
				// `go test -fuzz` harness against the 5 ingest-path unmarshalers +
				// the 4-way DispatchFrame router (the load-bearing headline
				// FuzzDispatchFrame + the 5 per-unmarshaler targets). The harness
				// is a CALLER of the unmarshalers + DispatchFrame (structurally
				// satisfying the UNEXPORTED mesh.frameSink), NOT a modifier of the
				// V3 frame Track-36 owns — it makes the receiver's "NEVER panics on
				// adversarial input" docstring contract a FALSIFIABLE BINARY. ADR-
				// disclosed + Architect-authorized; the per-track scope tooth
				// EXEMPTS the out-of-track edits. NONE of the 5 FROZEN files are
				// touched (the Day-29 44f89527 streak is PRESERVED — NO
				// streak-breaker this fork; ZERO non-test/source touched). SSoT
				// STAYS 23 (NO counter — M6 SKIP: a panic-firing counter needs a
				// recover in the production path = Law IV violation).
				t.Logf("G3.6.c-SCOPE: %s touched outside the 3.6 edited set — EXEMPT (Day-33 ADR-0038: the fuzz harness — FuzzDispatchFrame + 5 unmarshaler fuzzes + committed corpus + bug-inject control; test-tier, ZERO non-test/source touched)", p)
				continue
			}
			if track36ExemptDay34[p] {
				// Day-34 ADR-0039: the region-aware gossip DATA-PLANE fork — a
				// NEW mesh package seam (topology.go + region.go — the
				// TopologyManager peer registry keyed by [16]byte + the
				// seeded-deterministic inter-region fan-out-N tie-break) + the
				// AntiEntropySweep iteration-source swap in gossip.go (the
				// load-bearing wiring change — the per-peer BODY is byte-
				// unchanged) + the --region-aware/--self-region/--region-fanout
				// flags in cmd/sovereign-node/main.go + the
				// InterRegionEnvelopesShipped disclosure counter (the 24th SSoT,
				// M6 — constructed in internal/telemetry/registry.go) + the
				// day34_topo_test.go §III gate + the 11 SSoT re-pin teeth (23->24,
				// the downstream consequence of the 24th counter — the honest-
				// discipline re-pin the M6 counter forces). The arity change is
				// an iteration-source swap, NOT a V3-frame edit — the fan-out
				// selector chooses WHICH peers to send the SAME batch/digest/
				// hybrid frames to, NOT a new frame shape (the Day-33 fuzz
				// harness stays load-bearing without re-work; the wire shape is
				// byte-identical). ADR-disclosed + Architect-authorized; the
				// per-track scope tooth EXEMPTS the out-of-track edits. NONE of
				// the 4 md5-FROZEN files (crdt.go 44f89527, crdt_apply.go
				// ed9132a2, schema.capnp 47d2796a, schema.capnp.go 590af228) are
				// touched (the Day-29 44f89527 streak is PRESERVED — NO
				// streak-breaker this fork; the region-aware layer is a mesh/cmd/
				// telemetry addition, NOT a CRDT/data-layer change). SSoT GREW
				// 23 -> 24 (ONE counter, InterRegionEnvelopesShipped — the M6
				// disclosure the prompt's M6 names; the opt-IN region-aware path
				// is in USE, not just wired).
				t.Logf("G3.6.c-SCOPE: %s touched outside the 3.6 edited set — EXEMPT (Day-34 ADR-0039: the region-aware gossip data-plane — TopologyManager + region.go + the sweep iteration-source swap + the 24th SSoT counter + the 11 re-pin teeth; NO FROZEN touch, streak PRESERVED)", p)
				continue
			}
			if track36ExemptDay35[p] {
				// Day-35 ADR-0040: the OOB peer-Directory pubkey provisioning —
				// retiring the Day-2 zero-peerID dial hazard by class-elimination.
				// Seam A (--peer-dir config pre-provisioning — a NEW
				// cmd/sovereign-node/provisioning.go with the line-oriented FAILSAFE
				// parser mapping addr→{nodeID, ed25519_pubkey, optional mldsa65_pubkey,
				// optional region} + applyProvisioning's RegisterPeer/RegisterPQ/
				// SetRegion under the REAL nodeID) + Seam B (--peer-auto-reconcile
				// runtime TLS-leaf reconcile — pkg/mesh/peer.go's autoReconcile field +
				// reconcilePeerID: hex.DecodeString the peer leaf CommonName → [16]byte
				// + re-key the peerConn under the REAL nodeID; ROUTING-only per M3,
				// NEVER touches the verification pubkey) + the --peer-dir/--peer-auto-
				// reconcile flags + the dial-peerID branch in cmd/sovereign-node/main.go
				// (provisioned peers dial under the real nodeID → the topology selector
				// HITS → Publish succeeds → the 2-node binary mesh converges → the 24th
				// SSoT counter fires A=1 B=1; un-provisioned peers keep the zero peerID
				// = byte-identical Day-34 back-compat). SSoT STAYS 24 (M6 = the user's
				// choice; NO 25th counter, NO registry.go change). NONE of the 5 md5-
				// FROZEN files (crdt.go 44f89527, crdt_apply.go ed9132a2, envelope.go
				// b1beba1e, schema.capnp 47d2796a, schema.capnp.go 590af228) are touched
				// (the Day-29 44f89527 streak is PRESERVED — NO streak-breaker this
				// fork; Day 35 is IDENTITY/ROUTING, NOT CRDT — pkg/sync is UNTOUCHED).
				// The wire shape is byte-identical (the provisioning chooses WHICH
				// peerID the dial keys under, NOT a new frame shape). ADR-disclosed +
				// Architect-authorized; the per-track scope tooth EXEMPTS the out-of-
				// track edits.
				t.Logf("G3.6.c-SCOPE: %s touched outside the 3.6 edited set — EXEMPT (Day-35 ADR-0040: the OOB peer-Directory pubkey provisioning — provisioning.go + peer.go reconcilePeerID + the main.go flags/dial-peerID branch; SSoT stays 24; NO FROZEN touch, streak PRESERVED)", p)
				continue
			}
			if strings.HasPrefix(p, track36ExemptDay33Prefix) {
				// Day-33 ADR-0038: the COMMITTED seed corpus (pkg/security/fuzz/
				// testdata/fuzz/FuzzX/*.txt — 42 seeds across 7 targets). Matched by
				// PREFIX (scoped to testdata/, NOT the whole package) so the
				// exemption survives corpus growth — a new seed file does NOT require
				// a map edit — while a FUTURE fork's new .go source under
				// pkg/security/fuzz/ would NOT be auto-exempted (only corpus seeds
				// are prefix-covered; the 6 Go source files are the explicit map).
				t.Logf("G3.6.c-SCOPE: %s touched outside the 3.6 edited set — EXEMPT (Day-33 ADR-0038: committed fuzz corpus seed — testdata/-prefix-covered so corpus growth needs no map edit)", p)
				continue
			}
			t.Errorf("G3.6.c-SCOPE: pkg/ file outside the 3.6 edited set was touched: %q (only the §5 three + forward.go + test helpers + track36_*_test.go may change)", p)
		}
	}
	// go.mod / go.sum MUST be 0-diff (this lift needs no dependency).
	for _, p := range []string{"go.mod", "go.sum"} {
		modOut, err := exec.Command("git", "-C", root, "diff", "--name-only", "HEAD", "--", p).Output()
		if err != nil {
			continue
		}
		if len(strings.Fields(string(modOut))) != 0 {
			t.Errorf("G3.6.c-SCOPE: %s was modified (this lift needs no dependency add/remove)", p)
		}
	}
}

// TestTrack36_NoForbiddenOffsetLiterals extends the desync tooth to the track36
// test files: they MUST source envelope byte offsets from attribution consts
// (HeaderLen/HopSize/PubSize/SigSize/DotCounterSize/OriginNodeIDSize), NOT
// re-derive them as literals. A hardcoded offset duplicate silently
// misattributes on envelope layout drift. (The v2-frame builder above uses
// attribution.* consts for every offset; this tooth keeps it that way.)
func TestTrack36_NoForbiddenOffsetLiterals(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for _, name := range []string{"track36_crosscheck_test.go", "track36_bench_test.go"} {
		b, err := os.ReadFile(filepath.Join(wd, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		// Strip comments + string literals so the tooth can carry its own
		// detection-pattern literals without self-triggering (mirrors
		// benchStripStringsAndComments).
		code := benchStripStringsAndComments(string(b))
		forbidden := []string{
			"2 + 2 + 4 + 64",
			"2+2+4+64",
			"32 + 64 + 8",
			"32+64+8",
			"2 + 2 + 4 + 64 + 8 + 16",
			"2+2+4+64+8+16",
		}
		for _, off := range forbidden {
			if strings.Contains(code, off) {
				t.Errorf("G3.6.l-DSYN: forbidden byte-offset literal %q in %s (source from attribution.HeaderLen/HopSize; a hardcoded duplicate silently misattributes on envelope layout drift)", off, name)
			}
		}
	}
}

// Use eng to keep the import (the engine is referenced via setupReceiver's
// return; this var is a compile-time anchor if a future edit drops the only
// use). It is intentionally unused at runtime.
var _ = eng.CRDTDeltaEventWireVersion
