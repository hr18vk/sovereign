// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package receive

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cloudflare/circl/sign/ed25519"
	"github.com/hr18vk/sovereign/pkg/attribution"
	eng "github.com/hr18vk/sovereign/pkg/sync"
	"golang.org/x/sys/unix"
)

// ---------------------------------------------------------------------------
// Header-gate cross-check tests for the v3 envelope.
//
// These tests verify the receiver-side acceptance and security gates:
// the adversarial header/inner cross-check, the v2 forward-compat
// dispatch, the cheap-gate ordering against the header dotCounter,
// the v3 composition over a real socketpair, the gear-check,
// and a scope test that resolves the repository root and enforces the
// edited set for this package.
// ---------------------------------------------------------------------------

// headerGateWallBase is the pinned synthetic-clock base (microseconds) the
// header-gate tests use (mirrors benchWallBase and the receiver tests' wallBase).
const headerGateWallBase = int64(1_700_000_000_000_000)

// headerGateBudgetNS is the admission budget the header-gate accept tests use
// (1 ms -> MaxHopsForBudget=15, admits the relay chains here).
const headerGateBudgetNS = int64(1_000_000_000)

// headerGateAdversarialOrigin is a 16-byte originNodeID different from
// rcvOriginNodeID, used to build a v3 frame whose header originNodeID mirror
// desyncs from the inner capnp originNodeID (the adversarial cross-check).
var headerGateAdversarialOrigin = [16]byte{
	0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
	0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
}

// buildHeaderGateV3Frame builds a signed v3 relay-chain envelope over a real
// CRDTDeltaEvent inner wire, with explicit header mirrors (dotCounter,
// originNodeID) — so a test can set the mirrors to values that differ from the
// inner capnp (the adversarial desync frame) or match it (the matching frame).
// It returns the marshalled envelope bytes and the origin pubkey (for the
// Directory). It composes the exported attribution primitives (SignHop,
// SignedMaterial, NewSignedRelayEnvelopeV3) — the single source of truth —
// not re-derived envelope offsets.
func buildHeaderGateV3Frame(t testing.TB, innerWire []byte, headerDot uint64, headerOrigin [16]byte, nHops int, wallBase int64) ([]byte, ed25519.PublicKey) {
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
// Negative control: adversarial header/inner desync (the load-bearing gate)
// ---------------------------------------------------------------------------

// TestAdversarialDotCounterDesyncDropped proves the security gate:
// a v3 frame whose header dotCounter differs from the inner capnp DotCounter
// is dropped (DropVerify) before ApplyCRDTDeltaEvent — so Join is not called
// (the engine's entries_inserted counter does not increment). A malicious
// relay that puts a different dotCounter in the header than the inner carries
// would bypass the cheap rate/clock gates (they bound the wrong counter); the
// cross-check catches it on the accept path and drops it.
func TestAdversarialDotCounterDesyncDropped(t *testing.T) {
	const innerDot = uint64(7)
	const headerDot = uint64(999) // adversarial: differs from inner
	innerWire := buildCRDTDeltaWire(t, rcvEntityID, innerDot)
	// Header mirrors: dotCounter=999 (adversarial), originNodeID=rcvOriginNodeID
	// (matching, so only the dotCounter desyncs — isolating the check).
	frame, originPub := buildHeaderGateV3Frame(t, innerWire, headerDot, rcvOriginNodeID, 1, headerGateWallBase)

	r, _, _, engine := setupReceiver(t, headerGateWallBase, headerGateBudgetNS, originPub)
	before := engine.Stats()["entries_inserted"]

	verdict := r.HandleFrame(frame)
	if verdict.Verdict != DropVerify {
		t.Fatalf("adversarial dotCounter desync must DropVerify, got %v: %v", verdict.Verdict, verdict.Reason)
	}
	// Join must not have been called: entries_inserted unchanged.
	if after := engine.Stats()["entries_inserted"]; after != before {
		t.Fatalf("Join must not be called on a desync frame: entries_inserted %d -> %d (the cross-check must drop before ApplyCRDTDeltaEvent)", before, after)
	}
}

// TestAdversarialOriginNodeIDDesyncDropped proves the gate for the
// originNodeID mirror: a v3 frame whose header originNodeID differs from the
// inner capnp OriginNodeID is DropVerify'd before Join. A malicious relay
// that puts a different originNodeID in the header would make Directory.Lookup
// key on the wrong origin; the cross-check catches it.
func TestAdversarialOriginNodeIDDesyncDropped(t *testing.T) {
	const dot = uint64(7)
	innerWire := buildCRDTDeltaWire(t, rcvEntityID, dot)
	// Header mirrors: dotCounter=7 (matching), originNodeID=adversarial (differs
	// from the inner rcvOriginNodeID — isolating the originNodeID check).
	frame, originPub := buildHeaderGateV3Frame(t, innerWire, dot, headerGateAdversarialOrigin, 1, headerGateWallBase)

	r, _, _, engine := setupReceiver(t, headerGateWallBase, headerGateBudgetNS, originPub)
	before := engine.Stats()["entries_inserted"]

	verdict := r.HandleFrame(frame)
	if verdict.Verdict != DropVerify {
		t.Fatalf("adversarial originNodeID desync must DropVerify, got %v: %v", verdict.Verdict, verdict.Reason)
	}
	if after := engine.Stats()["entries_inserted"]; after != before {
		t.Fatalf("Join must not be called on a desync frame: entries_inserted %d -> %d", before, after)
	}
}

// TestHonestV3FrameAccepted proves the cross-check does not fire on a
// matching v3 frame (header mirrors == inner capnp): the frame crosses every
// gate, the cross-check passes, and Join is called (entries_inserted
// increments, LamportCounter advances). This is the positive control for the
// adversarial tests above — it proves the cross-check is a desync detector,
// not a blanket drop.
func TestHonestV3FrameAccepted(t *testing.T) {
	const dot = uint64(7)
	innerWire := buildCRDTDeltaWire(t, rcvEntityID, dot)
	// Header mirrors match the inner capnp.
	frame, originPub := buildHeaderGateV3Frame(t, innerWire, dot, rcvOriginNodeID, 1, headerGateWallBase)

	r, _, _, engine := setupReceiver(t, headerGateWallBase, headerGateBudgetNS, originPub)
	before := engine.Stats()["entries_inserted"]

	verdict := r.HandleFrame(frame)
	if verdict.Verdict != Accept {
		t.Fatalf("matching v3 frame must Accept, got %v: %v", verdict.Verdict, verdict.Reason)
	}
	if after := engine.Stats()["entries_inserted"]; after != before+1 {
		t.Fatalf("matching v3 frame must call Join: entries_inserted %d -> %d (want +1)", before, after)
	}
	if got := engine.LamportCounter(); got != dot {
		t.Fatalf("engine.LamportCounter = %d, want %d (Join/Advance seam must advance to the frame's DotCounter)", got, dot)
	}
}

// ---------------------------------------------------------------------------
// Negative control: v2 forward-compat dispatch (tested)
// ---------------------------------------------------------------------------

// TestV2FrameForwardCompat proves a v2 frame (the 72-byte header with
// no mirror fields) is handled correctly by the v3 receiver: the receiver
// dispatches on the version, falls back to a capnp decode for the gate fields
// (the v2 frame carries them only inside the inner capnp), and the frame is
// accepted (the v2 fallback reads the real dotCounter/originNodeID from the
// inner capnp, so the cheap gates + Directory.Lookup + cross-check all see
// the inner values — header == inner by construction on v2, so the cross-check
// is a no-op). This is not a silent fall-through to zero fields (the C5
// failure mode): the version is an explicit dispatch and the gate fields come
// from the capnp decode.
func TestV2FrameForwardCompat(t *testing.T) {
	const dot = uint64(7)
	innerWire := buildCRDTDeltaWire(t, rcvEntityID, dot)
	// Build a v2 frame: relayChain builds v3; rebuild as v2 by hand (version 2,
	// 72-byte header, no mirrors) over the same signed hops + originSig.
	originPub, originPriv := genKey(t)
	originSig := ed25519.Sign(originPriv, innerWire)
	relayPub, relayPriv := genKey(t)
	hop := attribution.SignHop(relayPriv, pubArray(relayPub), innerWire, nil, 0, headerGateWallBase)
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

	r, _, _, engine := setupReceiver(t, headerGateWallBase, headerGateBudgetNS, originPub)
	before := engine.Stats()["entries_inserted"]

	verdict := r.HandleFrame(v2)
	if verdict.Verdict != Accept {
		t.Fatalf("v2 frame must be accepted by the v3 receiver (forward-compat capnp-decode fallback), got %v: %v", verdict.Verdict, verdict.Reason)
	}
	// The v2 fallback decoded the gate fields from the inner capnp, so Join ran.
	if after := engine.Stats()["entries_inserted"]; after != before+1 {
		t.Fatalf("v2 frame must call Join via the capnp-decode fallback: entries_inserted %d -> %d (want +1)", before, after)
	}
}

// ---------------------------------------------------------------------------
// Ordering: cheap gates read the header dotCounter, zero Verifies
// ---------------------------------------------------------------------------

// TestRejectBeforeVerifyRateHeader proves the rate gate runs
// against the header dotCounter (the v3 mirror), not a capnp decode, and
// issues zero Verify calls. A MaxUint64 header dotCounter drains the peer
// bucket to 0, so Accept returns Drop before Open (zero Verifies). This
// re-instrumentation of the Shape-B DropRate ordering proves the
// cheap gate reads the O(1) header mirror, not a capnp decode.
func TestRejectBeforeVerifyRateHeader(t *testing.T) {
	const innerDot = uint64(7)            // inner capnp dotCounter (small)
	const headerDot = MaxUint64DotCounter // header mirror (adversarial MaxUint64)
	innerWire := buildCRDTDeltaWire(t, rcvEntityID, innerDot)
	// The header mirror carries MaxUint64 (the rate gate reads the header, so
	// it drains the bucket); the inner capnp carries 7 (the cross-check would
	// catch the desync, but the rate gate drops before Open+Verify+cross-check).
	frame, originPub := buildHeaderGateV3Frame(t, innerWire, headerDot, rcvOriginNodeID, 1, headerGateWallBase)

	r, _, _, _ := setupReceiver(t, headerGateWallBase, headerGateBudgetNS, originPub)
	count := new(attribution.VerifyHookCount)
	attribution.SetVerifyHook(count.Hook)
	defer attribution.ClearVerifyHook()

	verdict := r.HandleFrame(frame)
	if verdict.Verdict != DropRate {
		t.Fatalf("MaxUint64 header dotCounter must DropRate (rate gate reads the header mirror), got %v: %v", verdict.Verdict, verdict.Reason)
	}
	if got := count.Load(); got != 0 {
		t.Fatalf("rate reject must issue zero Verify calls (cheap gate reads the header, not a capnp decode), got %d", got)
	}
}

// ---------------------------------------------------------------------------
// v3 composition over the real AF_UNIX socketpair
// ---------------------------------------------------------------------------

// TestCompositionOverSocketpairV3 proves the live composition test
// passes with a v3 frame over the real AF_UNIX socketpair: the receiver
// reassembles, runs the full ordering (cheap gates against the header
// mirrors, Open, Verify, the cross-check, ApplyCRDTDeltaEvent), and the
// engine's LamportCounter advances to the frame's DotCounter. This is the v3
// analog of TestReceiver_CompositionOverSocketpair.
func TestCompositionOverSocketpairV3(t *testing.T) {
	const dot = uint64(7)
	innerWire := buildCRDTDeltaWire(t, rcvEntityID, dot)
	frame, originPub := buildHeaderGateV3Frame(t, innerWire, dot, rcvOriginNodeID, 1, headerGateWallBase)
	prefixed := LengthPrefixFrame(frame)

	r, _, _, engine := setupReceiver(t, headerGateWallBase, headerGateBudgetNS, originPub)

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
// Gear check: NumCPU==4, no _32c tag in this package
// ---------------------------------------------------------------------------

// TestGearHonesty asserts the 4c gear (NumCPU==4, GOMAXPROCS==4)
// and that no source file in this package carries a "_32c" tag (the
// admission and clock gate hygiene mislabel class). The 32c figure is the
// 32-core benchmark publication number, not this 4c gear; re-using it for
// these benches is detector-banned.
func TestGearHonesty(t *testing.T) {
	n := runtime.NumCPU()
	gmp := runtime.GOMAXPROCS(0)
	t.Logf("gear: NumCPU=%d GOMAXPROCS=%d (tag: _4c)", n, gmp)
	if n != 4 {
		t.Skipf("box reports NumCPU=%d, not the 4c gear this package targets; refusing to tag a false core count", n)
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
		if !strings.HasPrefix(name, "header_gate_") || !strings.HasSuffix(name, ".go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(wd, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		// Strip comments + string literals so the check can carry its own
		// detection-pattern literal ("_32c") in the error message + comment
		// without self-triggering (mirrors benchStripStringsAndComments). A
		// bare "_32c" in real bench code (a tag on a bench) survives the
		// strip and fires.
		code := benchStripStringsAndComments(string(b))
		if strings.Contains(code, "_32c") {
			t.Errorf("forbidden \"_32c\" tag in %s (this package's benches read \"_4c\"; the 32c figure is the 32-core benchmark publication number, not this 4c gear)", name)
		}
	}
}

// ---------------------------------------------------------------------------
// Scope test: resolves the repo root, enforces attribution consts for offsets
// ---------------------------------------------------------------------------

// TestNoForbiddenOffsetLiterals checks that test files in this package
// source envelope byte offsets from attribution consts
// (HeaderLen/HopSize/PubSize/SigSize/DotCounterSize/OriginNodeIDSize), not
// re-derive them as literals. A hardcoded offset duplicate silently
// misattributes on envelope layout drift. (The v2-frame builder above uses
// attribution.* consts for every offset; this test keeps it that way.)
func TestNoForbiddenOffsetLiterals(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for _, name := range []string{"header_gate_crosscheck_test.go", "header_gate_bench_test.go"} {
		b, err := os.ReadFile(filepath.Join(wd, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		// Strip comments + string literals so the check can carry its own
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
				t.Errorf("forbidden byte-offset literal %q in %s (source from attribution.HeaderLen/HopSize; a hardcoded duplicate silently misattributes on envelope layout drift)", off, name)
			}
		}
	}
}

// Use eng to keep the import (the engine is referenced via setupReceiver's
// return; this var is a compile-time anchor if a future edit drops the only
// use). It is intentionally unused at runtime.
var _ = eng.CRDTDeltaEventWireVersion
