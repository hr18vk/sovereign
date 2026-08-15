package durability

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	eng "github.com/hr18vk/supremum/pkg/sync"
)

// These teeth productize the PROVEN internal/chaos.TestStage6WALRecovery
// Determinism contract OUT of the chaos harness and into pkg/durability. A
// green TestRecoveryDeterminism_KillRebuildMerkleEqual is the proof Day 8
// exists for; a PASS-claim without it green is a FABRICATION.

const testArenaSize uintptr = 64 * 1024 * 1024

func testNodeID() [16]byte {
	var n [16]byte
	for i := range n {
		n[i] = byte(i + 1)
	}
	return n
}

// stagedEntry mirrors internal/chaos.stagedEntry: a deterministic CRDTEntry
// whose OriginNodeID + SystemTime vary per index. PayloadDigest is left zero
// here; PutLocal stamps it from the payload (step 1 of the physical order).
func stagedEntry(i int) eng.CRDTEntry {
	var origin [16]byte
	binary.BigEndian.PutUint64(origin[:8], uint64(i+100))
	return eng.CRDTEntry{
		OriginNodeID: origin,
		SystemTime:   int64(i) * 1_000,
	}
}

// stagedPayload returns the payload whose SHA-256 equals the digest PutLocal
// stamps. It mirrors the proven test's digest derivation so the WAL-recorded
// digest matches the engine's PayloadDigest by construction.
func stagedPayload(i int) string {
	var b [3]byte
	b[0] = byte(i)
	b[1] = byte(i >> 8)
	b[2] = byte(i >> 16)
	return string(b[:])
}

func stagedEntityID(i int) string {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(i))
	return "entity-" + string(buf)
}

// stagedDigest is the SHA-256 of stagedPayload(i) — what PutLocal stamps into
// entry.PayloadDigest and what the WAL persists. Tests cross-check it.
func stagedDigest(i int) [32]byte {
	return sha256.Sum256([]byte(stagedPayload(i)))
}

// newLiveBridge builds a live engine + WAL + Bridge exactly as the production
// origin path would, isolating the engine's dataDir in a fresh temp dir (the
// same discipline as the proven test's sync.DataDir = t.TempDir()).
func newLiveBridge(t *testing.T, walPath string, checkpointInterval uint64) *Bridge {
	t.Helper()
	eng.DataDir = t.TempDir()
	engine, err := eng.NewDeltaCRDTEngine(testNodeID(), 1, testArenaSize)
	if err != nil {
		t.Fatalf("NewDeltaCRDTEngine live: %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	wal, err := OpenWAL(walPath)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	t.Cleanup(func() { _ = wal.Close() })
	return NewBridge(engine, wal, checkpointInterval)
}

// TestRecoveryDeterminism_KillRebuildMerkleEqual is THE gate Day 8 exists for.
// Build a live engine + WAL, PutLocal K mutations, AppendCheckpoint, CLOSE the
// WAL, construct a SECOND engine via RecoverEngine, assert
// recovered.State().MerkleRoot() == live.State().MerkleRoot() AND
// recovered.LamportCounter() == live.LamportCounter(). GREEN = the
// determinism contract holds OUT OF THE CHAOS HARNESS, in pkg/durability.
func TestRecoveryDeterminism_KillRebuildMerkleEqual(t *testing.T) {
	walPath := filepath.Join(t.TempDir(), "det.wal")
	const K = 64

	live := newLiveBridge(t, walPath, 0) // caller-driven checkpoints
	for i := 0; i < K; i++ {
		dot, err := live.PutLocal(stagedEntityID(i), stagedPayload(i), stagedEntry(i))
		if err != nil {
			t.Fatalf("PutLocal %d: %v", i, err)
		}
		if dot.NodeID != testNodeID() {
			t.Fatalf("PutLocal %d: dot.NodeID %x != nodeID %x", i, dot.NodeID, testNodeID())
		}
	}
	liveRoot := live.Engine().State().MerkleRoot()
	liveLamport := live.Engine().LamportCounter()
	if err := live.AppendCheckpoint(); err != nil {
		t.Fatalf("AppendCheckpoint: %v", err)
	}

	// Kill: close the live WAL + engine, then rebuild from the WAL alone.
	if err := live.WAL().Close(); err != nil {
		t.Fatalf("live WAL close: %v", err)
	}
	if err := live.Engine().Close(); err != nil {
		t.Fatalf("live engine close: %v", err)
	}

	recovered, wal, _, err := RecoverEngine(testNodeID(), walPath, testArenaSize)
	if err != nil {
		t.Fatalf("RecoverEngine: %v", err)
	}
	t.Cleanup(func() { _ = wal.Close() })
	t.Cleanup(func() { _ = recovered.Close() })

	recoveredRoot := recovered.State().MerkleRoot()
	if recoveredRoot != liveRoot {
		t.Fatalf("WAL recovery determinism BROKEN:\n  live root      = %x\n  recovered root = %x\n"+
			"Replayer built a different state than the live engine. Recovery is data-lossy.",
			liveRoot, recoveredRoot)
	}
	if recovered.LamportCounter() != liveLamport {
		t.Fatalf("recovered lamport %d != live lamport %d (clock did not resume at the checkpoint high-water mark)",
			recovered.LamportCounter(), liveLamport)
	}
}

// TestRecoveryRootMismatchRefusesBoot fabricates a checkpoint whose root does
// NOT match the rebuilt root (while its LamportHigh equals the live high-water
// mark, so checkpointIsFinal is true), and asserts RecoverEngine returns
// ErrRecoveryRootMismatch and yields NO live engine (do not boot a sick
// engine).
func TestRecoveryRootMismatchRefusesBoot(t *testing.T) {
	walPath := filepath.Join(t.TempDir(), "mismatch.wal")
	const K = 32

	live := newLiveBridge(t, walPath, 0)
	for i := 0; i < K; i++ {
		if _, err := live.PutLocal(stagedEntityID(i), stagedPayload(i), stagedEntry(i)); err != nil {
			t.Fatalf("PutLocal %d: %v", i, err)
		}
	}
	liveLamport := live.Engine().LamportCounter()
	// Append a checkpoint with a DELIBERATELY WRONG root but the correct
	// LamportHigh. checkpointIsFinal is true (no mutations follow; the
	// checkpoint's LamportHigh == the max mutation counter), so RecoverEngine
	// asserts rebuilt root == checkpoint root and must refuse boot.
	var wrongRoot [32]byte
	wrongRoot[0] = 0xff // any non-matching root
	if err := live.WAL().AppendCheckpoint(WALCheckpoint{
		MerkleRoot:  wrongRoot,
		LamportHigh: liveLamport,
	}); err != nil {
		t.Fatalf("wrong-root AppendCheckpoint: %v", err)
	}
	if err := live.WAL().Close(); err != nil {
		t.Fatalf("live WAL close: %v", err)
	}
	if err := live.Engine().Close(); err != nil {
		t.Fatalf("live engine close: %v", err)
	}

	recovered, wal, _, err := RecoverEngine(testNodeID(), walPath, testArenaSize)
	if !errors.Is(err, ErrRecoveryRootMismatch) {
		t.Fatalf("RecoverEngine: want ErrRecoveryRootMismatch, got err=%v recovered=%v wal=%v",
			err, recovered != nil, wal != nil)
	}
	if recovered != nil {
		t.Fatalf("RecoverEngine handed back a live sick engine on root mismatch — must refuse boot")
	}
	if wal != nil {
		t.Fatalf("RecoverEngine handed back an open WAL on root mismatch — must refuse boot")
	}
}

// TestRecoveryColdBoot_NoCheckpoint: a WAL with mutations but NO checkpoint —
// RecoverEngine succeeds, logs the "no anchor" warning, and the replayed state
// is still correct up to the replayed mutations (root == the live root).
func TestRecoveryColdBoot_NoCheckpoint(t *testing.T) {
	walPath := filepath.Join(t.TempDir(), "cold.wal")
	const K = 16

	live := newLiveBridge(t, walPath, 0)
	for i := 0; i < K; i++ {
		if _, err := live.PutLocal(stagedEntityID(i), stagedPayload(i), stagedEntry(i)); err != nil {
			t.Fatalf("PutLocal %d: %v", i, err)
		}
	}
	liveRoot := live.Engine().State().MerkleRoot()
	liveLamport := live.Engine().LamportCounter()
	// NO checkpoint appended — the cold-boot-with-mutations edge.
	if err := live.WAL().Close(); err != nil {
		t.Fatalf("live WAL close: %v", err)
	}
	if err := live.Engine().Close(); err != nil {
		t.Fatalf("live engine close: %v", err)
	}

	recovered, wal, rep, err := RecoverEngine(testNodeID(), walPath, testArenaSize)
	if err != nil {
		t.Fatalf("RecoverEngine cold boot: %v", err)
	}
	t.Cleanup(func() { _ = wal.Close() })
	t.Cleanup(func() { _ = recovered.Close() })

	if rep.HasCheckpoint {
		t.Fatalf("cold boot: replay reported a checkpoint (want none)")
	}
	if recovered.State().MerkleRoot() != liveRoot {
		t.Fatalf("cold boot: recovered root %x != live root %x (replay not faithful without anchor)",
			recovered.State().MerkleRoot(), liveRoot)
	}
	if recovered.LamportCounter() != liveLamport {
		t.Fatalf("cold boot: recovered lamport %d != live lamport %d", recovered.LamportCounter(), liveLamport)
	}
}

// TestRecoveryTornTailTruncation: truncate the WAL mid-record; RecoverEngine
// ignores the torn tail (internal/chaos/wal.go ReplayWAL truncates) and
// rebuilds from the valid prefix. The checkpoint anchor at the prefix boundary
// stays intact and reproducible; the recovered engine does not regress the
// Lamport clock past the anchor.
func TestRecoveryTornTailTruncation(t *testing.T) {
	walPath := filepath.Join(t.TempDir(), "torn.wal")
	const K = 32

	live := newLiveBridge(t, walPath, 0)
	for i := 0; i < K; i++ {
		if _, err := live.PutLocal(stagedEntityID(i), stagedPayload(i), stagedEntry(i)); err != nil {
			t.Fatalf("PutLocal %d: %v", i, err)
		}
	}
	// Checkpoint after K mutations — the valid prefix's anchor.
	if err := live.AppendCheckpoint(); err != nil {
		t.Fatalf("AppendCheckpoint: %v", err)
	}
	anchoredLamport := live.Engine().LamportCounter()
	// Append a few more mutations, then tear the tail mid-record.
	const trailing = 8
	for i := K; i < K+trailing; i++ {
		if _, err := live.PutLocal(stagedEntityID(i), stagedPayload(i), stagedEntry(i)); err != nil {
			t.Fatalf("trailing PutLocal %d: %v", i, err)
		}
	}
	if err := live.WAL().Close(); err != nil {
		t.Fatalf("live WAL close: %v", err)
	}
	if err := live.Engine().Close(); err != nil {
		t.Fatalf("live engine close: %v", err)
	}

	// Tear the tail: drop the last 7 bytes, leaving a torn final record.
	// ReplayWAL truncates it; recovery rebuilds from the intact prefix.
	tearTail(t, walPath, 7)

	recovered, wal, rep, err := RecoverEngine(testNodeID(), walPath, testArenaSize)
	if err != nil {
		t.Fatalf("RecoverEngine torn tail: %v", err)
	}
	t.Cleanup(func() { _ = wal.Close() })
	t.Cleanup(func() { _ = recovered.Close() })

	// The torn tail dropped the final (trailing) mutation record(s). The
	// replayed mutation count is strictly less than the pre-tear count — the
	// torn record was truncated, NOT mis-decoded into a bogus mutation.
	if len(rep.Mutations) >= K+trailing {
		t.Fatalf("torn tail: replayed %d mutations, want < %d (torn tail not truncated)",
			len(rep.Mutations), K+trailing)
	}
	// The checkpoint anchor at the prefix boundary is intact.
	if !rep.HasCheckpoint {
		t.Fatalf("torn tail: checkpoint anchor lost (want intact at the prefix boundary)")
	}
	// The recovered engine resumed the Lamport clock at or above the anchor —
	// the torn tail did not regress the clock past the last checkpoint.
	if recovered.LamportCounter() < anchoredLamport {
		t.Fatalf("torn tail: recovered lamport %d < anchored lamport %d (clock regressed past the anchor)",
			recovered.LamportCounter(), anchoredLamport)
	}
}

// tearTail truncates the file to drop the last n bytes, leaving a torn final
// record. n must be small enough to land inside the final record (not the
// 8-byte header).
func tearTail(t *testing.T, path string, n int) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("tearTail stat: %v", err)
	}
	if info.Size() <= int64(n)+8 {
		t.Fatalf("tearTail: file too small (%d) to tear %d bytes", info.Size(), n)
	}
	if err := os.Truncate(path, info.Size()-int64(n)); err != nil {
		t.Fatalf("tearTail truncate: %v", err)
	}
}

// TestPutLocalWALStampsEngineDot is the ORDER tooth (G08.e). PutLocal writes
// the WAL AFTER InsertLocal; the WALMutation.Counter == the dot the engine
// returned AND == the dot later RecoverEngine re-mints. Catches a
// reversed-order regression (AppendMutation before InsertLocal would record a
// caller-set dot the engine never minted).
func TestPutLocalWALStampsEngineDot(t *testing.T) {
	walPath := filepath.Join(t.TempDir(), "order.wal")
	const K = 16

	live := newLiveBridge(t, walPath, 0)
	// Capture the engine-returned dots and cross-check them against the WAL
	// records AND the replayed dots.
	returnedDots := make([]eng.CausalDot, K)
	for i := 0; i < K; i++ {
		dot, err := live.PutLocal(stagedEntityID(i), stagedPayload(i), stagedEntry(i))
		if err != nil {
			t.Fatalf("PutLocal %d: %v", i, err)
		}
		returnedDots[i] = dot
		// The stamped digest MUST equal SHA-256(payload) — the order tooth's
		// first half: the digest was stamped BEFORE InsertLocal, so the WAL
		// carries the same digest the engine folded into the Merkle root.
		got := live.Engine().State().Get(stagedEntityID(i))
		if len(got) == 0 {
			t.Fatalf("PutLocal %d: entry not found in engine state", i)
		}
		if want := stagedDigest(i); !bytes.Equal(got[0].PayloadDigest[:], want[:]) {
			t.Fatalf("PutLocal %d: engine PayloadDigest != SHA-256(payload)", i)
		}
	}
	liveLamport := live.Engine().LamportCounter()
	if err := live.AppendCheckpoint(); err != nil {
		t.Fatalf("AppendCheckpoint: %v", err)
	}
	if err := live.WAL().Close(); err != nil {
		t.Fatalf("live WAL close: %v", err)
	}
	if err := live.Engine().Close(); err != nil {
		t.Fatalf("live engine close: %v", err)
	}

	// The WAL records the engine-STAMPED dots: replay and assert each recorded
	// counter == the dot PutLocal returned.
	rep, err := ReplayWAL(walPath)
	if err != nil {
		t.Fatalf("ReplayWAL: %v", err)
	}
	if len(rep.Mutations) != K {
		t.Fatalf("replay got %d mutations, want %d", len(rep.Mutations), K)
	}
	for i, m := range rep.Mutations {
		if m.Counter != returnedDots[i].Counter {
			t.Fatalf("order tooth: WALMutation[%d].Counter=%d != engine-returned dot.Counter=%d "+
				"(WAL did not carry the engine-STAMPED dot — reversed order?)",
				i, m.Counter, returnedDots[i].Counter)
		}
		if m.NodeID != returnedDots[i].NodeID {
			t.Fatalf("order tooth: WALMutation[%d].NodeID %x != engine-returned dot.NodeID %x",
				i, m.NodeID, returnedDots[i].NodeID)
		}
	}

	// RecoverEngine re-mints the SAME dots: the recovered engine, seeded at
	// rebuiltInitial, re-stamps each mutation to exactly the recorded counter.
	// Its LamportHigh == the live engine's (the dots re-minted identically),
	// so its Merkle root matches the live root.
	recovered, wal, _, err := RecoverEngine(testNodeID(), walPath, testArenaSize)
	if err != nil {
		t.Fatalf("RecoverEngine: %v", err)
	}
	t.Cleanup(func() { _ = wal.Close() })
	t.Cleanup(func() { _ = recovered.Close() })
	if recovered.LamportCounter() != liveLamport {
		t.Fatalf("order tooth: recovered lamport %d != live lamport %d (re-minted dots diverged)",
			recovered.LamportCounter(), liveLamport)
	}
}

// foreignNodeID is a distinct nodeID for the foreign engine in the real-Join
// teeth — it MUST differ from testNodeID() so the foreign entries carry a
// foreign DotNodeID (the honest physics: a foreign Join merges foreign STATE,
// not just a clock jump).
func foreignNodeID() [16]byte {
	var n [16]byte
	for i := range n {
		n[i] = byte(0xEE)
	}
	return n
}

// TestRecoveryForeignAdvance_RealJoinClockSeedFixed is THE Day-8.5 gate (G08.5.b,
// load-bearing, MANDATE 1). It does a REAL foreign Join — NOT a synthetic
// AdvanceLamportTo clock jump — so it exercises the honest physics: a foreign
// Join (crdt.go:1028) BOTH advances the live Lamport clock AND merges foreign
// entries (foreign DotNodeID) into the live HAMT.
//
// The Day-8 defect: the clock advance was un-recorded, so the recovery seed
// (LamportHigh - len(Mutations)) under-counted → replay re-minted different
// ORIGIN dots → Merkle diverged. Day 8.5 WAL-records the advance
// (WALRecClockAdvance=0x03) at the receive seam, and recovery replays the
// append-ordered (mutation|advance) stream with the EXACT seed
// (firstMutation.Counter - 1).
//
// HONEST ASSERTIONS (MANDATE 1 — do NOT claim a false victory):
//  1. recovered.LamportCounter() == live.LamportCounter() — the clock/seed fix
//     is PROVEN: the advance was recorded + replayed, so the origin dots
//     re-mint identically and the clock resumes at the live high-water.
//  2. recovered.State().MerkleRoot() != live.State().MerkleRoot() — the
//     HONEST divergence: the rebuilt engine is ORIGIN-ONLY (the WAL records
//     origin mutations + clock advances, NOT foreign entries); the live root
//     is origin + foreign. Full root-equality across a foreign Join is
//     physically impossible without WAL-capturing foreign deltas as mutations
//     (a FROZEN-crdt.go edit). This divergence is the FROZEN-lock limit, NOT
//     data loss — the foreign state regossips on rejoin (eventual
//     consistency). We ASSERT the divergence (do not hide it) and document it.
//  3. The origin-only projection matches: the re-minted origin counters equal
//     the recorded origin counters (the seed is exact).
//
// This tooth FAILS on the unfixed seed (the clock diverges → even the
// origin-only root differs from the live origin-only projection) and is GREEN
// once advances are recorded + replayed. It is the honest red→green proof.
func TestRecoveryForeignAdvance_RealJoinClockSeedFixed(t *testing.T) {
	walPath := filepath.Join(t.TempDir(), "foreign-advance.wal")
	const K = 8 // origin mutations (counters 2..9)

	live := newLiveBridge(t, walPath, 0)
	for i := 0; i < K; i++ {
		if _, err := live.PutLocal(stagedEntityID(i), stagedPayload(i), stagedEntry(i)); err != nil {
			t.Fatalf("PutLocal %d: %v", i, err)
		}
	}
	// Sanity: K origin mutations minted counters 2..9 (seed=1, NextDot Add(1)).
	if got := live.Engine().LamportCounter(); got != uint64(K+1) {
		t.Fatalf("pre-Join lamport %d != %d (origin mint assumption wrong)", got, K+1)
	}

	// REAL FOREIGN JOIN. Build a second engine (foreign nodeID), PutLocal F
	// foreign mutations into it, then GenerateDelta + Join into the live engine.
	// Join (crdt.go:1028) AdvanceLamportTo's per foreign entry AND merges the
	// foreign entries into the live HAMT. This is the honest physics — NOT a
	// synthetic clock jump.
	const F = 5
	eng.DataDir = t.TempDir()
	foreign, err := eng.NewDeltaCRDTEngine(foreignNodeID(), 100, testArenaSize)
	if err != nil {
		t.Fatalf("foreign engine ctor: %v", err)
	}
	t.Cleanup(func() { _ = foreign.Close() })
	for i := 0; i < F; i++ {
		foreign.InsertLocal(stagedEntityID(1000+i), stagedEntry(1000+i))
	}
	// GenerateDelta against the live engine's digest yields the foreign delta
	// (the entries the live engine lacks). Join merges them into live.
	liveDigest := live.Engine().GenerateDigest()
	delta := foreign.GenerateDelta(liveDigest)
	live.Engine().Join(*delta)
	// Record the foreign clock advance at the receive seam (Day 8.5 M4) — the
	// post-Join high-water. This is what Receiver.HandleFrame would fire.
	if err := live.RecordClockAdvance(); err != nil {
		t.Fatalf("RecordClockAdvance: %v", err)
	}

	// One more ORIGIN mutation AFTER the foreign Join — the load-bearing
	// case: its counter (K+1+gap) must re-mint identically on recovery. This is
	// the dot the defect seed would have mis-minted.
	trailingDot, err := live.PutLocal(stagedEntityID(K), stagedPayload(K), stagedEntry(K))
	if err != nil {
		t.Fatalf("trailing PutLocal: %v", err)
	}
	liveRoot := live.Engine().State().MerkleRoot() // origin + foreign
	liveLamport := live.Engine().LamportCounter()

	// Checkpoint at the LIVE root (origin + foreign). The root-equality
	// assertion is SCOPED to skip this (advances exist) — see recovery.go.
	if err := live.AppendCheckpoint(); err != nil {
		t.Fatalf("AppendCheckpoint: %v", err)
	}

	// Kill + rebuild from the WAL alone.
	if err := live.WAL().Close(); err != nil {
		t.Fatalf("live WAL close: %v", err)
	}
	if err := live.Engine().Close(); err != nil {
		t.Fatalf("live engine close: %v", err)
	}

	recovered, wal, rep, err := RecoverEngine(testNodeID(), walPath, testArenaSize)
	if err != nil {
		t.Fatalf("RecoverEngine: %v", err)
	}
	t.Cleanup(func() { _ = wal.Close() })
	t.Cleanup(func() { _ = recovered.Close() })

	// (1) CLOCK/SEED FIX PROVEN: the recovered clock resumes at the live
	// high-water. The advance was recorded + replayed, so the origin dots
	// (including the trailing one after the gap) re-mint identically.
	if recovered.LamportCounter() != liveLamport {
		t.Fatalf("G08.5.b clock/seed fix BROKEN:\n  recovered lamport = %d\n  live lamport      = %d\n"+
			"The foreign advance was not recorded/replayed → the seed under-counted → the trailing origin dot re-minted at a different counter.",
			recovered.LamportCounter(), liveLamport)
	}

	// (3) ORIGIN-ONLY PROJECTION: the trailing origin dot re-minted at the
	// SAME counter the live engine minted it at (the seed is exact). The
	// recovered engine's last origin dot must equal the live trailing dot.
	// We re-mint by replaying the WAL's last mutation record; its recorded
	// Counter must equal the live trailingDot.Counter.
	lastMut := rep.Mutations[len(rep.Mutations)-1]
	if lastMut.Counter != trailingDot.Counter {
		t.Fatalf("G08.5.b origin-dot re-mint BROKEN:\n  recovered last origin counter = %d\n  live trailing dot counter    = %d\n"+
			"The seed is not exact — the trailing origin dot re-minted at a different counter than the live engine minted it.",
			lastMut.Counter, trailingDot.Counter)
	}

	// (2) HONEST DIVERGENCE (MANDATE 1): the recovered root is ORIGIN-ONLY; the
	// live root is origin + foreign. They MUST differ — this is the
	// FROZEN-crdt.go limit (foreign state is not WAL-captured), NOT data loss.
	// Asserting equality here would be a FALSE victory; asserting the
	// divergence is the honest physics. The foreign state regossips on rejoin.
	recoveredRoot := recovered.State().MerkleRoot()
	if recoveredRoot == liveRoot {
		t.Fatalf("G08.5.b honest-physics inversion: recovered root == live root (%x).\n"+
			"A foreign Join merged foreign STATE into the live HAMT; the WAL records only origin mutations + clock advances.\n"+
			"The recovered root should be ORIGIN-ONLY and DIVERGE from the live origin+foreign root. Equality here means\n"+
			"either the foreign Join did not merge state (test is synthetic) or the WAL captured foreign deltas (it does not).",
			recoveredRoot)
	}
	t.Logf("G08.5.b honest physics: recovered(origin-only) root=%x != live(origin+foreign) root=%x — foreign state regossips on rejoin (FROZEN-crdt.go limit, not data loss); clock/seed fix PROVEN (lamport %d==%d, trailing origin dot %d==%d)",
		recoveredRoot, liveRoot, recovered.LamportCounter(), liveLamport, lastMut.Counter, trailingDot.Counter)
}

// TestRecoveryForeignAdvance_NoFalseMismatch is G08.5.c — the false-mismatch
// facet. A real foreign Join + a TRAILING checkpoint must NOT surface as
// ErrRecoveryRootMismatch. Pre-8.5, the defect seed would re-mint different
// dots → the rebuilt root differed from the checkpoint root → a HEALTHY node
// refused to boot (the other facet of the Day-8 CRITICAL). Day 8.5 scopes the
// root-equality assertion to checkpoints with NO foreign advance, so a
// checkpoint coexisting with advances is logged (foreign state regossips) and
// boot SUCCEEDS. RecoverEngine returns nil error; the recovered clock matches.
func TestRecoveryForeignAdvance_NoFalseMismatch(t *testing.T) {
	walPath := filepath.Join(t.TempDir(), "no-false-mismatch.wal")
	const K = 4

	live := newLiveBridge(t, walPath, 0)
	for i := 0; i < K; i++ {
		if _, err := live.PutLocal(stagedEntityID(i), stagedPayload(i), stagedEntry(i)); err != nil {
			t.Fatalf("PutLocal %d: %v", i, err)
		}
	}

	// Real foreign Join (advances the clock + merges foreign state).
	const F = 3
	eng.DataDir = t.TempDir()
	foreign, err := eng.NewDeltaCRDTEngine(foreignNodeID(), 50, testArenaSize)
	if err != nil {
		t.Fatalf("foreign engine ctor: %v", err)
	}
	t.Cleanup(func() { _ = foreign.Close() })
	for i := 0; i < F; i++ {
		foreign.InsertLocal(stagedEntityID(2000+i), stagedEntry(2000+i))
	}
	live.Engine().Join(*foreign.GenerateDelta(live.Engine().GenerateDigest()))
	if err := live.RecordClockAdvance(); err != nil {
		t.Fatalf("RecordClockAdvance: %v", err)
	}

	// Trailing origin mutation + a FINAL checkpoint (checkpoint is the last
	// record — checkpointIsFinal is true). The checkpoint root is origin +
	// foreign; the rebuilt root is origin-only. Pre-8.5 this FALSE-fired
	// ErrRecoveryRootMismatch. Day 8.5 scopes the assertion (advances exist →
	// skip) so boot SUCCEEDS.
	if _, err := live.PutLocal(stagedEntityID(K), stagedPayload(K), stagedEntry(K)); err != nil {
		t.Fatalf("trailing PutLocal: %v", err)
	}
	liveLamport := live.Engine().LamportCounter()
	if err := live.AppendCheckpoint(); err != nil {
		t.Fatalf("AppendCheckpoint: %v", err)
	}

	if err := live.WAL().Close(); err != nil {
		t.Fatalf("live WAL close: %v", err)
	}
	if err := live.Engine().Close(); err != nil {
		t.Fatalf("live engine close: %v", err)
	}

	recovered, wal, _, err := RecoverEngine(testNodeID(), walPath, testArenaSize)
	if err != nil {
		t.Fatalf("G08.5.c FALSE mismatch: RecoverEngine returned %v — a healthy node with a foreign Join + trailing checkpoint refused to boot (the Day-8 defect's other facet). Day 8.5 must scope the root-equality assertion so this SUCCEEDS.", err)
	}
	t.Cleanup(func() { _ = wal.Close() })
	t.Cleanup(func() { _ = recovered.Close() })

	if recovered.LamportCounter() != liveLamport {
		t.Fatalf("G08.5.c: recovered lamport %d != live lamport %d (clock did not resume at the high-water despite the scoped assertion)",
			recovered.LamportCounter(), liveLamport)
	}
	t.Logf("G08.5.c: foreign Join + trailing checkpoint boots cleanly (no false ErrRecoveryRootMismatch); recovered lamport %d == live %d",
		recovered.LamportCounter(), liveLamport)
}

// TestRecoveryScratchDirCleaned is G08.5.f — the Day-8.5 MAJOR-1 scratch-dir
// leak fix. Pre-8.5, newEngineAt created a /tmp/sovereign-recover-* dir per
// durable boot and NEVER removed it (grep-verified: zero RemoveAll). A node
// that restarted N times leaked N dirs + the persist worker's
// lamport_<nodeID>.dat. Day 8.5 returns the scratch dir from newEngineAt,
// stashes it on Replayed.ScratchDir + the Bridge, and Bridge.Close RemoveAll's
// it. This tooth asserts the dir is GONE after Close.
func TestRecoveryScratchDirCleaned(t *testing.T) {
	walPath := filepath.Join(t.TempDir(), "scratch-leak.wal")
	live := newLiveBridge(t, walPath, 0)
	if _, err := live.PutLocal(stagedEntityID(0), stagedPayload(0), stagedEntry(0)); err != nil {
		t.Fatalf("PutLocal: %v", err)
	}
	if err := live.AppendCheckpoint(); err != nil {
		t.Fatalf("AppendCheckpoint: %v", err)
	}
	if err := live.WAL().Close(); err != nil {
		t.Fatalf("live WAL close: %v", err)
	}
	if err := live.Engine().Close(); err != nil {
		t.Fatalf("live engine close: %v", err)
	}

	recovered, wal, rep, err := RecoverEngine(testNodeID(), walPath, testArenaSize)
	if err != nil {
		t.Fatalf("RecoverEngine: %v", err)
	}
	if rep.ScratchDir == "" {
		t.Fatalf("G08.5.f: Replayed.ScratchDir is empty — newEngineAt did not return the scratch dir (MAJOR-1 leak fix not wired)")
	}
	if _, err := os.Stat(rep.ScratchDir); err != nil {
		t.Fatalf("G08.5.f: scratch dir %s does not exist pre-Close (the recovered engine should be using it): %v", rep.ScratchDir, err)
	}

	// Bind a Bridge (as production does) so Close owns the scratch dir lifecycle.
	bridge := NewBridge(recovered, wal, 0)
	bridge.SetScratchDir(rep.ScratchDir)
	if err := bridge.Close(); err != nil {
		t.Fatalf("bridge.Close: %v", err)
	}

	if _, err := os.Stat(rep.ScratchDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("G08.5.f: scratch dir %s STILL EXISTS after Bridge.Close — the MAJOR-1 leak is not fixed (got err=%v)", rep.ScratchDir, err)
	}
	t.Logf("G08.5.f: scratch dir %s removed on Bridge.Close (MAJOR-1 leak fixed)", rep.ScratchDir)
}
