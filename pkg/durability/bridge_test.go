// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package durability

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// These tests exercise WAL recovery directly through pkg/durability, without
// the chaos harness. TestRecoveryDeterminism_KillRebuildMerkleEqual checks the
// central contract: replay reconstructs the live Merkle root and Lamport clock.

const testArenaSize uintptr = 64 * 1024 * 1024

func testNodeID() [16]byte {
	var n [16]byte
	for i := range n {
		n[i] = byte(i + 1)
	}
	return n
}

// stagedEntry returns a deterministic CRDTEntry with index-dependent origin
// and system time. PutLocal fills PayloadDigest from the corresponding payload.
func stagedEntry(i int) eng.CRDTEntry {
	var origin [16]byte
	binary.BigEndian.PutUint64(origin[:8], uint64(i+100))
	return eng.CRDTEntry{
		OriginNodeID: origin,
		SystemTime:   int64(i) * 1_000,
	}
}

// stagedPayload returns three deterministic bytes whose SHA-256 is the digest
// PutLocal stores in both the engine entry and WAL record.
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

// stagedDigest is SHA-256(stagedPayload(i)).
func stagedDigest(i int) [32]byte {
	return sha256.Sum256([]byte(stagedPayload(i)))
}

// newLiveBridge constructs an engine, WAL, and Bridge with an isolated engine
// data directory.
func newLiveBridge(t *testing.T, walPath string, checkpointInterval uint64) *Bridge {
	return newLiveBridgeArena(t, walPath, checkpointInterval, testArenaSize)
}

// newLiveBridgeArena is newLiveBridge with an explicit arena size for tests
// whose concurrent readers and writers exceed the shared 64 MiB default.
func newLiveBridgeArena(t *testing.T, walPath string, checkpointInterval uint64, arenaSize uintptr) *Bridge {
	t.Helper()
	eng.DataDir = t.TempDir()
	engine, err := eng.NewDeltaCRDTEngine(testNodeID(), 1, arenaSize)
	if err != nil {
		t.Fatalf("NewDeltaCRDTEngine live: %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	wal, err := OpenWAL(walPath)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	t.Cleanup(func() { _ = wal.Close() })
	b := NewBridge(engine, wal, checkpointInterval)
	// Under the decouple the periodic checkpoint runs on a background goroutine.
	// Drain it before the engine/WAL close cleanups run — t.Cleanup is LIFO, so
	// this (registered last) runs first — or a checkpoint could outlive the test
	// and write to a closed WAL/engine (a use-after-free class). No-op when no
	// checkpoint is pending, so it is safe for the K=0 / caller-driven tests too.
	t.Cleanup(func() { b.waitCheckpointsIdle() })
	return b
}

// TestRecoveryDeterminism_KillRebuildMerkleEqual writes K mutations and a
// checkpoint, closes the live engine and WAL, then rebuilds from the WAL. The
// recovered Merkle root and Lamport counter must equal their live values.
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
		t.Fatalf("WAL replay produced a different Merkle root:\n  live root      = %x\n  recovered root = %x\n"+
			"Recovery did not reconstruct the live state.",
			liveRoot, recoveredRoot)
	}
	if recovered.LamportCounter() != liveLamport {
		t.Fatalf("recovered lamport %d != live lamport %d (clock did not resume at the checkpoint high-water mark)",
			recovered.LamportCounter(), liveLamport)
	}
}

// TestRecoveryForgedRoot_FullPathBootsLoudly verifies that full replay does not
// reject a checkpoint solely because its root differs from the rebuilt root.
// The WAL records local mutations but not foreign entries received by gossip,
// so a valid anchor that includes foreign state and a forged anchor can present
// the same mismatch. Root equality is meaningful on the bounded path, where the
// image supplies those entries, but not on full replay.
//
// Full replay instead checks sequence contiguity and record integrity, and the
// witness must show that its post-tail root comparison is disabled. The bounded
// path retains root and fingerprint checks, covered by
// TestRootAssertionArmedWithForeignAdvances and the snapshot integrity tests.
func TestRecoveryForgedRoot_FullPathBootsLoudly(t *testing.T) {
	walPath := filepath.Join(t.TempDir(), "mismatch.wal")
	const K = 32

	live := newLiveBridge(t, walPath, 0)
	for i := 0; i < K; i++ {
		if _, err := live.PutLocal(stagedEntityID(i), stagedPayload(i), stagedEntry(i)); err != nil {
			t.Fatalf("PutLocal %d: %v", i, err)
		}
	}
	liveLamport := live.Engine().LamportCounter()
	// Use a deliberately wrong root with the correct LamportHigh. This legacy
	// 0x02 final checkpoint is indistinguishable on full replay from an anchor
	// that legitimately included foreign state.
	var wrongRoot [32]byte
	wrongRoot[0] = 0xff
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

	recovered, wal, rep, witness, err := RecoverEngineWithSnapshot(testNodeID(), walPath, nil, testArenaSize)
	if err != nil {
		t.Fatalf("full replay rejected a root mismatch that foreign entries could explain: %v", err)
	}
	if recovered == nil || wal == nil {
		t.Fatalf("recovery must return a live engine and an open WAL")
	}
	defer func() { _ = wal.Close(); _ = recovered.Close() }()
	if witness == nil || witness.PostTailRootArmed {
		t.Fatalf("post-tail root comparison must be disabled on full replay; witness=%+v", witness)
	}
	if !rep.SeqContiguityVerified || rep.RecordsVerified != K+1 {
		t.Fatalf("sequence verification must cover all %d records; verified=%v count=%d", K+1, rep.SeqContiguityVerified, rep.RecordsVerified)
	}
	// The full 32 local mutations must all be back — the WAL is the truth.
	if got := len(rep.Mutations); got != K {
		t.Fatalf("replayed %d mutations, want %d", got, K)
	}
}

// TestRecoveryColdBoot_NoCheckpoint verifies that RecoverEngine accepts a WAL
// containing mutations but no checkpoint. It logs the missing-anchor warning,
// and the replayed root and Lamport clock must match the live values.
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
	// No checkpoint appended — the cold-boot-with-mutations edge.
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

// TestRecoveryTornTailTruncation removes bytes from the middle of the final WAL
// record. ReplayWAL must discard the incomplete tail and rebuild from the valid
// prefix, retaining its checkpoint anchor and Lamport high-water.
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
	// torn record was truncated, not mis-decoded into a bogus mutation.
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

// TestPutLocalWALStampsEngineDot checks the write ordering required by
// ADR-0013. Each WALMutation must carry the dot returned by InsertLocal, and
// RecoverEngine must restore that recorded dot rather than minting a new one.
// Appending first would instead persist caller-supplied zero dot fields.
func TestPutLocalWALStampsEngineDot(t *testing.T) {
	walPath := filepath.Join(t.TempDir(), "order.wal")
	const K = 16

	live := newLiveBridge(t, walPath, 0)
	// Compare the returned dots and payload digests with the WAL and replayed state.
	returnedDots := make([]eng.CausalDot, K)
	for i := 0; i < K; i++ {
		dot, err := live.PutLocal(stagedEntityID(i), stagedPayload(i), stagedEntry(i))
		if err != nil {
			t.Fatalf("PutLocal %d: %v", i, err)
		}
		returnedDots[i] = dot
		// PutLocal computes the digest before InsertLocal, so the engine and WAL
		// must cover the same payload bytes. PointGet avoids building State per entity.
		got := live.Engine().PointGet(stagedEntityID(i))
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

	// Each WAL mutation must carry the dot returned by InsertLocal.
	rep, err := ReplayWAL(walPath)
	if err != nil {
		t.Fatalf("ReplayWAL: %v", err)
	}
	if len(rep.Mutations) != K {
		t.Fatalf("replay got %d mutations, want %d", len(rep.Mutations), K)
	}
	for i, m := range rep.Mutations {
		if m.Counter != returnedDots[i].Counter {
			t.Fatalf("order check: WALMutation[%d].Counter=%d != engine-returned dot.Counter=%d "+
				"(WAL did not carry the engine-stamped dot; check append order)",
				i, m.Counter, returnedDots[i].Counter)
		}
		if m.NodeID != returnedDots[i].NodeID {
			t.Fatalf("order check: WALMutation[%d].NodeID %x != engine-returned dot.NodeID %x",
				i, m.NodeID, returnedDots[i].NodeID)
		}
	}

	// RecoverEngine joins each mutation at its recorded dot (ADR-0045 §4), so
	// its Lamport high-water and Merkle root match the live engine.
	recovered, wal, _, err := RecoverEngine(testNodeID(), walPath, testArenaSize)
	if err != nil {
		t.Fatalf("RecoverEngine: %v", err)
	}
	t.Cleanup(func() { _ = wal.Close() })
	t.Cleanup(func() { _ = recovered.Close() })
	if recovered.LamportCounter() != liveLamport {
		t.Fatalf("order check: recovered lamport %d != live lamport %d (re-minted dots diverged)",
			recovered.LamportCounter(), liveLamport)
	}
}

// foreignNodeID is a distinct nodeID for the foreign engine in the real-Join
// tests — it must differ from testNodeID() so the foreign entries carry a
// foreign DotNodeID (a foreign Join merges foreign state,
// not just a clock jump).
func foreignNodeID() [16]byte {
	var n [16]byte
	for i := range n {
		n[i] = byte(0xEE)
	}
	return n
}

// TestRecoveryForeignAdvance_RealJoinClockSeedFixed joins entries from a second
// engine rather than injecting a synthetic clock jump. Join both merges the
// foreign entries and advances the live Lamport clock; RecordClockAdvance then
// appends that high-water as a 0x03 WAL record (ADR-0045 §4).
//
// Recovery must restore the recorded clock and the exact dots of subsequent
// origin mutations. Deriving a seed from LamportHigh or the first mutation is
// not valid when minting and WAL appends can be reordered.
//
// The recovered root must differ from the live root because the WAL contains
// origin mutations and clock advances, not the foreign entries joined into the
// live engine. This is a limit of full replay, not loss of durable local writes;
// foreign entries can arrive again through gossip. The test checks the clock,
// the trailing origin dot, and this expected root divergence separately.
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

	// Build a foreign engine, generate the entries missing from live, and join
	// them. Join advances the clock for each foreign entry and merges its state.
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
	liveDigest := live.Engine().GenerateDigest()
	delta := foreign.GenerateDelta(liveDigest)
	defer delta.Release() // release the delta's EBR participant before foreign.Close quiesces
	live.Engine().Join(*delta)
	// Receiver.HandleFrame records the same post-Join high-water at this seam.
	if err := live.RecordClockAdvance(); err != nil {
		t.Fatalf("RecordClockAdvance: %v", err)
	}

	// The next origin mutation must retain its recorded counter (K+1+gap) on
	// recovery rather than deriving a different counter from mutation counts.
	trailingDot, err := live.PutLocal(stagedEntityID(K), stagedPayload(K), stagedEntry(K))
	if err != nil {
		t.Fatalf("trailing PutLocal: %v", err)
	}
	liveRoot := live.Engine().State().MerkleRoot() // origin + foreign
	liveLamport := live.Engine().LamportCounter()

	// The anchor covers origin and foreign state. Full replay skips its root
	// comparison when clock advances show that foreign state may be absent.
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

	// The ordered advance record must restore the live clock high-water.
	if recovered.LamportCounter() != liveLamport {
		t.Fatalf("recovered Lamport clock mismatch:\n  recovered lamport = %d\n  live lamport      = %d\n"+
			"The foreign advance was not restored at the live high-water.",
			recovered.LamportCounter(), liveLamport)
	}

	// The last WAL mutation must restore the exact trailing origin counter.
	lastMut := rep.Mutations[len(rep.Mutations)-1]
	if lastMut.Counter != trailingDot.Counter {
		t.Fatalf("origin-dot restoration mismatch:\n  recovered last origin counter = %d\n  live trailing dot counter    = %d\n"+
			"Replay did not restore the counter recorded for the trailing origin mutation.",
			lastMut.Counter, trailingDot.Counter)
	}

	// Foreign entries are absent from the WAL, so the origin-only recovered root
	// must differ from the live origin+foreign root. Foreign state can regossip.
	recoveredRoot := recovered.State().MerkleRoot()
	if recoveredRoot == liveRoot {
		t.Fatalf("recovered root unexpectedly equals live root %x.\n"+
			"The foreign Join should merge foreign state into the live HAMT, while the WAL records only origin mutations and clock advances.\n"+
			"The recovered root should be origin-only and differ from the live origin+foreign root.\n"+
			"Equality means either Join did not merge state or the WAL captured foreign entries.",
			recoveredRoot)
	}
	t.Logf("origin-only recovered root=%x != live origin+foreign root=%x; clock %d==%d and trailing origin dot %d==%d restored",
		recoveredRoot, liveRoot, recovered.LamportCounter(), liveLamport, lastMut.Counter, trailingDot.Counter)
}

// TestRecoveryForeignAdvance_NoFalseMismatch joins foreign state and then writes
// a final checkpoint. Full replay cannot reproduce the foreign entries, so it
// must not report ErrRecoveryRootMismatch merely because the checkpoint root
// includes them. Recovery must succeed and restore the live Lamport clock.
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
	fdelta := foreign.GenerateDelta(live.Engine().GenerateDigest())
	defer fdelta.Release() // release the delta's EBR participant before foreign.Close quiesces
	live.Engine().Join(*fdelta)
	if err := live.RecordClockAdvance(); err != nil {
		t.Fatalf("RecordClockAdvance: %v", err)
	}

	// The final checkpoint includes foreign state, while full replay rebuilds
	// only origin mutations. The clock advance tells recovery not to compare
	// those roots as though they covered identical state.
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
		t.Fatalf("recovery rejected a healthy foreign Join and final checkpoint: %v", err)
	}
	t.Cleanup(func() { _ = wal.Close() })
	t.Cleanup(func() { _ = recovered.Close() })

	if recovered.LamportCounter() != liveLamport {
		t.Fatalf("recovered lamport %d != live lamport %d (clock did not resume at the high-water despite the scoped assertion)",
			recovered.LamportCounter(), liveLamport)
	}
	t.Logf("foreign Join + trailing checkpoint boots cleanly (no false ErrRecoveryRootMismatch); recovered lamport %d == live %d",
		recovered.LamportCounter(), liveLamport)
}

// TestRecoveryScratchDirCleaned checks that Bridge.Close removes the recovery
// directory returned in Replayed.ScratchDir. Recovery creates this directory
// under os.TempDir for constructor and lamport_<nodeID>.dat state; without an
// owner, each restart would leave another directory behind.
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
		t.Fatalf("Replayed.ScratchDir is empty; recovery must return its scratch directory")
	}
	if _, err := os.Stat(rep.ScratchDir); err != nil {
		t.Fatalf("scratch dir %s is unavailable before Close: %v", rep.ScratchDir, err)
	}

	// Bind a Bridge so Close owns the scratch directory lifecycle.
	bridge := NewBridge(recovered, wal, 0)
	bridge.SetScratchDir(rep.ScratchDir)
	if err := bridge.Close(); err != nil {
		t.Fatalf("bridge.Close: %v", err)
	}

	if _, err := os.Stat(rep.ScratchDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("scratch dir %s remains after Bridge.Close; err=%v", rep.ScratchDir, err)
	}
	t.Logf("scratch dir %s removed by Bridge.Close", rep.ScratchDir)
}
