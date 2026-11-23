// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package chaos

// WAL recovery determinism test.
//
// Recovery must rebuild an engine whose MerkleRoot equals the root recorded
// in the WAL's last checkpoint. This test checks that property directly,
// without spawning a process.
//
// This test checks that restoring the recorded entries in WAL order reproduces
// the checkpoint root. HAMT.MerkleRoot folds only DotNodeID and DotCounter, and
// NewWALMutation preserves both from the live engine. The recovered engine uses
// the same node ID, but its initial counter is immaterial because Join restores
// each recorded dot rather than minting a new one. A fresh maphash.Seed does not
// affect the root. Process-crash recovery is covered separately by
// survival_test.go.

import (
	"crypto/sha256"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hr18vk/sovereign/pkg/sync"
)

// TestWALRecoveryDeterminism appends mutations and a checkpoint, then restores
// them into a fresh engine with the same node ID. It compares the recovered
// Merkle root with the live root and checks that Join advances the recovered
// Lamport clock to the replay high-water mark. The initial counter passed to
// the recovered engine does not affect the result because no dots are re-minted.
func TestWALRecoveryDeterminism(t *testing.T) {
	walPath := filepath.Join(t.TempDir(), "det.wal")
	wal, err := OpenWAL(walPath)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	t.Cleanup(func() { _ = wal.Close() })

	var nodeID [16]byte
	for i := range nodeID {
		nodeID[i] = byte(i + 1)
	}
	const initialCounter uint64 = 7
	const N = 64

	// Build a "live" engine exactly as the worker would, inserting N mutations
	// and appending each to the WAL (fsync on every append). The WAL captures
	// the (DotNodeID, DotCounter) the live engine minted.
	sync.DataDir = t.TempDir()
	live, err := sync.NewDeltaCRDTEngine(nodeID, initialCounter, 64*1024*1024)
	if err != nil {
		t.Fatalf("NewDeltaCRDTEngine live: %v", err)
	}
	t.Cleanup(func() { _ = live.Close() })

	var liveRoot [32]byte
	liveDots := make([]sync.CausalDot, 0, N)
	for i := 0; i < N; i++ {
		entityID := stagedEntityID(i)
		entry := stagedEntry(i)
		dot := live.InsertLocal(entityID, entry)
		liveDots = append(liveDots, dot)
		// NewWALMutation (ADR-0045 §4): stamps the engine-returned dot + origin
		// into the persisted 120-byte entry.
		if err := wal.AppendMutation(NewWALMutation(entityID, dot, entry)); err != nil {
			t.Fatalf("AppendMutation %d: %v", i, err)
		}
	}
	liveRoot = live.State().MerkleRoot()
	if err := wal.AppendCheckpoint(WALCheckpoint{
		MerkleRoot:  liveRoot,
		LamportHigh: live.LamportCounter(),
	}); err != nil {
		t.Fatalf("AppendCheckpoint: %v", err)
	}

	// Construct the recovered engine with the live engine's node ID. Production
	// recovery uses ReplayWAL at worker boot; this test exercises the same engine
	// constructor without the process layer. Join below restores the recorded dots
	// and advances the Lamport clock, so the constructor's initial counter is not
	// derived from the log.
	rep, err := ReplayWAL(walPath)
	if err != nil {
		t.Fatalf("ReplayWAL: %v", err)
	}
	if len(rep.Mutations) != N {
		t.Fatalf("replay got %d mutations, want %d", len(rep.Mutations), N)
	}
	recoverDir := t.TempDir()
	sync.DataDir = recoverDir
	// Recovery restores the recorded dots; it never mints replacements
	// (ADR-0045 §4). Deriving a seed from LamportHigh-len(Mutations) or the
	// first mutation counter is invalid when concurrent counter minting and WAL
	// appends reorder records. The synthetic delta below uses Join, as production
	// recovery does, and Join preserves each entry's recorded Dot. Duplicates are
	// no-ops, and the live engine's initialCounter=7 needs no inverse calculation.
	recovered, err := sync.NewDeltaCRDTEngine(nodeID, 1, 64*1024*1024)
	if err != nil {
		t.Fatalf("NewDeltaCRDTEngine recovered: %v", err)
	}
	t.Cleanup(func() { _ = recovered.Close() })

	// Check that the WAL preserved the live-minted dots rather than persisting
	// zero values or minting replacements during replay.
	for i, m := range rep.Mutations {
		if m.NodeID != liveDots[i].NodeID || m.Counter != liveDots[i].Counter {
			t.Fatalf("record %d carries dot (%x,%d), want the live-minted (%x,%d) — the WAL did not record the stamped dot",
				i, m.NodeID, m.Counter, liveDots[i].NodeID, liveDots[i].Counter)
		}
	}
	muts := rep.Mutations
	delta := sync.CRDTDelta{Entries: func(yield func(string, sync.CRDTEntry) bool) {
		for i := range muts {
			// Full carries the engine-stamped dot (NewWALMutation, §6); Join
			// honors it verbatim — no re-mint, no seed arithmetic.
			if !yield(muts[i].EntityID, muts[i].Full) {
				return
			}
		}
	}}
	recovered.Join(delta)

	recoveredRoot := recovered.State().MerkleRoot()
	if recoveredRoot != liveRoot {
		t.Fatalf("WAL recovery root mismatch:\n  checkpoint root = %x\n  recovered root = %x\n"+
			"Replay built different state from the live engine.",
			liveRoot, recoveredRoot)
	}
	// Join must also advance the recovered Lamport clock to the replay high-water
	// mark, so a subsequent NextDot cannot reuse an earlier counter.
	if recovered.LamportCounter() != rep.LamportHigh {
		t.Fatalf("recovered lamport %d != checkpoint lamportHigh %d",
			recovered.LamportCounter(), rep.LamportHigh)
	}
}

// TestWALTornTailTruncation checks that a crash during a record append leaves
// a replayable prefix. ReplayWAL ignores the incomplete suffix and returns the
// complete records; OpenWAL truncates that suffix before a later append.
func TestWALTornTailTruncation(t *testing.T) {
	walPath := filepath.Join(t.TempDir(), "torn.wal")
	wal, err := OpenWAL(walPath)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	var nodeID [16]byte
	nodeID[0] = 0xAA
	for i := 0; i < 5; i++ {
		if err := wal.AppendMutation(NewWALMutation(stagedEntityID(i), sync.CausalDot{NodeID: nodeID, Counter: uint64(i + 1)}, stagedEntry(i))); err != nil {
			t.Fatalf("AppendMutation %d: %v", i, err)
		}
	}
	if err := wal.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Corrupt the last record by appending a partial header (3 bytes < 13), as
	// if the worker was killed mid-write of its 6th append. Open append-only
	// (no O_TRUNC) so the valid 5-record prefix is preserved.
	appendPartial := func(p string, b []byte) {
		f, err := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			t.Fatalf("open append %s: %v", p, err)
		}
		if _, err := f.Write(b); err != nil {
			t.Fatalf("append partial: %v", err)
		}
		_ = f.Close()
	}
	appendPartial(walPath, []byte{0x01, 0x02, 0x03}) // truncated record header

	rep, err := ReplayWAL(walPath)
	if err != nil {
		t.Fatalf("ReplayWAL on torn tail: %v", err)
	}
	if len(rep.Mutations) != 5 {
		t.Fatalf("torn-tail replay got %d mutations, want 5 (prefix preserved)", len(rep.Mutations))
	}
}

// TestWALOversizedPayloadRejected checks that ReplayWAL rejects a record length
// above maxRecordPayloadLen before allocating its payload (ADR-0045). A damaged
// uint32 length could otherwise request almost 4 GiB. The crafted record has no
// payload, so without the guard it would take the torn-tail path and return no
// error; the err == nil assertion makes that missing guard visible. Replay checks
// the length before sequence contiguity, so the deliberately skipped sequence
// number in this fixture does not mask the expected length error.
func TestWALOversizedPayloadRejected(t *testing.T) {
	walPath := filepath.Join(t.TempDir(), "huge.wal")
	wal, err := OpenWAL(walPath)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	// One valid record so the log has a clean prefix before the corrupt one.
	var nodeID [16]byte
	nodeID[0] = 0xAA
	if err := wal.AppendMutation(NewWALMutation(stagedEntityID(0), sync.CausalDot{NodeID: nodeID, Counter: 1}, stagedEntry(0))); err != nil {
		t.Fatalf("AppendMutation: %v", err)
	}
	if err := wal.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Append only a header whose length is maxRecordPayloadLen+1. The sequence
	// deliberately skips 1 because replay must reject the length before checking
	// contiguity; no large payload allocation should occur.
	f, err := os.OpenFile(walPath, os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatalf("open append: %v", err)
	}
	rec := make([]byte, 13)                                              // header only, no payload
	binary.BigEndian.PutUint64(rec[0:8], 2)                              // skip seq 1; the length check runs first
	rec[8] = byte(WALRecMutationV2)                                      // a valid record type
	binary.BigEndian.PutUint32(rec[9:13], uint32(maxRecordPayloadLen)+1) // exceeds the replay bound
	if _, err := f.Write(rec); err != nil {
		t.Fatalf("write crafted record: %v", err)
	}
	_ = f.Close()

	_, err = ReplayWAL(walPath)
	if err == nil {
		t.Fatalf("a record claiming payloadLen=%d (> maxRecordPayloadLen=%d) must be rejected, not silently replayed", uint32(maxRecordPayloadLen)+1, maxRecordPayloadLen)
	}
	if !strings.Contains(err.Error(), "exceeds max") {
		t.Fatalf("error = %v, want the 'exceeds max' payload-length refusal — a different error means the bound did not fire first", err)
	}
}

// TestWALSequenceMonotonic proves OpenWAL on an existing log keeps nextSeq
// monotonic across reopen — so a recovered worker's subsequent appends never
// collide with pre-crash seq numbers (the durability ordering invariant).
func TestWALSequenceMonotonic(t *testing.T) {
	walPath := filepath.Join(t.TempDir(), "seq.wal")
	wal, _ := OpenWAL(walPath)
	var nodeID [16]byte
	nodeID[0] = 0x5
	for i := 0; i < 3; i++ {
		_ = wal.AppendMutation(NewWALMutation(stagedEntityID(i), sync.CausalDot{NodeID: nodeID, Counter: uint64(i + 1)}, stagedEntry(i)))
	}
	firstSeq := wal.NextSeq()
	_ = wal.Close()
	if firstSeq != 3 {
		t.Fatalf("first run NextSeq=%d want 3", firstSeq)
	}
	wal2, err := OpenWAL(walPath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if wal2.NextSeq() != 3 {
		t.Fatalf("reopened NextSeq=%d want 3 (monotonic across reopen)", wal2.NextSeq())
	}
	_ = wal2.AppendMutation(NewWALMutation("doc-x", sync.CausalDot{NodeID: nodeID, Counter: 99}, stagedEntry(99)))
	if wal2.NextSeq() != 4 {
		t.Fatalf("post-reopen append NextSeq=%d want 4", wal2.NextSeq())
	}
	_ = wal2.Close()
}

// TestWALForeignFileRejected proves a foreign or corrupt header is rejected
// explicitly rather than being silently misinterpreted on recovery (the no-
// silent-misinterpretation rule in the WAL header docs).
func TestWALForeignFileRejected(t *testing.T) {
	walPath := filepath.Join(t.TempDir(), "foreign.bin")
	f := openForAppend(t, walPath)
	_, _ = f.Write([]byte("NOT_A_WAL_FILE_GARBAGE_HEADER_BYTES"))
	_ = f.Close()
	if _, err := OpenWAL(walPath); err == nil {
		t.Fatalf("OpenWAL accepted a file with a bad magic (silent misinterpretation risk)")
	}
	if _, err := ReplayWAL(walPath); err == nil {
		t.Fatalf("ReplayWAL accepted a file with a bad magic")
	}
}

// stagedEntry produces a deterministic CRDTEntry for index i so the test's
// mutation stream is reproducible across runs. The PayloadDigest is derived
// from i so each mutation is content-distinct.
func stagedEntry(i int) sync.CRDTEntry {
	var d [32]byte
	h := sha256.Sum256([]byte{byte(i), byte(i >> 8), byte(i >> 16)})
	copy(d[:], h[:])
	var origin [16]byte
	binary.BigEndian.PutUint64(origin[:8], uint64(i+100))
	return sync.CRDTEntry{
		PayloadDigest: d,
		OriginNodeID:  origin,
		SystemTime:    int64(i) * 1_000,
	}
}

// stagedEntityID is a stable, content-distinct entity id per mutation index.
func stagedEntityID(i int) string {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(i))
	return "entity-" + string(buf)
}

// openForAppend creates or truncates path for writing and fails the test on an
// OS error. Tests use it to install invalid file contents before calling OpenWAL
// or ReplayWAL.
func openForAppend(t *testing.T, p string) *os.File {
	t.Helper()
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		t.Fatalf("open append %s: %v", p, err)
	}
	return f
}
