// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package chaos

// ---------------------------------------------------------------------------
// §2 — WAL recovery determinism gate.
// ---------------------------------------------------------------------------
//
// Ruthless Go Engine Verification Blueprint, §2, mandates crash-
// consistency: a worker that dies mid-flight and restarts from the WAL MUST
// rebuild an engine whose MerkleRoot() equals the root the WAL's last
// checkpoint recorded. "Survival is not enough if the acknowledged state
// diverges." This test enforces that single property directly, deterministically,
// without spawning a process.
//
// WHAT IS PROVEN HERE (and what is NOT):
// PROVEN: identical (localNodeID, initialLamport) + identical mutation replay
// order ⟹ identical MerkleRoot(). This is the engine's determinism contract:
// MerkleRoot() folds ONLY DotNodeID + DotCounter (see HAMT.MerkleRoot in
// pkg/sync/hamt.go), and both are reproduced exactly when the recovered
// engine is constructed with the same nodeID and the same initial lamport
// high-water as the crashed worker, and mutations are re-applied in WAL order.
// The maphash.Seed (which Go documents as non-serializable across processes)
// DOES NOT affect MerkleRoot, so a fresh seed in the recovered process does
// not perturb the root.
// NOT PROVEN HERE: end-to-end process-crash recovery (that is survival_test.go).
// ---------------------------------------------------------------------------

import (
	"crypto/sha256"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hr18vk/sovereign/pkg/sync"
)

// TestWALRecoveryDeterminism appends N mutations + a checkpoint to a WAL,
// replays it into a FRESH engine seeded with the same (nodeID, lamportHigh),
// and asserts the replayed MerkleRoot() equals the checkpointed root. This is
// the single property §2's "crash-consistency, not liveness" rule keys
// off. A failure means recovery is silently data-lossy.
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
		// NewWALMutation (ADR-0045): stamps the engine-returned dot + origin
		// into the persisted 120-byte entry — the safe construction.
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

	// Recovery: fresh engine seeded from the WAL (same nodeID + lamportHigh).
	// In production the worker main does this at boot (CHAOS_WORKER_NODEFX +
	// Lookahead from ReplayWAL); here we exercise the exact same logic against
	// the same engine constructor so the determinism contract is proven in
	// isolation, without the process layer.
	rep, err := ReplayWAL(walPath)
	if err != nil {
		t.Fatalf("ReplayWAL: %v", err)
	}
	if len(rep.Mutations) != N {
		t.Fatalf("replay got %d mutations, want %d", len(rep.Mutations), N)
	}
	recoverDir := t.TempDir()
	sync.DataDir = recoverDir
	// DETERMINISM CONTRACT (ADR-0045 — the seed-formula class is refuted):
	// recovery RESTORES the recorded dots; it never re-mints. The two historical
	// seed derivations (rebuiltInitial = LamportHigh - len(Mutations);
	// Mutations[0].Counter - 1) are refuted under concurrent mint/append
	// reordering and appear nowhere here. This test is the INDEPENDENT
	// in-package check: an exact-dot rebuild via a synthetic-delta Join (Join
	// honors the recorded Dot() verbatim — a duplicate is a no-op under Join),
	// the same law the production recovery path (pkg/durability) implements.
	// The seed counter is irrelevant — nothing is re-minted — so the live
	// engine's initialCounter=7 start needs no derivation.
	recovered, err := sync.NewDeltaCRDTEngine(nodeID, 1, 64*1024*1024)
	if err != nil {
		t.Fatalf("NewDeltaCRDTEngine recovered: %v", err)
	}
	t.Cleanup(func() { _ = recovered.Close() })

	// Cross-check: the WAL must carry the live-minted dots VERBATIM (a
	// persisted zero-dot is the defect this guard exists to catch).
	for i, m := range rep.Mutations {
		if m.NodeID != liveDots[i].NodeID || m.Counter != liveDots[i].Counter {
			t.Fatalf("record %d carries dot (%x,%d), want the live-minted (%x,%d) — the WAL did not record the stamped dot",
				i, m.NodeID, m.Counter, liveDots[i].NodeID, liveDots[i].Counter)
		}
	}
	muts := rep.Mutations
	delta := sync.CRDTDelta{Entries: func(yield func(string, sync.CRDTEntry) bool) {
		for i := range muts {
			// Full carries the engine-stamped dot (NewWALMutation, ADR-0045); Join
			// honors it verbatim — no re-mint, no seed arithmetic.
			if !yield(muts[i].EntityID, muts[i].Full) {
				return
			}
		}
	}}
	recovered.Join(delta)

	recoveredRoot := recovered.State().MerkleRoot()
	if recoveredRoot != liveRoot {
		t.Fatalf("WAL recovery determinism BROKEN:\n checkpoint root = %x\n recovered root = %x\n"+
			"Replayer built a different state than the live engine. Recovery is data-lossy.",
			liveRoot, recoveredRoot)
	}
	// Also assert the checkpoint's LamportHigh matches the replayed engine's
	// counter: the recovered lamport clock resumes at exactly the checkpoint's
	// high-water mark, which is why the very NextDot reproduces the right Counter.
	if recovered.LamportCounter() != rep.LamportHigh {
		t.Fatalf("recovered lamport %d != checkpoint lamportHigh %d",
			recovered.LamportCounter(), rep.LamportHigh)
	}
}

// TestWALTornTailTruncation proves a crash mid-record leaves a REPLAYABLE
// log. A torn final byte sequence must NOT corrupt the valid prefix; ReplayWAL
// truncates and returns the good records. This is the standard WAL tail-tear
// guarantee §2 leans on so a crash during an append is recoverable.
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

	// Corrupt the LAST record by appending a partial header (3 bytes < 13), as
	// if the worker was killed mid-write of its 6th append. Open append-ONLY
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

// TestWALOversizedPayloadRejected (ADR-0045): a
// record whose 4-byte length field claims a payload beyond maxRecordPayloadLen
// must be HARD-REJECTED at replay with the "exceeds max" error — never a
// multi-GiB make([]byte, payloadLen) allocation cliff, never a silent skip. The
// length field is corruption-controlled (a flipped byte can claim up to 4 GiB),
// so the bound is enforced BEFORE the allocation (wal.go: the payloadLen >
// maxRecordPayloadLen guard precedes the make).
//
// RED (bug-inject): remove the `payloadLen > maxRecordPayloadLen` guard and this
// test FAILS — replay then falls through to make([]byte, maxRecordPayloadLen+1)
// and a short read, returning the TORN-TAIL path (err == nil, the crafted record
// silently dropped), so the `err == nil` assertion below fires. The guard is the
// only thing standing between a corrupt length byte and a multi-MiB/GiB make().
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

	// Hand-craft a header claiming payloadLen = maxRecordPayloadLen+1 with NO
	// payload bytes — the length field ALONE is the attack (the guard must fire
	// before any allocation).
	f, err := os.OpenFile(walPath, os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatalf("open append: %v", err)
	}
	rec := make([]byte, 13)                                              // header only, no payload
	binary.BigEndian.PutUint64(rec[0:8], 2)                              // seq
	rec[8] = byte(WALRecMutationV2)                                      // a real record type
	binary.BigEndian.PutUint32(rec[9:13], uint32(maxRecordPayloadLen)+1) // the lie
	if _, err := f.Write(rec); err != nil {
		t.Fatalf("write crafted record: %v", err)
	}
	_ = f.Close()

	_, err = ReplayWAL(walPath)
	if err == nil {
		t.Fatalf("T-C6: a record claiming payloadLen=%d (> maxRecordPayloadLen=%d) must be REJECTED, not silently replayed", uint32(maxRecordPayloadLen)+1, maxRecordPayloadLen)
	}
	if !strings.Contains(err.Error(), "exceeds max") {
		t.Fatalf("T-C6: error = %v, want the 'exceeds max' payload-length refusal — a different error means the bound did not fire FIRST", err)
	}
}

// TestWALSequenceMonotonic proves OpenWAL on an existing log keeps
// nextSeq monotonic across reopen — so a recovered worker's subsequent appends
// never collide with pre-crash seq numbers (the durability ordering invariant).
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

// TestWALForeignFileRejected proves a foreign / corrupt header is rejected
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

// openForAppend opens path for append+write, failing the test if the OS denies
// it. Used only by the torn-tail test to splice partial bytes onto the log.
func openForAppend(t *testing.T, p string) *os.File {
	t.Helper()
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		t.Fatalf("open append %s: %v", p, err)
	}
	return f
}
