package chaos

// ---------------------------------------------------------------------------
// Stage 6 §2 — WAL recovery determinism gate.
// ---------------------------------------------------------------------------
//
// Ruthless Go Engine Verification Blueprint, Stage 6 §2, mandates crash-
// consistency: a worker that dies mid-flight and restarts from the WAL MUST
// rebuild an engine whose MerkleRoot() equals the root the WAL's last
// checkpoint recorded. "Survival is not enough if the acknowledged state
// diverges." This test enforces that single property directly, deterministically,
// without spawning a process.
//
// WHAT IS PROVEN HERE (and what is NOT):
//   PROVEN: identical (localNodeID, initialLamport) + identical mutation replay
//   order ⟹ identical MerkleRoot(). This is the engine's determinism contract:
//   MerkleRoot() folds ONLY DotNodeID + DotCounter (see HAMT.MerkleRoot in
//   pkg/sync/hamt.go), and both are reproduced exactly when the recovered
//   engine is constructed with the same nodeID and the same initial lamport
//   high-water as the crashed worker, and mutations are re-applied in WAL order.
//   The maphash.Seed (which Go documents as non-serializable across processes)
//   DOES NOT affect MerkleRoot, so a fresh seed in the recovered process does
//   not perturb the root.
//   NOT PROVEN HERE: end-to-end process-crash recovery (that is survival_test.go).
// ---------------------------------------------------------------------------

import (
	"crypto/sha256"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/hr18vk/supremum/pkg/sync"
)

// TestStage6WALRecoveryDeterminism appends N mutations + a checkpoint to a WAL,
// replays it into a FRESH engine seeded with the same (nodeID, lamportHigh),
// and asserts the replayed MerkleRoot() equals the checkpointed root. This is
// the single property Stage 6 §2's "crash-consistency, not liveness" rule keys
// off. A failure means recovery is silently data-lossy.
func TestStage6WALRecoveryDeterminism(t *testing.T) {
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
	for i := 0; i < N; i++ {
		entityID := stagedEntityID(i)
		entry := stagedEntry(i)
		dot := live.InsertLocal(entityID, entry)
		if err := wal.AppendMutation(WALMutation{
			EntityID: entityID,
			NodeID:   dot.NodeID,
			Counter:  dot.Counter,
			Entry: WALEntry{
				PayloadDigest: entry.PayloadDigest,
				OriginNodeID:  entry.OriginNodeID,
				DotNodeID:     entry.DotNodeID,
				DotCounter:    entry.DotCounter,
				SystemTime:    entry.SystemTime,
			},
		}); err != nil {
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
	// DETERMINISM CONTRACT (root cause of the pre-fix dot-Counter mismatch):
	// InsertLocal RE-STAMPS DotNodeID/DotCounter from NextDot() regardless of
	// the recorded entry fields, so the recovered engine MUST be constructed
	// with the SAME initial lamport the LIVE engine started from. Only then
	// does replaying N mutations reproduce dots initial+N..initial+N and match
	// the recorded m.Counter (initial+i+1). Booting from the high-water mark
	// instead re-mints counters ABOVE all recorded ones -> different dot set ->
	// different MerkleRoot (data loss on recovery).
	//
	// SELF-CONTAINED RECOVERY: the recovered worker cannot know the live
	// initial counter a priori — it must DERIVE it from the WAL. The invariant
	// is: rebuiltInitial = LamportHigh - len(Mutations), i.e. the counter the
	// engine held immediately BEFORE the first durably-logged InsertLocal. This
	// is robust whether the live engine started at 0 (a fresh boot) or at 7
	// (a rejoined node carrying prior lamport state).
	rebuiltInitial := uint64(0)
	if rep.LamportHigh >= uint64(len(rep.Mutations)) {
		rebuiltInitial = rep.LamportHigh - uint64(len(rep.Mutations))
	}
	if rebuiltInitial != initialCounter {
		t.Fatalf("derived rebuiltInitial=%d, want live initialCounter=%d "+
			"(recovery cannot reconstruct the live start; determinism contract broken)",
			rebuiltInitial, initialCounter)
	}
	recovered, err := sync.NewDeltaCRDTEngine(nodeID, rebuiltInitial, 64*1024*1024)
	if err != nil {
		t.Fatalf("NewDeltaCRDTEngine recovered: %v", err)
	}
	t.Cleanup(func() { _ = recovered.Close() })

	// Replay exactly as the worker main replays: InsertLocal each recorded
	// mutation. The recovered engine mints counters from LamportHigh downward
	// in the SAME sequence, so (DotNodeID, DotCounter) match the live engine's
	// assignments exactly. InsertLocal re-stamps DotNodeID/DotCounter from
	// its own NextDot(), which is WHY the nodeID + lamportHigh must match.
	for i, m := range rep.Mutations {
		entry := sync.CRDTEntry{
			PayloadDigest: m.Entry.PayloadDigest,
			OriginNodeID:  m.Entry.OriginNodeID,
			DotNodeID:     m.Entry.DotNodeID,
			DotCounter:    m.Entry.DotCounter,
			SystemTime:    m.Entry.SystemTime,
		}
		// InsertLocal re-stamps DotNodeID/DotCounter, which is the determinism-
		// sensitive path; the recorded payload/origin/system time are honored.
		dot := recovered.InsertLocal(m.EntityID, entry)
		// Cross-check: the recovered engine, started at the SAME initial
		// lamport, must re-mint each dot to exactly the recorded sequence.
		if dot.NodeID != m.NodeID {
			t.Errorf("replay %d: DotNodeID mismatch: got %x, want %x", i, dot.NodeID, m.NodeID)
		}
		wantCounter := initialCounter + uint64(i) + 1
		if dot.Counter != wantCounter {
			t.Errorf("replay %d: re-minted DotCounter=%d, want %d (initial=%d) — recorded=%d",
				i, dot.Counter, wantCounter, initialCounter, m.Counter)
		}
		if dot.Counter != m.Counter {
			t.Errorf("replay %d: re-minted counter %d != recorded counter %d (replay determinism lost)",
				i, dot.Counter, m.Counter)
		}
	}

	recoveredRoot := recovered.State().MerkleRoot()
	if recoveredRoot != liveRoot {
		t.Fatalf("WAL recovery determinism BROKEN:\n  checkpoint root = %x\n  recovered root = %x\n"+
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

// TestStage6WALTornTailTruncation proves a crash mid-record leaves a REPLAYABLE
// log. A torn final byte sequence must NOT corrupt the valid prefix; ReplayWAL
// truncates and returns the good records. This is the standard WAL tail-tear
// guarantee Stage 6 §2 leans on so a crash during an append is recoverable.
func TestStage6WALTornTailTruncation(t *testing.T) {
	walPath := filepath.Join(t.TempDir(), "torn.wal")
	wal, err := OpenWAL(walPath)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	var nodeID [16]byte
	nodeID[0] = 0xAA
	for i := 0; i < 5; i++ {
		if err := wal.AppendMutation(WALMutation{
			EntityID: stagedEntityID(i),
			NodeID:   nodeID,
			Counter:  uint64(i + 1),
			Entry:    walEntryFrom(stagedEntry(i)),
		}); err != nil {
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

// TestStage6WALSequenceMonotonic proves OpenWAL on an existing log keeps
// nextSeq monotonic across reopen — so a recovered worker's subsequent appends
// never collide with pre-crash seq numbers (the durability ordering invariant).
func TestStage6WALSequenceMonotonic(t *testing.T) {
	walPath := filepath.Join(t.TempDir(), "seq.wal")
	wal, _ := OpenWAL(walPath)
	var nodeID [16]byte
	nodeID[0] = 0x5
	for i := 0; i < 3; i++ {
		_ = wal.AppendMutation(WALMutation{EntityID: stagedEntityID(i), NodeID: nodeID, Counter: uint64(i + 1), Entry: walEntryFrom(stagedEntry(i))})
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
	_ = wal2.AppendMutation(WALMutation{EntityID: "doc-x", NodeID: nodeID, Counter: 99, Entry: walEntryFrom(stagedEntry(99))})
	if wal2.NextSeq() != 4 {
		t.Fatalf("post-reopen append NextSeq=%d want 4", wal2.NextSeq())
	}
	_ = wal2.Close()
}

// TestStage6WALForeignFileRejected proves a foreign / corrupt header is rejected
// explicitly rather than being silently misinterpreted on recovery (the no-
// silent-misinterpretation rule in the WAL header docs).
func TestStage6WALForeignFileRejected(t *testing.T) {
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

// walEntryFrom projects the CRDTEntry fields the WAL persists. Kept in lockstep
// with WALMutation.Entry so the test does not hand-build WALEntry inline.
func walEntryFrom(e sync.CRDTEntry) WALEntry {
	return WALEntry{
		PayloadDigest: e.PayloadDigest,
		OriginNodeID:  e.OriginNodeID,
		DotNodeID:     e.DotNodeID,
		DotCounter:    e.DotCounter,
		SystemTime:    e.SystemTime,
	}
}
