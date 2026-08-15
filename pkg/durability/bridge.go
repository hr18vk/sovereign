package durability

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"
	"os"

	eng "github.com/hr18vk/supremum/pkg/sync"

	"github.com/hr18vk/supremum/internal/database"
)

// Bridge is the write-through bridge between the in-memory δ-CRDT engine and
// the fsync-per-mutation WAL. It is the Day-8 origin-path durability seam.
//
// ROOT CAUSE (one sentence): InsertLocal publishes the entry to the in-memory
// HAMT; AppendMutation fsyncs the (DotNodeID, DotCounter, PayloadDigest,
// OriginNodeID, SystemTime, entityID) to the WAL; a checkpoint periodically
// anchors MerkleRoot+LamportHigh so replay can PROVE equality.
//
// PHYSICAL ORDER (the single load-bearing correctness invariant, §6):
//  1. dgst := sha256.Sum256(payload); entry.PayloadDigest = dgst
//  2. dot := engine.InsertLocal(entityID, entry)   // stamps Dot/Origin INTERNALLY
//  3. wal.AppendMutation(WALMutation{EntityID, dot.NodeID, dot.Counter, WALEntry{...}})
//  4. return dot
//
// AppendMutation MUST come AFTER InsertLocal: the WAL carries the
// engine-STAMPED dot (DotNodeID/DotCounter come from NextDot INSIDE InsertLocal
// at crdt.go:912 — the determinism-sensitive stamped values). A WAL written
// BEFORE InsertLocal cannot carry the stamped dot; replay would re-mint
// different dots → Merkle mismatch → silent data loss. The order tooth G08.e
// catches a reversed-order regression.
//
// fsync-on-every-mutation is the EXISTING internal/chaos/wal.go contract
// (AppendMutation writes then fsyncs before returning). Day 8 does NOT
// downgrade it to a group-commit: the NVMe fsync (~1.5µs p99, the E5 32c
// PROVEN number) is a real write-path cost, measured by G08.g and hidden by
// no one.
type Bridge struct {
	// field order is layout-only (the PutLocal ORDER INVARIANT lives in the
	// method, not the struct): pointers → strings → uint64s → bool, so the
	// struct carries no padding (fieldalignment-clean; off the hot path either
	// way — the Bridge is one per node, not per op).
	engine               *eng.DeltaCRDTEngine
	wal                  *WAL
	snapshotter          *LocalFS
	scratchDir           string
	snapshotFallbackDir  string
	checkpointInterval   uint64
	mutationsSinceCkpt   uint64
	snapshotIndexEnabled bool
}

// Bridge field docs (kept out of the struct decl so fieldalignment reordering
// does not fight the comments):
//   scratchDir          — RecoverEngine's isolated temp dir (Day 8.5 MAJOR-1
//                         leak fix). Close RemoveAll's it. Empty for a
//                         cold-constructed bridge. The WAL is the authoritative
//                         durability substrate; this dir is redundant scratch.
//   checkpointInterval  — K for periodic AppendCheckpoint (0 = caller-driven
//                         only). BOUNDS replay length: every K mutations an
//                         anchor means a subsequent recovery replays ≤ K.
//                         The fsync-per-mutation floor is NOT downgraded.
//   mutationsSinceCkpt  — running count since the last checkpoint.
//   snapshotter         — Day 11: when non-nil, AppendCheckpoint writes the
//                         dot-bearing recovery image (+ the Arrow index when
//                         snapshotIndexEnabled) to `snapshotter` AFTER the
//                         WAL checkpoint fsync. ZERO behavior change when nil
//                         (the back-compat WAL-anchor-only path, Day-8/8.5).
//                         Set via SetSnapshotter.
//   snapshotIndexEnabled — also write the Arrow query index (M8) on checkpoint.
//   snapshotFallbackDir  — the MemTable's local spool if a (LocalFS-only) Arrow
//                          upload were to fail; derived in SetSnapshotter.

// NewBridge binds an engine to an open WAL. The WAL must already be open for
// append (OpenWAL or the WAL handed back by RecoverEngine). checkpointInterval
// is the K for periodic AppendCheckpoint (0 = caller-driven checkpoints only).
// scratchDir is the recovered engine's isolated temp dir (empty for a
// cold-constructed engine); Bridge.Close owns its lifecycle (MAJOR-1 leak fix).
func NewBridge(engine *eng.DeltaCRDTEngine, wal *WAL, checkpointInterval uint64) *Bridge {
	return &Bridge{
		engine:             engine,
		wal:                wal,
		checkpointInterval: checkpointInterval,
	}
}

// SetScratchDir binds the recovered engine's isolated temp dir so Bridge.Close
// RemoveAll's it (Day 8.5 MAJOR-1). RecoverEngine sets this; a cold-constructed
// bridge leaves it empty (nothing to clean). The dir is the FROZEN constructor's
// recoverLamport scratch space, redundant with the WAL.
func (b *Bridge) SetScratchDir(dir string) { b.scratchDir = dir }

// SetSnapshotter wires the Day-11 bounded-recovery seam. When `lfs` is non-nil,
// every AppendCheckpoint (explicit or periodic inside PutLocal) writes the
// dot-bearing recovery image to `lfs` at "ckpt/<LamportHigh>" AFTER the WAL
// checkpoint record is fsync'd; when enableIndex is true it ALSO writes the
// Arrow query index (the M8 wire of internal/database). When `lfs` is nil the
// Bridge reverts to the Day-8/8.5 WAL-anchor-only behavior (ZERO behavior
// change — back-compat). cmd/sovereign-node calls this only when --lsm-root is
// given alongside --wal-path.
//
// ORDERING INVARIANT (the dangling-anchor guard, ADR-0016 §5): the WAL
// checkpoint is fsync'd BEFORE the snapshot image. A crash between the two —
// or mid-image-write — leaves a WAL anchor with NO usable image, which the
// recovery path detects (SnapshotExists false, or decode refuses the torn
// image) and falls back to full replay (T2). Recovery always rebuilds;
// boundedness is best-effort against the durable image.
func (b *Bridge) SetSnapshotter(lfs *LocalFS, enableIndex bool) {
	b.snapshotter = lfs
	b.snapshotIndexEnabled = enableIndex
	if lfs != nil {
		b.snapshotFallbackDir = lfs.Root() + "/fallback"
		_ = os.MkdirAll(b.snapshotFallbackDir, 0o755)
	} else {
		b.snapshotFallbackDir = ""
	}
}

// Close releases the bridge's engine + WAL and RemoveAll's the recovered
// engine's scratch dir (Day 8.5 MAJOR-1 — the scratch-dir leak fix). It is
// idempotent (a nil engine/WAL is a no-op). The caller (cmd/sovereign-node on
// shutdown, or a test's t.Cleanup) invokes this so a durable boot does not leak
// a /tmp dir + the persist worker's lamport_<nodeID>.dat across restarts.
func (b *Bridge) Close() error {
	var werr, eerr error
	if b.wal != nil {
		werr = b.wal.Close()
	}
	if b.engine != nil {
		eerr = b.engine.Close()
	}
	if b.scratchDir != "" {
		_ = os.RemoveAll(b.scratchDir)
	}
	if werr != nil {
		return werr
	}
	return eerr
}

// RecordClockAdvance WAL-records a peer-driven Lamport clock advance (Day 8.5
// M4 — the foreign-advance seed fix). It is the receive-seam hook: after a
// successful foreign Join (which AdvanceLamportTo'd the clock inside the FROZEN
// engine), the caller records the post-Join high-water mark so the WAL is the
// complete clock history and the recovery seed is exact. fsync-on-commit (the
// same durability floor as AppendMutation — a clock advance that survives in
// memory but not on disk would re-introduce the gap on crash).
//
// HONEST CAVEAT (ADR-0013 §7(h)): this records the post-Accept LamportHigh,
// not the exact foreign-but-pre-mint counter — a slight over-record, harmless
// for the seed (the recorded advance's counter is the high-water the replay
// must reach).
func (b *Bridge) RecordClockAdvance() error {
	return b.wal.AppendClockAdvance(b.engine.LamportCounter())
}

// Engine returns the bound engine. Recovery and the control path read
// State().MerkleRoot() + LamportCounter() through this handle.
func (b *Bridge) Engine() *eng.DeltaCRDTEngine { return b.engine }

// WAL returns the bound WAL.
func (b *Bridge) WAL() *WAL { return b.wal }

// PutLocal is the write-through origin insertion point. It stamps the payload
// digest, publishes to the in-memory HAMT, then fsyncs the engine-STAMPED dot
// to the WAL — in that order (see the struct doc for the physical order and
// why it is load-bearing). Returns the engine-minted CausalDot.
//
// If the WAL append fails AFTER InsertLocal succeeded, the in-memory state has
// advanced but the durable log has not. This is a durability loss for that one
// mutation: the returned dot is still valid in-memory, but a crash before the
// next successful append + checkpoint would lose it. The error is surfaced
// (never swallowed) so the caller can fail the client ACK — the
// ACK-before-durability contract (internal/chaos/wal.go pre-mortem #1).
func (b *Bridge) PutLocal(entityID, payload string, entry eng.CRDTEntry) (eng.CausalDot, error) {
	// 1. Digest the payload so the receive-side integrity check
	// (ReconstructEntry cross-validates PayloadDigest == SHA-256(payload)) and
	// the WAL's persisted digest are consistent by construction.
	dgst := sha256.Sum256([]byte(payload))
	entry.PayloadDigest = dgst

	// 2. InsertLocal stamps DotNodeID/DotCounter/OriginNodeID INTERNALLY from
	// NextDot() + localNodeID (crdt.go:912); it ignores caller-set dot fields.
	dot := b.engine.InsertLocal(entityID, entry)

	// 3. AppendMutation AFTER InsertLocal — the WAL carries the engine-STAMPED
	// dot. This is the determinism contract: replay seeds a fresh engine at
	// rebuiltInitial = LamportHigh - len(Mutations) and re-mints the SAME dots.
	if err := b.wal.AppendMutation(WALMutation{
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
		return dot, err
	}

	// 4. Periodic checkpoint anchor (optional, bounds replay length). The
	// checkpoint is fsync'd by AppendCheckpoint; it does NOT replace the
	// per-mutation fsync, it adds a MerkleRoot+LamportHigh anchor so a later
	// recovery can assert crash-consistency (G08.b/G08.c).
	if b.checkpointInterval > 0 {
		b.mutationsSinceCkpt++
		if b.mutationsSinceCkpt >= b.checkpointInterval {
			if err := b.AppendCheckpoint(); err != nil {
				return dot, err
			}
			b.mutationsSinceCkpt = 0
		}
	}
	return dot, nil
}

// LocalItem is the batch-inject shape Bridge.PutLocals accepts (ADR-0044, Day 39).
// It is the per-entry triple the /v1/batch-insert path collects: the entity ID,
// the payload the cache retains (engine discards it after InsertLocal per Ruling
// 3), and the bitemporal-stamped CRDTEntry (the control port stamps
// SystemTime/ValidTime/AssertionTime per entry verbatim from handleInsert before
// the batch call). It mirrors PutLocal's (entityID, payload, entry) arg triple —
// the batch method is the N-item generalization of the single-item origin path.
type LocalItem struct {
	EntityID string
	Payload  string
	Entry    eng.CRDTEntry
}

// PutLocals is the ADR-0044 (Day 39) WAL group-commit origin path: N items →
// N × InsertLocal (stamps dots, in-memory HAMT advances) → ONE AppendMutations
// (N writes + ONE fsync). It is the /v1/batch-insert durability primitive; PutLocal
// (above) stays byte-identical for /v1/insert. The per-item PHYSICAL ORDER is
// byte-identical to PutLocal: digest → InsertLocal (stamps dot BEFORE the WAL
// carries it) → the WALMutation built from the engine-STAMPED dot — so the
// determinism contract (replay re-mints the SAME dots) is preserved per item.
//
// ATOMICITY (the ADR-0044 §4 semantic change, disclosed HONESTLY): if
// AppendMutations returns (firstFailIdx, err) != (-1, nil) — a Write failure at
// index i OR the final Sync failure — PutLocals returns (dots, 0, err): the
// caller ACKs ALL entries as 503 (the WHOLE batch is un-durable). It does NOT
// return a partial [0, firstFailIdx) range: entries [0, i) sit in the OS page
// cache (may or may not survive a crash) and [i, N) were never written, so we
// CANNOT assert durability of any subset — the standard WAL atomic-batch model.
// The honest contract: ONE Write-failure OR ONE Sync-failure = ALL 503. The
// in-memory HAMT has already advanced (InsertLocal minted the dots before the
// append), but on crash the WAL replay misses the whole batch; the Merkle root
// matches the durable state, NOT the in-memory state — the same
// ACK-before-durability floor PutLocal upholds for the single-entry path.
//
// PER-BATCH vs PER-ENTRY (the granularity CHANGE): PutLocal upholds PER-ENTRY 503
// (a Sync fail → 503 for THAT entry; the caller retries that one entry).
// PutLocals upholds PER-BATCH 503 (a Sync fail → 503 for ALL entries; the caller
// retries the WHOLE batch). Both are strict atomicity; the granularity differs.
// /v1/insert keeps PutLocal (per-entry); /v1/batch-insert uses PutLocals (per-
// batch). The Day-37 T-BatchInsertWALFailPerEntry tooth stays GREEN: it posts
// all-success and all-fail batches separately (never a mixed batch), so both
// semantics produce the same all-200 / all-503 observations — the tooth is
// agnostic to the granularity (the resolution verified at the working tree).
func (b *Bridge) PutLocals(items []LocalItem) (dots []eng.CausalDot, failedFrom int, err error) {
	dots = make([]eng.CausalDot, len(items))
	mutations := make([]WALMutation, len(items))
	for i, it := range items {
		// 1. Digest the payload so the receive-side integrity check
		// (ReconstructEntry cross-validates PayloadDigest == SHA-256(payload))
		// and the WAL's persisted digest are consistent by construction — the
		// SAME digest PutLocal derives from the SAME payload the cache stores.
		dgst := sha256.Sum256([]byte(it.Payload))
		it.Entry.PayloadDigest = dgst

		// 2. InsertLocal stamps DotNodeID/DotCounter/OriginNodeID INTERNALLY from
		// NextDot() + localNodeID (crdt.go:965, FROZEN — byte-identical call); it
		// ignores caller-set dot fields. The dot is stamped BEFORE the WAL carries
		// it — the determinism contract.
		dot := b.engine.InsertLocal(it.EntityID, it.Entry)
		dots[i] = dot

		// 3. Build the WALMutation from the engine-STAMPED dot — byte-identical
		// field set to PutLocal's AppendMutation arg (bridge.go:192). The WAL
		// carries the stamped dot; replay re-mints the SAME dots.
		mutations[i] = WALMutation{
			EntityID: it.EntityID,
			NodeID:   dot.NodeID,
			Counter:  dot.Counter,
			Entry: WALEntry{
				PayloadDigest: it.Entry.PayloadDigest,
				OriginNodeID:  it.Entry.OriginNodeID,
				DotNodeID:     it.Entry.DotNodeID,
				DotCounter:    it.Entry.DotCounter,
				SystemTime:    it.Entry.SystemTime,
			},
		}
	}

	// 4. ONE AppendMutations — N writes + ONE fsync (the count cut). On ANY
	// failure (Write at i OR Sync at end) → the WHOLE batch is un-durable →
	// failedFrom=0, err non-nil → the caller ACKs ALL as 503 (atomicity above).
	_, appendErr := b.wal.AppendMutations(mutations)
	if appendErr != nil {
		return dots, 0, appendErr
	}

	// 5. Periodic checkpoint anchor (the SAME optional bound PutLocal applies,
	// with the mutation count advance = len(items), NOT 1). The checkpoint is
	// fsync'd by AppendCheckpoint; it does NOT replace the batch fsync, it adds a
	// MerkleRoot+LamportHigh anchor so a later recovery can assert crash-consistency.
	if b.checkpointInterval > 0 {
		b.mutationsSinceCkpt += uint64(len(items))
		if b.mutationsSinceCkpt >= b.checkpointInterval {
			if err := b.AppendCheckpoint(); err != nil {
				return dots, 0, err
			}
			b.mutationsSinceCkpt = 0
		}
	}
	return dots, -1, nil
}

// AppendCheckpoint records an explicit MerkleRoot + LamportHigh anchor. Tests
// and the control path use it to pin a known-good root before a simulated
// crash; the periodic path inside PutLocal uses the same underlying call.
//
// Day 11: when a snapshotter is wired (SetSnapshotter) it ALSO writes the
// dot-bearing recovery image (+ the Arrow query index when enabled) to the
// LocalFS at "ckpt/<LamportHigh>" — the O(post-checkpoint) recovery seam. The
// WAL checkpoint is fsync'd FIRST; the snapshot follows. See SetSnapshotter
// for the dangling-anchor ordering invariant.
func (b *Bridge) AppendCheckpoint() error {
	ckpt := WALCheckpoint{
		MerkleRoot:  b.engine.State().MerkleRoot(),
		LamportHigh: b.engine.LamportCounter(),
	}
	if err := b.wal.AppendCheckpoint(ckpt); err != nil {
		return err
	}
	if b.snapshotter == nil {
		return nil // back-compat: WAL anchor only.
	}
	// Construct a FRESH per-checkpoint MemTable (the Arrow index target). A
	// MemTable is stateful (skipList + inflight flush), so it is NOT reused
	// across checkpoints; NewJemallocAllocator is a trivial handle (no cgo
	// init), so per-checkpoint construction is cheap. Close drains inflight
	// flushes and frees the arena — no leak, no cross-checkpoint state.
	var mt *database.MemTable
	if b.snapshotIndexEnabled {
		_, _, mt0, err := NewSnapshotMemTable(b.snapshotter, b.snapshotFallbackDir)
		if err != nil {
			return fmt.Errorf("durability: snapshot memtable ctor: %w", err)
		}
		// G4 (Day-11.5 honesty): the MemTable.Close error is NOT swallowed.
		// A failed Close on the checkpoint's MemTable surfaces an async L0
		// flush error that landed post-SnapshotToLSM — exactly the fsync-class
		// durability error ATTACK 3 (ADR-0013) warns against. Discarding it
		// would silently accept an un-backed snapshot image, the same class of
		// silent-durability-loss the receive-seam swallowed-error fix (Day 8.5)
		// closed. We surface it as a checkpoint error so the Bridge caller sees
		// the snapshot flush failed (the WAL checkpoint record is already
		// fsync'd; the image may be partial — recovery's missing-image fallback
		// (T2) is the safety net). Return AFTER the SnapshotToLSM call so the
		// image is written before the close-MemTable drain is observed.
		defer func() {
			if cerr := mt0.Close(context.Background()); cerr != nil {
				// Best-effort surfacing: if SnapshotToLSM returned nil we
				// propagate the close error; if it already errored we log
				// the close error alongside (do not mask the primary error).
				log.Printf("durability: snapshot memtable Close error: %v", cerr)
			}
		}()
		mt = mt0
	}
	return SnapshotToLSM(context.Background(), b.engine, mt, ckpt, b.snapshotter)
}
