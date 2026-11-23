// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package durability

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	eng "github.com/hr18vk/sovereign/pkg/sync"

	"github.com/hr18vk/sovereign/internal/database"
)

// Bridge connects the in-memory δ-CRDT engine to the WAL on the origin write
// path. Checkpoints periodically anchor the Merkle root and Lamport high-water
// so recovery can compare replayed state with durable state.
//
// PutLocal preserves this order:
//  1. Compute the payload digest and store it in the entry.
//  2. Call InsertLocal, which assigns the dot and origin.
//  3. Append a WAL mutation containing the returned dot and the full entry.
//  4. Return the dot after the WAL append and fsync complete.
//
// InsertLocal must precede AppendMutation because NextDot assigns DotNodeID and
// DotCounter inside InsertLocal. A WAL record written earlier could not contain
// those values, and replaying different dots would produce a different Merkle
// root. TestPutLocalWALStampsEngineDot guards this ordering.
//
// The single-mutation path writes and fsyncs each WAL record before returning;
// it does not use group commit. The measured NVMe fsync cost, approximately
// 1.5 µs at p99, is therefore part of origin-write latency.
type Bridge struct {
	// Field order affects layout only; PutLocal owns the write-order invariant.
	engine              *eng.DeltaCRDTEngine
	wal                 *WAL
	snapshotter         *LocalFS
	scratchDir          string
	snapshotFallbackDir string
	checkpointInterval  uint64
	// indexFeeder is nil by default. When configured, PutLocal and PutLocals
	// invoke it synchronously after InsertLocal and before the WAL result is
	// known. The index therefore mirrors live engine state even if the append
	// fails and the caller rejects the write: the engine retains the dot and
	// the index retains its derived record. SetIndexFeeder must be called once,
	// before the first write; this field has no synchronization of its own.
	indexFeeder func(entityID string, h3Index uint64, systemTime int64)
	// ckptCounter advances monotonically and is never reset. For a caller whose
	// mutations cover (n-len, n], the crossing predicate n/K > (n-len)/K
	// designates one owner for each interval boundary. This avoids both lost
	// crossings and the repeated checkpoints caused by resetting a shared count
	// after a slow checkpoint; the older scheme produced 13 checkpoints for 10
	// crossings in one measured run.
	//
	// ckptState packs a runner flag and the pending-crossing count into one
	// atomic word. Claiming the runner and recording a crossing happen in one
	// compare-and-swap, so a runner cannot exit between those two operations and
	// strand a checkpoint. ckptErrors counts failures that are logged but not
	// returned to callers whose mutations are already durable.
	ckptCounter atomic.Uint64
	ckptState   atomic.Uint64
	ckptErrors  atomic.Uint64
	// AppendCheckpoint records the engine arena's allocation high-water after
	// each checkpoint. The single-pinned-walk implementation should leave this
	// value unchanged, allowing memory accounting to distinguish checkpoint
	// allocations from writer allocations.
	lastCkptArenaHighWater atomic.Uint64
	// Every AppendMutation or AppendMutations call is timed on both success and
	// failure. These counters captured a ~213 s single-batch commit that had
	// otherwise been visible only through a 30 s client timeout and 188.885 s
	// convergence latency. Timing costs two clock reads and at most three atomic
	// operations per commit, rather than per entry.
	commitCount       atomic.Uint64
	commitAppendNs    atomic.Int64 // Σ AppendMutation(s) wall time
	commitMaxAppendNs atomic.Int64 // worst single-commit append wall time
	// slowCommitLogNs controls the SLOW COMMIT log threshold. NewBridge sets it
	// to 1 s: four orders of magnitude above the measured ~1.5 µs NVMe fsync
	// floor and 10% of the 10 s convergence objective. Tests may set it directly.
	slowCommitLogNs      atomic.Int64
	snapshotIndexEnabled bool
	// debugInlineCheckpoint is test-only. It forces designateCheckpoint to run
	// inline so the checkpoint-decoupling test can verify that an asynchronous
	// runner is what keeps a stalled flush off the commit path.
	debugInlineCheckpoint atomic.Bool
	// debugFullQueryFlush is test-only. It bypasses delta selection and forces a
	// full query-tier flush, providing a comparison for the fsync-count test.
	debugFullQueryFlush atomic.Bool
	// lastFlushedDot records the greatest dot durably written to the query-tier
	// Arrow index for each entity. AppendCheckpoint writes only changed dots:
	// O(Δ) files and fsyncs per checkpoint instead of O(N), avoiding O(N²) work
	// across checkpoints. Keys are heap-copied so they outlive the EBR pin.
	//
	// The periodic path has one runner, but direct AppendCheckpoint calls can
	// overlap, so lastFlushedMu protects the map. A nil map makes the first
	// checkpoint a full flush. The map is not persisted; after a restart the
	// first checkpoint flushes every entity again, which is safe because the
	// resolver merges all files under an entity's prefix.
	lastFlushedMu  sync.Mutex
	lastFlushedDot map[string]eng.CausalDot
}

// Additional field contracts:
//   - scratchDir is recovery scratch space owned by Close. It is empty for a
//     cold-constructed bridge and is configured separately by SetScratchDir.
//   - checkpointInterval is the mutation interval between checkpoints; zero
//     disables periodic checkpoints. With a usable image, each checkpoint bounds
//     the following recovery tail without changing per-mutation fsync behavior.
//   - snapshotter receives the recovery image, and the Arrow index when
//     snapshotIndexEnabled is set, after the WAL checkpoint fsync. A nil store
//     leaves the WAL-anchor-only path unchanged.
//   - snapshotFallbackDir is the MemTable's local spool if an Arrow upload
//     fails. SetSnapshotter derives it from the LocalFS root.

// NewBridge binds an engine to a WAL that is already open for append, either
// from OpenWAL or RecoverEngine. checkpointInterval sets the number of mutations
// between periodic checkpoints; zero leaves checkpointing to the caller. Use
// SetScratchDir separately when recovery returns scratch space for Close to own.
func NewBridge(engine *eng.DeltaCRDTEngine, wal *WAL, checkpointInterval uint64) *Bridge {
	b := &Bridge{
		engine:             engine,
		wal:                wal,
		checkpointInterval: checkpointInterval,
	}
	// One second is four orders of magnitude above the measured ~1.5 µs NVMe
	// fsync floor and 10% of the 10 s convergence objective.
	b.slowCommitLogNs.Store(int64(time.Second))
	return b
}

// noteCommit records the elapsed time of one WAL append, including its fsync,
// and emits SLOW COMMIT when it exceeds the configured threshold. Failure paths
// call it too: a timed-out or otherwise failed commit is part of the latency
// distribution this instrumentation is intended to expose.
func (b *Bridge) noteCommit(d time.Duration, items int) {
	ns := d.Nanoseconds()
	b.commitCount.Add(1)
	b.commitAppendNs.Add(ns)
	for {
		cur := b.commitMaxAppendNs.Load()
		if ns <= cur || b.commitMaxAppendNs.CompareAndSwap(cur, ns) {
			break
		}
	}
	if thr := b.slowCommitLogNs.Load(); thr > 0 && ns > thr {
		log.Printf("durability: SLOW COMMIT: %d item(s) committed in %s (N writes + one fsync — the WAL group-commit tail, ADR-0045 §7): a 10 s convergence SLO cannot be met behind a %s disk barrier (commit #%d, worst so far %s)",
			items, d, d, b.commitCount.Load(), time.Duration(b.commitMaxAppendNs.Load()))
	}
}

// CommitStats returns the number of timed WAL commits, their total append
// duration including fsync, and the longest single append. Gossiper exposes
// these as commit_* fields on /v1/merkle so callers can observe commit latency
// directly (ADR-0045 §7).
func (b *Bridge) CommitStats() (count uint64, totalAppendNs, maxAppendNs int64) {
	return b.commitCount.Load(), b.commitAppendNs.Load(), b.commitMaxAppendNs.Load()
}

// SetScratchDir gives Bridge ownership of the isolated temporary directory
// returned by recovery. Close removes it. Cold-constructed bridges leave it
// empty. The directory holds constructor and Lamport-persistence scratch state;
// the WAL remains the authoritative durable record.
func (b *Bridge) SetScratchDir(dir string) { b.scratchDir = dir }

// SetSnapshotter enables recovery images for explicit and periodic checkpoints.
// A non-nil LocalFS receives ckpt/<LamportHigh> after the WAL checkpoint fsync;
// enableIndex also writes the Arrow query index. A nil LocalFS restores the
// WAL-anchor-only path. The node configures this when --lsm-root accompanies
// --wal-path.
//
// The WAL anchor precedes the image so recovery can recognize a crash between
// the two writes. A missing or undecodable image causes exact WAL replay rather
// than partial recovery. Bounded recovery is therefore best-effort; full replay
// remains available when the image is unusable.
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

// Close drains checkpoint work, closes the WAL and engine, and removes recovery
// scratch space, including the persist worker's lamport_<nodeID>.dat. Nil fields
// are skipped.
//
// The closing bit rejects new checkpoint designations. Close then waits for the
// runner bit and pending count to clear before releasing resources. The runner
// clears its bit only after its final AppendCheckpoint returns, so no checkpoint
// goroutine can access the WAL or engine after teardown. Production shutdown is
// currently process-driven on SIGINT or SIGTERM; the drain also supports direct
// callers and tests that close a bridge without exiting.
func (b *Bridge) Close() error {
	// The closing, pending, and runner fields share one word, so no designation
	// can slip between the decision to close and the drain below.
	for {
		s := b.ckptState.Load()
		if s&ckptClosingBit != 0 {
			break // already closing (idempotent)
		}
		if b.ckptState.CompareAndSwap(s, s|ckptClosingBit) {
			break
		}
	}
	b.waitCheckpointsIdle()

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

// RecordClockAdvance appends the engine's current Lamport high-water after a
// successful foreign Join. Replay applies the ordered mutation and advance
// records so recovery resumes at the recorded clock instead of deriving it from
// mutation counters. AppendClockAdvance fsyncs before returning, as the mutation
// path does; an advance retained only in memory would be lost on a crash.
//
// The recorded value is the post-accept high-water, which can exceed the exact
// foreign counter before the next local mint. This is safe because replay takes
// a monotone maximum and must reach at least the recorded value.
func (b *Bridge) RecordClockAdvance() error {
	return b.wal.AppendClockAdvance(b.engine.LamportCounter())
}

// Engine returns the bound engine. Recovery and the control path read
// State().MerkleRoot() + LamportCounter() through this handle.
func (b *Bridge) Engine() *eng.DeltaCRDTEngine { return b.engine }

// WAL returns the bound WAL.
func (b *Bridge) WAL() *WAL { return b.wal }

// SetIndexFeeder configures the secondary-index callback. Its primitive
// arguments keep internal/index out of this package's API; cmd/sovereign-node
// supplies the closure that applies them to the index. A nil callback, the
// default, disables the feed. Configure it once before the first write. The
// callback runs synchronously on each writer's goroutine.
func (b *Bridge) SetIndexFeeder(fn func(entityID string, h3Index uint64, systemTime int64)) {
	b.indexFeeder = fn
}

// feedIndex updates derived index state after InsertLocal. The callback has no
// error result and cannot reject the write, but it completes before PutLocal or
// PutLocals returns.
func (b *Bridge) feedIndex(entityID string, entry eng.CRDTEntry) {
	if b.indexFeeder != nil {
		b.indexFeeder(entityID, entry.H3Index, entry.SystemTime)
	}
}

// PutLocal computes the payload digest, inserts the entry into the engine, and
// appends the returned dot and full entry to the WAL. It returns the engine's
// CausalDot after the append and fsync finish.
//
// If the WAL append fails, InsertLocal has already advanced in-memory state but
// the mutation is not durable and a crash can lose it. PutLocal returns both the
// dot and the error so the caller can reject the client acknowledgement rather
// than claiming durability. The secondary-index callback, when configured, runs
// after insertion and before the append outcome is known.
func (b *Bridge) PutLocal(entityID, payload string, entry eng.CRDTEntry) (eng.CausalDot, error) {
	// 1. Digest the payload so the receive-side integrity check
	// (ReconstructEntry cross-validates PayloadDigest == SHA-256(payload)) and
	// the WAL's persisted digest are consistent by construction.
	dgst := sha256.Sum256([]byte(payload))
	entry.PayloadDigest = dgst

	// 2. InsertLocal stamps DotNodeID/DotCounter/OriginNodeID internally from
	// NextDot() + localNodeID; it ignores caller-set dot fields.
	dot := b.engine.InsertLocal(entityID, entry)

	// The index callback follows insertion but precedes the WAL result. A failed
	// append therefore leaves the index consistent with the live engine, which
	// retains the dot even though the caller rejects the write.
	b.feedIndex(entityID, entry)

	// 3. NewWALMutation combines the returned dot with the full 120-byte entry.
	// The caller's pre-insert entry has zero dot fields because InsertLocal
	// assigned them on its own copy. Replay restores the persisted values.
	// AppendMutation performs one write and one fsync, timed by noteCommit.
	appendStart := time.Now()
	if err := b.wal.AppendMutation(NewWALMutation(entityID, dot, entry)); err != nil {
		b.noteCommit(time.Since(appendStart), 1) // record failed commit latency too
		return dot, err
	}
	b.noteCommit(time.Since(appendStart), 1)

	// 4. An optional periodic checkpoint adds a MerkleRoot+LamportHigh anchor;
	// it does not replace the mutation's fsync. The asynchronous scheduler logs
	// and counts checkpoint failures without returning them: the mutation is
	// already durable, and rejecting it could cause duplicate dots on retry.
	b.noteMutations(1)
	return dot, nil
}

// LocalItem is the batch-inject shape Bridge.PutLocals accepts. It is the
// per-entry triple the /v1/batch-insert path collects: the entity ID, the
// payload the cache retains (engine discards it after InsertLocal), and the
// bitemporal-stamped CRDTEntry (the control port stamps
// SystemTime/ValidTime/AssertionTime per entry verbatim from handleInsert before
// the batch call). It mirrors PutLocal's (entityID, payload, entry) arg triple —
// the batch method is the N-item generalization of the single-item origin path.
type LocalItem struct {
	EntityID string
	Payload  string
	Entry    eng.CRDTEntry
}

// PutLocals inserts each item into the engine, then appends all N mutations
// with one AppendMutations call and one fsync. It backs /v1/batch-insert;
// /v1/insert uses PutLocal. Each WALMutation contains the dot returned by that
// item's InsertLocal, so replay restores the same dots.
//
// Any append or sync error returns (dots, 0, err), directing the caller to fail
// the entire batch with 503. Earlier records may remain in the OS page cache
// and later records may be absent, so no prefix can be acknowledged as durable.
// InsertLocal has already advanced in-memory state, but recovery contains only
// the durable records.
//
// The failure granularity differs deliberately by endpoint: PutLocal rejects one
// mutation after a sync failure, while PutLocals rejects the whole batch. A
// caller retrying a failed batch must reuse the all-or-nothing contract.
func (b *Bridge) PutLocals(items []LocalItem) (dots []eng.CausalDot, failedFrom int, err error) {
	dots = make([]eng.CausalDot, len(items))
	mutations := make([]WALMutation, len(items))
	for i, it := range items {
		// 1. Digest the payload so the receive-side integrity check
		// (ReconstructEntry cross-validates PayloadDigest == SHA-256(payload))
		// and the WAL's persisted digest are consistent by construction — the
		// same digest PutLocal derives from the same payload the cache stores.
		dgst := sha256.Sum256([]byte(it.Payload))
		it.Entry.PayloadDigest = dgst

		// 2. InsertLocal stamps DotNodeID/DotCounter/OriginNodeID internally from
		// NextDot() + localNodeID (byte-identical call); it ignores caller-set
		// dot fields. The dot is stamped before the WAL carries it — the
		// determinism contract.
		dot := b.engine.InsertLocal(it.EntityID, it.Entry)
		// 2b. The per-item secondary-index tap — the same synchronous-after-
		// InsertLocal placement PutLocal uses, so a batch's items are indexed
		// the moment each lands in the engine, before the one AppendMutations
		// fsync below. Read-your-writes holds per item; a WAL-fail 503 for the
		// whole batch leaves the engine holding every minted dot, and the index
		// mirrors the engine.
		b.feedIndex(it.EntityID, it.Entry)
		dots[i] = dot

		// 3. Build the WALMutation from the engine-stamped dot + the full entry
		// — byte-identical discipline to PutLocal's AppendMutation arg. Replay
		// restores the recorded dot; it never re-mints.
		mutations[i] = NewWALMutation(it.EntityID, dot, it.Entry)
	}

	// 4. One AppendMutations — N writes + one fsync (the count cut). On any
	// failure (write at i or sync at end) the whole batch is un-durable →
	// failedFrom=0, err non-nil → the caller ACKs all as 503 (atomicity
	// above). This call is the group commit — the ~213 s single-batch
	// commit was this call's duration.
	appendStart := time.Now()
	_, appendErr := b.wal.AppendMutations(mutations)
	b.noteCommit(time.Since(appendStart), len(mutations))
	if appendErr != nil {
		return dots, 0, appendErr
	}

	// 5. Periodic checkpoint anchor (the same optional bound PutLocal
	// applies, with the mutation count advance = len(items), not 1).
	// Interval-owned scheduling; a checkpoint failure is logged + metered,
	// never returned — the batch is already durable (the AppendMutations
	// fsync landed above), so the caller ACKs 200.
	b.noteMutations(uint64(len(items)))
	return dots, -1, nil
}

// AppendCheckpoint records a MerkleRoot and LamportHigh anchor in the WAL. It is
// used by the periodic scheduler and by tests and control-path callers.
//
// With a snapshotter configured, it also writes a dot-bearing recovery image at
// ckpt/<LamportHigh>, plus the Arrow query index when enabled. The WAL fsync
// precedes both writes, as described by SetSnapshotter. Recovery can then replay
// only records at or above the checkpoint's CutSeq when the image is usable.
func (b *Bridge) AppendCheckpoint() error {
	// NextSeq is the recovery-tail horizon. Every record below it completed its
	// append, and therefore its InsertLocal, before the walk begins. Such records
	// belong in the image; records at Seq >= CutSeq remain in the replay tail.
	cutSeq := b.wal.NextSeq()
	// One EBR-pinned walk produces the root, local watermark, and image without
	// rebuilding State() or reading LamportCounter as the watermark. The pin
	// protects the arena-backed entityID strings captured from the live shards.
	ebr := b.engine.EBR()
	participant := ebr.Acquire()
	participant.Enter(ebr)
	// Encoding the image copies entity IDs into the image buffer, and planning
	// delta rows clones them onto the heap. Release the pin before the per-entity
	// flush, which uses only the MemTable's own arena afterward. The deferred
	// release covers errors; the explicit release permits EBR reclamation during
	// the O(Δ) fsyncs.
	released := false
	release := func() {
		if !released {
			ebr.Release(participant)
			released = true
		}
	}
	defer release()

	var image *SnapshotImage
	var latest map[string]eng.CRDTEntry
	if b.snapshotter != nil {
		image = &SnapshotImage{}
		latest = make(map[string]eng.CRDTEntry, 256)
	}
	root, maxLocalDot := b.engine.CaptureShardsPinned(func(entityID string, entries []eng.CRDTEntry) bool {
		if image == nil {
			return true
		}
		for i := range entries {
			image.Records = append(image.Records, SnapshotRecord{
				EntityID: entityID,
				Entry:    entries[i],
			})
			// Latest = max (DotNodeID, DotCounter) — the add-wins "winner" for
			// the query index's one-row-per-entity representative.
			cur, ok := latest[entityID]
			if !ok || compareDotsLocal(cur.Dot(), entries[i].Dot()) < 0 {
				latest[entityID] = entries[i]
			}
		}
		return true
	})
	ckpt := WALCheckpoint{
		MerkleRoot:  root,
		LamportHigh: maxLocalDot, // greatest local dot observed by the pinned walk
		CutSeq:      cutSeq,      // NextSeq captured before the walk; record type 0x05
		// ClockHigh is the live clock at checkpoint time (ADR-0045 §4).
		// LamportHigh excludes foreign advances, including a raise caused by a
		// frame that failed verification before any 0x03 record was written.
		// Reading after the walk covers every counter the walk observed.
		ClockHigh: b.engine.LamportCounter(),
		HasCutSeq: true,
	}
	if image != nil {
		// Fingerprint: fold the payload-covering check over the records the
		// same pinned walk already captured — no second walk, no State(). When
		// there is no image (snapshotter == nil), HasFingerprint stays false —
		// stamping the empty-state fingerprint beside the real root would make
		// every later boot compare real state against the empty fold.
		ckpt.Fingerprint = fingerprintRecords(image.Records)
		ckpt.HasFingerprint = true
	}
	if err := b.wal.AppendCheckpoint(ckpt); err != nil {
		return err
	}
	b.lastCkptArenaHighWater.Store(b.engine.Arena().HighWater())
	if b.snapshotter == nil {
		return nil // back-compat: WAL anchor only.
	}
	image.LamportHigh = maxLocalDot
	// The image header carries the anchor's CutSeq + root, so a load that finds
	// the image no longer matches the WAL's final 0x05 record (the ckpt/<watermark>
	// key repeats across back-to-back checkpoints) is detected and falls back to
	// exact-WAL replay instead of trusting a stale-but-valid image.
	image.CutSeq = cutSeq
	image.MerkleRoot = root
	// Construct a fresh per-checkpoint MemTable (the Arrow index target). A
	// MemTable is stateful (skipList + inflight flush), so it is not reused
	// across checkpoints; NewJemallocAllocator is a trivial handle (no cgo
	// init), so per-checkpoint construction is cheap. Close drains inflight
	// flushes and frees the arena — no leak, no cross-checkpoint state.
	var mt *database.MemTable
	if b.snapshotIndexEnabled {
		_, _, mt0, err := NewSnapshotMemTable(b.snapshotter, b.snapshotFallbackDir)
		if err != nil {
			return fmt.Errorf("durability: snapshot memtable ctor: %w", err)
		}
		// The MemTable.Close error is not swallowed. A failed Close surfaces an
		// async L0 flush error that landed after the explicit flush below — the
		// fsync-class durability error warns against this. The deferred Close runs
		// at function return (after the explicit mt.Flush, which leaves the
		// MemTable empty so Close's own final flush is a no-op) and frees the
		// arena — no leak.
		defer func() {
			if cerr := mt0.Close(context.Background()); cerr != nil {
				log.Printf("durability: snapshot memtable Close error: %v", cerr)
			}
		}()
		mt = mt0
	}

	// WriteSnapshotImage encodes the full dot-bearing image (encodeSnapshotImage
	// copies every arena-backed entityID into the image buffer) — step (1) of the
	// snapshot, unchanged: one cheap file, the recovery artifact the binding and
	// phantom checks guard.
	if err := b.snapshotter.WriteSnapshotImage(context.Background(), image); err != nil {
		return fmt.Errorf("durability: snapshot image write: %w", err)
	}
	if mt == nil {
		return nil // back-compat: recovery image only, no query-tier index.
	}

	// The query tier is flushed delta-only. planQueryTierDelta diffs `latest`
	// against lastFlushedDot and returns only the changed rows, each with a
	// heap-copied key — so after this line nothing references the engine arena.
	delta := b.planQueryTierDelta(latest)
	release() // early pin release: the flush below touches no engine-arena memory.

	// Stage + flush the delta (the slow per-entity fsyncs). stageAndFlushQueryTierDelta
	// writes the delta rows into the MemTable's own arena and flushes them —
	// O(Δ) files, O(Δ) fsyncs, off the commit path and off the EBR pin (the
	// release above). The watermark advances only on a durable flush, so a failed
	// flush re-includes these entities next checkpoint.
	flushErr := stageAndFlushQueryTierDelta(context.Background(), mt, delta)
	if flushErr == nil {
		b.commitQueryTierDelta(delta)
	}
	return flushErr
}

// ckptDeltaRow is one entity's query-tier delta row: the heap-copied entityID
// (safe to hold after the EBR pin releases) + its latest entry (a value copy).
type ckptDeltaRow struct {
	heapKey string
	entry   eng.CRDTEntry
}

// planQueryTierDelta returns the entities whose max-dot changed since the last
// durable query-tier flush (the delta, O(Δ) not O(N)). It runs under the EBR
// pin (it reads latest's arena-backed keys) and heap-copies each changed key,
// so the returned rows are safe to stage after the pin releases. The first
// checkpoint (lastFlushedDot == nil) returns every entity — a full flush, the
// correct conservative seed.
func (b *Bridge) planQueryTierDelta(latest map[string]eng.CRDTEntry) []ckptDeltaRow {
	b.lastFlushedMu.Lock()
	defer b.lastFlushedMu.Unlock()
	var delta []ckptDeltaRow
	for e, entry := range latest {
		if !b.debugFullQueryFlush.Load() { // test-only bypass: force the O(N) full flush
			prev, ok := b.lastFlushedDot[e]
			if ok && prev == entry.Dot() {
				continue // unchanged since the last durable flush — skip (the delta)
			}
		}
		// strings.Clone forces a heap copy of the arena-backed key (it must
		// outlive the EBR pin). entry is a 120-byte value struct — self-contained.
		delta = append(delta, ckptDeltaRow{heapKey: strings.Clone(e), entry: entry})
	}
	return delta
}

// commitQueryTierDelta advances the delta watermark to the just-flushed rows.
// Called only after a durable flush (stageAndFlushQueryTierDelta returned nil);
// a failed flush leaves lastFlushedDot so the next checkpoint re-flushes the
// missed delta. heapKeys are already heap-copied (planQueryTierDelta).
func (b *Bridge) commitQueryTierDelta(delta []ckptDeltaRow) {
	b.lastFlushedMu.Lock()
	defer b.lastFlushedMu.Unlock()
	if b.lastFlushedDot == nil {
		b.lastFlushedDot = make(map[string]eng.CausalDot, len(delta))
	}
	for _, r := range delta {
		b.lastFlushedDot[r.heapKey] = r.entry.Dot()
	}
}

// stageAndFlushQueryTierDelta writes the delta rows into the checkpoint's fresh
// MemTable and flushes them (one Arrow file + 2 fsyncs per changed entity). It
// runs pin-free: the rows are heap-owned, and mt.Write copies the entityID into
// the MemTable's own arena, so no engine-arena memory is touched.
func stageAndFlushQueryTierDelta(ctx context.Context, mt *database.MemTable, delta []ckptDeltaRow) error {
	for _, r := range delta {
		if err := mt.Write(ctx, queryTierEvent(r.heapKey, r.entry)); err != nil {
			return fmt.Errorf("durability: delta memtable write %q: %w", r.heapKey, err)
		}
	}
	if err := mt.Flush(ctx); err != nil {
		return fmt.Errorf("durability: delta memtable flush: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// The interval-ownership checkpoint scheduler
// ---------------------------------------------------------------------------

// ckptState packs three fields into one atomic word:
//
//	bit 63     — closing: Bridge.Close sets this once, after which
//	             designateCheckpoint rejects new work.
//	bits 62..1 — pending-crossing count.
//	bit 0      — runner: drainCheckpoints is in flight.
//
// Sharing the word makes designation and shutdown one atomic decision: Close
// cannot observe an idle state and then tear down while another writer claims
// the runner. The masks below ignore the closing bit when counting pending work.
const (
	ckptRunnerBit  = uint64(1) << 0
	ckptClosingBit = uint64(1) << 63
	// ckptPendingMask selects the pending-count field after a >>1 (it strips
	// the closing bit, which a >>1 would otherwise drag into the count).
	ckptPendingMask = (uint64(1) << 62) - 1
)

// ckptPending extracts the pending-crossing count from a ckptState word.
func ckptPending(s uint64) uint64 { return (s >> 1) & ckptPendingMask }

// ckptIdle reports whether no runner is in flight and no crossings are pending
// (the closing bit is ignored — a closing-but-drained bridge is idle).
func ckptIdle(s uint64) bool { return s&^ckptClosingBit == 0 }

// noteMutations advances the never-reset checkpoint counter by n and, iff this
// caller's half-open interval (total-n, total] contains a multiple of K,
// designates this caller as the crossing's sole owner. The predicate
// total/K > (total-n)/K fires for exactly one caller per K-multiple: disjoint
// intervals tile [0, total], so every multiple lands in exactly one interval.
// Wait-free: one AddUint64 on the write path, no CAS to count, no mutex.
func (b *Bridge) noteMutations(n uint64) {
	if b.checkpointInterval == 0 {
		return
	}
	total := b.ckptCounter.Add(n)
	if total/b.checkpointInterval == (total-n)/b.checkpointInterval {
		return // no K-multiple in this caller's interval
	}
	b.designateCheckpoint()
}

// designateCheckpoint records one pending checkpoint crossing and runs the
// drain if no checkpoint body is in flight. The packed ckptState word makes
// "claim the runner" and "add a pending unit" one atomic step, so a crossing
// can never strand between a runner's exit and a flag store (the Bool+Bool
// split has exactly that window — the exact-count assertion forbids it).
//
// A loser (a checkpoint already in flight) does one CAS (+2 = one more pending
// unit) and returns — it never blocks, never runs a checkpoint body.
//
// The winner now spawns the drain on a background goroutine (`go
// b.drainCheckpoints()`) instead of running it inline. The commit path
// (PutLocal/PutLocals) returns after its own WAL fsync; the checkpoint — a
// replay-length optimization, no business on the durability-ACK path — flushes
// off the commit path. The ckptState claim is unchanged (the winner still
// atomically sets the runner bit + the first pending unit before spawning), so
// exactly one drain goroutine exists per idle→running transition and the
// exact-count contract is preserved.
//
// A closing bridge refuses new designations. The closing bit is checked on the
// same load the CAS acts on, so a designation can never slip in after Close has
// set it (the CAS would fail on the changed word and retry into the refuse
// branch).
func (b *Bridge) designateCheckpoint() {
	for {
		s := b.ckptState.Load()
		if s&ckptClosingBit != 0 {
			return // Close has started; reject new designations.
		}
		if s&ckptRunnerBit != 0 {
			// In flight: record the pending crossing; the runner drains it.
			if b.ckptState.CompareAndSwap(s, s+2) {
				return
			}
			continue
		}
		// Idle: claim the runner and take this crossing as the first pending
		// unit, atomically (s has bit0 clear: +2 raises the count, |1 runs).
		if b.ckptState.CompareAndSwap(s, (s+2)|ckptRunnerBit) {
			if b.debugInlineCheckpoint.Load() {
				b.drainCheckpoints() // test-only synchronous negative control
			} else {
				go b.drainCheckpoints() // keep checkpoint I/O off the commit path
			}
			return
		}
	}
}

// drainCheckpoints runs one AppendCheckpoint per pending crossing, then goes
// idle when the count drains — atomically, so a designation racing the exit is
// seen (its CAS either lands before the exit CAS, or fails the exit CAS and
// retries into a fresh runner claim). Total runs == total designations, under
// any interleaving (the exact-count contract).
//
// A checkpoint failure is logged + metered (ckptErrors), never returned to any
// caller. The mutations the checkpoint would anchor are already durable (their
// own fsyncs landed before noteMutations ran); a checkpoint is a replay-length
// optimization, not part of the caller's durability contract. Failing the ACK
// here would 503 a durable write and the client's retry would mint a second set
// of dots for the same keys (the second candidate mechanism for the extra dots
// — distinguished from replay double-minting by the exact-dot replay, which
// removes the other candidate).
func (b *Bridge) drainCheckpoints() {
	for {
		if err := b.AppendCheckpoint(); err != nil {
			b.ckptErrors.Add(1)
			log.Printf("durability: periodic checkpoint failed (writes are durable; the caller's ACK is unaffected): %v", err)
		}
		for {
			s := b.ckptState.Load()
			pending := ckptPending(s)
			if pending == 1 {
				// Consume the last unit and clear the runner in one CAS while
				// preserving the closing bit so no late designation can follow.
				if b.ckptState.CompareAndSwap(s, s&ckptClosingBit) {
					return
				}
				continue
			}
			// pending > 1 (a runner always holds ≥1): consume one, run again.
			if b.ckptState.CompareAndSwap(s, s-2) {
				break
			}
		}
	}
}

// waitCheckpointsIdle blocks until no checkpoint runner is in flight and no
// crossings are pending (ckptState, ignoring the closing bit, reaches 0). It is
// the Close-drain and the test-synchrony primitive: under the decouple,
// checkpoint completion is async, so a test that counts WAL anchor records or
// the absorbed-error meter must drain before reading, or it observes a short
// count or a zero meter that is an artifact of asynchrony, not a real exact-count
// break.
//
// Liveness: it terminates because (a) every designation is already CAS'd into
// ckptState before its PutLocal/PutLocals returns, so the pending count is
// final once the callers are done, and (b) the single runner drains one unit per
// bounded AppendCheckpoint. It never waits on a new designation arriving — that
// is the caller's contract (drain after the writers quiesce, or after Close sets
// the closing bit).
func (b *Bridge) waitCheckpointsIdle() {
	for !ckptIdle(b.ckptState.Load()) {
		runtime.Gosched()
	}
}

// CheckpointErrors returns the count of periodic-checkpoint failures absorbed
// (logged, metered, never surfaced to the caller's ACK). The guard asserts on
// this counter; an operator alert can scrape it.
func (b *Bridge) CheckpointErrors() uint64 { return b.ckptErrors.Load() }

// LastCheckpointArenaHighWater returns the engine arena's bump-allocation
// high-water mark (bytes) observed at the end of the most recent
// AppendCheckpoint. A checkpoint path that allocates arena (the pre-State()
// merged view) moves this number; the single-pinned-walk path leaves it flat.
// 0 before the first checkpoint.
func (b *Bridge) LastCheckpointArenaHighWater() uint64 { return b.lastCkptArenaHighWater.Load() }
