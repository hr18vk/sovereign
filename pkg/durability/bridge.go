// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

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

// Bridge is the write-through bridge between the in-memory δ-CRDT engine and
// the fsync-per-mutation WAL. It is the origin-path durability seam.
//
// ROOT CAUSE (one sentence): InsertLocal publishes the entry to the in-memory
// HAMT; AppendMutation fsyncs the (DotNodeID, DotCounter, PayloadDigest,
// OriginNodeID, SystemTime, entityID) to the WAL; a checkpoint periodically
// anchors MerkleRoot+LamportHigh so replay can PROVE equality.
//
// PHYSICAL ORDER (the single load-bearing correctness invariant, §6):
// 1. dgst:= sha256.Sum256(payload); entry.PayloadDigest = dgst
// 2. dot:= engine.InsertLocal(entityID, entry) // stamps Dot/Origin INTERNALLY
// 3. wal.AppendMutation(WALMutation{EntityID, dot.NodeID, dot.Counter, WALEntry{...}})
// 4. return dot
//
// AppendMutation MUST come AFTER InsertLocal: the WAL carries the
// engine-STAMPED dot (DotNodeID/DotCounter come from NextDot INSIDE InsertLocal
// at crdt.go:912 — the determinism-sensitive stamped values). A WAL written
// BEFORE InsertLocal cannot carry the stamped dot; replay would re-mint
// different dots → Merkle mismatch → silent data loss. The order guard
// catches a reversed-order regression.
//
// fsync-on-every-mutation is the EXISTING internal/chaos/wal.go contract
// (AppendMutation writes then fsyncs before returning). The bridge does NOT
// downgrade it to a group-commit: the NVMe fsync (~1.5µs p99, the E5 32c
// PROVEN number) is a real write-path cost, measured by the write-path cost
// gate and hidden by no one.
type Bridge struct {
	// field order is layout-only (the PutLocal ORDER INVARIANT lives in the
	// method, not the struct): pointers → strings → uint64s → bool, so the
	// struct carries no padding (fieldalignment-clean; off the hot path either
	// way — the Bridge is one per node, not per op).
	engine              *eng.DeltaCRDTEngine
	wal                 *WAL
	snapshotter         *LocalFS
	scratchDir          string
	snapshotFallbackDir string
	checkpointInterval  uint64
	// (ADR-0045) — the periodic-checkpoint race repair. ckptCounter is a
	// monotone atomic that is NEVER RESET: every mutation advances it, and the
	// crossing predicate (n/K > (n-len)/K over the caller's own half-open
	// interval) designates EXACTLY ONE owner per K-multiple — the non-atomic
	// `+=` it replaces lost updates under concurrency (crossings MISSED) and
	// the post-body reset made every goroutine see >= K for the whole slow
	// body (N checkpoints per crossing — 13 vs 10 measured). ckptState packs
	// the scheduler: bit0 = a checkpoint body is in flight; bits 1.. = the
	// pending-crossing count. Claim-and-pend move in ONE CompareAndSwap, so a
	// designation can never strand between a runner's exit and its flag store
	// (the Bool+Bool split has that window; T17's exact count forbids it).
	// ckptErrors meters checkpoint failures (logged + counted, NEVER
	// returned to the caller — the writes are already durable).
	ckptCounter atomic.Uint64
	ckptState   atomic.Uint64
	ckptErrors  atomic.Uint64
	// (ADR-0045) — the checkpoint path's arena-touch witness.
	// AppendCheckpoint stores the engine arena's bump-allocation high-water
	// after every checkpoint; under the single-pinned-walk design it must
	// NEVER move because of the checkpoint itself (T20). Machine-observable
	// so the silicon run's RSS accounting can charge arena growth to its
	// true source.
	lastCkptArenaHighWater atomic.Uint64
	// (ADR-0045) — the WAL commit-latency instrument.
	// Every AppendMutation/AppendMutations call (the commit: N writes + ONE
	// fsync) is timed. This is the record of the ~213 s single-batch commit
	// that §15.15 proved was the admission-gate SLO mechanism: before this
	// instrument the number was observable only as its downstream symptoms
	// (the 30 s client timeout, the 188.885 s "convergence"). Two clock reads
	// + ≤3 atomic ops per COMMIT (not per entry); the ingest path is not the
	// zero-alloc scaling crucible.
	commitCount       atomic.Uint64
	commitAppendNs    atomic.Int64 // Σ AppendMutation(s) wall time
	commitMaxAppendNs atomic.Int64 // worst single-commit append wall time
	// slowCommitLogNs is the LOUD threshold: a single commit whose append
	// crosses it logs a SLOW COMMIT line (the production emitter for the
	// 213 s class). Default 1 s (NewBridge) — four orders over the healthy
	// NVMe fsync floor, 10% of the 10 s gate SLO. Tests set it directly.
	slowCommitLogNs      atomic.Int64
	snapshotIndexEnabled bool
	// TEST-ONLY negative-control toggle. Zero in production
	// (NewBridge leaves it false; only the T-A1 guard sets it).
	// debugInlineCheckpoint makes designateCheckpoint run drainCheckpoints INLINE
	// (the pre-decouple shape) so T-A1's negative control can PROVE the decouple
	// is what unblocks the commit path. It exists so the guard is falsifiable,
	// not a tautology.
	debugInlineCheckpoint atomic.Bool
	// debugFullQueryFlush is a TEST-ONLY negative control (T-B1): when
	// set, planQueryTierDelta returns the FULL latest set (the pre-O(N)
	// re-flush) so the guard can PROVE the delta-flush is what cuts the fsync
	// count. Zero in production.
	debugFullQueryFlush atomic.Bool
	// HALF B — the query-tier DELTA flush. lastFlushedDot records,
	// per entity, the max-dot the query-tier Arrow index has DURABLY flushed as of
	// the last successful checkpoint. AppendCheckpoint flushes only the entities
	// whose current max-dot differs — the DELTA, O(Δ) files/fsyncs per checkpoint
	// instead of O(N) — killing the O(N²) cross-checkpoint re-flush. Keys are
	// HEAP-copied (they outlive the EBR pin). Guarded by lastFlushedMu: the
	// periodic path is single-runner (ckptState), but AppendCheckpoint is also
	// reachable directly (tests, the control path), and the guard keeps the map
	// race-free under -race regardless. OFF the per-op hot path (touched once per
	// checkpoint). Nil until the first flush (⇒ the first checkpoint is a FULL
	// flush). In-memory only: a restart rebuilds it empty, so the first post-boot
	// checkpoint conservatively re-flushes all — never a correctness hazard, since
	// the resolver merges every file under an entity's prefix regardless.
	lastFlushedMu  sync.Mutex
	lastFlushedDot map[string]eng.CausalDot
}

// Bridge field docs (kept out of the struct decl so fieldalignment reordering
// does not fight the comments):
// scratchDir — RecoverEngine's isolated temp dir (MAJOR-1
// leak fix). Close RemoveAll's it. Empty for a
// cold-constructed bridge. The WAL is the authoritative
// durability substrate; this dir is redundant scratch.
// checkpointInterval — K for periodic AppendCheckpoint (0 = caller-driven
// only). BOUNDS replay length: every K mutations an
// anchor means a subsequent recovery replays ≤ K.
// The fsync-per-mutation floor is NOT downgraded.
// ckptCounter/ckptState/ckptErrors — the interval-ownership checkpoint
// scheduler (see the struct fields above).
// snapshotter — when non-nil, AppendCheckpoint writes the
// dot-bearing recovery image (+ the Arrow index when
// snapshotIndexEnabled) to `snapshotter` AFTER the
// WAL checkpoint fsync. ZERO behavior change when nil
// (the back-compat WAL-anchor-only path).
// Set via SetSnapshotter.
// snapshotIndexEnabled — also write the Arrow query index (M8) on checkpoint.
// snapshotFallbackDir — the MemTable's local spool if a (LocalFS-only) Arrow
// upload were to fail; derived in SetSnapshotter.

// NewBridge binds an engine to an open WAL. The WAL must already be open for
// append (OpenWAL or the WAL handed back by RecoverEngine). checkpointInterval
// is the K for periodic AppendCheckpoint (0 = caller-driven checkpoints only).
// scratchDir is the recovered engine's isolated temp dir (empty for a
// cold-constructed engine); Bridge.Close owns its lifecycle (MAJOR-1 leak fix).
func NewBridge(engine *eng.DeltaCRDTEngine, wal *WAL, checkpointInterval uint64) *Bridge {
	b := &Bridge{
		engine:             engine,
		wal:                wal,
		checkpointInterval: checkpointInterval,
	}
	// (ADR-0045): the SLOW COMMIT loud threshold. 1 s is
	// four orders of magnitude over the healthy NVMe fsync floor (~1.5 µs p99)
	// and 10% of the 10 s convergence SLO — a single commit past it is a
	// gate-relevant event, never noise.
	b.slowCommitLogNs.Store(int64(time.Second))
	return b
}

// noteCommit records one WAL commit's append wall time (writes + fsync — the
// group-commit tail instrument, ADR-0045) and logs LOUDLY when a single
// commit crosses the slow threshold. Called on the success AND failure paths:
// a failed 30 s commit is exactly the SLO-killing shape the instrument exists
// to name, so the error path may not skip the record.
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
		log.Printf("durability: SLOW COMMIT: %d item(s) committed in %s (N writes + ONE fsync — the WAL group-commit tail, ADR-0045): a 10 s convergence SLO cannot be met behind a %s disk barrier (commit #%d, worst so far %s)",
			items, d, d, b.commitCount.Load(), time.Duration(b.commitMaxAppendNs.Load()))
	}
}

// CommitStats returns the WAL commit-latency instruments: the number of
// commits timed, their Σ append wall time, and the single worst. The Gossiper
// surfaces these on /v1/merkle (commit_*) so the gate and the orchestrator can
// read the commit tail DIRECTLY instead of inferring it from convergence
// symptoms.
func (b *Bridge) CommitStats() (count uint64, totalAppendNs, maxAppendNs int64) {
	return b.commitCount.Load(), b.commitAppendNs.Load(), b.commitMaxAppendNs.Load()
}

// SetScratchDir binds the recovered engine's isolated temp dir so Bridge.Close
// RemoveAll's it (MAJOR-1). RecoverEngine sets this; a cold-constructed
// bridge leaves it empty (nothing to clean). The dir is the protected-core constructor's
// recoverLamport scratch space, redundant with the WAL.
func (b *Bridge) SetScratchDir(dir string) { b.scratchDir = dir }

// SetSnapshotter wires the bounded-recovery seam. When `lfs` is non-nil,
// every AppendCheckpoint (explicit or periodic inside PutLocal) writes the
// dot-bearing recovery image to `lfs` at "ckpt/<LamportHigh>" AFTER the WAL
// checkpoint record is fsync'd; when enableIndex is true it ALSO writes the
// Arrow query index (the M8 wire of internal/database). When `lfs` is nil the
// Bridge reverts to the WAL-anchor-only behavior (ZERO behavior
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
// engine's scratch dir (MAJOR-1 — the scratch-dir leak fix). It is
// idempotent (a nil engine/WAL is a no-op). The caller (cmd/sovereign-node on
// shutdown, or a test's t.Cleanup) invokes this so a durable boot does not leak
// a /tmp dir + the persist worker's lamport_<nodeID>.dat across restarts.
//
// (I5 — the Close-drain; the UAF lesson). The decouple runs
// the checkpoint on a background goroutine, so Close must NOT tear down the
// engine/WAL while a checkpoint is in flight. Close first sets the ckptState
// CLOSING bit (atomically rejecting any new designation), then waits for the
// in-flight runner to drain (runner bit clear, pending 0) BEFORE closing the
// WAL/engine. Because the drain waits for the runner's exit CAS — which lands
// only AFTER its last AppendCheckpoint returns — no checkpoint goroutine can
// touch the engine/WAL after Close proceeds: no use-after-free, no
// write-to-closed-WAL. Production teardown is process-exit (SIGINT/SIGTERM), so
// this Close-drain is a TEST-hygiene + future-graceful-shutdown guarantee, not a
// production emergency path.
func (b *Bridge) Close() error {
	// I5: stop new designations, then drain the in-flight runner. The closing
	// bit + the pending/runner fields share one word, so a designation can never
	// slip in between this observation and the teardown below.
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

// RecordClockAdvance WAL-records a peer-driven Lamport clock advance (
// M4 — the foreign-advance clock fix). It is the receive-seam hook: after a
// successful foreign Join (which AdvanceLamportTo'd the clock inside the protected-core
// engine), the caller records the post-Join high-water mark so the WAL is the
// complete clock history and the replay can nail the clock to the recorded
// high-water (recovery.go's final AdvanceLamportTo — the seed-DERIVATION era
// is over, ADR-0045). fsync-on-commit (the same durability floor as
// AppendMutation — a clock advance that survives in memory but not on disk
// would re-introduce the gap on crash).
//
// HONEST CAVEAT (ADR-0013 §7(h)): this records the post-Accept LamportHigh,
// not the exact foreign-but-pre-mint counter — a slight over-record, harmless
// for the clock nail (the recorded advance's counter is a high-water the
// replay must reach; monotone max makes the over-record a no-op).
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
	// NextDot() + localNodeID (crdt.go:966-969); it ignores caller-set dot fields.
	dot := b.engine.InsertLocal(entityID, entry)

	// 3. AppendMutation AFTER InsertLocal — the WAL carries the engine-STAMPED
	// dot AND the FULL 120-byte entry (ADR-0045, WALRecMutationV2).
	// NewWALMutation stamps dot+origin from InsertLocal's RETURNED CausalDot —
	// the blocker fix: the caller's pre-insert struct carries ZERO dot/origin
	// (InsertLocal stamped its own copy), so persisting it (the earlier
	// shape) wrote zeros the Merkle root cannot see. Replay RESTORES the
	// recorded dot — it never re-mints (ADR-0045).
	// the commit is TIMED — AppendMutation is this path's ONE
	// write + ONE fsync, the unit the §15.15 group-commit tail is measured in.
	appendStart := time.Now()
	if err := b.wal.AppendMutation(NewWALMutation(entityID, dot, entry)); err != nil {
		b.noteCommit(time.Since(appendStart), 1) // a failed commit's latency is the SLO-killer shape; record it too
		return dot, err
	}
	b.noteCommit(time.Since(appendStart), 1)

	// 4. Periodic checkpoint anchor (optional, bounds replay length). The
	// checkpoint is fsync'd by AppendCheckpoint; it does NOT replace the
	// per-mutation fsync, it adds a MerkleRoot+LamportHigh anchor so a later
	// recovery can assert crash-consistency (ADR-0045):
	// the scheduler is interval-owned + never-blocking, and a checkpoint
	// failure is logged + metered, NEVER returned — the mutation above is
	// already durable; failing the ACK would 503 a durable write and the
	// client retry would mint DUPLICATE dots.
	b.noteMutations(1)
	return dot, nil
}

// LocalItem is the batch-inject shape Bridge.PutLocals accepts (ADR-0044).
// It is the per-entry triple the /v1/batch-insert path collects: the entity ID,
// the payload the cache retains (engine discards it after InsertLocal),
// and the bitemporal-stamped CRDTEntry (the control port stamps
// SystemTime/ValidTime/AssertionTime per entry verbatim from handleInsert before
// the batch call). It mirrors PutLocal's (entityID, payload, entry) arg triple —
// the batch method is the N-item generalization of the single-item origin path.
type LocalItem struct {
	EntityID string
	Payload  string
	Entry    eng.CRDTEntry
}

// PutLocals is the ADR-0044 WAL group-commit origin path: N items →
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
// batch). The batch-insert WAL-failure guard stays GREEN: it posts
// all-success and all-fail batches separately (never a mixed batch), so both
// semantics produce the same all-200 / all-503 observations — the guard is
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
		// NextDot() + localNodeID (crdt.go:965, protected-core — byte-identical call); it
		// ignores caller-set dot fields. The dot is stamped BEFORE the WAL carries
		// it — the determinism contract.
		dot := b.engine.InsertLocal(it.EntityID, it.Entry)
		dots[i] = dot

		// 3. Build the WALMutation from the engine-STAMPED dot + the FULL entry —
		// byte-identical discipline to PutLocal's AppendMutation arg (the
		// blocker fix + ADR-0045 full persistence). Replay RESTORES the
		// recorded dot; it never re-mints.
		mutations[i] = NewWALMutation(it.EntityID, dot, it.Entry)
	}

	// 4. ONE AppendMutations — N writes + ONE fsync (the count cut). On ANY
	// failure (Write at i OR Sync at end) → the WHOLE batch is un-durable →
	// failedFrom=0, err non-nil → the caller ACKs ALL as 503 (atomicity above).
	// TIMED: this call IS the group commit — the ~213 s
	// single-batch commit was this call's duration.
	appendStart := time.Now()
	_, appendErr := b.wal.AppendMutations(mutations)
	b.noteCommit(time.Since(appendStart), len(mutations))
	if appendErr != nil {
		return dots, 0, appendErr
	}

	// 5. Periodic checkpoint anchor (the SAME optional bound PutLocal applies,
	// with the mutation count advance = len(items), NOT 1) (ADR-0045):
	// interval-owned scheduling; a checkpoint failure is logged + metered,
	// NEVER returned — the batch is already durable (the AppendMutations fsync
	// landed above), so the caller ACKs 200.
	b.noteMutations(uint64(len(items)))
	return dots, -1, nil
}

// AppendCheckpoint records an explicit MerkleRoot + LamportHigh anchor. Tests
// and the control path use it to pin a known-good root before a simulated
// crash; the periodic path inside PutLocal uses the same underlying call.
//
// when a snapshotter is wired (SetSnapshotter) it ALSO writes the
// dot-bearing recovery image (+ the Arrow query index when enabled) to the
// LocalFS at "ckpt/<LamportHigh>" — the O(post-checkpoint) recovery seam. The
// WAL checkpoint is fsync'd FIRST; the snapshot follows. See SetSnapshotter
// for the dangling-anchor ordering invariant.
func (b *Bridge) AppendCheckpoint() error {
	// (ADR-0045): the tail-cut horizon is NextSeq() captured BEFORE
	// the walk. Every record below it completed its append — hence its
	// InsertLocal — before the walk began, so it is IN the image by
	// construction; the recovery tail is Seq >= CutSeq and the walk→append
	// window (T19's live hole: counter 94, seq 96, watermark 95, cut 104)
	// closes at the source.
	cutSeq := b.wal.NextSeq()
	// (ADR-0045): ONE EBR-pinned walk produces the root, the
	// watermark, AND the image — never State() (the N1 merged-view arena
	// blowup merkle_sharded.go removed from the sweep path) and never LamportCounter()
	// (a mint high-water that can sit ABOVE the walked image — the
	// skew source). The pin is acquired HERE, before the walk, and held across
	// the WAL append and the entire image write: the captured
	// entityID strings are arena-backed views of the live shards.
	ebr := b.engine.EBR()
	participant := ebr.Acquire()
	participant.Enter(ebr)
	// HALF B: the pin is released EARLY — right after the image is
	// encoded and the delta rows are planned (both COPY the arena-backed entityID
	// strings: encodeSnapshotImage into the image buffer, MemTable.Write into the
	// MemTable's own arena, the delta planner into a heap clone) — and BEFORE the
	// slow per-entity flush, which serializes the MemTable's OWN arena, not the
	// engine's. release() is idempotent; the defer is the error-path safety net,
	// and the explicit release() before the flush is the early release that lets
	// EBR reclamation proceed during the O(Δ) fsyncs instead of holding the pin
	// for the flush's whole duration.
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
		LamportHigh: maxLocalDot, // §7b (c): derived FROM THE WALK, never LamportCounter()
		CutSeq:      cutSeq,      // §7b the pre-walk horizon → record type 0x05
		// ClockHigh (ADR-0045): the LIVE clock at checkpoint time.
		// LamportHigh (maxLocalDot) can never bound a foreign advance; ClockHigh
		// covers exactly that — including a clock raised by a verify-failed frame
		// with NO 0x03 record on disk. Read INSIDE the EBR pin, after the walk,
		// so it is at least every counter the walk observed.
		ClockHigh: b.engine.LamportCounter(),
		HasCutSeq: true,
	}
	if image != nil {
		// Fingerprint (ADR-0045, §15.16 §11.7-§11.9): fold the
		// payload-covering check over the records the SAME pinned walk already
		// captured — NO second walk, NO State() (the N1 merged-view arena blowup
		// removed). §11.9: when there is no image (snapshotter == nil),
		// HasFingerprint stays FALSE — stamping the EMPTY-state fingerprint
		// beside the REAL root would make every later boot compare real state
		// against the empty fold.
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
	// §11.5 — the BINDING: the image header carries the anchor's CutSeq + root,
	// so a load that finds the image no longer matches the WAL's final 0x05
	// record (the ckpt/<watermark> key repeats across back-to-back checkpoints)
	// is DETECTED and falls back to exact-WAL replay instead of trusting a
	// stale-but-valid image.
	image.CutSeq = cutSeq
	image.MerkleRoot = root
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
		// honesty: the MemTable.Close error is NOT swallowed.
		// A failed Close surfaces an async L0 flush error that landed after the
		// explicit flush below — the fsync-class durability error ATTACK 3
		// (ADR-0013) warns against. The deferred Close runs at function return
		// (AFTER the explicit mt.Flush, which leaves the MemTable empty so Close's
		// own final flush is a no-op) and frees the arena — no leak.
		defer func() {
			if cerr := mt0.Close(context.Background()); cerr != nil {
				log.Printf("durability: snapshot memtable Close error: %v", cerr)
			}
		}()
		mt = mt0
	}

	// === PINNED: recovery image (FULL) + the DELTA plan ===
	// WriteSnapshotImage encodes the FULL dot-bearing image (encodeSnapshotImage
	// copies every arena-backed entityID into the image buffer) — step (1) of the
	// snapshot, unchanged: one cheap file, the recovery artifact the binding
	// (recovery.go:336) + phantom (recovery.go:376) checks guard. I2/I3 preserved:
	// the WAL anchor (above) still precedes it, and it still carries the binding.
	if err := b.snapshotter.WriteSnapshotImage(context.Background(), image); err != nil {
		return fmt.Errorf("durability: snapshot image write: %w", err)
	}
	if mt == nil {
		return nil // back-compat: recovery image only, no query-tier index.
	}

	// HALF B: the query tier is flushed DELTA-ONLY. planQueryTierDelta
	// diffs `latest` against lastFlushedDot and returns ONLY the changed rows, each
	// with a HEAP-COPIED key — so after this line NOTHING references the engine arena.
	delta := b.planQueryTierDelta(latest)
	release() // EARLY pin release: the flush below touches no engine-arena memory.

	// === PIN-FREE: stage + flush the DELTA (the slow per-entity fsyncs) ===
	// stageAndFlushQueryTierDelta writes the delta rows into the MemTable's OWN
	// arena and flushes them — O(Δ) files, O(Δ) fsyncs, off the commit path (HALF A)
	// AND off the EBR pin (the release above). The watermark advances ONLY on a
	// durable flush, so a failed flush re-includes these entities next checkpoint.
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
// durable query-tier flush (the DELTA, O(Δ) not O(N)). It runs UNDER the EBR pin
// (it reads latest's arena-backed keys) and HEAP-copies each changed key, so the
// returned rows are safe to stage after the pin releases. The FIRST checkpoint
// (lastFlushedDot == nil) returns every entity — a full flush, the correct
// conservative seed.
func (b *Bridge) planQueryTierDelta(latest map[string]eng.CRDTEntry) []ckptDeltaRow {
	b.lastFlushedMu.Lock()
	defer b.lastFlushedMu.Unlock()
	var delta []ckptDeltaRow
	for e, entry := range latest {
		if !b.debugFullQueryFlush.Load() { // TEST-ONLY bypass: force the O(N) full flush
			prev, ok := b.lastFlushedDot[e]
			if ok && prev == entry.Dot() {
				continue // unchanged since the last durable flush — skip (the delta)
			}
		}
		// strings.Clone forces a HEAP copy of the arena-backed key (it must
		// outlive the EBR pin). entry is a 120-byte value struct — self-contained.
		delta = append(delta, ckptDeltaRow{heapKey: strings.Clone(e), entry: entry})
	}
	return delta
}

// commitQueryTierDelta advances the delta watermark to the just-flushed rows.
// Called ONLY after a durable flush (stageAndFlushQueryTierDelta returned nil);
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
// MemTable and flushes them (one Arrow file + 2 fsyncs per CHANGED entity). It
// runs PIN-FREE: the rows are heap-owned, and mt.Write copies the entityID into
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
///(ADR-0045) — the interval-ownership checkpoint scheduler
// ---------------------------------------------------------------------------

// ckptState packed-word bit layout. The word packs THREE
// fields:
//
//	bit 63 — CLOSING: set once by Bridge.Close (I5). Once set,
//
// designateCheckpoint refuses new designations, so the
// Close-drain can never livelock or race a late designation.
//
//	bits 62..1 — the pending-crossing count (the exact-count field).
//	bit 0 — RUNNER: a checkpoint body (drainCheckpoints) is in flight.
//
// The closing bit lives in the SAME word as the runner/pending fields so the
// designate-vs-close decision is ONE atomic load+CAS: a designation can never
// slip in between Close observing an idle word and Close tearing down (the
// use-after-free class). When the closing bit is clear (every normal
// operation, and all of T17/T7's exact-count window), every mask and CAS below
// reduces EXACTLY to the earlier arithmetic — the exact-count contract is
// unchanged.
const (
	ckptRunnerBit  = uint64(1) << 0
	ckptClosingBit = uint64(1) << 63
	// ckptPendingMask selects the pending-count field after a >>1 (it strips
	// the closing bit, which a >>1 would otherwise drag into the count).
	ckptPendingMask = (uint64(1) << 62) - 1
)

// ckptPending extracts the pending-crossing count from a ckptState word.
func ckptPending(s uint64) uint64 { return (s >> 1) & ckptPendingMask }

// ckptIdle reports whether no runner is in flight AND no crossings are pending
// (the closing bit is ignored — a closing-but-drained bridge IS idle).
func ckptIdle(s uint64) bool { return s&^ckptClosingBit == 0 }

// noteMutations advances the NEVER-RESET checkpoint counter by n and, iff this
// caller's half-open interval (total-n, total] contains a multiple of K,
// designates this caller as the crossing's SOLE owner. The predicate
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
// "claim the runner" and "add a pending unit" ONE atomic step, so a crossing
// can never strand between a runner's exit and a flag store (the Bool+Bool
// split has exactly that window — T17's exact-count assertion forbids it).
//
// A loser (a checkpoint already in flight) does ONE CAS (+2 = one more pending
// unit) and returns — it NEVER blocks, never runs a checkpoint body.
//
// (HALF A — the decouple): the winner now SPAWNS the drain on a
// background goroutine (`go b.drainCheckpoints()`) instead of running it inline.
// The commit path (PutLocal/PutLocals) returns after its own WAL fsync; the
// checkpoint — a replay-length OPTIMIZATION (bridge.go:566), no business on the
// durability-ACK path — flushes off the commit path. The ckptState claim is
// UNCHANGED (the winner still atomically sets the runner bit + the first pending
// unit BEFORE spawning), so exactly one drain goroutine exists per idle→running
// transition and the exact-count contract (T17) is preserved.
//
// I5: a closing bridge refuses new designations. The closing bit is checked on
// the SAME load the CAS acts on, so a designation can never slip in after Close
// has set it (the CAS would fail on the changed word and retry into the refuse
// branch).
func (b *Bridge) designateCheckpoint() {
	for {
		s := b.ckptState.Load()
		if s&ckptClosingBit != 0 {
			return // I5: Close in progress — no new designations.
		}
		if s&ckptRunnerBit != 0 {
			// In flight: record the pending crossing; the runner drains it.
			if b.ckptState.CompareAndSwap(s, s+2) {
				return
			}
			continue
		}
		// Idle: claim the runner AND take this crossing as the first pending
		// unit, atomically (s has bit0 clear: +2 raises the count, |1 runs).
		if b.ckptState.CompareAndSwap(s, (s+2)|ckptRunnerBit) {
			if b.debugInlineCheckpoint.Load() {
				b.drainCheckpoints() // TEST-ONLY negative control: the pre-decouple inline shape
			} else {
				go b.drainCheckpoints() // DECOUPLE: off the commit path (HALF A)
			}
			return
		}
	}
}

// drainCheckpoints runs ONE AppendCheckpoint per pending crossing, then goes
// idle when the count drains — atomically, so a designation racing the exit is
// seen (its CAS either lands before the exit CAS, or fails the exit CAS and
// retries into a fresh runner claim). Total runs == total designations, under
// ANY interleaving (T17's exact-count contract).
//
// a checkpoint failure is LOGGED + METERED (ckptErrors), never returned
// to any caller. The mutations the checkpoint would anchor are ALREADY durable
// (their own fsyncs landed before noteMutations ran); a checkpoint is a
// replay-length OPTIMIZATION, not part of the caller's durability contract.
// Failing the ACK here would 503 a durable write and the client's retry would
// mint a second set of dots for the same keys (the second candidate
// mechanism for the 800 extra dots — distinguished from replay double-minting
// by the exact-dot replay, which removes the OTHER candidate).
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
				// Consuming the last unit: go idle in the SAME CAS, but PRESERVE
				// the closing bit (I5) — a closing bridge stays closed
				// across the drain exit so no late designation can follow.
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
// the I5 Close-drain AND the T-A3 test-synchrony primitive: under the
// decouple, checkpoint completion is ASYNC, so a test that counts WAL anchor
// records (T17/T7) or the absorbed-error meter (T16) must drain BEFORE reading,
// or it observes a short count / a zero meter that is an artifact of asynchrony,
// not a real exact-count break.
//
// Liveness: it terminates because (a) every designation is already CAS'd into
// ckptState before its PutLocal/PutLocals returns, so the pending count is final
// once the callers are done, and (b) the single runner drains one unit per
// bounded AppendCheckpoint. It never waits on a NEW designation arriving — that
// is the caller's contract (drain AFTER the writers quiesce, or after Close set
// the closing bit).
func (b *Bridge) waitCheckpointsIdle() {
	for !ckptIdle(b.ckptState.Load()) {
		runtime.Gosched()
	}
}

// CheckpointErrors returns the count of periodic-checkpoint failures absorbed
// (logged, metered, never surfaced to the caller's ACK). The T16 guard
// asserts on this counter; an operator alert can scrape it.
func (b *Bridge) CheckpointErrors() uint64 { return b.ckptErrors.Load() }

// LastCheckpointArenaHighWater returns the engine arena's bump-allocation
// high-water mark (bytes) observed at the end of the most recent
// AppendCheckpoint (ADR-0045). A checkpoint path that allocates
// arena (the pre-State() merged view) moves this number; the
// single-pinned-walk path leaves it flat. 0 before the first checkpoint.
func (b *Bridge) LastCheckpointArenaHighWater() uint64 { return b.lastCkptArenaHighWater.Load() }
