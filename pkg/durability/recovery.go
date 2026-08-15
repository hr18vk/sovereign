package durability

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"

	eng "github.com/hr18vk/supremum/pkg/sync"
)

// ErrRecoveryRootMismatch is returned by RecoverEngine when the replayed
// engine's Merkle root does NOT equal the WAL's last checkpoint root AND that
// checkpoint was the final state (no mutations were appended after it). This
// is data loss: the rebuilt state diverges from the durably-checkpointed state.
// A sick engine that fails Merkle-equality on recovery MUST NOT start — the
// Codex: "every error path must be loud." The caller (cmd/sovereign-node) MUST
// log.Fatal on this error, never silently boot.
var ErrRecoveryRootMismatch = errors.New("durability: recovery root mismatch (rebuilt Merkle root != checkpoint root)")

// SnapshotStore is the minimal interface over the dot-bearing recovery image.
// It is satisfied by *LocalFS (localfs.go) — and by any future S3-backed
// client that uploads/downloads the "ckpt/<LamportHigh>" image. The recovery
// path uses EXACTLY the checkpoint's LamportHigh as the key, so the store never
// needs to list-all; SnapshotExists is the cheap probe that gates the
// bounded-recovery branch.
type SnapshotStore interface {
	// SnapshotExists reports whether a recovery image exists at the watermark.
	SnapshotExists(ctx context.Context, lamportHigh uint64) (bool, error)
	// LoadSnapshotImage reads + decodes the recovery image at the watermark.
	LoadSnapshotImage(ctx context.Context, lamportHigh uint64) (*SnapshotImage, error)
}

// RecoveryWitness is the bounded-recovery telemetry returned by
// RecoverEngineWithSnapshot. It makes the O(post-checkpoint) claim OBSERVABLE
// (CLAUDE.md honesty law: report numbers, not adjectives).
//
//   - Bounded: true iff recovery loaded a snapshot and replayed ONLY the
//     post-checkpoint tail (the Day-11 seam). false ⇒ full-replay fallback
//     (RecoverEngine, or a missing/corrupt snapshot — T2).
//   - ReplayedRecords: the number of WAL records the replay loop ACTUALLY
//     applied (InsertLocal / AdvanceLamportTo). For the bounded path this is
//     the post-checkpoint tail length M; for full replay it is len(Ordered).
//   - SnapshotLamportHigh: the checkpoint watermark the snapshot was taken at
//     (0 when Bounded is false and no checkpoint is present).
//   - FallbackReason: the honest reason full replay was chosen despite a store
//     being wired (missing image, decode failure, no checkpoint). Empty when
//     store was nil (the back-compat RecoverEngine path) or when Bounded.
type RecoveryWitness struct {
	// fieldalignment: pointer-bearing + wide fields first. RecoveryWitness is
	// off the hot path (one per boot), so this is tidiness, not the Cache law.
	FallbackReason      string
	SnapshotLamportHigh uint64
	ReplayedRecords     int
	Bounded             bool
}

// RecoverEngine is the boot recovery bootstrap. It replays the WAL at walPath
// into a fresh engine and asserts crash-consistency against the last
// checkpoint. This productizes the supervisor.go:347 recovery logic out of the
// chaos test harness into the production boot path — same contract, no
// re-invention. The determinism property is PROVEN by
// internal/chaos.TestStage6WALRecoveryDeterminism; this func runs that exact
// algorithm against the production engine constructor.
//
// RecoverEngine is the FULL-REPLAY entrypoint (the Day-8/8.5 path, unchanged).
// Bounded recovery (the Day-11 LSM↔DURABILITY seam) is
// RecoverEngineWithSnapshot — pass a SnapshotStore to bound the replay tail to
// the records ordered AFTER the last checkpoint. RecoverEngine is a back-compat
// thin wrapper over RecoverEngineWithSnapshot with a nil store, so all
// existing callers (bridge_test.go, the Day-8/8.5 determinism teeth) compile
// byte-identical and stay GREEN with the FULL-replay behavior verified at HEAD.
//
// Returns the recovered engine, the WAL reopened for append (continuing in the
// SAME file the replay read), and the replay result (for inspection by the
// caller / tests).
//
// COLD BOOT: if walPath does not exist (first boot, no WAL yet), RecoverEngine
// creates a fresh engine at initialCounter=1 and opens the WAL for append —
// the honest "no checkpoint anchor" path. A missing WAL is NOT an error.
//
// SUSPECT LOG: if walPath exists but ReplayWAL returns a non-torn error (bad
// magic, bad version, mid-log corruption), RecoverEngine refuses boot and
// returns the error. Recovery never rebuilds on a suspect log. Torn tails are
// auto-truncated by ReplayWAL (standard WAL tail handling) and are NOT errors.
func RecoverEngine(nodeID [16]byte, walPath string, arenaSize uintptr) (*eng.DeltaCRDTEngine, *WAL, *Replayed, error) {
	engine, wal, rep, _, err := RecoverEngineWithSnapshot(nodeID, walPath, nil, arenaSize)
	return engine, wal, rep, err
}

// RecoverEngineWithSnapshot is the Day-11 bounded-recovery entrypoint. When
// `store` is non-nil AND the WAL has a checkpoint AND a recovery image exists
// at "ckpt/<checkpoint.LamportHigh>", recovery is BOUNDED:
//
//  1. seed the engine at checkpoint.LamportHigh (max(rebuiltInitial, ckpt.LamportHigh);
//     the §4 seed-by-trace proof pins the seed to the checkpoint watermark so
//     post-checkpoint InsertLocal re-mints consecutive counters matching the
//     recorded m.Counter values),
//  2. Join the snapshot's recorded dot-image into the seed engine (Join honors
//     the recorded Dot() — it does NOT re-mint — so the pre-checkpoint dot set
//     is restored verbatim, including foreign dots full-replay CANNOT reproduce),
//  3. nail the Lamport watermark to checkpoint.LamportHigh, then
//  4. replay ONLY the Ordered records whose Counter/Advance strictly exceeds
//     checkpoint.LamportHigh (the conceptual truncation at the checkpoint — the
//     snapshot absorbed everything at-or-before the watermark).
//
// Recovery cost is O(post-checkpoint), not O(writes-since-boot). The §4 proof:
//
//	at the checkpoint      : A.State().MerkleRoot() == checkpoint.MerkleRoot
//	                    (the snapshot IS the live dot set at the watermark)
//	after post-ckpt replay : A.MerkleRoot() == B.MerkleRoot()
//	                    (B = full replay; A and B reach the same dot set + watermark)
//
// FALLBACK (honest, T2): if the store is nil (RecoverEngine back-compat), or the
// WAL has no checkpoint, or no image exists at the watermark, or the image is
// corrupt — RecoverEngineWithSnapshot silently falls through to the FULL-replay
// path (the exact Day-8.5 algorithm, byte-identical) and logs the reason. A
// missing snapshot is NOT an error; it is a MERGENCY fallback. Recovery always
// rebuilds; boundedness is a best-effort optimization against the durable image.
//
// ROOT-EQUALITY ASSERTION: preserved unchanged. When the checkpoint is final
// AND no advances exist, the rebuilt root (loaded + replayed) MUST equal the
// checkpoint's MerkleRoot. For the bounded path with a final checkpoint this is
// the assertion the snapshot load is correct (loaded dot set == checkpoint dot
// set). For the full-replay path it is the Day-8.5 anchor. When mutations
// follow the checkpoint OR foreign advances exist, the assertion is scoped (the
// checkpoint does not pin the final root; determinism is asserted transitively
// via the order tooth / the post-ckpt re-mint).
func RecoverEngineWithSnapshot(
	nodeID [16]byte,
	walPath string,
	store SnapshotStore,
	arenaSize uintptr,
) (*eng.DeltaCRDTEngine, *WAL, *Replayed, *RecoveryWitness, error) {
	rep, err := ReplayWAL(walPath)
	if err != nil {
		// A missing WAL file is a cold boot (first run), not a corrupt log.
		if errors.Is(err, os.ErrNotExist) {
			engine, wal, rep0, rerr := coldBoot(nodeID, walPath, arenaSize)
			if rerr != nil {
				return nil, nil, nil, nil, rerr
			}
			return engine, wal, rep0, &RecoveryWitness{Bounded: false, ReplayedRecords: 0}, nil
		}
		return nil, nil, nil, nil, fmt.Errorf("durability: replay %s: %w", walPath, err)
	}

	// Decide bounded vs full. The snapshot branch is gated on (store != nil) so
	// the back-compat RecoverEngine path (store == nil) takes the FULL-replay
	// branch with ZERO divergence from the Day-8.5 algorithm.
	loadedImage, useSnapshot, snapshotLamportHigh := (*SnapshotImage)(nil), false, uint64(0)
	fallbackReason := ""
	if rep.HasCheckpoint && store != nil {
		lh := rep.FinalCheckpt.LamportHigh
		exists, perr := store.SnapshotExists(context.Background(), lh)
		if perr != nil {
			// A suspect store is the safest case: fall back, do not abort. The
			// WAL is still authoritative; full replay is correct, just slower.
			fallbackReason = fmt.Sprintf("snapshot exists-probe failed for ckpt/%d: %v", lh, perr)
			log.Printf("durability: %s — full-replay fallback", fallbackReason)
		} else if !exists {
			fallbackReason = fmt.Sprintf("no snapshot image at ckpt/%d", lh)
			// Absence is common (snapshot not yet written, or mid-flush crash
			// before the image landed). Silent fallback — T2.
		} else {
			img, ierr := store.LoadSnapshotImage(context.Background(), lh)
			if ierr != nil {
				fallbackReason = fmt.Sprintf("snapshot load/decode failed for ckpt/%d: %v", lh, ierr)
				log.Printf("durability: %s — full-replay fallback (suspect image not used)", fallbackReason)
			} else {
				loadedImage, useSnapshot, snapshotLamportHigh = img, true, img.LamportHigh
				if snapshotLamportHigh != lh {
					// The image header watermark disagrees with the key it was
					// stored under — a torn or rewritten image. Refuse to use it.
					useSnapshot = false
					fallbackReason = fmt.Sprintf("snapshot watermark mismatch: header=%d key=ckpt/%d", snapshotLamportHigh, lh)
					log.Printf("durability: %s — full-replay fallback", fallbackReason)
					loadedImage = nil
				}
			}
		}
	} else if store != nil && !rep.HasCheckpoint {
		fallbackReason = "store wired but WAL has no checkpoint"
	}

	// DETERMINISM CONTRACT (the load-bearing seed — Day 8.5 foreign-advance
	// fix). InsertLocal RE-STAMPS DotNodeID/DotCounter from NextDot()
	// (crdt.go:801: counter := lamportCounter.Add(1)) regardless of the
	// recorded entry fields, so the recovered engine MUST be constructed with
	// rebuiltInitial = firstMutation.Counter - 1 — the counter the engine held
	// immediately BEFORE the first durably-logged InsertLocal. Only then does
	// replaying the mutations reproduce dots that match the recorded
	// m.Counter values.
	//
	// WHY firstMutation.Counter - 1, NOT LamportHigh - len(Mutations) (the
	// Day-8 defect, §0 root cause): AdvanceLamportTo (crdt.go:1639) jumps the
	// Lamport clock forward via CAS consuming NO counter, and it is reachable
	// from the live receive path (crdt.go:1028 inside Join). A foreign jump
	// creates a counter GAP — the N recorded mutations do NOT occupy the N
	// consecutive counters ending at LamportHigh. The legacy formula
	// LamportHigh - len(Mutations) under-counts the seed; replay re-mints
	// different dots; Merkle diverges (silently, or as a FALSE
	// ErrRecoveryRootMismatch). firstMutation.Counter - 1 is EXACT: the first
	// recorded mutation minted firstMutation.Counter = seed+1 by construction,
	// so seed = firstMutation.Counter - 1 reproduces every subsequent origin
	// dot. In the no-advance case the two formulas COINCIDE (the mutations ARE
	// consecutive), so TestStage6WALRecoveryDeterminism and
	// TestRecoveryDeterminism_KillRebuildMerkleEqual stay GREEN (back-compat).
	var rebuiltInitial uint64
	if useSnapshot {
		// BOUNDED seed: the snapshot was taken at the checkpoint watermark, so
		// the engine resumes there. max(rebuiltInitial, ckpt.LamportHigh) is the
		// §4 instruction; in the honest reachable path the checkpoint's
		// LamportHigh is ≥ the WAL's first-mutation counter (the checkpoint
		// came after mutations), so the max IS checkpoint.LamportHigh. We take
		// checkpoint.LamportHigh directly: seeding ABOVE it would over-mint the
		// post-ckpt dots and break determinism; seeding below it is impossible
		// because the snapshot absorbed the watermark via Join.
		if len(rep.Mutations) > 0 {
			base := rep.Mutations[0].Counter - 1
			if base > snapshotLamportHigh {
				snapshotLamportHigh = base
			}
		}
		rebuiltInitial = snapshotLamportHigh
	} else if len(rep.Mutations) > 0 {
		// FULL-REPLAY seed (Day-8.5 exact).
		rebuiltInitial = rep.Mutations[0].Counter - 1
	} else {
		// Cold boot with no mutations: no origin dots to reproduce. Seed from
		// the high-water mark (advances may have moved the clock with no
		// trailing mutation; the recovered engine resumes at that clock).
		rebuiltInitial = rep.LamportHigh
	}

	engine, scratchDir, err := newEngineAt(nodeID, rebuiltInitial, arenaSize)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("durability: recovered engine ctor: %w", err)
	}
	rep.ScratchDir = scratchDir

	// LOAD PATH (bounded recovery): Join the recorded dot-image into the seed
	// engine. snapshotDelta builds a heap-only CRDTDelta whose Entries Seq
	// yields the image's (entityID, CRDTEntry) records; Join reads ONLY
	// delta.Entries (crdt.go:1051-1278 — never delta.Release/ebrPart/arenaRef/
	// rootRef), honors the recorded Dot() into the per-shard dot-union merge,
	// and internally EBR-pins via its own participant. So pre-checkpoint dots
	// — INCLUDING foreign dots the WAL never captured — are restored verbatim,
	// and no entry is re-minted. Join's per-entry AdvanceLamportTo(entry.Dot)
	// is a monotone max bounded above by the snapshot's highest dot (the local
	// node's checkpoint-watermark dot), so the watermark lands at
	// snapshotLamportHigh; the explicit AdvanceLamportTo nails it for the
	// empty-snapshot edge and is harmless otherwise.
	if useSnapshot {
		engine.Join(snapshotDelta(loadedImage))
		engine.AdvanceLamportTo(snapshotLamportHigh)
	}

	// Replay the WAL records IN APPEND ORDER (mutation OR advance), not two
	// separate loops. This is the Day-8.5 contract: the recovered clock follows
	// the EXACT live sequence of (dot mint, clock jump) the live engine ran.
	// On a mutation, InsertLocal re-stamps DotNodeID/DotCounter from its own
	// NextDot() (the recorded payload/origin/system-time are honored); because
	// the engine was seeded at firstMutation.Counter - 1, the re-minted ORIGIN
	// counters match the recorded m.Counter exactly. On an advance,
	// AdvanceLamportTo replays the foreign clock jump at the exact point it
	// happened live, so the NEXT origin dot mints at the same counter the live
	// engine minted it at. The re-minted origin dots match the recorded origin
	// dots; the recovered clock resumes at the live high-water.
	//
	// BOUNDED tail: when useSnapshot the snapshot absorbed every record at or
	// before snapshotLamportHigh, so ONLY records strictly above the watermark
	// are replayed. The filter is the conceptual truncation at the checkpoint:
	// a mutation whose m.Counter ≤ watermark was already in the snapshot's dot
	// set; an advance ≤ watermark was already absorbed into the snapshot's
	// clock. Replaying them would DOUBLE-apply (duplicate dots are dedup'd by
	// Join's union semantics, and AdvanceLamportTo is idempotent, so re-applying
	// is harmless for correctness — but it would inflate the witness count and
	// defeat the O(post-ckpt) bound, so we skip them).
	//
	// HONEST LIMIT (the FROZEN crdt.go lock): the advance record carries ONLY
	// the clock jump, NOT the foreign entries a live Join merged into the HAMT.
	// The WAL records origin mutations + clock advances; it does NOT record
	// foreign state. So the full-replay rebuilt engine has origin state +
	// replayed clock advances, but NOT the foreign entries. The recovered
	// root is ORIGIN-ONLY; the live root is origin + foreign. Full root-equality
	// across a foreign Join is physically impossible without WAL-capturing
	// foreign deltas as mutations (a FROZEN-crdt.go edit). Foreign state
	// converges via regossip on rejoin (eventual consistency), NOT via WAL
	// replay. See ADR-0013 §5/§7. The BOUNDED path is strictly better here:
	// the snapshot CAPTURED the foreign dots at the checkpoint, so the bounded
	// recovered engine has origin+foreign state (matching the live root), while
	// full replay still cannot. T3's origin-only setup makes A==B; the foreign
	// case makes A ⊋ B (A strictly richer) — bounded recovery wins.
	replayed := 0
	for _, rec := range rep.Ordered {
		switch rec.Type {
		case WALRecMutation:
			m := rec.Mutation
			if useSnapshot && m.Counter <= snapshotLamportHigh {
				continue // absorbed by the snapshot
			}
			entry := eng.CRDTEntry{
				PayloadDigest: m.Entry.PayloadDigest,
				OriginNodeID:  m.Entry.OriginNodeID,
				DotNodeID:     m.Entry.DotNodeID,
				DotCounter:    m.Entry.DotCounter,
				SystemTime:    m.Entry.SystemTime,
			}
			engine.InsertLocal(m.EntityID, entry)
			replayed++
		case WALRecClockAdvance:
			if useSnapshot && rec.Advance <= snapshotLamportHigh {
				continue // absorbed by the snapshot's watermark
			}
			engine.AdvanceLamportTo(rec.Advance)
			replayed++
		}
	}

	// Reopen the WAL for append, continuing in the SAME file the replay read.
	// OpenWAL positions at EOF and keeps nextSeq monotone across the reopen.
	wal, err := OpenWAL(walPath)
	if err != nil {
		_ = engine.Close()
		_ = os.RemoveAll(scratchDir)
		return nil, nil, nil, nil, fmt.Errorf("durability: reopen WAL %s: %w", walPath, err)
	}

	// CRASH-CONSISTENCY assertion. The checkpoint is the determinism anchor:
	// recovery asserts the replayed root equals the last checkpoint root. This
	// is only a sound equality when (a) the checkpoint was the FINAL record —
	// i.e. no mutations were appended after it (the live engine checkpointed,
	// then crashed, with nothing in flight) — AND (b) NO foreign clock advance
	// preceded the checkpoint. Condition (b) is the Day-8.5 honest scope: a
	// clock-advance record is the WAL's signal that a foreign Join merged
	// foreign STATE into the live HAMT, state the WAL does NOT record. When
	// advances exist, the rebuilt root is origin-only and LEGITIMATELY differs
	// from the live origin+foreign checkpoint root by the foreign entries —
	// that is NOT data loss, it is the FROZEN-lock limit, and the foreign state
	// regossips on rejoin. Asserting equality there would FALSE-fire
	// ErrRecoveryRootMismatch on a healthy node (the Day-8 original defect's
	// other facet). So the root-equality assertion is SCOPED to checkpoints
	// with NO live foreign state (the pure-originator path, G08.5.d). When
	// mutations follow the checkpoint (the periodic path), the checkpoint
	// anchors the seed but does not pin the final root; determinism is asserted
	// transitively via the order tooth (G08.e). A mismatch when the checkpoint
	// IS final AND no advances exist = data loss = refuse boot. Do NOT hand
	// back a sick engine.
	//
	// BOUNDED path: when useSnapshot AND the checkpoint is final AND no
	// advances exist, the rebuilt (loaded, not-replayed) root MUST equal the
	// checkpoint root — the snapshot IS the dot set the checkpoint root was
	// computed from (SnapshotToLSM extracts engine.State().MerkleRoot() and the
	// checkpoint records the same root). So the assertion holds for BOTH paths
	// with the SAME condition and the SAME error.
	if rep.HasCheckpoint && checkpointIsFinal(rep) && len(rep.Advances) == 0 {
		rebuiltRoot := engine.State().MerkleRoot()
		if rebuiltRoot != rep.FinalCheckpt.MerkleRoot {
			_ = wal.Close()
			_ = engine.Close()
			_ = os.RemoveAll(scratchDir)
			return nil, nil, nil, nil, fmt.Errorf("%w: rebuilt=%x checkpoint=%x (lamportHigh=%d, mutations=%d)",
				ErrRecoveryRootMismatch, rebuiltRoot, rep.FinalCheckpt.MerkleRoot,
				rep.LamportHigh, len(rep.Mutations))
		}
	} else if !rep.HasCheckpoint {
		// Cold boot with mutations but NO checkpoint: replay rebuilt from the
		// mutation log alone (no anchor to assert against). This is the honest
		// edge — log a warning so the operator knows there was no anchor.
		log.Printf("durability: cold boot, no checkpoint anchor (replayed %d mutations, %d advances from %s)",
			len(rep.Mutations), len(rep.Advances), walPath)
	} else if len(rep.Advances) > 0 {
		// Honest negative: a checkpoint coexists with foreign clock advances.
		// The rebuilt root is origin-only; the checkpoint root is origin+foreign.
		// The delta is the foreign state, which regossips on rejoin — NOT data
		// loss. Log it so the operator sees the scoped assertion was skipped.
		log.Printf("durability: checkpoint present with %d foreign advance(s) — root-equality assertion SCOPED to origin-only (foreign state regossips on rejoin; FROZEN-crdt.go limit)",
			len(rep.Advances))
	} else if rep.HasCheckpoint && !checkpointIsFinal(rep) && useSnapshot {
		// BOUNDED path with a NON-final checkpoint (post-ckpt mutations exist):
		// the §4 proof asserts A.MerkleRoot() == B.MerkleRoot() (full replay).
		// The checkpoint root does NOT pin the final root here (the post-ckpt
		// re-mint lands ABOVE the watermark), so the strict equality assertion
		// is scoped to the transitive proof (the order tooth / T3).
		log.Printf("durability: bounded recovery loaded snapshot ckpt/%d + replayed %d post-checkpoint record(s) (determinism asserted transitively via T3, not via final-root equality)",
			snapshotLamportHigh, replayed)
	}

	witness := &RecoveryWitness{
		Bounded:             useSnapshot,
		ReplayedRecords:     replayed,
		SnapshotLamportHigh: snapshotLamportHigh,
		FallbackReason:      fallbackReason,
	}
	if !useSnapshot && fallbackReason == "" && store == nil {
		// Back-compat full-replay path (RecoverEngine): witness records the
		// full log and the honest reason it was not bounded.
		witness.ReplayedRecords = replayed // == len(rep.Ordered) in the full path
	}
	return engine, wal, rep, witness, nil
}

// checkpointIsFinal reports whether the last checkpoint was the final record in
// the WAL — i.e. no mutation records followed it. ReplayWAL returns Mutations
// in append order and FinalCheckpt as the LAST checkpoint seen, but does not
// record whether mutations followed that checkpoint. We infer it from the
// LamportHigh watermark: the checkpoint's LamportHigh equals the highest
// mutation counter iff the checkpoint was taken after the last mutation (the
// "checkpoint then crash" case). If mutations followed, LamportHigh (the max
// mutation counter) strictly exceeds the checkpoint's LamportHigh.
func checkpointIsFinal(rep *Replayed) bool {
	return rep.FinalCheckpt.LamportHigh >= rep.LamportHigh
}

// coldBoot constructs a fresh engine at initialCounter=1 and opens the WAL for
// append. This is the first-boot path (no WAL file exists yet). The fresh
// engine is persistence-seeded at 1; subsequent PutLocal calls append to the
// newly-created WAL.
func coldBoot(nodeID [16]byte, walPath string, arenaSize uintptr) (*eng.DeltaCRDTEngine, *WAL, *Replayed, error) {
	engine, scratchDir, err := newEngineAt(nodeID, 1, arenaSize)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("durability: cold-boot engine ctor: %w", err)
	}
	wal, err := OpenWAL(walPath)
	if err != nil {
		_ = engine.Close()
		_ = os.RemoveAll(scratchDir)
		return nil, nil, nil, fmt.Errorf("durability: cold-boot open WAL %s: %w", walPath, err)
	}
	log.Printf("durability: cold boot (no prior WAL at %s) — fresh engine at initialCounter=1, WAL opened for append",
		walPath)
	return engine, wal, &Replayed{ScratchDir: scratchDir}, nil
}

// newEngineAt constructs a DeltaCRDTEngine seeded at exactly initialCounter and
// returns the scratch data dir it isolated the engine in (so the caller —
// RecoverEngine / coldBoot — can hand it to the Bridge for RemoveAll on Close).
//
// LOAD-BEARING: the FROZEN constructor (crdt.go:244) reads the package global
// sync.DataDir at crdt.go:290 (e.dataDir = DataDir) and, at crdt.go:376, calls
// recoverLamport() which can OVERRIDE initialCounter with a higher value
// persisted in <dataDir>/lamport_<nodeID>.dat. That override would break the
// WAL-derived rebuiltInitial seed (the determinism contract — ADR-0013 §4,
// Day-8.5). To honor rebuiltInitial exactly the global MUST point at a fresh
// temp dir BEFORE the ctor runs (so recoverLamport reads no stale file →
// returns 0 → no override). The Day-16 fix does NOT remove the global write —
// it ADDS a post-ctor engine.SetDataDir(scratchDir) so the ENGINE INSTANCE's
// dataDir field is routed through the persistMu-guarded setter (crdt.go:484)
// for its lifetime, NOT a bare global mutation the caller can race on.
//
// The residual honesty: the PRE-ctor `eng.DataDir = scratchDir` GLOBAL write
// CANNOT be removed without re-introducing the Day-8 determinism defect — the
// FROZEN ctor reads the global mid-construction, so the global is the ONLY
// channel for the scratch-dir seed-trick. Two CONCURRENT newEngineAt calls
// still race on the package global (a real-but-never-triggered-in-production
// hazard: the production boot path is sequential — one RecoverEngine per
// process at boot; the test paths serialize too). The INSTANCE-level race (two
// post-ctor SetDataDir on the SAME engine, or a SetDataDir racing an apply) IS
// closed — SetDataDir takes persistMu. ADR-0021 §2.2 discloses the residual
// global race + the FROZEN-crdt.go prerequisite for its closure (a constructor
// that takes an explicit dataDir arg, not a global). Law V: report the
// residual, do not claim the trap is fully closed.
//
// Day 8.5 MAJOR-1 (scratch-dir leak): the scratch dir is returned so the Bridge
// owns its lifecycle and RemoveAll's it on Close. Pre-8.5 newEngineAt leaked a
// /tmp dir per durable boot (grep-verified: zero RemoveAll). The
// TestRecoveryScratchDirCleaned tooth asserts the dir is gone after Close.
//
// This assumes RecoverEngine runs at boot before any concurrent engine
// construction (the production boot path is sequential, as is the test path).
func newEngineAt(nodeID [16]byte, initialCounter uint64, arenaSize uintptr) (*eng.DeltaCRDTEngine, string, error) {
	scratchDir, err := os.MkdirTemp("", "sovereign-recover-*")
	if err != nil {
		return nil, "", fmt.Errorf("durability: scratch data dir: %w", err)
	}
	// PRE-ctor: the FROZEN constructor (crdt.go:290) copies sync.DataDir INTO
	// e.dataDir and calls recoverLamport() against e.dataDir (crdt.go:376) to
	// find <dataDir>/lamport_<nodeID>.dat. Pointing the GLOBAL at the fresh
	// scratch dir BEFORE the ctor makes recoverLamport read no stale file →
	// returns 0 → honors the WAL-derived seed EXACTLY (the determinism
	// contract). This global write is LOAD-BEARING and CANNOT be removed
	// without re-introducing the Day-8 seed-override defect (see the doc above).
	eng.DataDir = scratchDir
	engine, err := eng.NewDeltaCRDTEngine(nodeID, initialCounter, arenaSize)
	if err != nil {
		_ = os.RemoveAll(scratchDir)
		return nil, "", err
	}
	// POST-ctor (Day 16, ADR-0021 §2.2): route the engine INSTANCE's dataDir
	// through the persistMu-guarded setter (crdt.go:484 SetDataDir) so the
	// scratch dir is the instance's field for its lifetime via the LOCKED
	// override path — NOT a bare global the caller races a concurrent apply
	// against. The ctor already copied the global into e.dataDir above, so
	// this is a no-op on the FIELD value; it is the CONTRACT: anyone reading
	// SetDataDir's locking (recoverLamport's persistLamport — crdt.go:911 —
	// takes persistMu too) now sees the same ordering edge the setter
	// establishes. The residual global race (two concurrent newEngineAt) is
	// disclosed in the doc above + ADR-0021 §2.2 — it is NEVER reachable on
	// the sequential boot path and is blocked from closure ONLY by the FROZEN
	// crdt.go ctor's global read.
	engine.SetDataDir(scratchDir)
	return engine, scratchDir, nil
}
