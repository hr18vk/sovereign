// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package durability

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"

	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// ErrRecoveryRootMismatch is returned by RecoverEngine when the replayed
// engine's Merkle root does NOT equal the WAL's last checkpoint root AND that
// checkpoint was the final state (no mutations were appended after it). This
// is data loss: the rebuilt state diverges from the durably-checkpointed state.
// A sick engine that fails Merkle-equality on recovery MUST NOT start — the
// "every error path must be loud." The caller (cmd/sovereign-node) MUST
// log.Fatal on this error, never silently boot.
var ErrRecoveryRootMismatch = errors.New("durability: recovery root mismatch (rebuilt Merkle root != checkpoint root)")

// ErrRecoveryFingerprintMismatch is returned by RecoverEngineWithSnapshot when
// the rebuilt state's FINGERPRINT (state_fingerprint.go — folds the entityID +
// all ten CRDTEntry fields) does NOT equal the checkpoint's persisted
// fingerprint while the image is bound to its anchor. This is the
// "same dots, wrong bytes" class the dot-only Merkle root is structurally blind
// to — a torn/lossy persistence layer that kept every dot but corrupted an
// entry's bytes. Distinct from ErrRecoveryRootMismatch so an operator can tell
// "wrong dots" from "right dots, wrong bytes". Both are fatal at boot
// (cmd/sovereign-node log.Fatalf).
var ErrRecoveryFingerprintMismatch = errors.New("durability: recovery fingerprint mismatch (rebuilt state bytes != checkpoint fingerprint — same dots, wrong bytes)")

// ErrRecoveryImageDuplicate is returned when the checkpoint image's Join into
// the fresh seed engine skipped one or more records. A faithful image is the
// canonical sort of a unique-keyed map walk (encodeSnapshotImage) and CANNOT
// contain a duplicate (entityID, dot) pair, so a skip means the on-disk bytes
// are not writer-producible — corruption. Per ADR-0045: an earlier
// revision treated the skip as a reason to DISARM the fingerprint
// check, which made the check a corruption-controlled kill switch (duplicate
// one record, bump recordCount, and byte corruption the fingerprint would have
// refused booted). The skip REFUSES the boot instead.
var ErrRecoveryImageDuplicate = errors.New("durability: recovery image contains duplicate (entityID, dot) records — not writer-producible, refusing boot")

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
// (honesty law: report numbers, not adjectives).
//
// - Bounded: true iff recovery loaded a snapshot and replayed ONLY the
// post-checkpoint tail (the seam). false ⇒ full-replay fallback
// (RecoverEngine, or a missing/corrupt snapshot).
// - ReplayedRecords: the number of WAL records the replay loop ACTUALLY
// applied (exact-dot synthetic-delta Joins / AdvanceLamportTo — NEVER
// InsertLocal; replay RESTORES, it never re-mints, ADR-0045). For the
// bounded path this is the post-checkpoint tail length M; for full replay
// it is len(Ordered).
// - SnapshotLamportHigh: the checkpoint watermark the snapshot was taken at
// (0 when Bounded is false and no checkpoint is present).
// - FallbackReason: the honest reason full replay was chosen despite a store
// being wired (missing image, decode failure, no checkpoint). Empty when
// store was nil (the back-compat RecoverEngine path) or when Bounded.
type RecoveryWitness struct {
	// fieldalignment: pointer-bearing + wide fields first. RecoveryWitness is
	// off the hot path (one per boot), so this is tidiness, not the Cache law.
	FallbackReason      string
	SnapshotLamportHigh uint64
	ReplayedRecords     int
	Bounded             bool
	// CheckpointSeq (ADR-0045) is the on-disk sequence number of the final
	// checkpoint RECORD. For a legacy 0x02 record the tail cut is Seq >
	// CheckpointSeq; for a V2 0x05 record the tail cut is the record's own
	// CutSeq horizon and CheckpointSeq identifies the record itself.
	// 0 when there was no checkpoint.
	CheckpointSeq uint64
	// LocalPhantomsRejected is the count of local image dots discarded
	// along with their image because they had no durable WAL identity. 0 when
	// the image was used or absent for a benign reason.
	LocalPhantomsRejected int
	// ExactWALFallback is true iff a bounded recovery was possible
	// (checkpoint + store wired) but recovery fell back to exact-WAL full replay
	// (missing, suspect, or phantom image). A fallback is never silent.
	ExactWALFallback bool
	// LegacyRecords (ADR-0045) is the count of replayed mutation records in
	// the LEGACY 80-byte format (0x01): for those records the five
	// temporal/H3 fields are UNKNOWN, not zero. 0 when every replayed record
	// was a full-fidelity 0x04 record. The honest statement is "N records
	// replayed from the legacy format; tri-temporal + H3 fields unknown for
	// them" — never "they are zero".
	LegacyRecords int
	// HolesRepaired (ADR-0045) is the count of durable mutation
	// records that sat BELOW the checkpoint tail cut yet were ABSENT from the
	// image — the legacy walk→append window — and were exact-restored by the
	// defensive repair pass. 0 on every V2 (horizon-cut) checkpoint by
	// construction; nonzero means a legacy log carried the window AND the
	// repair closed it (the root assertion is disarmed for that anchor — the
	// repaired state is a strict superset of what the anchor covers).
	HolesRepaired int
	// IntegrityChecksArmed (ADR-0045) is TRUE
	// iff the pre-tail root+fingerprint check actually RAN against the
	// checkpoint anchor (the image bound to the anchor, the anchor carries a
	// fingerprint, and the image Join skipped nothing). FALSE means the boot
	// carried NO integrity assertion — the machine-observable answer to "was
	// the check on?" so a silicon PASS can never again be taken with the
	// check OFF.
	IntegrityChecksArmed bool
	// LegacyCheckpoint is TRUE iff the FINAL
	// checkpoint record carries no fingerprint (a legacy 0x02, a legacy 48-byte
	// 0x05, or the 56-byte snapshotter-less form) — it tracks the final record's
	// OWN form, never an earlier record's. For such an anchor the fingerprint
	// half of the integrity check is DISARMED — recorded here so the disarm is
	// never silent.
	LegacyCheckpoint bool
	// PostTailRootArmed is TRUE iff the post-tail root
	// assertion actually RAN (bounded path, final checkpoint, intact anchor).
	// It is FALSE on every replay-only path — where the comparand is invalid
	// (the rebuilt root is origin-only; the anchor folds foreign entries) and
	// the assertion is SCOPED OFF, loudly. The machine-observable answer to
	// "did the post-tail check run?" so a PASS can never again imply coverage
	// it did not get.
	PostTailRootArmed bool
	// SeqContiguityVerified / RecordsVerified are the
	// replay's record-LOSS check: TRUE iff every WAL record's seq was verified
	// against the unbroken-ascending-run law (a gap fails the replay with
	// ErrWALSeqGap before any state is built). This is the coverage that
	// REPLACES the scoped-off post-tail root assertion on replay-only paths —
	// the check MOVED, it did not vanish.
	SeqContiguityVerified bool
	RecordsVerified       int
	// ClockHighClamped / ClockHighRaw report that a 0x05
	// checkpoint's ClockHigh exceeded the credibility ceiling and was floored
	// to the log's durable high-water at decode. A clamped boot is SAFE (the
	// clock re-derives from the log's own durable evidence) but it is NEVER
	// silent.
	ClockHighClamped bool
	ClockHighRaw     uint64
}

// RecoverEngine is the boot recovery bootstrap. It replays the WAL at walPath
// into a fresh engine and asserts crash-consistency against the last
// checkpoint. This productizes the supervisor.go:347 recovery logic out of the
// chaos test harness into the production boot path — same contract, no
// re-invention. The determinism property is PROVEN by
// internal/chaos.TestWALRecoveryDeterminism; this func runs that exact
// algorithm against the production engine constructor.
//
// RecoverEngine is the FULL-REPLAY entrypoint (the original path, unchanged).
// Bounded recovery (the LSM↔DURABILITY seam) is
// RecoverEngineWithSnapshot — pass a SnapshotStore to bound the replay tail to
// the records ordered AFTER the last checkpoint. RecoverEngine is a back-compat
// thin wrapper over RecoverEngineWithSnapshot with a nil store, so all
// existing callers (bridge_test.go, the WAL-recovery determinism guards) compile
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

// RecoverEngineWithSnapshot is the bounded-recovery entrypoint. When
// `store` is non-nil AND the WAL has a checkpoint AND a recovery image exists
// at "ckpt/<checkpoint.LamportHigh>", recovery is BOUNDED:
//
// 1. seed the engine's clock at max(rep.LamportHigh, ckpt.ClockHigh) — the
// folded WAL high-water (mutation counters + checkpoint watermarks +
// clock advances, the fold) combined with the checkpoint's persisted
// live clock (a verify-failed frame raises the clock with no 0x03
// record). The seed arrives via the CONSTRUCTOR, so the skew EWMA
// stays 0.0 — no fail-open window;
// 2. Join the snapshot's recorded dot-image into the seed engine (Join honors
// the recorded Dot() — it does NOT re-mint — so the pre-checkpoint dot set
// is restored verbatim, including foreign dots full-replay CANNOT reproduce);
// 3. replay ONLY the Ordered records at Seq >= the checkpoint's cut (the
// sequence horizon — CutSeq for a V2 0x05 record, FinalCheckptSeq+1 for a
// legacy 0x02), each restored at its WAL-RECORDED dot via a synthetic-delta
// Join (NEVER InsertLocal — replay RESTORES, it never re-mints,
// ADR-0045); then
// 4. nail the clock to the seed value (a no-op CAS — the seed already covers
// it, so no skew-EWMA write).
//
// Recovery cost is O(post-checkpoint), not O(writes-since-boot). The §4 proof:
//
//	at the checkpoint: A.State().MerkleRoot() == checkpoint.MerkleRoot
//
// (the snapshot IS the live dot set at the watermark)
//
//	after post-ckpt replay: A.MerkleRoot() == B.MerkleRoot()
//
// (B = full replay; A and B reach the same dot set + watermark)
//
// FALLBACK (honest): if the store is nil (RecoverEngine back-compat), or the
// WAL has no checkpoint, or no image exists at the watermark, or the image is
// corrupt — RecoverEngineWithSnapshot silently falls through to the FULL-replay
// path (the exact algorithm, byte-identical) and logs the reason. A
// missing snapshot is NOT an error; it is an emergency fallback. Recovery always
// rebuilds; boundedness is a best-effort optimization against the durable image.
//
// INTEGRITY ASSERTIONS (ADR-0045 — the ARMED check).
// TWO checks, each armed exactly where its comparison is meaningful:
//
//	PRE-TAIL (bounded path only): immediately after the image Join the rebuilt
//	state IS the checkpoint image, so BOTH the Merkle root AND the state
//	fingerprint (the payload-folding check) are compared against the anchor.
//	This arms on every bounded boot, tail or no tail — checkpointFinal is NOT a
//	gate. It requires the image to be BOUND to the anchor (the image header's
//	CutSeq+root == the anchor's; a mismatch is a stale-but-valid image ⇒ loud
//	exact-WAL fallback, NEVER a refusal), and the anchor to carry a fingerprint.
//	The image Join itself must skip NOTHING: a duplicate (entityID, dot) is not
//	writer-producible and REFUSES the boot outright (ErrRecoveryImageDuplicate
//	— the old disarm-on-skip was a corruption-controlled kill switch). An
//	armed mismatch is FATAL (ErrRecoveryRootMismatch /
//	ErrRecoveryFingerprintMismatch).
//
//	POST-TAIL (root-only): arms ONLY on the bounded path
//	(useSnapshot) with a final checkpoint — the one shape where the comparand
//	is valid, because the image supplies the foreign entries. On EVERY
//	replay-only path (fallback or store == nil) it is SCOPED OFF, loudly: the
//	WAL holds no foreign entries, so the rebuilt root is origin-only and can
//	never equal an anchor that folded foreign state — and no field on the
//	0x05 anchor says whether it did. The record-LOSS coverage that pairing
//	loses is replaced by WAL seq contiguity (ReplayWAL's ErrWALSeqGap), a
//	sound check with no false-positive path. When mutations follow the
//	checkpoint, the post-tail assertion is scoped (the checkpoint does not
//	pin the final root; determinism is asserted transitively via the
//	exact-dot replay).
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

	// If ReplayWAL clamped an incredible ClockHigh at
	// decode, say so LOUDLY. The clock seed below then derives from the log's
	// own durable high-water — the safe fall-back-to-the-log semantics — and the
	// witness carries the clamp. A silent clamp is a silent fallback.
	if rep.ClockHighClamped {
		log.Printf("durability: CHECKPOINT-CLAMP: a checkpoint's ClockHigh was not credible (raw=%d exceeds the %d ceiling — the wrap/poison class) and was FLOORED to the log's durable high-water; the boot proceeds on the WAL's own evidence. This node is SAFE (no clock wrap, no counter reuse) but the on-disk record was not byte-perfect — investigate the cause (no checksum exists to localize it)",
			rep.ClockHighRaw, uint64(MaxCredibleClockHigh))
	}

	// Decide bounded vs full. The snapshot branch is gated on (store != nil) so
	// the back-compat RecoverEngine path (store == nil) takes the FULL-replay
	// branch with ZERO divergence from the algorithm.
	loadedImage, useSnapshot, snapshotLamportHigh := (*SnapshotImage)(nil), false, uint64(0)
	fallbackReason := ""
	// exactWALFallback / localPhantomsRejected are the machine-observable
	// markers surfaced on the witness. exactWALFallback is true iff a bounded
	// recovery was possible (checkpoint + store wired) but we fell back to
	// exact-WAL full replay because the image was missing, suspect, or carried a
	// local phantom. A fallback is NEVER silent in this repo.
	exactWALFallback := false
	localPhantomsRejected := 0
	if rep.HasCheckpoint && store != nil {
		lh := rep.FinalCheckpt.LamportHigh
		exists, perr := store.SnapshotExists(context.Background(), lh)
		if perr != nil {
			// A suspect store is the safest case: fall back, do not abort. The
			// WAL is still authoritative; full replay is correct, just slower.
			fallbackReason = fmt.Sprintf("snapshot exists-probe failed for ckpt/%d: %v", lh, perr)
			exactWALFallback = true
			log.Printf("durability: EXACT-WAL-FALLBACK: %s", fallbackReason)
		} else if !exists {
			// Absence is common (snapshot not yet written, or mid-flush crash
			// before the image landed). Benign, but NEVER silent: the witness
			// records the fallback and a log token makes it greppable.
			fallbackReason = fmt.Sprintf("no snapshot image at ckpt/%d", lh)
			exactWALFallback = true
			log.Printf("durability: EXACT-WAL-FALLBACK: %s", fallbackReason)
		} else {
			img, ierr := store.LoadSnapshotImage(context.Background(), lh)
			if ierr != nil {
				fallbackReason = fmt.Sprintf("snapshot load/decode failed for ckpt/%d: %v", lh, ierr)
				exactWALFallback = true
				log.Printf("durability: EXACT-WAL-FALLBACK: %s (suspect image not used)", fallbackReason)
			} else {
				loadedImage, useSnapshot, snapshotLamportHigh = img, true, img.LamportHigh
				if snapshotLamportHigh != lh {
					// The image header watermark disagrees with the key it was
					// stored under — a torn or rewritten image. Refuse to use it.
					useSnapshot = false
					fallbackReason = fmt.Sprintf("snapshot watermark mismatch: header=%d key=ckpt/%d", snapshotLamportHigh, lh)
					exactWALFallback = true
					log.Printf("durability: EXACT-WAL-FALLBACK: %s", fallbackReason)
					loadedImage = nil
				} else if rep.FinalCheckpt.HasCutSeq &&
					(img.CutSeq != rep.FinalCheckpt.CutSeq || img.MerkleRoot != rep.FinalCheckpt.MerkleRoot) {
					// THE BINDING (ADR-0045). The image must be the
					// one THIS anchor describes. ckpt/<watermark> is keyed on
					// maxLocalDot, which REPEATS across back-to-back checkpoints
					// (drainCheckpoints runs one AppendCheckpoint per pending
					// crossing with no intervening local write), so the file at
					// the key can be a LATER checkpoint's image — or an OLDER one
					// after an interrupted overwrite. That is a stale-but-valid
					// image: NOT corruption. DISARM the integrity checks and fall
					// back to exact-WAL replay — NEVER fatal: the WAL is the
					// truth and the missing state re-arrives by anti-entropy.
					// (The check runs only for a V2 anchor; a legacy 0x02 record
					// carries no CutSeq to bind against.)
					useSnapshot = false
					loadedImage = nil
					exactWALFallback = true
					fallbackReason = fmt.Sprintf("image/anchor binding mismatch: image (CutSeq=%d root=%x) != anchor (CutSeq=%d root=%x) — the image at ckpt/%d was overwritten by a different checkpoint; rebuilding from the full log",
						img.CutSeq, img.MerkleRoot, rep.FinalCheckpt.CutSeq, rep.FinalCheckpt.MerkleRoot, lh)
					log.Printf("durability: EXACT-WAL-FALLBACK: %s", fallbackReason)
				}
			}
		}
	} else if store != nil && !rep.HasCheckpoint {
		fallbackReason = "store wired but WAL has no checkpoint"
	}

	// — LOCAL-PHANTOM REJECTION (the image is bound to the durable log). Every
	// LOCAL dot the image carries (DotNodeID == this node) must have a
	// corresponding durable WAL mutation identity. The WAL holds ONLY
	// local-origin mutations (the sole AppendMutation callers are Bridge.PutLocal
	// /PutLocals — foreign state arrives by gossip Join and is never WAL-appended),
	// so a local image dot with no WAL identity means the image was taken from a
	// state the durable log does not justify. RULED (ADR-0045): DISCARD THE
	// IMAGE — not merely the entry — and fall back to exact-WAL full replay with a
	// loud marker. Dropping only the entry would silently lose a mutation that may
	// be durable on a peer AND would keep a snapshot we have just proven
	// untrustworthy. Foreign dots need no WAL identity (the WAL never holds them);
	// they are KEPT when the image is otherwise anchored.
	if useSnapshot {
		localDots := make(map[eng.CausalDot]struct{}, len(rep.Mutations))
		for _, m := range rep.Mutations {
			localDots[eng.CausalDot{NodeID: m.NodeID, Counter: m.Counter}] = struct{}{}
		}
		phantoms := 0
		for _, r := range loadedImage.Records {
			if r.Entry.DotNodeID == nodeID {
				if _, ok := localDots[eng.CausalDot{NodeID: r.Entry.DotNodeID, Counter: r.Entry.DotCounter}]; !ok {
					phantoms++
				}
			}
		}
		if phantoms > 0 {
			localPhantomsRejected = phantoms
			useSnapshot = false
			loadedImage = nil
			exactWALFallback = true
			fallbackReason = fmt.Sprintf("snapshot image ckpt/%d carries %d local dot(s) with no durable WAL identity (phantom) — image discarded", snapshotLamportHigh, phantoms)
			log.Printf("durability: EXACT-WAL-FALLBACK: %s — rebuilding from the full log", fallbackReason)
		}
	}

	// SEED (ADR-0045 — the seed-formula class is DELETED, not repaired).
	// Replay now RESTORES every mutation at its WAL-recorded dot via a
	// synthetic-delta Join (it never re-mints, so the engine no longer needs to
	// be seeded to "predict" the first minted counter). The two historical
	// formulas — LamportHigh - len(Mutations) and firstMutation.Counter - 1 —
	// are REFUTED under concurrent mint/append reordering (ADR-0045)
	// and are gone. The seed only has to be a LOWER bound on the live clock so
	// the monotone-max replay lands exactly on it without overshooting:
	// rep.LamportHigh is the WAL's own folded high-water (every mutation
	// counter, every checkpoint watermark, AND every clock advance — the
	// fold, ADR-0045) and is always ≤ the live clock (every
	// recorded counter was minted live), so it can never overshoot.
	//
	// ClockHigh closes the remaining hole: the live clock can sit ABOVE
	// every RECORDED value — the receiver raises it at admission BEFORE the
	// verify gate, so a verify-failed frame leaves the clock raised with NO 0x03
	// record on disk. The checkpoint's ClockHigh persisted that live value, so
	// the seed takes max(rep.LamportHigh, ClockHigh).
	//
	// WHY THE CONSTRUCTOR, NOT AdvanceLamportTo: the clock MUST
	// arrive via the constructor seed. NewDeltaCRDTEngine Stores initialCounter
	// and resets the skew EWMA to 0.0 (crdt.go:402-414); an
	// AdvanceLamportTo with a large delta would WRITE that EWMA
	// (0.1*(remote-current)) and widen the post-recovery inbound accept
	// envelope into a fail-open window (~54M wide on the measured shape).
	// With the seed covering every recorded value, the replay-path advances and
	// the final nail below are no-op CASes that write nothing.
	rebuiltInitial := rep.LamportHigh
	if rep.HasCheckpoint && rep.FinalCheckpt.ClockHigh > rebuiltInitial {
		rebuiltInitial = rep.FinalCheckpt.ClockHigh
	}

	engine, scratchDir, err := newEngineAt(nodeID, rebuiltInitial, arenaSize)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("durability: recovered engine ctor: %w", err)
	}
	rep.ScratchDir = scratchDir

	// LOAD PATH (bounded recovery): Join the recorded dot-image into the seed
	// engine FIRST. snapshotDelta builds a heap-only CRDTDelta whose Entries
	// Seq yields the image's (entityID, CRDTEntry) records; Join reads ONLY
	// delta.Entries (crdt.go:1051-1278 — never delta.Release/ebrPart/arenaRef/
	// rootRef), honors the recorded Dot() into the per-shard dot-union merge,
	// and internally EBR-pins via its own participant. So pre-checkpoint dots —
	// INCLUDING foreign dots the WAL never captured — are restored verbatim, and
	// no entry is re-minted.
	//
	// WHY IMAGE FIRST: the merge compares DOTS ONLY (compareDots ignores
	// the digest and every temporal field), so a 120-byte image entry and an
	// 80-byte WAL-derived entry at the SAME dot are indistinguishable to the
	// merge, and the EXISTING one keeps its bytes (perShardMerge crdt.go:1257-1262
	// → equal dot ⇒ existing wins, incoming skipped). The image carries the
	// RICHEST (full 120-byte) bytes, so it is Joined first and wins every
	// same-dot overlap with a tail entry. And the image and tail are Joined in
	// SEPARATE Join calls (never one combined delta): Join sorts with
	// slices.SortFunc (crdt.go:1152, NOT stable) and dedups keeping the FIRST of
	// an equal run, so a combined image+tail delta would have an UNSPECIFIED
	// winner. Two Joins make the outcome deterministic.
	if useSnapshot {
		engine.Join(snapshotDelta(loadedImage))
		// (ADR-0045): a skipped image record REFUSES the boot — it is
		// NEVER a reason to disarm a check. A faithful image is the canonical
		// sort of a unique-keyed map walk (encodeSnapshotImage) and CANNOT
		// contain a duplicate (entityID, dot); a skip therefore means the
		// on-disk bytes are not writer-producible. An earlier revision folded
		// the skip into the pre-tail arming term below, which made the
		// fingerprint check a corruption-controlled kill switch — confirmed by
		// TestDuplicateDisarmsKillSwitch (the attack booted with the
		// corrupted bytes live). This check MUST sit before the tail replay:
		// tail records legitimately skip against image dots (equal dot ⇒
		// existing wins), so entries_skipped is only pure HERE.
		if skipped := engine.Stats()["entries_skipped"]; skipped != 0 {
			_ = engine.Close()
			_ = os.RemoveAll(scratchDir)
			return nil, nil, nil, nil, fmt.Errorf("%w: the image Join skipped %d record(s) — a faithful image cannot contain a duplicate (entityID, dot), so the on-disk bytes are not writer-producible",
				ErrRecoveryImageDuplicate, skipped)
		}
	}

	// PRE-TAIL INTEGRITY CHECK (ADR-0045).
	// At this point the engine's state IS the checkpoint image: the engine was
	// empty at construction (newEngineAt) and the image Join is the only write
	// so far. That is exactly what the checkpoint's root + fingerprint describe —
	// so BOTH integrity checks belong HERE, before the tail replay, where they
	// arm on EVERY bounded boot, tail or no tail. `checkpointFinal` is NOT a
	// gate here: gating on it was the defect that, on the crash-mid-inject
	// shape, let the post-tail check below never arm, and two silicon
	// leg-passes were taken with the check switched OFF.
	//
	// ARMING:
	// - useSnapshot ⟹ the image bound to its anchor at load (a binding
	// mismatch already fell back above) — the anchor is TRUSTWORTHY;
	// - rep.FinalCheckpt.HasFingerprint — a fingerprint-less 0x05 (legacy
	// 48-byte, or the snapshotter-less 56-byte form) has nothing to compare.
	//
	// (The retired third term — `entries_skipped == 0` — is REMOVED, not
	// relocated: a skipped image record is now REFUSED above, so the skip
	// count is provably zero here. Keeping the term would re-latent the kill
	// switch under any future bypass of the refuse.)
	//
	// A mismatch HERE is FATAL (both sentinels surface to main.go's log.Fatalf):
	// the binding matched, so differing bytes are genuine corruption, not a
	// stale image. The fingerprint half closes the "same dots, wrong bytes"
	// class the dot-only Merkle root is structurally blind to.
	integrityArmed := false
	if useSnapshot && rep.FinalCheckpt.HasFingerprint {
		integrityArmed = true
		rebuiltRoot := engine.MerkleRootFromShards()
		if rebuiltRoot != rep.FinalCheckpt.MerkleRoot {
			_ = engine.Close()
			_ = os.RemoveAll(scratchDir)
			return nil, nil, nil, nil, fmt.Errorf("%w: pre-tail image root mismatch: rebuilt=%x checkpoint=%x (CutSeq=%d)",
				ErrRecoveryRootMismatch, rebuiltRoot, rep.FinalCheckpt.MerkleRoot, rep.FinalCheckpt.CutSeq)
		}
		rebuiltFingerprint := StateFingerprint(engine)
		if rebuiltFingerprint != rep.FinalCheckpt.Fingerprint {
			_ = engine.Close()
			_ = os.RemoveAll(scratchDir)
			return nil, nil, nil, nil, fmt.Errorf("%w: pre-tail image fingerprint mismatch: rebuilt=%x checkpoint=%x (CutSeq=%d) — the image's dots match the anchor but its BYTES do not",
				ErrRecoveryFingerprintMismatch, rebuiltFingerprint, rep.FinalCheckpt.Fingerprint, rep.FinalCheckpt.CutSeq)
		}
	}

	// REPLAY — exact-dot restore, in bounded chunks, NEVER InsertLocal.
	//
	// — RESTORE, never re-mint: each mutation is applied at its WAL-RECORDED
	// dot through a synthetic-delta Join (the snapshotDelta mechanism), so Join's
	// dot-union dedups it against the image (equal dot ⇒ existing wins ⇒
	// idempotent). InsertLocal is FORBIDDEN here — it re-mints a fresh dot from
	// NextDot() and would double-mint every leaked tail entry.
	//
	// — the tail cut is the RECORD SEQUENCE, never a scalar counter. A Lamport
	// scalar cannot express "which records the checkpoint absorbed" once more
	// than one origin exists; the WAL's total order can. On the full-replay path
	// (useSnapshot == false) there is no image, so the cut is unused and EVERY
	// record is replayed.
	//
	// — WHERE the cut sits. A legacy 0x02 checkpoint cuts at its
	// OWN record seq (replay Seq > FinalCheckptSeq). A V2 0x05 checkpoint carries
	// CutSeq, the pre-walk NextSeq() horizon: every record below CutSeq completed
	// its append — hence its InsertLocal — BEFORE the image walk began, so it is
	// in the image BY CONSTRUCTION, and the tail is Seq >= CutSeq. The legacy cut
	// left the walk→append window open (a live hole was caught here: counter 94,
	// seq 96, watermark 95, cut 104 — an ACKed write below the cut yet absent
	// from the image). The defensive repair pass below heals that window for
	// legacy logs and VERIFIES it stays empty on V2 logs.
	//
	// Boundary direction: exact-dot replay is idempotent, so
	// replaying MORE is always safe and replaying FEWER loses data — with the
	// horizon cut the tail may include image-absorbed dots; idempotency makes
	// the double application a no-op, not a double-mint.
	//
	// CHUNKING: one Join per record wastes ~3x the mallocs; one
	// Join for the whole tail costs ~757 B/element of transient scratch (a 1M-
	// record tail would spike ~757 MB on a node already near its memory budget).
	// We replay in replayChunkSize-record Joins — a few thousand records per Join
	// keeps the transient at ~1.5 MB per Join.
	cutFrom := rep.FinalCheckptSeq + 1 // legacy 0x02: strictly after the checkpoint record
	if rep.HasCheckpoint && rep.FinalCheckpt.HasCutSeq {
		cutFrom = rep.FinalCheckpt.CutSeq // 0x05: the pre-walk horizon
	}
	replayed := 0
	legacyRecords := 0
	chunk := make([]SnapshotRecord, 0, replayChunkSize)
	flushChunk := func() {
		if len(chunk) == 0 {
			return
		}
		// A heap-only delta over the chunk; Join pins via its own participant and
		// a heap delta needs no Release (crdt.go:1494 ebrPart == nil short-circuit).
		engine.Join(snapshotDelta(&SnapshotImage{Records: chunk}))
		chunk = chunk[:0]
	}
	for _, rec := range rep.Ordered {
		if useSnapshot && rec.Seq < cutFrom {
			continue // absorbed by the image (the sequence cut)
		}
		switch rec.Type {
		case WALRecMutation, WALRecMutationV2:
			// 0x01 (legacy 80-byte) and 0x04 (full 120-byte) records restore
			// through the same exact-dot path; restoreEntry branches on
			// m.Legacy for the field-fidelity difference.
			m := rec.Mutation
			// Structural sanity on the record we are about to make engine
			// state. The WAL holds ONLY local-origin mutations, so a zero dot,
			// an empty entityID, or a counter past the absolute ceiling is a
			// corrupt record (or a restore-side field mix-up — this check is the
			// runtime canary for that class). Fail LOUDLY; never build state
			// on a suspect record.
			if err := checkMutationRecord(m, nodeID); err != nil {
				_ = engine.Close()
				_ = os.RemoveAll(scratchDir)
				return nil, nil, nil, nil, err
			}
			if m.Legacy {
				legacyRecords++
			}
			chunk = append(chunk, SnapshotRecord{EntityID: m.EntityID, Entry: restoreEntry(m, nodeID)})
			if len(chunk) >= replayChunkSize {
				flushChunk()
			}
			replayed++
		case WALRecClockAdvance:
			// Replay the foreign clock jump. AdvanceLamportTo is a monotone max,
			// so this is idempotent and order-safe against the Joins. Combined with
			// the final AdvanceLamportTo(rep.LamportHigh) below, this lands the
			// clock exactly on the live high-water (ADR-0045 clock nail-down).
			engine.AdvanceLamportTo(rec.Advance)
			replayed++
		}
	}
	flushChunk()

	// HOLE REPAIR (bounded path only). The tail cut guarantees "below the
	// cut ⇒ in the image" ONLY for V2 (horizon-cut) checkpoints, by
	// construction. A LEGACY 0x02 checkpoint leaves the walk→append window
	// open: a mutation whose InsertLocal landed after the walk passed its
	// shard but whose WAL record landed before the checkpoint record is
	// durable, below the cut, and ABSENT from the image — an ACKed write
	// bounded recovery would silently lose (a live instance of this hole was
	// caught). Scan the
	// below-cut records and exact-restore any the image missed. The check is
	// O(below-cut records) map lookups — no Joins unless a hole exists; the
	// restore is idempotent exact-dot, the count is machine-observable
	// (witness.HolesRepaired), and a nonzero count disarms the root assertion
	// below (the checkpoint root under-covers the repaired state by
	// construction — asserting against it would manufacture a false
	// ErrRecoveryRootMismatch).
	holesRepaired := 0
	if useSnapshot {
		type dotKey [24]byte
		inImage := make(map[dotKey]struct{}, len(loadedImage.Records))
		for _, r := range loadedImage.Records {
			var k dotKey
			copy(k[:16], r.Entry.DotNodeID[:])
			binary.BigEndian.PutUint64(k[16:], r.Entry.DotCounter)
			inImage[k] = struct{}{}
		}
		for _, rec := range rep.Ordered {
			if rec.Type != WALRecMutation && rec.Type != WALRecMutationV2 {
				continue
			}
			if rec.Seq >= cutFrom {
				continue // the tail already applied it
			}
			m := rec.Mutation
			var k dotKey
			copy(k[:16], m.NodeID[:])
			binary.BigEndian.PutUint64(k[16:], m.Counter)
			if _, ok := inImage[k]; ok {
				continue
			}
			if err := checkMutationRecord(m, nodeID); err != nil {
				_ = engine.Close()
				_ = os.RemoveAll(scratchDir)
				return nil, nil, nil, nil, err
			}
			chunk = append(chunk, SnapshotRecord{EntityID: m.EntityID, Entry: restoreEntry(m, nodeID)})
			if len(chunk) >= replayChunkSize {
				flushChunk()
			}
			holesRepaired++
		}
		flushChunk()
		if holesRepaired > 0 {
			log.Printf("durability: R9c HOLE REPAIR: restored %d durable mutation(s) that sat BELOW the checkpoint cut yet were ABSENT from the image (the legacy walk→append window); the checkpoint root under-covers the rebuilt state — root assertion disarmed for this anchor", holesRepaired)
		}
	}
	// Nail the clock to the durable high-water. The target is exactly the value
	// the constructor was seeded at above — max(rep.LamportHigh,
	// ckpt.ClockHigh) — so this CAS is already satisfied and writes NO
	// skew EWMA (crdt.go:1762 writes it only inside a succeeded CAS).
	// rep.LamportHigh folds every mutation counter
	// (internal/chaos/wal.go:899-900,:909-910), every checkpoint watermark
	// (:940-941,:964-965), AND every clock advance (:927-928 — the fold),
	// so below-cut advances are covered even though the replay loop's
	// skip never applies them. ClockHigh covers the raises that were
	// never recorded at all. Monotone max; harmless if already reached.
	engine.AdvanceLamportTo(rebuiltInitial)

	// Reopen the WAL for append, continuing in the SAME file the replay read.
	// OpenWAL positions at EOF and keeps nextSeq monotone across the reopen.
	wal, err := OpenWAL(walPath)
	if err != nil {
		_ = engine.Close()
		_ = os.RemoveAll(scratchDir)
		return nil, nil, nil, nil, fmt.Errorf("durability: reopen WAL %s: %w", walPath, err)
	}

	// Checkpoint finality, by RECORD SEQUENCE (this replaces the refuted
	// scalar-watermark checkpointIsFinal). The checkpoint is FINAL iff no
	// mutation record sits at or above the cut (Seq >= cutFrom — the horizon
	// for a V2 checkpoint, the record-seq cut for a legacy one). Advances
	// after the checkpoint move the clock but not the dot set, so they do not
	// disturb finality.
	checkpointFinal := true
	for _, rec := range rep.Ordered {
		if (rec.Type == WALRecMutation || rec.Type == WALRecMutationV2) && rec.Seq >= cutFrom {
			checkpointFinal = false
			break
		}
	}

	// CRASH-CONSISTENCY assertion (RE-ARMED, and RE-SCOPED to where its
	// comparand is VALID). The
	// checkpoint is the determinism anchor: recovery asserts the rebuilt root
	// equals the final checkpoint root. This POST-TAIL check complements the
	// pre-tail check above: the pre-tail check compares the IMAGE (where the
	// rebuilt state IS the image) on the bounded path; THIS check compares the
	// FULL post-replay state. It is root-only (dot-folded): the fingerprint
	// half cannot run here, because on the bounded-with-tail path the post-tail
	// state legitimately includes the tail.
	//
	// ARMING — on `useSnapshot` ONLY (ADR-0045). The
	// assertion's comparand is valid iff the image supplies the foreign
	// entries: the WAL records ONLY local mutations, so on ANY replay-only
	// path (fallback or store == nil) the rebuilt root is origin-only while
	// the anchor's root folds every entry the node ever held — equality is
	// unsatisfiable on a node that has ever received foreign state. The
	// earlier arming predicate armed here whenever `len(rep.Advances) == 0`,
	// but that count is a CLOCK-ADVANCE-RECORD count, not a foreign-state
	// detector: the receiver merges the Join BEFORE consulting the recorder
	// (receiver.go:622-658 — "Join is IRREVERSIBLE … already merged … by the
	// time Apply returned") and the recorder is gated on `post > preAdvance`
	// (receiver.go:652/:920/:1193), so a verified frame whose counters do not
	// raise the local clock MERGES FOREIGN STATE AND RECORDS NOTHING. On that
	// shape the disjunct armed the assertion with an unsatisfiable comparand
	// and a node whose WAL was byte-perfect was refused a boot
	// (ErrRecoveryRootMismatch → main.go log.Fatalf) — the
	// fail-stop brick. The 0x05 anchor carries NO field from which recovery
	// could learn whether foreign entries were folded (its payload is
	// MerkleRoot ‖ LamportHigh ‖ CutSeq ‖ ClockHigh ‖ [Fingerprint] —
	// internal/chaos/wal.go encodeCheckpointRecord), so no arming term on
	// this path can be sound; the assertion is therefore SCOPED OFF here,
	// LOUDLY (below), on every replay-only path.
	//
	// THE COVERAGE MOVED, IT DID NOT VANISH: record LOSS on the
	// replay-only path is now detected by WAL SEQ CONTIGUITY
	// (ReplayWAL refuses a gapped log with ErrWALSeqGap before any state is
	// built; sound by the advance-as-you-write discipline, and strictly
	// stronger on the loss axis: it covers EVERY record type, including the
	// 0x03 advances and 0x05 checkpoints the dot-fold never saw). What is
	// still NOT covered anywhere is bit ROT inside a record's payload — the
	// root folds dots only and there is no checksum (a known gap, deferred).
	//
	// - BOUNDED path (useSnapshot): the image carries the foreign entries
	// (all 120 bytes), so the rebuilt root MUST equal the checkpoint root
	// EVEN WITH foreign advances present. This is the re-arming — it
	// STAYS.
	// - FULL path (no snapshot / image discarded): scoped off, loudly —
	// the TestRecoveryForeignAdvance_NoFalseMismatch contract, now
	// unconditional rather than advance-count-dependent.
	// A mismatch on an armed assertion = data loss = refuse boot (do NOT hand
	// back a sick engine). When the checkpoint is NOT final (a post-checkpoint
	// tail exists) the checkpoint does not pin the final root; determinism is
	// then asserted transitively via the exact-dot replay.
	// (ADR-0045): a checkpoint taken MID-PutLocals (between the
	// batch's InsertLocal calls and its AppendMutations fsync) anchors a root
	// that covers dots the durable log never received. Recovery's phantom
	// check discards that image, and the full-log rebuild then CANNOT equal
	// the checkpoint root — the phantom dots were never fsync'd, never ACKed,
	// and are honestly LOST (the un-ACKed-write contract). Asserting equality
	// against the torn anchor manufactures ErrRecoveryRootMismatch on a log
	// that is NOT corrupt, and main.go:822 would Fatalf — a false data-loss
	// verdict refusing to boot a healthy node. So the assertion is armed only
	// when the anchor is intact (no phantom discard). The skip is LOUD.
	postTailArmed := rep.HasCheckpoint && checkpointFinal && useSnapshot && localPhantomsRejected == 0 && holesRepaired == 0
	if postTailArmed {
		rebuiltRoot := engine.MerkleRootFromShards()
		if rebuiltRoot != rep.FinalCheckpt.MerkleRoot {
			_ = wal.Close()
			_ = engine.Close()
			_ = os.RemoveAll(scratchDir)
			return nil, nil, nil, nil, fmt.Errorf("%w: rebuilt=%x checkpoint=%x (lamportHigh=%d, mutations=%d)",
				ErrRecoveryRootMismatch, rebuiltRoot, rep.FinalCheckpt.MerkleRoot,
				rep.LamportHigh, len(rep.Mutations))
		}
	} else if rep.HasCheckpoint && localPhantomsRejected > 0 {
		// the anchor was discarded as torn (phantom local dots — a
		// mid-PutLocals checkpoint). The assertion is skipped for it BY RULE
		// (see above); say so loudly.
		log.Printf("durability: checkpoint anchor torn (R6 rejected %d local phantom dot(s) — the R9a mid-batch window): root-equality assertion SKIPPED for this anchor; state rebuilt from the durable log alone (the un-ACKed phantom dots are honestly lost)",
			localPhantomsRejected)
	} else if rep.HasCheckpoint && holesRepaired > 0 {
		// the anchor is intact but under-covers the rebuilt state (the
		// repair pass restored below-cut dots the walk missed). The strict
		// equality assertion cannot hold for it by construction — skip loudly.
		log.Printf("durability: checkpoint anchor under-covers the rebuilt state (R9c repaired %d below-cut hole(s)): root-equality assertion SKIPPED for this anchor; the repaired state is the durable truth",
			holesRepaired)
	} else if !rep.HasCheckpoint {
		// Cold boot with mutations but NO checkpoint: replay rebuilt from the
		// mutation log alone (no anchor to assert against). This is the honest
		// edge — log a warning so the operator knows there was no anchor.
		log.Printf("durability: cold boot, no checkpoint anchor (replayed %d mutations, %d advances from %s)",
			len(rep.Mutations), len(rep.Advances), walPath)
	} else if !useSnapshot {
		// EVERY replay-only path (exact-WAL fallback or
		// store == nil). The rebuilt root is origin-only; the anchor's root
		// folds every entry the node ever held. Whether foreign state was among
		// it is UNKNOWABLE from the log (the advances count cannot say — it
		// tracks clock records, not state — and the anchor carries no entry
		// count), so the root-equality comparand is invalid here by
		// construction and the assertion is SCOPED OFF — LOUDLY, with the
		// replacement check named in the same breath. NOT data loss: foreign
		// state regossips on rejoin (the merge law's exact-dot limit), and
		// record LOSS is covered by the seq-contiguity check that already ran
		// in ReplayWAL.
		log.Printf("durability: replay-only path (exact-WAL; no usable image) with a checkpoint anchor — post-tail root-equality assertion SCOPED OFF: the rebuilt root is origin-only, the anchor may fold foreign entries (the anchor-fold case; foreign state regossips on rejoin; the merge law's exact-dot limit). Coverage: WAL seq contiguity VERIFIED over %d record(s); %d foreign advance(s) replayed.",
			rep.RecordsVerified, len(rep.Advances))
	} else if useSnapshot && !checkpointFinal {
		// BOUNDED path with a NON-final checkpoint (a post-ckpt tail exists): the
		// checkpoint root does NOT pin the final root (the tail lands above the
		// cut), so the strict equality assertion is scoped to the transitive
		// exact-dot replay proof.
		log.Printf("durability: bounded recovery loaded snapshot ckpt/%d + replayed %d post-checkpoint record(s) (determinism asserted transitively via T3, not via final-root equality)",
			snapshotLamportHigh, replayed)
	}

	witness := &RecoveryWitness{
		Bounded:               useSnapshot,
		ReplayedRecords:       replayed,
		SnapshotLamportHigh:   snapshotLamportHigh,
		FallbackReason:        fallbackReason,
		CheckpointSeq:         rep.FinalCheckptSeq,
		LocalPhantomsRejected: localPhantomsRejected,
		ExactWALFallback:      exactWALFallback,
		LegacyRecords:         legacyRecords,
		HolesRepaired:         holesRepaired,
		IntegrityChecksArmed:  integrityArmed,
		LegacyCheckpoint:      rep.LegacyCheckpoint,
		PostTailRootArmed:     postTailArmed,
		SeqContiguityVerified: rep.SeqContiguityVerified,
		RecordsVerified:       rep.RecordsVerified,
		ClockHighClamped:      rep.ClockHighClamped,
		ClockHighRaw:          rep.ClockHighRaw,
	}
	return engine, wal, rep, witness, nil
}

// replayChunkSize bounds how many WAL mutation records are restored per
// synthetic-delta Join (ADR-0045 cost decision). A single Join for the whole
// tail costs ~757 B/record of transient scratch (a 1M-record tail would spike
// ~757 MB on a node already near its memory budget); per-record Joins waste ~3x
// the mallocs. 2048 records/Join keeps the transient at ~1.5 MB per Join while
// amortizing the per-Join fixed cost. Recovery is a boot path, not the hot path,
// so this is a transient-memory bound, not a 0-allocs/op concern.
const replayChunkSize = 2048

// maxPlausibleCounter is the absolute ceiling for a WAL mutation's counter
// (ADR-0045). It is a CORRUPTION canary, not a semantic limit: a real
// counter is bounded by the node's total mints (even 50M ops/s for a decade is
// ~1.6e16). 1<<60 (~1.15e18) is far above any conceivable honest value yet
// catches uninitialized/garbage/attacker-inflated counters before a corrupt
// record becomes engine state. Join applies NO validation, so recovery is
// the sole authority on dot values — this check is the load-bearing gate.
const maxPlausibleCounter = 1 << 60

// restoreEntry builds the CRDTEntry a WAL mutation is restored (ADR-0045).
//
// V2 (0x04) records restore the FULL persisted entry verbatim — the V2 format
// closed the field loss for every record written after it. LEGACY (0x01)
// records persisted only five fields; for those, the dot comes from the
// TOP-LEVEL WALMutation fields (m.NodeID, m.Counter) — NEVER from
// m.Entry.DotNodeID/DotCounter, which are ZERO in legacy production records
// (the legacy defect: InsertLocal stamped the dot on its own copy of the entry,
// and the earlier bridge built the persisted WALEntry from the caller's
// pre-insert struct) — and OriginNodeID is SYNTHESIZED as the recovering
// node's ID: the WAL holds ONLY local-origin mutations (the sole
// AppendMutation callers are Bridge.PutLocal/PutLocals; foreign state arrives
// by gossip Join and is never WAL-appended), so every replayed mutation was
// locally originated. Restoring OriginNodeID = nodeID keeps the entry
// classified SELF by shipDelta (gossip.go:1765-1780) so a relaunched node
// re-serves its own pre-crash payloads from the payloadCache.
//
// For legacy records the five bitemporal/H3 fields are UNKNOWN (surfaced as
// zero with witness.LegacyRecords counting them — never silently). The Merkle
// root is unaffected either way (it folds only DotNodeID+DotCounter).
func restoreEntry(m WALMutation, nodeID [16]byte) eng.CRDTEntry {
	if !m.Legacy {
		// V2 (0x04, ADR-0045): the FULL 120-byte entry was persisted — dot,
		// origin, and all five temporal/H3 fields survive verbatim. The origin
		// is the PERSISTED one (no synthesis); checkMutationRecord has already
		// cross-checked the entry's dot against the top-level dot and the
		// origin against this node.
		return m.Full
	}
	// LEGACY (0x01): only five fields were persisted; ValidTimeStart/End,
	// AssertionTime, DecisionTime, H3Index are UNKNOWN (not "zero" — the
	// witness counts these records in LegacyRecords and the fallback marker
	// makes the loss loud). OriginNodeID is SYNTHESIZED as the recovering
	// node's ID: the legacy record's embedded origin is ZERO in
	// production (the legacy defect), and every WAL mutation is local-origin,
	// so the synthesis keeps the entry classified SELF by shipDelta
	// (gossip.go:1765-1780).
	return eng.CRDTEntry{
		PayloadDigest: m.Entry.PayloadDigest,
		OriginNodeID:  nodeID,
		DotNodeID:     m.NodeID,
		DotCounter:    m.Counter,
		SystemTime:    m.Entry.SystemTime,
	}
}

// checkMutationRecord is the structural-sanity gate on a WAL mutation about
// to become engine state. Recovery applies NO other validation (Join is
// permissive by design, ADR-0045), so this is the sole authority on dot
// plausibility.
// A violation means the record is corrupt (or the restore read the wrong field —
// this is the runtime canary for the legacy-dot corruption class). It fails
// LOUDLY (recovery refuses to build on a suspect record), never silently drops.
func checkMutationRecord(m WALMutation, nodeID [16]byte) error {
	var zero [16]byte
	if m.EntityID == "" {
		return fmt.Errorf("durability: WAL mutation with empty entityID at dot (%x, %d) — corrupt record", m.NodeID, m.Counter)
	}
	if m.NodeID == zero || m.Counter == 0 {
		return fmt.Errorf("durability: WAL mutation %q carries a zero dot (nodeID=%x counter=%d) — corrupt record or restore-side field mix-up (R3-BLOCKER canary)", m.EntityID, m.NodeID, m.Counter)
	}
	if m.NodeID != nodeID {
		// The WAL holds only LOCAL-origin mutations. A foreign dot here
		// means the WAL is not this node's log (wrong --node-id or corruption).
		return fmt.Errorf("durability: WAL mutation %q carries a foreign dot (nodeID=%x, this node=%x) — the WAL holds only local-origin mutations (R3-b invariant violated)", m.EntityID, m.NodeID, nodeID)
	}
	if m.Counter > maxPlausibleCounter {
		return fmt.Errorf("durability: WAL mutation %q counter %d exceeds the absolute ceiling %d — corrupt record", m.EntityID, m.Counter, maxPlausibleCounter)
	}
	if !m.Legacy {
		// V2 (0x04) cross-checks: the persisted full entry must agree with the
		// top-level dot, and its origin must be THIS node (the WAL holds only
		// local-origin mutations). A disagreement is mid-log corruption that
		// the Merkle root cannot see (it folds only the dot) — catch it here.
		if m.Full.DotNodeID != m.NodeID || m.Full.DotCounter != m.Counter {
			return fmt.Errorf("durability: WAL mutation %q (V2) full-entry dot (%x,%d) disagrees with top-level dot (%x,%d) — corrupt record", m.EntityID, m.Full.DotNodeID, m.Full.DotCounter, m.NodeID, m.Counter)
		}
		if m.Full.OriginNodeID != nodeID {
			return fmt.Errorf("durability: WAL mutation %q (V2) carries origin %x != this node %x — the WAL holds only local-origin mutations (R3-b invariant violated)", m.EntityID, m.Full.OriginNodeID, nodeID)
		}
	}
	return nil
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
// LOAD-BEARING: the DeltaCRDTEngine constructor (crdt.go:244) reads the package
// global sync.DataDir at crdt.go:290 (e.dataDir = DataDir) and, at crdt.go:376,
// calls recoverLamport() which can OVERRIDE initialCounter with a higher value
// persisted in <dataDir>/lamport_<nodeID>.dat. That override would break the
// WAL-derived rebuiltInitial seed (the determinism contract — ADR-0013 §4).
// To honor rebuiltInitial exactly the global MUST point at a fresh
// temp dir BEFORE the ctor runs (so recoverLamport reads no stale file →
// returns 0 → no override). The fix does NOT remove the global write —
// it ADDS a post-ctor engine.SetDataDir(scratchDir) so the ENGINE INSTANCE's
// dataDir field is routed through the persistMu-guarded setter (crdt.go:484)
// for its lifetime, NOT a bare global mutation the caller can race on.
//
// The residual honesty: the PRE-ctor `eng.DataDir = scratchDir` GLOBAL write
// CANNOT be removed without re-introducing the determinism defect — the
// constructor reads the global mid-construction, so the global is the ONLY
// channel for the scratch-dir seed-trick. Two CONCURRENT newEngineAt calls
// still race on the package global (a real-but-never-triggered-in-production
// hazard: the production boot path is sequential — one RecoverEngine per
// process at boot; the test paths serialize too). The INSTANCE-level race (two
// post-ctor SetDataDir on the SAME engine, or a SetDataDir racing an apply) IS
// closed — SetDataDir takes persistMu. ADR-0021 §2.2 discloses the residual
// global race + the crdt.go prerequisite for its closure (a constructor
// that takes an explicit dataDir arg, not a global). Report the
// residual; do not claim the trap is fully closed.
//
// The scratch-dir leak fix: the scratch dir is returned so the Bridge
// owns its lifecycle and RemoveAll's it on Close. An earlier newEngineAt leaked
// a /tmp dir per durable boot (grep-verified: zero RemoveAll). The
// TestRecoveryScratchDirCleaned guard asserts the dir is gone after Close.
//
// This assumes RecoverEngine runs at boot before any concurrent engine
// construction (the production boot path is sequential, as is the test path).
func newEngineAt(nodeID [16]byte, initialCounter uint64, arenaSize uintptr) (*eng.DeltaCRDTEngine, string, error) {
	scratchDir, err := os.MkdirTemp("", "sovereign-recover-*")
	if err != nil {
		return nil, "", fmt.Errorf("durability: scratch data dir: %w", err)
	}
	// PRE-ctor: the constructor (crdt.go:290) copies sync.DataDir INTO
	// e.dataDir and calls recoverLamport() against e.dataDir (crdt.go:376) to
	// find <dataDir>/lamport_<nodeID>.dat. Pointing the GLOBAL at the fresh
	// scratch dir BEFORE the ctor makes recoverLamport read no stale file →
	// returns 0 → honors the WAL-derived seed EXACTLY (the determinism
	// contract). This global write is LOAD-BEARING and CANNOT be removed
	// without re-introducing the seed-override defect (see the doc above).
	eng.DataDir = scratchDir
	engine, err := eng.NewDeltaCRDTEngine(nodeID, initialCounter, arenaSize)
	if err != nil {
		_ = os.RemoveAll(scratchDir)
		return nil, "", err
	}
	// POST-ctor (ADR-0021 §2.2): route the engine INSTANCE's dataDir
	// through the persistMu-guarded setter (crdt.go:484 SetDataDir) so the
	// scratch dir is the instance's field for its lifetime via the LOCKED
	// override path — NOT a bare global the caller races a concurrent apply
	// against. The ctor already copied the global into e.dataDir above, so
	// this is a no-op on the FIELD value; it is the CONTRACT: anyone reading
	// SetDataDir's locking (recoverLamport's persistLamport — crdt.go:911 —
	// takes persistMu too) now sees the same ordering edge the setter
	// establishes. The residual global race (two concurrent newEngineAt) is
	// disclosed in the doc above + ADR-0021 §2.2 — it is NEVER reachable on
	// the sequential boot path and is blocked from closure ONLY by the
	// crdt.go constructor's global read.
	engine.SetDataDir(scratchDir)
	return engine, scratchDir, nil
}
