// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

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

// ErrRecoveryRootMismatch reports that a checkpoint root differs from the
// corresponding recovered image or final recovered state. The node must not
// start after this error; cmd/sovereign-node treats it as fatal.
var ErrRecoveryRootMismatch = errors.New("durability: recovery root mismatch (rebuilt Merkle root != checkpoint root)")

// ErrRecoveryFingerprintMismatch reports that a snapshot bound to its
// checkpoint has the expected dots but different entry bytes. StateFingerprint
// folds the entity ID and all ten CRDTEntry fields, detecting corruption that
// the dot-only Merkle root cannot. The node treats this error as fatal.
var ErrRecoveryFingerprintMismatch = errors.New("durability: recovery fingerprint mismatch (rebuilt state bytes != checkpoint fingerprint — same dots, wrong bytes)")

// ErrRecoveryImageDuplicate reports duplicate (entityID, dot) records in a
// checkpoint image. encodeSnapshotImage writes a sorted walk of a unique-keyed
// map, so a duplicate cannot come from the writer and recovery refuses the
// image rather than disabling integrity checks (ADR-0045).
var ErrRecoveryImageDuplicate = errors.New("durability: recovery image contains duplicate (entityID, dot) records — not writer-producible, refusing boot")

// SnapshotStore provides access to a recovery image stored at
// "ckpt/<LamportHigh>". LocalFS implements it; an S3-backed store can use the
// same key scheme. Recovery looks up one watermark and does not list objects.
type SnapshotStore interface {
	// SnapshotExists reports whether a recovery image exists at the watermark.
	SnapshotExists(ctx context.Context, lamportHigh uint64) (bool, error)
	// LoadSnapshotImage reads + decodes the recovery image at the watermark.
	LoadSnapshotImage(ctx context.Context, lamportHigh uint64) (*SnapshotImage, error)
}

// RecoveryWitness reports which recovery path ran and which checks were
// performed. Bounded is true when a snapshot was loaded and only its WAL tail
// was replayed. ReplayedRecords counts applied mutations and clock advances;
// replay restores recorded dots and never calls InsertLocal (ADR-0045).
// SnapshotLamportHigh is the snapshot watermark, and FallbackReason explains a
// full replay when a store was supplied.
type RecoveryWitness struct {
	// Pointer-bearing and wide fields come first; this struct is built once per boot.
	FallbackReason      string
	SnapshotLamportHigh uint64
	ReplayedRecords     int
	Bounded             bool
	// CheckpointSeq is the final checkpoint's WAL sequence number. A legacy
	// 0x02 checkpoint replays records after this sequence; a V2 0x05 checkpoint
	// instead uses its CutSeq horizon. It is zero without a checkpoint.
	CheckpointSeq uint64
	// LocalPhantomsRejected counts local image dots without a corresponding
	// durable WAL mutation. Their presence causes the whole image to be rejected.
	LocalPhantomsRejected int
	// ExactWALFallback reports full replay after a store and checkpoint were
	// available but the image was missing, invalid, or inconsistent with the WAL.
	ExactWALFallback bool
	// LegacyRecords counts 80-byte 0x01 mutations. Their temporal and H3 fields
	// were not persisted and are unknown, rather than known to be zero.
	LegacyRecords int
	// HolesRepaired counts durable mutations below a legacy checkpoint cut that
	// were absent from its image and restored during recovery. V2 CutSeq
	// checkpoints cannot have this walk/append gap. Repairs disable root equality
	// because the checkpoint does not cover the additional restored dots.
	HolesRepaired int
	// IntegrityChecksArmed reports that both pre-tail checks ran against an image
	// bound to a fingerprint-bearing checkpoint. False means neither the root nor
	// fingerprint comparison supplied integrity coverage for this recovery.
	IntegrityChecksArmed bool
	// LegacyCheckpoint reports that the final checkpoint has no fingerprint,
	// whether it is a 0x02 record, a legacy 48-byte 0x05 record, or the 56-byte
	// snapshotter-less form. Fingerprint verification is unavailable in that case.
	LegacyCheckpoint bool
	// PostTailRootArmed reports a root comparison after bounded replay of a
	// final checkpoint with an intact image. Replay-only recovery cannot make
	// this comparison because its rebuilt state excludes foreign entries.
	PostTailRootArmed bool
	// SeqContiguityVerified reports validation of an unbroken ascending WAL
	// sequence before state reconstruction; RecordsVerified is its record count.
	// ReplayWAL returns ErrWALSeqGap on a gap, including on replay-only paths.
	SeqContiguityVerified bool
	RecordsVerified       int
	// ClockHighClamped reports that decode replaced an excessive checkpoint
	// ClockHigh with the log's durable high-water. ClockHighRaw retains the value
	// read from disk.
	ClockHighClamped bool
	ClockHighRaw     uint64
}

// RecoverEngine replays walPath into a new engine and returns the engine, the
// same WAL reopened for append, and the replay result. It uses full replay;
// RecoverEngineWithSnapshot can instead restore a checkpoint image and only
// replay its tail.
//
// A missing WAL is a cold boot and is created at initialCounter=1. Invalid WAL
// data returns an error, while ReplayWAL repairs a torn final record.
//
// IndexFeeder receives the primitive fields needed by the secondary index for
// each record restored during boot. A nil feeder disables index updates.
type IndexFeeder func(entityID string, h3Index uint64, systemTime int64)

func RecoverEngine(nodeID [16]byte, walPath string, arenaSize uintptr) (*eng.DeltaCRDTEngine, *WAL, *Replayed, error) {
	engine, wal, rep, _, err := RecoverEngineWithSnapshot(nodeID, walPath, nil, arenaSize)
	return engine, wal, rep, err
}

// RecoverEngineWithSnapshot restores a checkpoint image when store, a WAL
// checkpoint, and "ckpt/<checkpoint.LamportHigh>" are available. It then
// replays only records at or after the checkpoint cut: CutSeq for V2 0x05, or
// FinalCheckptSeq+1 for legacy 0x02.
//
// The constructor seeds the clock at max(rep.LamportHigh, ckpt.ClockHigh).
// Join restores recorded image and tail dots without minting replacements,
// including foreign dots that the local-only WAL cannot reproduce. Exact-dot
// replay is idempotent, so overlapping image and tail records are safe.
//
// A missing or unusable image selects full replay and records the reason in the
// witness and log. Bounded recovery reduces replay work to the post-checkpoint
// tail; it does not change the recovered state (ADR-0045).
//
// Integrity checks run where their comparison is meaningful (ADR-0045).
// Immediately after an image Join, both its Merkle root and state fingerprint
// must match the bound, fingerprint-bearing checkpoint. Duplicate image dots
// return ErrRecoveryImageDuplicate; mismatches return the corresponding
// integrity error.
//
// After tail replay, root equality is checked only for bounded recovery from a
// final, intact checkpoint. Full replay excludes foreign entries that may be in
// the checkpoint root, so equality is not a valid invariant there. ReplayWAL's
// sequence-contiguity check covers missing records on that path instead. A
// non-final checkpoint does not constrain the root after its tail is applied.
func RecoverEngineWithSnapshot(
	nodeID [16]byte,
	walPath string,
	store SnapshotStore,
	arenaSize uintptr,
) (*eng.DeltaCRDTEngine, *WAL, *Replayed, *RecoveryWitness, error) {
	return recoverEngineWithFeeder(nodeID, walPath, store, arenaSize, nil)
}

// RecoverEngineWithSnapshotFed also feeds every restored image, tail, and
// legacy-hole repair record to the secondary index before returning. Legacy
// records pass the zero values restored into the engine, keeping the index
// consistent with recovered state. A nil feeder is equivalent to
// RecoverEngineWithSnapshot.
func RecoverEngineWithSnapshotFed(
	nodeID [16]byte,
	walPath string,
	store SnapshotStore,
	arenaSize uintptr,
	feeder IndexFeeder,
) (*eng.DeltaCRDTEngine, *WAL, *Replayed, *RecoveryWitness, error) {
	return recoverEngineWithFeeder(nodeID, walPath, store, arenaSize, feeder)
}

// recoverEngineWithFeeder implements recovery with an optional index feeder.
func recoverEngineWithFeeder(
	nodeID [16]byte,
	walPath string,
	store SnapshotStore,
	arenaSize uintptr,
	feeder IndexFeeder,
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

	// A clamped ClockHigh is replaced with the log's durable high-water. Record
	// the adjustment in both the log and witness.
	if rep.ClockHighClamped {
		log.Printf("durability: checkpoint ClockHigh %d exceeded the credibility ceiling %d and was replaced with the WAL's durable high-water; recovery continues without counter reuse, but the on-disk record should be investigated",
			rep.ClockHighRaw, uint64(MaxCredibleClockHigh))
	}

	// A nil store selects full replay; otherwise a usable checkpoint image can
	// bound the replay to its tail.
	loadedImage, useSnapshot, snapshotLamportHigh := (*SnapshotImage)(nil), false, uint64(0)
	fallbackReason := ""
	// The witness and log distinguish an unavailable bounded path from bounded
	// recovery. Missing or invalid images and local phantom dots select full replay.
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
			// The image may not have been written yet, or a crash may have
			// interrupted its upload. Record the benign fallback in the witness
			// and log before rebuilding from the WAL.
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
					// A V2 image must match its checkpoint's CutSeq and root. The
					// watermark key can repeat across checkpoints without intervening
					// local writes, so the object may belong to a different checkpoint.
					// Treat that binding mismatch as a stale image, not corruption:
					// replay the authoritative WAL instead. Legacy 0x02 anchors have no
					// CutSeq and cannot perform this binding check (ADR-0045).
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

	// Every local dot in the image must have a durable WAL mutation. The WAL
	// contains local mutations only; foreign entries arrive through Join. A local
	// image dot absent from the WAL makes the entire image untrustworthy, so
	// discard it and rebuild from the log rather than deleting only that entry.
	// Foreign dots need no WAL identity and remain in an otherwise valid image
	// (ADR-0045).
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

	// Seed from durable evidence, not from an inferred first dot. Concurrent
	// minting and WAL appends can be reordered, so rep.LamportHigh folds every
	// mutation counter, checkpoint watermark, and clock advance. ClockHigh also
	// covers receiver clock raises that occurred before signature verification
	// failed and therefore have no advance record.
	//
	// NewDeltaCRDTEngine installs this value while initializing the skew EWMA.
	// Calling AdvanceLamportTo with a large delta instead would update that EWMA
	// and widen the inbound acceptance window. Subsequent replay advances and
	// the final clock update are no-ops when the seed covers the durable high
	// (ADR-0045).
	rebuiltInitial := rep.LamportHigh
	if rep.HasCheckpoint && rep.FinalCheckpt.ClockHigh > rebuiltInitial {
		rebuiltInitial = rep.FinalCheckpt.ClockHigh
	}

	engine, scratchDir, err := newEngineAt(nodeID, rebuiltInitial, arenaSize)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("durability: recovered engine ctor: %w", err)
	}
	rep.ScratchDir = scratchDir

	// Join the image before the tail. The dot-only merge keeps the existing
	// entry on an equal dot, so this order preserves the image's full 120-byte
	// entry when an 80-byte legacy tail record has the same dot. Separate Joins
	// also avoid relying on the unstable sort used to deduplicate a combined
	// delta. snapshotDelta supplies a heap-only delta whose recorded dots Join
	// restores without minting new ones.
	//
	// feed synchronously updates the derived index for every record restored
	// from the image, tail, or legacy-hole repair. Feed errors cannot fail boot.
	feed := func(rec SnapshotRecord) {
		if feeder != nil {
			feeder(rec.EntityID, rec.Entry.H3Index, rec.Entry.SystemTime)
		}
	}
	if useSnapshot {
		engine.Join(snapshotDelta(loadedImage))
		// A faithful image cannot contain duplicate (entityID, dot) records.
		// Check before replaying the tail, whose records may legitimately skip
		// against dots already supplied by the image (ADR-0045).
		if skipped := engine.Stats()["entries_skipped"]; skipped != 0 {
			_ = engine.Close()
			_ = os.RemoveAll(scratchDir)
			return nil, nil, nil, nil, fmt.Errorf("%w: the image Join skipped %d record(s) — a faithful image cannot contain a duplicate (entityID, dot), so the on-disk bytes are not writer-producible",
				ErrRecoveryImageDuplicate, skipped)
		}
		// Feed only an image that passed the duplicate check. An entity can have
		// multiple image records; index Apply resolves them by system time.
		for _, r := range loadedImage.Records {
			feed(r)
		}
	}

	// Before tail replay, the engine contains only the bound image, so both its
	// root and fingerprint can be compared directly with the checkpoint. These
	// checks run with or without a tail whenever the anchor has a fingerprint;
	// legacy fingerprint-less anchors cannot supply that comparison. Duplicate
	// image records were already rejected above.
	//
	// A mismatch after successful image/anchor binding indicates corrupt bytes,
	// not a stale image, and is fatal. The fingerprint detects entry corruption
	// that the dot-only root cannot (ADR-0045).
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
			return nil, nil, nil, nil, fmt.Errorf("%w: pre-tail image fingerprint mismatch: rebuilt=%x checkpoint=%x (CutSeq=%d) — the image's dots match the anchor but its entry bytes do not",
				ErrRecoveryFingerprintMismatch, rebuiltFingerprint, rep.FinalCheckpt.Fingerprint, rep.FinalCheckpt.CutSeq)
		}
	}

	// Replay restores each recorded dot through synthetic-delta Join, never
	// InsertLocal. The WAL sequence, rather than a Lamport counter, identifies
	// the checkpoint cut. Legacy 0x02 starts after the checkpoint record; V2
	// 0x05 starts at CutSeq, the NextSeq horizon captured before the image walk.
	// Full replay ignores the cut.
	//
	// Replaying an already-absorbed dot is idempotent. The repair pass below
	// handles the legacy walk/append gap. Chunking bounds transient scratch:
	// one Join per record has high allocation overhead, while one large Join
	// holds the entire tail at once (ADR-0045).
	cutFrom := rep.FinalCheckptSeq + 1 // legacy 0x02: after the checkpoint record
	if rep.HasCheckpoint && rep.FinalCheckpt.HasCutSeq {
		cutFrom = rep.FinalCheckpt.CutSeq // V2 0x05: pre-walk horizon
	}
	replayed := 0
	legacyRecords := 0
	chunk := make([]SnapshotRecord, 0, replayChunkSize)
	flushChunk := func() {
		if len(chunk) == 0 {
			return
		}
		// Join pins its own participant; a heap-only delta needs no Release.
		engine.Join(snapshotDelta(&SnapshotImage{Records: chunk}))
		chunk = chunk[:0]
	}
	for _, rec := range rep.Ordered {
		if useSnapshot && rec.Seq < cutFrom {
			continue // already supplied by the image
		}
		switch rec.Type {
		case WALRecMutation, WALRecMutationV2:
			// restoreEntry handles the field-fidelity difference between legacy
			// 80-byte and full 120-byte records.
			m := rec.Mutation
			// Reject empty entities, zero or foreign dots, and implausible
			// counters before they become engine state.
			if err := checkMutationRecord(m, nodeID); err != nil {
				_ = engine.Close()
				_ = os.RemoveAll(scratchDir)
				return nil, nil, nil, nil, err
			}
			if m.Legacy {
				legacyRecords++
			}
			rec := SnapshotRecord{EntityID: m.EntityID, Entry: restoreEntry(m, nodeID)}
			chunk = append(chunk, rec)
			// Feed the exact restored record, including zero values in legacy
			// fields, so the index mirrors engine state when recovery returns.
			feed(rec)
			if len(chunk) >= replayChunkSize {
				flushChunk()
			}
			replayed++
		case WALRecClockAdvance:
			// AdvanceLamportTo is a monotone maximum, so recorded clock jumps
			// are idempotent and safe to interleave with Joins.
			engine.AdvanceLamportTo(rec.Advance)
			replayed++
		}
	}
	flushChunk()

	// V2 CutSeq checkpoints include every earlier durable mutation in the image.
	// A legacy 0x02 checkpoint can miss a mutation whose WAL append preceded the
	// checkpoint but whose InsertLocal followed the image walk. Scan below-cut
	// records and restore any dots missing from the image. The lookup pass uses
	// no Joins unless it finds a hole. Repairs are idempotent and counted in the
	// witness; root equality is disabled because the old anchor excludes them
	// (ADR-0045).
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
			rec := SnapshotRecord{EntityID: m.EntityID, Entry: restoreEntry(m, nodeID)}
			chunk = append(chunk, rec)
			// Repaired records become engine state and must also reach the index.
			feed(rec)
			if len(chunk) >= replayChunkSize {
				flushChunk()
			}
			holesRepaired++
		}
		flushChunk()
		if holesRepaired > 0 {
			log.Printf("durability: legacy checkpoint repair restored %d durable mutation(s) below the checkpoint cut but absent from its image; root comparison skipped because the checkpoint does not cover them", holesRepaired)
		}
	}
	// The constructor already installed max(rep.LamportHigh, ClockHigh), so this
	// monotone update normally performs no CAS and does not alter the skew EWMA.
	// rep.LamportHigh includes below-cut advances that the tail loop skips.
	engine.AdvanceLamportTo(rebuiltInitial)

	// Continue appending to the replayed WAL with its next sequence preserved.
	wal, err := OpenWAL(walPath)
	if err != nil {
		_ = engine.Close()
		_ = os.RemoveAll(scratchDir)
		return nil, nil, nil, nil, fmt.Errorf("durability: reopen WAL %s: %w", walPath, err)
	}

	// A checkpoint is final when no mutation sits at or above its sequence cut.
	// Clock advances do not change the dot set and therefore do not affect
	// finality.
	checkpointFinal := true
	for _, rec := range rep.Ordered {
		if (rec.Type == WALRecMutation || rec.Type == WALRecMutationV2) && rec.Seq >= cutFrom {
			checkpointFinal = false
			break
		}
	}

	// The post-tail root check complements the pre-tail image checks. It runs
	// only for bounded recovery from a final, intact checkpoint, where the image
	// supplies any foreign entries needed for a valid comparison. A non-final
	// checkpoint does not constrain the root after its tail is applied.
	//
	// Full replay cannot make this comparison: the WAL contains local mutations
	// only, while the checkpoint root may include foreign entries. A delta can
	// merge without recording a clock advance, so len(rep.Advances) cannot infer
	// whether foreign state exists, and the anchor does not record that fact.
	// Sequence contiguity detects missing WAL records on this path; the dot-only
	// root does not detect payload bit rot because the WAL has no checksum.
	//
	// Phantom rejection and legacy-hole repair also disable root equality. A
	// mid-batch checkpoint can cover dots that were never durably appended, and
	// repaired dots legitimately extend the old checkpoint root (ADR-0045).
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
		// The image covered local dots absent from the durable log, possibly
		// because a checkpoint ran between batch inserts and their group fsync.
		log.Printf("durability: checkpoint image rejected with %d local dot(s) absent from the WAL: root comparison skipped; unacknowledged dots are not restored",
			localPhantomsRejected)
	} else if rep.HasCheckpoint && holesRepaired > 0 {
		// Repaired below-cut dots extend beyond the legacy checkpoint's root.
		log.Printf("durability: legacy checkpoint repair restored %d below-cut mutation(s): root comparison skipped because the checkpoint does not cover them",
			holesRepaired)
	} else if !rep.HasCheckpoint {
		// Mutation replay has no checkpoint root to compare against.
		log.Printf("durability: cold boot, no checkpoint anchor (replayed %d mutations, %d advances from %s)",
			len(rep.Mutations), len(rep.Advances), walPath)
	} else if !useSnapshot {
		// Full replay is origin-only, so its root cannot be compared with an
		// anchor that may include foreign entries. Sequence validation still
		// covers every record in the log.
		log.Printf("durability: exact-WAL replay has no usable image: post-tail root comparison skipped because the checkpoint may include foreign entries; WAL sequence contiguity verified over %d record(s), with %d clock advance(s) replayed",
			rep.RecordsVerified, len(rep.Advances))
	} else if useSnapshot && !checkpointFinal {
		// A post-checkpoint tail legitimately changes the final root.
		log.Printf("durability: bounded recovery loaded snapshot ckpt/%d and replayed %d post-checkpoint record(s); final-root equality does not apply after the tail",
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

// replayChunkSize bounds transient scratch during recovery. Batching avoids
// per-record Join overhead without holding the entire tail in one delta.
const replayChunkSize = 2048

// maxPlausibleCounter rejects corrupt WAL counters before Join accepts them.
// The ceiling is far above realistic node lifetimes; it is a structural check,
// not an operational limit (ADR-0045).
const maxPlausibleCounter = 1 << 60

// restoreEntry reconstructs a CRDTEntry from a WAL mutation (ADR-0045).
// Full 0x04 records are returned verbatim. Legacy 0x01 records take their dot
// from the top-level WALMutation because their embedded entry predates dot
// stamping. Their OriginNodeID is the recovering node: this WAL contains only
// local-origin mutations, and that classification lets shipDelta serve the
// restored payloads again.
//
// Legacy temporal and H3 fields were not persisted. Their zero values are
// unknown rather than measured zeros, and LegacyRecords discloses their count.
// The Merkle root folds only the dot and is unaffected by these missing fields.
func restoreEntry(m WALMutation, nodeID [16]byte) eng.CRDTEntry {
	if !m.Legacy {
		// Full 0x04 records preserve the dot, origin, and temporal/H3 fields.
		// checkMutationRecord has verified their dot and origin against the WAL.
		return m.Full
	}
	// Legacy 0x01 records did not persist ValidTimeStart/End, AssertionTime,
	// DecisionTime, or H3Index. Their top-level dot and recovering-node origin
	// restore local identity; LegacyRecords discloses the unknown fields.
	return eng.CRDTEntry{
		PayloadDigest: m.Entry.PayloadDigest,
		OriginNodeID:  nodeID,
		DotNodeID:     m.NodeID,
		DotCounter:    m.Counter,
		SystemTime:    m.Entry.SystemTime,
	}
}

// checkMutationRecord validates a WAL mutation before Join accepts it. The WAL
// contains local-origin mutations, so empty entities, zero or foreign dots, and
// excessive counters indicate corruption. Full records must also agree with
// their top-level dot and local origin; the dot-only Merkle root cannot detect
// those field mismatches.
func checkMutationRecord(m WALMutation, nodeID [16]byte) error {
	var zero [16]byte
	if m.EntityID == "" {
		return fmt.Errorf("durability: WAL mutation with empty entityID at dot (%x, %d) — corrupt record", m.NodeID, m.Counter)
	}
	if m.NodeID == zero || m.Counter == 0 {
		return fmt.Errorf("durability: WAL mutation %q carries a zero dot (nodeID=%x counter=%d) — corrupt record or inconsistent restore fields", m.EntityID, m.NodeID, m.Counter)
	}
	if m.NodeID != nodeID {
		// A foreign dot means this is another node's WAL or the record is corrupt.
		return fmt.Errorf("durability: WAL mutation %q carries foreign dot (nodeID=%x, this node=%x); only local-origin mutations are valid", m.EntityID, m.NodeID, nodeID)
	}
	if m.Counter > maxPlausibleCounter {
		return fmt.Errorf("durability: WAL mutation %q counter %d exceeds the absolute ceiling %d — corrupt record", m.EntityID, m.Counter, maxPlausibleCounter)
	}
	if !m.Legacy {
		// Full-entry fields must agree with the top-level WAL identity.
		if m.Full.DotNodeID != m.NodeID || m.Full.DotCounter != m.Counter {
			return fmt.Errorf("durability: WAL mutation %q (V2) full-entry dot (%x,%d) disagrees with top-level dot (%x,%d) — corrupt record", m.EntityID, m.Full.DotNodeID, m.Full.DotCounter, m.NodeID, m.Counter)
		}
		if m.Full.OriginNodeID != nodeID {
			return fmt.Errorf("durability: WAL mutation %q (V2) carries origin %x, want local node %x", m.EntityID, m.Full.OriginNodeID, nodeID)
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

// newEngineAt constructs an engine at exactly initialCounter and returns its
// scratch directory for the Bridge to remove on Close.
//
// NewDeltaCRDTEngine reads the package-global eng.DataDir and recoverLamport
// may replace initialCounter from a lamport file in that directory. Pointing
// the global at a fresh directory before construction prevents stale persisted
// state from overriding the WAL-derived seed. SetDataDir then uses the engine's
// persistMu-guarded setter for subsequent instance access.
//
// Concurrent newEngineAt calls still race on eng.DataDir. Recovery currently
// runs sequentially during process boot; removing that limitation requires a
// constructor that accepts the data directory explicitly (ADR-0021).
func newEngineAt(nodeID [16]byte, initialCounter uint64, arenaSize uintptr) (*eng.DeltaCRDTEngine, string, error) {
	scratchDir, err := os.MkdirTemp("", "sovereign-recover-*")
	if err != nil {
		return nil, "", fmt.Errorf("durability: scratch data dir: %w", err)
	}
	// Construction copies eng.DataDir and calls recoverLamport against it. A
	// fresh directory therefore prevents a persisted Lamport value from
	// overriding the WAL-derived initialCounter.
	eng.DataDir = scratchDir
	engine, err := eng.NewDeltaCRDTEngine(nodeID, initialCounter, arenaSize)
	if err != nil {
		_ = os.RemoveAll(scratchDir)
		return nil, "", err
	}
	// Use the persistMu-guarded setter for the instance's subsequent data-dir
	// accesses. The constructor already copied this value; the explicit setter
	// documents the locking contract for later Lamport persistence (ADR-0021).
	engine.SetDataDir(scratchDir)
	return engine, scratchDir, nil
}
