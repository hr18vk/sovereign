// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// Engine-side write-ahead log.
//
// The supervisor uses this log to recover persistent database state after a
// worker connection dies, then starts a fresh worker without dropping active
// HTTP connections.
//
// This is the engine's durability layer, distinct from PostgreSQL's WAL. It
// records every committed local mutation with enough state to rebuild an
// equivalent engine whose Merkle root matches the root recorded at append time.
//
// Determinism contract:
// HAMT.MerkleRoot folds only the CRDT causal dots (DotNodeID and DotCounter)
// under SHA-256. It does not depend on maphash.Seed, which Go cannot serialize
// or recreate in another process. A recovered worker with a fresh seed therefore
// reproduces the same Merkle root from the same mutation sequence, provided it
// restores the same localNodeID and Lamport assignments. The WAL persists those
// assignments. Recovery replays them into a fresh DeltaCRDTEngine; a mismatch
// with the last checkpoint root is treated as data loss.
//
// Durability contract:
// Append writes and fsyncs before returning. The worker must not acknowledge a
// mutation to its client before Append returns. Process survival alone is not
// sufficient if the acknowledged state diverges after a crash.

package chaos

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"sync"
	"sync/atomic"

	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// walMagic and walVersion identify the log format so recovery rejects a corrupt
// or foreign file instead of misinterpreting it.
const (
	walMagic   uint32 = 0x57414C00 // "WAL\0"
	walVersion uint16 = 1

	// maxRecordPayloadLen bounds the payload length ReplayWAL accepts from a
	// record header (ADR-0045). Without this check, a damaged length field could
	// request an allocation of almost 4 GiB. A mutation payload is only
	// 4 + len(entityID) + 16 + 8 + walEntryLen bytes, so 4 MiB leaves ample room
	// for entity keys. A complete header claiming more is treated as corruption,
	// not as a torn tail: replay returns an error rather than skipping the record.
	maxRecordPayloadLen = 4 << 20
)

// ErrWALSeqGap is returned by ReplayWAL when record sequence numbers do not
// form an unbroken ascending run. Each append consumes its sequence number after
// a successful write and before fsync. OpenWAL derives the next sequence from
// the on-disk maximum and truncates only a partial trailing record, and the log
// is never rotated. A gap or duplicate therefore indicates record loss or
// reordering, so recovery refuses to rebuild from the log. The error reports the
// expected and observed sequence numbers.
//
// Logs written with the older write-fsync-increment ordering could contain a
// duplicate sequence after an fsync failure: the record reached the file but its
// number was not consumed, so the next append reused it. ReplayWAL rejects such
// logs rather than accepting an ambiguous recovery order.
var ErrWALSeqGap = errors.New("chaos/wal: record sequence gap (a record is missing from the log)")

// MaxCredibleClockHigh bounds the 0x05 ClockHigh field at decode. Recovery's
// checkMutationRecord uses the same maxPlausibleCounter ceiling for mutation
// counters because ClockHigh is also a Lamport counter minted by the cluster.
// At the measured production ingest ceiling of 3.1e6 deltas/s, reaching 2^60
// would take about 11,800 node-years. The bound also leaves ample headroom
// before NextDot's uint64 increment wraps at 2^64, while rejecting corruption
// such as MaxUint64 or a high-bit flip to 2^63+7.
//
// An above-ceiling value is clamped to the log's durable high-water mark. The
// clamp is reported in Replayed.ClockHighClamped and ClockHighRaw, and recovery
// logs it. A clock raised by a frame that later fails verification can exceed
// every durable value without producing a mutation or clock-advance record, so
// the floor preserves the earlier recovery behaviour without accepting the
// damaged field.
//
// CRC-framed checkpoints reject content corruption before this clamp runs. For
// legacy checkpoints, clamping is only a mitigation: a corrupted value below
// the ceiling remains indistinguishable from a legitimate clock.
const MaxCredibleClockHigh uint64 = 1 << 60

// WALRecordType identifies the kind of each appended record.
type WALRecordType uint8

const (
	// WALRecMutation is a committed local mutation: (entityID, CausalDot,
	// CRDTEntry). Recovery replays mutation records in log order into a fresh
	// DeltaCRDTEngine.
	WALRecMutation WALRecordType = 0x01
	// WALRecCheckpoint records the engine's Merkle root at a batch boundary.
	// Recovery checks the rebuilt root against the last checkpoint root.
	WALRecCheckpoint WALRecordType = 0x02
	// WALRecClockAdvance records a peer-driven Lamport clock advance. Its payload
	// is the advanced-to counter as an 8-byte big-endian value. Recovery replays
	// advances in append order, interleaved with mutations, so its clock reaches
	// the recorded high-water mark. Without these records, a foreign
	// AdvanceLamportTo would leave an unrecorded gap and recovery would undershoot.
	WALRecClockAdvance WALRecordType = 0x03
	// WALRecMutationV2 (ADR-0045 §4) stores the full 120-byte CRDTEntry, including
	// all ten fields, rather than the legacy 80-byte subset. A 0x01 record holds
	// five fields; replay reconstructs the other five as zeros and marks the
	// mutation Legacy so they are not mistaken for persisted values. The separate
	// type byte keeps existing 0x01 logs readable without changing walVersion or
	// reinterpreting payload lengths. New binaries read both forms; older binaries
	// reject the unknown 0x04 type rather than decoding it incorrectly.
	WALRecMutationV2 WALRecordType = 0x04
	// WALRecCheckpointV2 (ADR-0045) adds CutSeq, a sequence horizon captured by
	// NextSeq before the snapshot walk. A legacy 0x02 checkpoint cuts the recovery
	// tail at its own record sequence, but the image is walked before that record
	// is appended. A mutation inserted after the walk passed its shard could append
	// before the checkpoint, leaving it below the cut but absent from the image.
	// One observed instance had counter 94, sequence 96, watermark 95, and cut 104.
	// Every record below CutSeq completed its append, and therefore its InsertLocal,
	// before the walk began. Replaying records with Seq >= CutSeq closes that window.
	//
	// The base payload is MerkleRoot(32) || LamportHigh(8) || CutSeq(8) ||
	// ClockHigh(8), or 56 bytes; a state fingerprint adds 32 bytes. ClockHigh is the
	// live Lamport clock at checkpoint time. Length-based decoding also accepts the
	// earlier 48-byte form. New binaries read 0x02 and 0x05; older binaries reject
	// the unknown 0x05 type.
	WALRecCheckpointV2 WALRecordType = 0x05
	// WALRecChecksummed (ADR-0053) wraps another record without changing its
	// payload layout:
	//
	//	innerType(1) || innerPayload(len) || crc32c(4, big-endian)
	//
	// The Castagnoli CRC covers innerType and innerPayload. The outer sequence and
	// payload length are checked separately by sequence contiguity and the length
	// bound. A single wrapper type protects mutations, checkpoints, and clock
	// advances while letting ReplayWAL reuse their existing decoders. Production
	// appends emit 0x06 by default. Replay also accepts unframed 0x01-0x05 records
	// for compatibility, but those legacy records have no content checksum.
	WALRecChecksummed WALRecordType = 0x06
)

// ErrWALCorrupt is returned by ReplayWAL when a complete WALRecChecksummed
// record's CRC32C does not match its innerType and innerPayload. The sequence
// and length checks cannot detect this kind of content corruption. The WAL has
// no alternate source of truth, so RecoverEngineWithSnapshot and the chaos
// supervisor propagate the error and refuse to boot from the damaged log.
// A truncated final record is different: replay drops it as a crash boundary
// before attempting the CRC check.
var ErrWALCorrupt = errors.New("chaos/wal: record content CRC32C mismatch (corrupt record)")

// castagnoliTable is shared by every append and replay. Using a package-level
// table avoids crc32.New setup and keeps CRC computation allocation-free. Go's
// hash/crc32 uses hardware CRC32 instructions for Castagnoli on supported ARM64
// processors.
var castagnoliTable = crc32.MakeTable(crc32.Castagnoli)

// walCRC32Skip is a test-only fault-injection switch. When true, replay still
// computes each 0x06 checksum but skips the comparison. Corruption tests use it
// to demonstrate that the comparison is what rejects a damaged record. Its zero
// value leaves verification enabled, and production code never sets it. Atomic
// access avoids races in replay tests; it is not used by the CRDT hot path.
var walCRC32Skip atomic.Bool

// WALMutation is the serializable form of one committed local mutation. The
// top-level NodeID and Counter hold the mutation's recovery identity; legacy
// records cannot be assumed to contain a usable dot inside the embedded entry.
//
// Full is the complete 120-byte CRDTEntry (ADR-0045 §4). A WALRecMutationV2
// record persists all ten fields. For a legacy 0x01 record, replay synthesizes
// Full from the five persisted fields and zeros ValidTimeStart, ValidTimeEnd,
// AssertionTime, DecisionTime, and H3Index. Legacy is true so consumers do not
// mistake those zeros for recorded values. Production appends encode a V2
// mutation inside a 0x06 checksum frame; unframed 0x04 records are for tests and
// existing logs.
//
// Entry is the legacy 80-byte subset. It remains populated, derived from Full
// for V2 records, so existing readers of Replayed.Mutations keep working.
type WALMutation struct {
	EntityID string
	Full     eng.CRDTEntry
	NodeID   [16]byte
	Counter  uint64
	Entry    WALEntry
	Legacy   bool
}

// NewWALMutation constructs a WALMutation from the CausalDot returned by
// InsertLocal and the pre-insert entry (ADR-0045 §4). It stamps DotNodeID,
// DotCounter, and OriginNodeID into the full entry exactly as InsertLocal stamps
// its internal copy; NextDot supplies the engine's local node ID. The legacy
// Entry subset is derived from that same entry so the two representations cannot
// drift.
func NewWALMutation(entityID string, dot eng.CausalDot, entry eng.CRDTEntry) WALMutation {
	entry.DotNodeID = dot.NodeID
	entry.DotCounter = dot.Counter
	entry.OriginNodeID = dot.NodeID
	return WALMutation{
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
		Full: entry,
	}
}

// validateV2 rejects a mutation whose Full entry is missing or inconsistent
// with its top-level dot. Such a value usually comes from bypassing
// NewWALMutation. Appending it would persist a zero-filled 120-byte entry whose
// missing fields are invisible to the dot-only Merkle root (ADR-0045 §4), so
// AppendMutation and AppendMutations return the error before writing it.
func validateV2(m WALMutation) error {
	if m.EntityID == "" {
		return errors.New("chaos/wal: mutation with empty entityID")
	}
	if m.Legacy {
		return fmt.Errorf("chaos/wal: mutation %q is marked Legacy — legacy records are replay-only, never written", m.EntityID)
	}
	if m.Full.DotNodeID != m.NodeID || m.Full.DotCounter != m.Counter {
		return fmt.Errorf("chaos/wal: mutation %q full-entry dot (%x,%d) inconsistent with top-level dot (%x,%d) — build it via NewWALMutation",
			m.EntityID, m.Full.DotNodeID, m.Full.DotCounter, m.NodeID, m.Counter)
	}
	var zero [16]byte
	if m.Full.OriginNodeID == zero {
		return fmt.Errorf("chaos/wal: mutation %q carries a zero OriginNodeID — build it via NewWALMutation", m.EntityID)
	}
	return nil
}

// WALEntry is the legacy 80-byte representation stored in 0x01 mutation
// records. It carries PayloadDigest, origin and dot identity, and SystemTime.
// V2 records persist the complete CRDTEntry instead; WALMutation.Entry is then
// derived from Full for compatibility with readers of the legacy subset.
type WALEntry struct {
	PayloadDigest [32]byte
	OriginNodeID  [16]byte
	DotNodeID     [16]byte
	DotCounter    uint64
	SystemTime    int64
}

// WALCheckpoint pairs a Merkle root with the Lamport counter at checkpoint
// time. Recovery uses them to compare the rebuilt root and resume the clock at
// the correct high-water mark.
//
// HasCutSeq selects a 0x05 checkpoint when true and a legacy 0x02 checkpoint
// when false. CutSeq is the NextSeq horizon captured before the snapshot walk:
// every earlier record is represented in the image, and recovery replays the
// tail beginning at Seq >= CutSeq. Bridge.AppendCheckpoint sets it in production.
// The zero value retains the legacy record-sequence cut for hand-built test logs
// and existing WALs (ADR-0045).
//
// ClockHigh is the engine's live Lamport clock, distinct from LamportHigh, the
// image's local-dot watermark. Receive admission advances the clock before frame
// verification, so a rejected frame can raise it above every recorded value
// without leaving a 0x03 record. New 0x05 checkpoints persist ClockHigh, and
// recovery seeds the replacement engine from max(rep.LamportHigh, ClockHigh).
// A legacy 48-byte 0x05 record decodes with ClockHigh == 0.
//
// Fingerprint and HasFingerprint record the checkpoint image's state fingerprint
// (ADR-0045). Bounded recovery compares it to detect identical dots with different
// payload bytes, which the dot-only Merkle root cannot detect. HasFingerprint is
// false when no image was captured: pairing an empty-state fingerprint with a
// real root would invalidate later comparisons. It is also false for legacy
// 48-byte checkpoints and 56-byte checkpoints written without a snapshotter.
type WALCheckpoint struct {
	MerkleRoot     [32]byte
	Fingerprint    [32]byte
	LamportHigh    uint64
	CutSeq         uint64
	ClockHigh      uint64
	HasCutSeq      bool
	HasFingerprint bool
}

// WAL is the append-only, fsync-on-commit engine write-ahead log. It is safe
// for concurrent Append from worker goroutines; recovery is single-threaded.
type WAL struct {
	mu   sync.Mutex
	f    *os.File
	path string
	// nextSeq is a per-wal monotonic sequence stamped on each append; the
	// recovery stream is ordered by this, so a concurrent appender cannot
	// interleave records out of order with respect to fsync boundaries.
	nextSeq uint64

	// syncHook is a test-only fsync hook (ADR-0044). OpenWAL leaves it nil, so
	// production calls the file's Sync method directly. Tests install it to count
	// one fsync per AppendMutations batch rather than one per mutation, or to
	// inject a sync failure and check that the caller rejects the whole batch.
	syncHook func() error
}

// SetSyncHookForTest installs a test-only fsync hook (ADR-0044). The hook
// replaces w.f.Sync rather than chaining to it: a counting hook returns nil
// without a real fsync, while a failure-injection hook returns its error. Tests
// use these behaviours to check group-commit fsync counts and whole-batch error
// handling. Passing nil restores the production path. The setter is not safe for
// concurrent use with appends and must be called before they begin.
func (w *WAL) SetSyncHookForTest(hook func() error) { w.syncHook = hook }

// sync calls the test hook when present and w.f.Sync otherwise. Production
// append paths instead call syncFile with a captured file after releasing w.mu.
// The test-only append helpers and holdMuAcrossSyncForTest call sync while holding
// w.mu. Because sync reads w.f directly, callers must hold that mutex: Close sets
// w.f to nil under the same lock. Unlocked callers must use syncFile.
func (w *WAL) sync() error {
	if w.syncHook != nil {
		return w.syncHook()
	}
	return w.f.Sync()
}

// syncFile fsyncs a captured *os.File, or routes the call through the test hook.
// AppendMutations, AppendMutation, AppendCheckpoint, and AppendClockAdvance each
// capture w.f while holding w.mu, release the mutex, and then call syncFile
// (ADR-0045). They must not read w.f after unlocking: Close sets it to nil under
// w.mu, so an unlocked read could race with Close and dereference nil.
//
// The captured file identifies the descriptor through which the records were
// written. A concurrent Close may cause Sync to return os.ErrClosed, which is an
// ordinary fsync error rather than a panic. Close also performs a final Sync
// under the lock, flushing records written before it acquired the mutex. The hook
// branch comes first and ignores f, preserving the test's count-or-fail behavior.
func (w *WAL) syncFile(f *os.File) error {
	if w.syncHook != nil {
		return w.syncHook()
	}
	if f == nil {
		return errors.New("chaos/wal: fsync on a closed WAL")
	}
	return f.Sync()
}

// OpenWAL opens or creates the engine WAL at path. A new file receives a header.
// For an existing file, OpenWAL verifies the header, scans complete records to
// restore the next sequence number, truncates a partial trailing record, and
// seeks to the clean append boundary. ReplayWAL separately rebuilds engine state.
func OpenWAL(path string) (*WAL, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return nil, fmt.Errorf("chaos/wal: open %s: %w", path, err)
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	w := &WAL{f: f, path: path}
	if info.Size() == 0 {
		if err := w.writeHeader(); err != nil {
			f.Close()
			return nil, err
		}
	} else {
		if err := w.verifyHeader(); err != nil {
			f.Close()
			return nil, err
		}
		// Count existing records so nextSeq stays monotonic across reopen, and
		// locate the last clean record boundary (scanRecords seeks to byte 8 and
		// walks forward, so the prior Seek(0, SeekEnd) is subsumed).
		seq, _, lastGood, err := scanRecords(f)
		if err != nil {
			f.Close()
			return nil, err
		}
		w.nextSeq = seq
		// Move the append offset to the last complete record before writing. A
		// crash can leave a partial trailing record. ReplayWAL stops at that tear,
		// but appending after it would make the next replay combine the damaged
		// bytes with the new header, potentially discarding later records or
		// rejecting an unknown type. The file uses O_RDWR rather than O_APPEND, so
		// truncate and seek to lastGood here. For a clean log, lastGood equals the
		// file size and truncation is a no-op (ADR-0045).
		if err := f.Truncate(lastGood); err != nil {
			f.Close()
			return nil, fmt.Errorf("chaos/wal: truncate torn tail at %d: %w", lastGood, err)
		}
		if _, err := f.Seek(lastGood, io.SeekStart); err != nil {
			f.Close()
			return nil, err
		}
	}
	return w, nil
}

// writeHeader writes the magic + version + record-count-zero header. Called
// once on a fresh log. The header is fixed-size (8 bytes) so record scanning
// starts at a known offset.
func (w *WAL) writeHeader() error {
	var hdr [8]byte
	binary.BigEndian.PutUint32(hdr[0:4], walMagic)
	binary.BigEndian.PutUint16(hdr[4:6], walVersion)
	// hdr[6:8] reserved (zero).
	if _, err := w.f.Write(hdr[:]); err != nil {
		return err
	}
	return w.f.Sync()
}

// verifyHeader reads and validates the magic/version. A foreign or truncated
// file is rejected explicitly (no silent misinterpretation on recovery).
func (w *WAL) verifyHeader() error {
	var hdr [8]byte
	if _, err := io.ReadFull(w.f, hdr[:]); err != nil {
		return fmt.Errorf("chaos/wal: header read: %w", err)
	}
	if binary.BigEndian.Uint32(hdr[0:4]) != walMagic {
		return errors.New("chaos/wal: bad magic (foreign or corrupt log)")
	}
	if v := binary.BigEndian.Uint16(hdr[4:6]); v != walVersion {
		return fmt.Errorf("chaos/wal: unsupported version %d (want %d)", v, walVersion)
	}
	return nil
}

// AppendMutation records a committed local mutation and returns after fsync.
// The caller may acknowledge the client only after a nil return; an earlier
// acknowledgment could claim durability that a crash has not established.
func (w *WAL) AppendMutation(m WALMutation) error {
	w.mu.Lock()
	// Unlock explicitly on every return. The success path releases w.mu before
	// fsync so a slow disk barrier does not serialize unrelated appends.
	if err := validateV2(m); err != nil {
		w.mu.Unlock()
		return err
	}
	// Production writes a 0x06 CRC32C frame. Its inner payload uses the same layout
	// as an unframed 0x04 mutation, and frameChecksummed allocates the record once.
	// The checksum protects the recorded content without changing it (ADR-0053).
	rec, err := encodeMutationV2Checksummed(w.nextSeq, m)
	if err != nil {
		w.mu.Unlock()
		return err
	}
	if _, err := w.f.Write(rec); err != nil {
		w.mu.Unlock()
		return fmt.Errorf("chaos/wal: write mutation: %w", err)
	}
	// Consume the sequence immediately after a successful write, before fsync
	// (ADR-0045). The bytes are already in the page cache, and another append's
	// fsync can flush them even if this fsync fails. Leaving the sequence
	// unconsumed would let the next append reuse it for different content and make
	// sequence-based recovery cuts ambiguous. AppendMutations follows the same rule.
	w.nextSeq++
	// Capture the file under the lock, then unlock before fsync. The write and
	// sequence increment have already fixed the record's order; fsync only makes
	// it durable. A concurrent append need not wait for this disk barrier.
	f := w.f
	w.mu.Unlock()
	if err := w.syncFile(f); err != nil {
		return fmt.Errorf("chaos/wal: fsync mutation: %w", err)
	}
	return nil
}

// AppendMutations implements WAL group commit (ADR-0044). It writes N mutation
// records under one w.mu critical section and issues one fsync for the batch
// through syncFile. On the measured NVMe path, roughly 2.1 ms per fsync made
// 10,000 individual syncs cost about 21 seconds against a 10-second objective;
// batching removes 9,999 of those barriers. It backs /v1/batch-insert, while
// AppendMutation serves /v1/insert.
//
// Both granularities use the same WAL and V2 mutation payload inside the default
// 0x06 frame. ReplayWAL reads the N individual records and produces the same
// Mutations slice as N AppendMutation calls. Recovery restores each recorded dot
// without minting a replacement (ADR-0045 §4), so group commit does not change
// the determinism contract checked by TestWALRecoveryDeterminism.
//
// A validation, encode, or write failure at index i returns (i, err); a final
// sync failure returns (-1, err). Bridge.PutLocals responds with 503 for every
// entry because no subset can be acknowledged as durable: entries before i may
// remain only in the page cache, while later entries were not written. The client
// can retry the whole batch. This is an all-or-none acknowledgment contract, not
// a rollback of bytes already written (ADR-0044 §4).
//
// nextSeq advances after each successful write, as in AppendMutation. A write
// failure therefore stops sequence consumption at the failed record.
// The write loop runs under w.mu, but fsync runs after Unlock (ADR-0045). On a
// measured 10,000-key injection, disk barriers lasted tens of seconds. Holding
// the mutex across them also blocked AppendClockAdvance on the receive path. In
// the 100-node run, that delayed cache.record population and first-round relay
// lookups on the seed. Releasing the lock lets receive-path advances proceed
// while a batch waits for the disk.
//
// Three properties make the split safe:
//
//  1. Record bytes and sequence numbers are written under w.mu in their final
//     order. fsync is a durability barrier and cannot reorder those bytes.
//  2. Error results retain their meaning: a write failure reports its index and
//     a sync failure reports (-1, err), so the caller rejects the whole batch.
//  3. Concurrent fsync calls on the shared file flush all dirty pages, not only
//     the caller's records. Each caller wrote its records before starting fsync,
//     so another sync can persist additional records but cannot weaken its own
//     durability guarantee.
//
// During the unlocked window, the tail may be in the page cache without being
// durable. A sync failure already has this state and produces the same whole-
// batch error. A nil return still means the batch's fsync completed.
func (w *WAL) AppendMutations(ms []WALMutation) (firstFailIdx int, err error) {
	w.mu.Lock()
	// Unlock explicitly on every return. A defer would hold w.mu through the
	// final syncFile call; an extra unlock after that call would panic. The success
	// path and every error path below each perform exactly one Unlock.
	for i, m := range ms {
		if e := validateV2(m); e != nil {
			// An invalid mutation (missing or inconsistent full entry) is the
			// same class as an encode error: the batch cannot be acknowledged.
			w.mu.Unlock()
			return i, fmt.Errorf("chaos/wal: validate mutation %d: %w", i, e)
		}
		// Wrap each V2 payload in a 0x06 frame. The shared payload writer keeps
		// this encoding identical to an unframed V2 record (ADR-0053).
		rec, e := encodeMutationV2Checksummed(w.nextSeq, m)
		if e != nil {
			// An encode error, such as an oversized EntityID, is a caller bug.
			// Entries before i may be in the page cache without an fsync, and no
			// later entry has been written. Reject the batch as a unit so the caller
			// returns 503 for every entry rather than acknowledging a subset.
			w.mu.Unlock()
			return i, fmt.Errorf("chaos/wal: encode mutation %d: %w", i, e)
		}
		if _, e := w.f.Write(rec); e != nil {
			w.mu.Unlock()
			return i, fmt.Errorf("chaos/wal: write mutation %d: %w", i, e)
		}
		w.nextSeq++
	}
	// The records and sequence numbers are fixed. Capture the file while holding
	// w.mu, because Close clears w.f under that lock, then unlock so a concurrent
	// receive-path AppendClockAdvance can proceed during this batch's fsync.
	f := w.f
	w.mu.Unlock()
	if e := w.syncFile(f); e != nil {
		return -1, fmt.Errorf("chaos/wal: fsync mutation batch: %w", e)
	}
	return -1, nil
}

// AppendCheckpoint records the current Merkle root + Lamport high-water mark.
// This is the determinism anchor: recovery asserts the replayed root equals
// the last checkpoint's root. Checkpoints are fsync'd for durability.
func (w *WAL) AppendCheckpoint(c WALCheckpoint) error {
	w.mu.Lock()
	// Unlock explicitly on every return so fsync stays outside the critical
	// section. The 0x06 frame protects ClockHigh and the fingerprint; replay
	// verifies their checksum before applying the legacy clamp or fingerprint
	// comparison (ADR-0053).
	rec := encodeCheckpointChecksummed(w.nextSeq, c)
	if _, err := w.f.Write(rec); err != nil {
		w.mu.Unlock()
		return fmt.Errorf("chaos/wal: write checkpoint: %w", err)
	}
	// Consume the sequence at write time, as in AppendMutation, so an fsync
	// failure cannot cause a later record to reuse it (ADR-0045).
	w.nextSeq++
	// The write and increment established the record order. Capture the file
	// under w.mu, then release the mutex before waiting for the disk.
	f := w.f
	w.mu.Unlock()
	if err := w.syncFile(f); err != nil {
		return fmt.Errorf("chaos/wal: fsync checkpoint: %w", err)
	}
	return nil
}

// AppendClockAdvance records a peer-driven Lamport clock advance with the same
// fsync-on-commit durability as AppendMutation and AppendCheckpoint. Without a
// durable record, a crash could restore the engine below logical time it had
// already observed.
func (w *WAL) AppendClockAdvance(advancedTo uint64) error {
	w.mu.Lock()
	// Unlock explicitly on every return. Receive-path appends share w.mu with
	// origin group commits, so holding it through fsync would let one slow sync
	// stall both paths. The 0x06 checksum rejects a damaged advance counter before
	// it can contribute to the replayed Lamport high-water mark (ADR-0053).
	rec := encodeClockAdvanceChecksummed(w.nextSeq, advancedTo)
	if _, err := w.f.Write(rec); err != nil {
		w.mu.Unlock()
		return fmt.Errorf("chaos/wal: write clock-advance: %w", err)
	}
	// Consume the sequence at write time, as in AppendMutation (ADR-0045).
	w.nextSeq++
	// Ordering is fixed by the write and increment under w.mu. Capture the file
	// before unlocking, then fsync it without blocking the other append paths.
	f := w.f
	w.mu.Unlock()
	if err := w.syncFile(f); err != nil {
		return fmt.Errorf("chaos/wal: fsync clock-advance: %w", err)
	}
	return nil
}

// NextSeq returns the next sequence number that will be stamped onto a record.
// Tests use this to assert monotonicity across an OpenWAL/Close/OpenWAL cycle.
func (w *WAL) NextSeq() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.nextSeq
}

// Close flushes and closes the underlying file.
func (w *WAL) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return nil
	}
	_ = w.f.Sync()
	err := w.f.Close()
	w.f = nil
	return err
}

// Path returns the on-disk path of this WAL (used by the supervisor's recovery
// loop to hand a stable path to the replacement worker).
func (w *WAL) Path() string { return w.path }

// ---------------------------------------------------------------------------
// Record encoding (length: seq(8) + type(1) + len(4) + payload)
// ---------------------------------------------------------------------------

func encodeMutationRecord(seq uint64, m WALMutation) ([]byte, error) {
	entityIdBytes := []byte(m.EntityID)
	// payload: entityIdLen(4) + entityId + NodeID(16) + Counter(8) + entry
	payloadLen := 4 + len(entityIdBytes) + 16 + 8 + walEntryLen
	rec := make([]byte, 13+payloadLen) // seq(8)+type(1)+len(4)+payload
	binary.BigEndian.PutUint64(rec[0:8], seq)
	rec[8] = byte(WALRecMutation)
	binary.BigEndian.PutUint32(rec[9:13], uint32(payloadLen))
	off := 13
	binary.BigEndian.PutUint32(rec[off:off+4], uint32(len(entityIdBytes)))
	off += 4
	copy(rec[off:off+len(entityIdBytes)], entityIdBytes)
	off += len(entityIdBytes)
	copy(rec[off:off+16], m.NodeID[:])
	off += 16
	binary.BigEndian.PutUint64(rec[off:off+8], m.Counter)
	off += 8
	encodeWALEntry(m.Entry, rec[off:off+walEntryLen])
	return rec, nil
}

// encodeMutationV2Record encodes an unframed 0x04 record (ADR-0045 §4). Its
// outer framing matches the legacy mutation, but encodeCRDTEntry writes the full
// 120-byte entry using the snapshot image layout. A WAL tail entry and an image
// entry at the same dot therefore have identical bytes. The top-level NodeID and
// Counter preserve the record's dot independently of the entry payload.
func encodeMutationV2Record(seq uint64, m WALMutation) ([]byte, error) {
	entityIdBytes := []byte(m.EntityID)
	// payload: entityIdLen(4) + entityId + NodeID(16) + Counter(8) + entry(120)
	payloadLen := 4 + len(entityIdBytes) + 16 + 8 + crdtEntryWireLen
	rec := make([]byte, 13+payloadLen) // seq(8)+type(1)+len(4)+payload
	binary.BigEndian.PutUint64(rec[0:8], seq)
	rec[8] = byte(WALRecMutationV2)
	binary.BigEndian.PutUint32(rec[9:13], uint32(payloadLen))
	putMutationV2Payload(rec[13:], m, entityIdBytes) // shared layout (no drift with 0x06)
	return rec, nil
}

// AppendMutationV1ForTest writes an unframed legacy 0x01 record with the
// 80-byte entry subset. Production uses V2 payloads inside 0x06 frames
// (ADR-0045 §4). Tests use this helper to build mixed-format logs and check that
// replay decodes both formats and marks legacy mutations explicitly.
func (w *WAL) AppendMutationV1ForTest(m WALMutation) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	rec, err := encodeMutationRecord(w.nextSeq, m)
	if err != nil {
		return err
	}
	if _, err := w.f.Write(rec); err != nil {
		return fmt.Errorf("chaos/wal: write legacy mutation: %w", err)
	}
	w.nextSeq++ // consume at write time, byte-identical to the V2 path
	if err := w.sync(); err != nil {
		return fmt.Errorf("chaos/wal: fsync legacy mutation: %w", err)
	}
	return nil
}

// AppendMutationV2ForTest writes an unframed 0x04 record containing the full
// 120-byte mutation. Production wraps the same payload in 0x06 (ADR-0053). Tests
// use the bare form in mixed-format logs and as the unprotected counterpart when
// checking corruption detection.
func (w *WAL) AppendMutationV2ForTest(m WALMutation) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	rec, err := encodeMutationV2Record(w.nextSeq, m)
	if err != nil {
		return err
	}
	if _, err := w.f.Write(rec); err != nil {
		return fmt.Errorf("chaos/wal: write v2 mutation (test): %w", err)
	}
	w.nextSeq++ // consume at write time, byte-identical to the wrapped path
	if err := w.sync(); err != nil {
		return fmt.Errorf("chaos/wal: fsync v2 mutation (test): %w", err)
	}
	return nil
}

// AppendCheckpointRawForTest writes a 0x05 checkpoint with payload exactly as
// supplied. Unlike encodeCheckpointRecord, which writes 56 bytes without a
// fingerprint or 88 with one, this helper can produce the legacy 48-byte form or
// a truncated payload. Tests use it to check that replay accepts a legacy
// checkpoint without a fingerprint and rejects payloads shorter than 48 bytes.
func (w *WAL) AppendCheckpointRawForTest(payload []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	rec := make([]byte, 13+len(payload))
	binary.BigEndian.PutUint64(rec[0:8], w.nextSeq)
	rec[8] = byte(WALRecCheckpointV2)
	binary.BigEndian.PutUint32(rec[9:13], uint32(len(payload)))
	copy(rec[13:], payload)
	if _, err := w.f.Write(rec); err != nil {
		return fmt.Errorf("chaos/wal: write raw checkpoint: %w", err)
	}
	w.nextSeq++ // consume at write time, byte-identical to AppendMutationV1ForTest
	if err := w.sync(); err != nil {
		return fmt.Errorf("chaos/wal: fsync raw checkpoint: %w", err)
	}
	return nil
}

func encodeCheckpointRecord(seq uint64, c WALCheckpoint) []byte {
	if c.HasCutSeq {
		// A 0x05 payload contains the root, watermark, pre-walk CutSeq horizon,
		// and live ClockHigh. The fingerprint is present only when an image was
		// captured. The payload is 56 bytes without it and 88 bytes with it
		// (ADR-0045).
		payloadLen := 32 + 8 + 8 + 8
		if c.HasFingerprint {
			payloadLen += 32
		}
		rec := make([]byte, 13+payloadLen)
		binary.BigEndian.PutUint64(rec[0:8], seq)
		rec[8] = byte(WALRecCheckpointV2)
		binary.BigEndian.PutUint32(rec[9:13], uint32(payloadLen))
		putCheckpointV2Payload(rec[13:], c) // shared layout (no drift with 0x06)
		return rec
	}
	payloadLen := 32 + 8 // MerkleRoot + LamportHigh
	rec := make([]byte, 13+payloadLen)
	binary.BigEndian.PutUint64(rec[0:8], seq)
	rec[8] = byte(WALRecCheckpoint)
	binary.BigEndian.PutUint32(rec[9:13], uint32(payloadLen))
	off := 13
	copy(rec[off:off+32], c.MerkleRoot[:])
	off += 32
	binary.BigEndian.PutUint64(rec[off:off+8], c.LamportHigh)
	return rec
}

func encodeClockAdvanceRecord(seq uint64, advancedTo uint64) []byte {
	payloadLen := 8 // advanced-to counter
	rec := make([]byte, 13+payloadLen)
	binary.BigEndian.PutUint64(rec[0:8], seq)
	rec[8] = byte(WALRecClockAdvance)
	binary.BigEndian.PutUint32(rec[9:13], uint32(payloadLen))
	putClockAdvancePayload(rec[13:21], advancedTo) // shared layout (no drift with 0x06)
	return rec
}

// frameChecksummed builds a WALRecChecksummed record with one allocation
// (ADR-0053):
//
//	seq(8) || 0x06(1) || payloadLen(4) || innerType(1) || innerPayload || crc32c(4)
//
// writeInner writes the inner payload at rec[14:14+innerLen]. The shared
// put*Payload helpers are used by both the unframed test encoders and these
// production encoders, so their 0x03, 0x04, and 0x05 layouts cannot drift.
// encodeCRDTEntry also preserves the snapshot entry layout.
//
// CRC32C covers innerType and innerPayload at rec[13:14+innerLen]. The outer
// sequence and payload length are protected separately by sequence contiguity
// and the length bound. The shared Castagnoli table makes checksum computation
// allocation-free, and no separate buffers are allocated for the frame pieces.
func frameChecksummed(seq uint64, innerType WALRecordType, innerLen int, writeInner func(dst []byte)) []byte {
	payloadLen := 1 + innerLen + 4 // innerType(1) + innerPayload + crc32c(4)
	rec := make([]byte, 13+payloadLen)
	binary.BigEndian.PutUint64(rec[0:8], seq)
	rec[8] = byte(WALRecChecksummed)
	binary.BigEndian.PutUint32(rec[9:13], uint32(payloadLen))
	rec[13] = byte(innerType)
	writeInner(rec[14 : 14+innerLen])
	crc := crc32.Checksum(rec[13:14+innerLen], castagnoliTable)
	binary.BigEndian.PutUint32(rec[14+innerLen:], crc)
	return rec
}

// putMutationV2Payload writes the 0x04 inner payload (entityIdLen, entityId,
// NodeID, Counter, entry) at dst. It is shared by encodeMutationV2Record for
// unframed test records and encodeMutationV2Checksummed for production records,
// keeping their layouts identical.
func putMutationV2Payload(dst []byte, m WALMutation, entityIdBytes []byte) {
	off := 0
	binary.BigEndian.PutUint32(dst[off:off+4], uint32(len(entityIdBytes)))
	off += 4
	copy(dst[off:off+len(entityIdBytes)], entityIdBytes)
	off += len(entityIdBytes)
	copy(dst[off:off+16], m.NodeID[:])
	off += 16
	binary.BigEndian.PutUint64(dst[off:off+8], m.Counter)
	off += 8
	encodeCRDTEntry(dst[off:off+crdtEntryWireLen], m.Full)
}

// putCheckpointV2Payload writes the 0x05 inner payload (root(32)‖watermark(8)‖
// CutSeq(8)‖ClockHigh(8)‖[fingerprint(32)]) at dst[0:]. Single source of the
// layout, shared by encodeCheckpointRecord (bare, test) and the production
// encodeCheckpointChecksummed (0x06).
func putCheckpointV2Payload(dst []byte, c WALCheckpoint) {
	off := 0
	copy(dst[off:off+32], c.MerkleRoot[:])
	off += 32
	binary.BigEndian.PutUint64(dst[off:off+8], c.LamportHigh)
	off += 8
	binary.BigEndian.PutUint64(dst[off:off+8], c.CutSeq)
	off += 8
	binary.BigEndian.PutUint64(dst[off:off+8], c.ClockHigh)
	off += 8
	if c.HasFingerprint {
		copy(dst[off:off+32], c.Fingerprint[:])
	}
}

// putClockAdvancePayload writes the 0x03 inner payload (advancedTo counter, 8
// bytes) at dst[0:8].
func putClockAdvancePayload(dst []byte, advancedTo uint64) {
	binary.BigEndian.PutUint64(dst[0:8], advancedTo)
}

// encodeMutationV2Checksummed is the production 0x06-framed form of a V2 mutation
// (single allocation); the inner payload is byte-identical to encodeMutationV2Record.
func encodeMutationV2Checksummed(seq uint64, m WALMutation) ([]byte, error) {
	entityIdBytes := []byte(m.EntityID)
	innerLen := 4 + len(entityIdBytes) + 16 + 8 + crdtEntryWireLen
	return frameChecksummed(seq, WALRecMutationV2, innerLen, func(dst []byte) {
		putMutationV2Payload(dst, m, entityIdBytes)
	}), nil
}

// encodeCheckpointChecksummed is the production 0x06-framed form of a checkpoint
// (single allocation). The 0x05 (horizon-cut) payload is byte-identical to
// encodeCheckpointRecord's HasCutSeq branch; a legacy 0x02 checkpoint (HasCutSeq
// false, written by older call sites) is framed as a 0x06-wrapped 0x02.
func encodeCheckpointChecksummed(seq uint64, c WALCheckpoint) []byte {
	if c.HasCutSeq {
		innerLen := 32 + 8 + 8 + 8 // root‖watermark‖cutseq‖clockhigh
		if c.HasFingerprint {
			innerLen += 32
		}
		return frameChecksummed(seq, WALRecCheckpointV2, innerLen, func(dst []byte) {
			putCheckpointV2Payload(dst, c)
		})
	}
	return frameChecksummed(seq, WALRecCheckpoint, 32+8, func(dst []byte) {
		copy(dst[0:32], c.MerkleRoot[:])
		binary.BigEndian.PutUint64(dst[32:40], c.LamportHigh)
	})
}

// encodeClockAdvanceChecksummed is the production 0x06-framed form of a 0x03
// clock advance (single allocation).
func encodeClockAdvanceChecksummed(seq uint64, advancedTo uint64) []byte {
	return frameChecksummed(seq, WALRecClockAdvance, 8, func(dst []byte) {
		putClockAdvancePayload(dst, advancedTo)
	})
}

// unwrapChecksummed verifies a 0x06 payload containing innerType, innerPayload,
// and a trailing CRC32C. A checksum mismatch in a complete record returns
// ErrWALCorrupt. On success it returns the inner type and payload so ReplayWAL
// uses the same decoders as for unframed records; the checksum changes only what
// is rejected, not what is replayed. A partial trailing record is discarded
// before this function, so a short frame here indicates corruption.
func unwrapChecksummed(payload []byte, seq uint64) (WALRecordType, []byte, error) {
	if len(payload) < 5 { // innerType(1) + crc32c(4) minimum
		return 0, nil, fmt.Errorf("%w: record seq %d checksummed frame too short (%d bytes)", ErrWALCorrupt, seq, len(payload))
	}
	body := payload[:len(payload)-4] // innerType ‖ innerPayload
	want := binary.BigEndian.Uint32(payload[len(payload)-4:])
	got := crc32.Checksum(body, castagnoliTable)
	// The comparison rejects damaged content. Tests set walCRC32Skip to bypass
	// it and verify that the same corrupted record would otherwise replay.
	if !walCRC32Skip.Load() && want != got {
		return 0, nil, fmt.Errorf("%w: record seq %d crc mismatch (stored %08x, computed %08x)", ErrWALCorrupt, seq, want, got)
	}
	return WALRecordType(body[0]), body[1:], nil
}

const walEntryLen = 32 + 16 + 16 + 8 + 8 // PayloadDigest + Origin + Dot + Counter + SystemTime

func encodeWALEntry(e WALEntry, dst []byte) {
	off := 0
	copy(dst[off:off+32], e.PayloadDigest[:])
	off += 32
	copy(dst[off:off+16], e.OriginNodeID[:])
	off += 16
	copy(dst[off:off+16], e.DotNodeID[:])
	off += 16
	binary.BigEndian.PutUint64(dst[off:off+8], e.DotCounter)
	off += 8
	binary.BigEndian.PutUint64(dst[off:off+8], uint64(e.SystemTime))
}

func decodeWALEntry(src []byte) WALEntry {
	var e WALEntry
	off := 0
	copy(e.PayloadDigest[:], src[off:off+32])
	off += 32
	copy(e.OriginNodeID[:], src[off:off+16])
	off += 16
	copy(e.DotNodeID[:], src[off:off+16])
	off += 16
	e.DotCounter = binary.BigEndian.Uint64(src[off : off+8])
	off += 8
	e.SystemTime = int64(binary.BigEndian.Uint64(src[off : off+8]))
	return e
}

// scanRecords walks from byte 8, immediately after the fixed header, to EOF. It
// returns one past the highest sequence seen, the number of complete records,
// and lastGood, the offset immediately after the last complete record (8 for an
// empty log). A partial final record leaves lastGood at that record's first
// byte. OpenWAL uses these results to restore nextSeq and truncate a torn tail
// before appending (ADR-0045).
func scanRecords(f *os.File) (nextSeq uint64, count uint64, lastGood int64, err error) {
	// Seek to right after the header.
	if _, err = f.Seek(8, io.SeekStart); err != nil {
		return 0, 0, 0, err
	}
	lastGood = 8 // the record region begins after the 8-byte header
	hdr := make([]byte, 13)
	for {
		n, e := io.ReadFull(f, hdr)
		if e == io.EOF {
			return nextSeq, count, lastGood, nil
		}
		if e == io.ErrUnexpectedEOF {
			// A torn final header (a crash left a partial record) — lastGood
			// stays at this record's first byte; the caller truncates there.
			return nextSeq, count, lastGood, nil
		}
		if e != nil {
			return 0, 0, 0, e
		}
		if n != 13 {
			return 0, 0, 0, errors.New("chaos/wal: short record header")
		}
		seq := binary.BigEndian.Uint64(hdr[0:8])
		// hdr[8] = type, ignored for scanning.
		payloadLen := binary.BigEndian.Uint32(hdr[9:13])
		if _, e := io.CopyN(io.Discard, f, int64(payloadLen)); e != nil {
			// Torn payload — lastGood stays at this record's first byte.
			return nextSeq, count, lastGood, nil
		}
		// The full record (13-byte header + payloadLen payload) is present.
		lastGood += 13 + int64(payloadLen)
		if seq >= nextSeq {
			nextSeq = seq + 1
		}
		count++
	}
}

// ---------------------------------------------------------------------------
// WAL replay (recovery substrate)
// ---------------------------------------------------------------------------

// WALRecord is one entry in the append-ordered replay stream. Type determines
// whether Mutation or Advance is populated.
//
// Seq is the sequence number decoded from the record header by ReplayWAL. It
// provides a total order across origins, unlike scalar Lamport counters, and
// identifies which records a checkpoint includes (ADR-0045). A legacy checkpoint
// cuts the recovery tail at Seq > FinalCheckptSeq; a V2 checkpoint instead uses
// its explicit CutSeq horizon.
type WALRecord struct {
	Type     WALRecordType
	Mutation WALMutation
	Advance  uint64
	Seq      uint64
}

// Replayed is the result of a full WAL replay: the records seen, the final
// checkpoint (if any), and the highest Lamport counter observed.
type Replayed struct {
	Mutations     []WALMutation
	Advances      []uint64
	Ordered       []WALRecord
	FinalCheckpt  WALCheckpoint
	HasCheckpoint bool
	LamportHigh   uint64
	NextSeq       uint64
	ScratchDir    string
	// FinalCheckptSeq is the on-disk sequence number of the checkpoint that
	// populated FinalCheckpt (ADR-0045). For a legacy checkpoint, records with
	// Seq > FinalCheckptSeq form the post-checkpoint tail. It is zero when
	// HasCheckpoint is false. Consuming sequence numbers at write time keeps this
	// cut unambiguous even after an fsync failure.
	FinalCheckptSeq uint64
	// LegacyCheckpoint reports whether the final checkpoint lacks a fingerprint:
	// a 0x02 record, a 48-byte 0x05 record, or a 56-byte record written without
	// a snapshotter. Replay assigns it at every checkpoint rather than accumulating
	// it, so an earlier legacy record cannot hide a fingerprint on the final one.
	// Recovery has no fingerprint comparison for a legacy anchor and reports that
	// limitation through its witness fields (ADR-0045).
	LegacyCheckpoint bool
	// SeqContiguityVerified is true after replay checks every complete record
	// against the contiguous ascending-sequence rule. RecordsVerified is the
	// number checked. An empty log returns true with RecordsVerified == 0.
	SeqContiguityVerified bool
	RecordsVerified       int
	// ClockHighClamped reports whether any 0x05 ClockHigh exceeded
	// MaxCredibleClockHigh and was reduced to the log's durable high-water mark.
	// ClockHighRaw records the largest rejected value. False and zero mean no
	// clamp occurred.
	ClockHighClamped bool
	ClockHighRaw     uint64
}

// ReplayWAL opens path and returns every complete record in append order.
// Recovery restores the recorded entries into a fresh engine without minting new
// dots, then compares the rebuilt Merkle root with FinalCheckpt. A partial final
// record is ignored as a crash boundary; OpenWAL truncates it before appending.
// Corruption in a complete record returns an error so recovery does not rebuild
// from a suspect log.
func ReplayWAL(path string) (*Replayed, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("chaos/wal: replay open %s: %w", path, err)
	}
	defer f.Close()
	var hdr [8]byte
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		return nil, fmt.Errorf("chaos/wal: replay header: %w", err)
	}
	if binary.BigEndian.Uint32(hdr[0:4]) != walMagic {
		return nil, errors.New("chaos/wal: replay bad magic")
	}
	if v := binary.BigEndian.Uint16(hdr[4:6]); v != walVersion {
		return nil, fmt.Errorf("chaos/wal: replay bad version %d", v)
	}
	out := &Replayed{}
	hdrBuf := make([]byte, 13)
	var prevSeq uint64
	for {
		n, err := io.ReadFull(f, hdrBuf)
		if err == io.EOF {
			break
		}
		if err == io.ErrUnexpectedEOF {
			// torn final record — truncate (standard WAL tail handling).
			break
		}
		if err != nil {
			return nil, fmt.Errorf("chaos/wal: replay record header: %w", err)
		}
		if n != 13 {
			return nil, errors.New("chaos/wal: replay short header")
		}
		seq := binary.BigEndian.Uint64(hdrBuf[0:8])
		recType := WALRecordType(hdrBuf[8])
		payloadLen := binary.BigEndian.Uint32(hdrBuf[9:13])
		// Bound the length before allocating. A short final payload is handled
		// below as a torn tail, but an excessive length in a complete header is
		// corruption and must not trigger a multi-GiB allocation or a silent skip.
		if payloadLen > maxRecordPayloadLen {
			return nil, fmt.Errorf("chaos/wal: record payload length %d exceeds max %d at seq %d (corrupt record)", payloadLen, maxRecordPayloadLen, seq)
		}
		// Require an unbroken ascending sequence beginning at zero. A successful
		// write consumes its sequence before fsync, and OpenWAL truncates only a
		// partial tail, so a gap or reorder means a record is missing. This check
		// covers mutations, clock advances, and checkpoints rather than relying on
		// the dot-only Merkle root to reveal loss. It runs after the length guard
		// and before the payload read.
		//
		// The CRC does not cover the outer sequence, and pairwise contiguity cannot
		// check the first record. A new WAL starts with nextSeq == 0 and is never
		// truncated at the front, so a non-zero first sequence is header corruption.
		if out.RecordsVerified == 0 && seq != 0 {
			return nil, fmt.Errorf("%w: first record seq is %d, want 0 (a WAL always starts at seq 0; a non-zero first seq is header corruption)", ErrWALSeqGap, seq)
		}
		if out.RecordsVerified > 0 && seq != prevSeq+1 {
			return nil, fmt.Errorf("%w: expected seq %d, observed %d (record #%d)", ErrWALSeqGap, prevSeq+1, seq, out.RecordsVerified)
		}
		payload := make([]byte, payloadLen)
		if _, err := io.ReadFull(f, payload); err != nil {
			if err == io.ErrUnexpectedEOF || err == io.EOF {
				// A partial payload is a crash boundary; exclude this record.
				break
			}
			return nil, fmt.Errorf("chaos/wal: replay payload: %w", err)
		}
		// The record is complete: count it and advance the contiguity cursor.
		// (A torn-tail record is neither counted nor checked — it is not a
		// record, it is a crash boundary.)
		prevSeq = seq
		out.RecordsVerified++
		if seq >= out.NextSeq {
			out.NextSeq = seq + 1
		}
		// Verify a 0x06 checksum before decoding its inner record. A mismatch in
		// this complete record returns ErrWALCorrupt; partial trailing records have
		// already been excluded. After verification, dispatch on the inner type so
		// the decoders below and the resulting Replayed content match the unframed
		// form. The checksum affects rejection, not replay semantics (ADR-0053).
		if recType == WALRecChecksummed {
			innerType, innerPayload, cerr := unwrapChecksummed(payload, seq)
			if cerr != nil {
				return nil, cerr
			}
			recType = innerType
			payload = innerPayload
		}
		switch recType {
		case WALRecMutation:
			m, err := decodeMutationPayload(payload)
			if err != nil {
				return nil, fmt.Errorf("chaos/wal: decode mutation at seq %d: %w", seq, err)
			}
			out.Mutations = append(out.Mutations, m)
			out.Ordered = append(out.Ordered, WALRecord{Type: WALRecMutation, Mutation: m, Seq: seq})
			if m.Counter > out.LamportHigh {
				out.LamportHigh = m.Counter
			}
		case WALRecMutationV2:
			m, err := decodeMutationV2Payload(payload)
			if err != nil {
				return nil, fmt.Errorf("chaos/wal: decode mutation-v2 at seq %d: %w", seq, err)
			}
			out.Mutations = append(out.Mutations, m)
			out.Ordered = append(out.Ordered, WALRecord{Type: WALRecMutationV2, Mutation: m, Seq: seq})
			if m.Counter > out.LamportHigh {
				out.LamportHigh = m.Counter
			}
		case WALRecClockAdvance:
			if len(payload) < 8 {
				return nil, fmt.Errorf("chaos/wal: short clock-advance at seq %d", seq)
			}
			advancedTo := binary.BigEndian.Uint64(payload[0:8])
			out.Advances = append(out.Advances, advancedTo)
			out.Ordered = append(out.Ordered, WALRecord{Type: WALRecClockAdvance, Advance: advancedTo, Seq: seq})
			// Fold the advance into LamportHigh, as the mutation and checkpoint
			// cases do. Recovery seeds the replacement clock from rep.LamportHigh
			// and its final AdvanceLamportTo call, so omitting this fold would lose
			// a durable observation of logical time. The maximum preserves the
			// highest value across all record kinds (ADR-0045 §4).
			if advancedTo > out.LamportHigh {
				out.LamportHigh = advancedTo
			}
		case WALRecCheckpoint:
			if len(payload) < 40 {
				return nil, fmt.Errorf("chaos/wal: short checkpoint at seq %d", seq)
			}
			var c WALCheckpoint
			copy(c.MerkleRoot[:], payload[0:32])
			c.LamportHigh = binary.BigEndian.Uint64(payload[32:40])
			out.FinalCheckpt = c
			out.HasCheckpoint = true
			out.FinalCheckptSeq = seq // The legacy recovery tail begins after this record.
			// A 0x02 checkpoint has no fingerprint, so recovery cannot perform
			// that comparison when it is the final checkpoint.
			out.LegacyCheckpoint = true
			if c.LamportHigh > out.LamportHigh {
				out.LamportHigh = c.LamportHigh
			}
		case WALRecCheckpointV2:
			if len(payload) < 48 {
				return nil, fmt.Errorf("chaos/wal: short V2 checkpoint at seq %d", seq)
			}
			var c WALCheckpoint
			copy(c.MerkleRoot[:], payload[0:32])
			c.LamportHigh = binary.BigEndian.Uint64(payload[32:40])
			c.CutSeq = binary.BigEndian.Uint64(payload[40:48])
			c.HasCutSeq = true
			// ClockHigh occupies [48:56] in the 56-byte form. A legacy 48-byte
			// checkpoint leaves it zero, reducing recovery's
			// max(rep.LamportHigh, ClockHigh) to rep.LamportHigh (ADR-0045 §4).
			if len(payload) >= 56 {
				c.ClockHigh = binary.BigEndian.Uint64(payload[48:56])
				// Reject an incredible clock before it can seed the replacement
				// engine. NextDot would eventually wrap and reissue counters; merge
				// keeps an existing entry for an equal dot, so peers could silently
				// discard later writes while root and fingerprint checks still pass.
				// Clamp to the durable high-water and report the raw value through
				// Replayed and the recovery log. A 0x06 frame catches such damage by
				// CRC first; this clamp protects legacy checkpoints without one.
				// ClockHigh remains necessary because receive admission can raise the
				// clock before verification without writing a 0x03 advance.
				if c.ClockHigh > MaxCredibleClockHigh {
					out.ClockHighClamped = true
					if c.ClockHigh > out.ClockHighRaw {
						out.ClockHighRaw = c.ClockHigh
					}
					floor := out.LamportHigh
					if c.LamportHigh > floor {
						floor = c.LamportHigh
					}
					c.ClockHigh = floor
				}
			}
			// The optional state fingerprint occupies [56:88]. A legacy 48-byte
			// checkpoint or a 56-byte checkpoint written without a snapshotter
			// leaves HasFingerprint false. Recovery then has no fingerprint to
			// compare and reports that through LegacyCheckpoint and its witness
			// fields (ADR-0045).
			if len(payload) >= 88 {
				copy(c.Fingerprint[:], payload[56:88])
				c.HasFingerprint = true
			}
			// Track the final checkpoint's own form. Assignment on every record
			// prevents an earlier fingerprint-less checkpoint from hiding a
			// fingerprint on the final one.
			out.LegacyCheckpoint = !c.HasFingerprint
			out.FinalCheckpt = c
			out.HasCheckpoint = true
			out.FinalCheckptSeq = seq // V2 recovery uses c.CutSeq for its tail cut.
			if c.LamportHigh > out.LamportHigh {
				out.LamportHigh = c.LamportHigh
			}
		default:
			// Unknown record type. Per the no-silent-misinterpretation rule
			// this is an error rather than a skip.
			return nil, fmt.Errorf("chaos/wal: unknown record type 0x%x at seq %d", recType, seq)
		}
	}
	// The loop reached EOF or a partial trailing record without a sequence
	// violation, so every complete record passed the contiguity check. For an
	// empty log, SeqContiguityVerified is true and RecordsVerified remains zero.
	out.SeqContiguityVerified = true
	return out, nil
}

func decodeMutationPayload(p []byte) (WALMutation, error) {
	if len(p) < 4 {
		return WALMutation{}, errors.New("mutation: truncated length prefix")
	}
	entityIDLen := binary.BigEndian.Uint32(p[0:4])
	need := int(4) + int(entityIDLen) + 16 + 8 + walEntryLen
	if len(p) < need {
		return WALMutation{}, fmt.Errorf("mutation: truncated payload (have %d, need %d)", len(p), need)
	}
	off := 4
	var m WALMutation
	if entityIDLen > 0 {
		m.EntityID = string(p[off : off+int(entityIDLen)])
	}
	off += int(entityIDLen)
	copy(m.NodeID[:], p[off:off+16])
	off += 16
	m.Counter = binary.BigEndian.Uint64(p[off : off+8])
	off += 8
	m.Entry = decodeWALEntry(p[off : off+walEntryLen])
	// A 0x01 record stores five fields; the other five are unavailable, not
	// persisted zeros. Full is synthesized from the stored fields, and Legacy
	// distinguishes those synthesized zeros from recorded values. Recovery counts
	// these records in its witness so the missing tri-temporal and H3 fields
	// remain explicit.
	m.Legacy = true
	m.Full = eng.CRDTEntry{
		PayloadDigest: m.Entry.PayloadDigest,
		OriginNodeID:  m.Entry.OriginNodeID,
		DotNodeID:     m.Entry.DotNodeID,
		DotCounter:    m.Entry.DotCounter,
		SystemTime:    m.Entry.SystemTime,
	}
	return m, nil
}

// decodeMutationV2Payload decodes a 0x04 record: entityID + top-level dot +
// the complete 120-byte CRDTEntry (all ten fields, byte-identical to the
// snapshot image's layout). The legacy Entry subset is derived so pre-V2
// readers keep working. The dot is cross-checked against the entry at restore
// time (recovery's checkMutationRecord), not here; replay preserves the bytes.
func decodeMutationV2Payload(p []byte) (WALMutation, error) {
	if len(p) < 4 {
		return WALMutation{}, errors.New("mutation-v2: truncated length prefix")
	}
	entityIDLen := binary.BigEndian.Uint32(p[0:4])
	need := int(4) + int(entityIDLen) + 16 + 8 + crdtEntryWireLen
	if len(p) < need {
		return WALMutation{}, fmt.Errorf("mutation-v2: truncated payload (have %d, need %d)", len(p), need)
	}
	off := 4
	var m WALMutation
	if entityIDLen > 0 {
		m.EntityID = string(p[off : off+int(entityIDLen)])
	}
	off += int(entityIDLen)
	copy(m.NodeID[:], p[off:off+16])
	off += 16
	m.Counter = binary.BigEndian.Uint64(p[off : off+8])
	off += 8
	m.Full = decodeCRDTEntry(p[off : off+crdtEntryWireLen])
	m.Entry = WALEntry{
		PayloadDigest: m.Full.PayloadDigest,
		OriginNodeID:  m.Full.OriginNodeID,
		DotNodeID:     m.Full.DotNodeID,
		DotCounter:    m.Full.DotCounter,
		SystemTime:    m.Full.SystemTime,
	}
	return m, nil
}
