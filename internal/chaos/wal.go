// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

// ---------------------------------------------------------------------------
// Engine-side Write-Ahead Log (§2 recovery substrate)
// ---------------------------------------------------------------------------
//
// §2: "The supervisor identifies the dead connection, recovers the
// persistent database state via the write-ahead log, and spins up a pristine
// worker engine. This entire recovery cycle must execute without ever dropping
// the active HTTP connections."
//
// This WAL is the engine's OWN durability layer, NOT PostgreSQL's WAL (which
// this design replaces). It records every committed local mutation with enough state to
// deterministically rebuild an equivalent engine whose Merkle root matches the
// root recorded at WAL-append time.
//
// DETERMINISM CONTRACT (the seed-defense):
// The HAMT's MerkleRoot() folds only the CRDT causal dots (DotNodeID +
// DotCounter) under SHA-256 — it does NOT depend on the maphash.Seed, which
// Go marks "cannot be serialized or recreated in a different process." So a
// recovered worker started from a fresh maphash.MakeSeed() reproduces an
// IDENTICAL Merkle root for the same mutation sequence, provided it replays
// the same (localNodeID, lamport) assignments. The WAL persists those
// assignments exactly. Recovery replays into a fresh DeltaCRDTEngine and the
// rebuild's final MerkleRoot MUST equal the root the WAL recorded at the
// last checkpoint — else recovery is treated as data loss (the protect-then-no-loss invariant).
//
// DURABILITY CONTRACT (ACK-before-durability):
// Append is SYNCHRONOUS: it writes then fsyncs before returning. The worker
// MUST NOT ack a mutation to a client before Append returns. This is the
// "crash-consistency, not liveness" rule: surviving is not enough if the
// acknowledged state diverges.
// ---------------------------------------------------------------------------

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

// WALMagic / WALVersion tag the log file so a corrupt or foreign file fails
// cleanly rather than being silently misinterpreted on recovery.
const (
	walMagic   uint32 = 0x57414C00 // "WAL\0"
	walVersion uint16 = 1

	// maxRecordPayloadLen bounds the payload length ReplayWAL will accept from a
	// record header (ADR-0045). Today the four length bytes are
	// corruption-controlled and fed straight to make([]byte, payloadLen) — a torn
	// or flipped length could request up to 4 GiB on a single record. A real
	// record's payload is tiny: a mutation is 4 + len(entityID) + 16 + 8 +
	// walEntryLen, and entityIDs are keys. 4 MiB is absurdly generous yet kills
	// the multi-GiB allocation cliff. A header claiming more is mid-log
	// CORRUPTION (not a clean torn tail), so it is a loud error, not a silent
	// truncate.
	maxRecordPayloadLen = 4 << 20
)

// ErrWALSeqGap is returned by ReplayWAL when the record sequence numbers do
// not form an unbroken ascending run (the SOUND replacement check for the
// replay-only root assertion). A gap means a record
// is GENUINELY GONE: the seq is consumed only after the record's bytes are in
// the file (advance-as-you-write — AppendMutation's Write → nextSeq++ →
// fsync ordering means a failed Write returns before the increment, and a
// failed fsync never unconsumes the seq), OpenWAL re-derives nextSeq from the
// on-disk maximum and truncates only the TORN TAIL before any append, and no
// rotation exists. No normal or failing append can produce a gap, so there is
// no false-positive path: a gap is record loss, and recovery refuses to build
// state on a log with a hole. The error names the expected and observed seq.
//
// SCOPE: the no-false-positive argument assumes the
// advance-as-you-write ordering (Write → nextSeq++ → fsync). A log written
// under the older ordering (write → fsync → nextSeq++) could carry a
// DUPLICATE seq on disk — a failed fsync left the record's bytes but did not
// consume the seq, so the next append re-stamped it (0,1,1,2). This check
// REFUSES such a legacy log: over-strict, NOT corrupting, pre-1.0, and the WAL
// already hard-errors on downgrade. The soundness claim covers
// advance-as-you-write logs.
var ErrWALSeqGap = errors.New("chaos/wal: record sequence gap (a record is missing from the log)")

// MaxCredibleClockHigh bounds the 0x05 ClockHigh field at decode. It is the
// SAME ceiling recovery's
// checkMutationRecord applies to a mutation counter (recovery.go's
// maxPlausibleCounter = 1<<60), because a ClockHigh IS a counter value — the
// live Lamport clock equals some counter the cluster minted. The bound is
// derived, not round-picked: (a) ATTAINABILITY — 2^60 mints at the measured
// ingest ceiling (3.1e6 deltas/s, the production mint path) is ~11,800
// node-years; no deployment reaches it, so no legitimate value is ever
// clamped; (b) WRAP-HEADROOM — NextDot is lamportCounter.Add(1)
// (crdt.go:854) and WRAPS at 2^64; from any seed below 2^60 the wrap needs
// ~2^64 further mints, which is physically unreachable; (c) it catches the
// observed corruptions (MaxUint64 and the single-bit 0x80 flip to
// 2^63+7, both >> 2^60). A ClockHigh above the ceiling is CLAMPED (floored to
// the log's own durable high-water), never accepted: the floor is exactly the
// earlier seed semantics, which were safe — a ClockHigh above every
// recorded value only ever covers a raise that produced NO mutation (the
// verify-failed frame), so no durable or legitimately-gossiped dot can live
// above the log's high-water on that record. The clamp is LOUD: the event is
// recorded on Replayed (ClockHighClamped/ClockHighRaw) and surfaced as a log
// line + witness fields by recovery. A silent clamp is a silent fallback.
// This is a MITIGATION, not a cure: a plausible-looking
// corrupted value below the ceiling is undetectable without a per-record
// checksum — that requires a per-record-checksum format change.
const MaxCredibleClockHigh uint64 = 1 << 60

// WALRecordType identifies the kind of each appended record.
type WALRecordType uint8

const (
	// WALRecMutation is a committed local mutation: (entityID, CausalDot,
	// CRDTEntry). The recovery replays ALL mutation records in order into a
	// fresh DeltaCRDTEngine to rebuild state.
	WALRecMutation WALRecordType = 0x01
	// WALRecCheckpoint records the engine's Merkle root at a batch boundary.
	// Recovery asserts the rebuilt root equals the last checkpoint root.
	WALRecCheckpoint WALRecordType = 0x02
	// WALRecClockAdvance records a peer-driven Lamport clock advance (the
	// foreign-advance seed fix). The payload is the advanced-to
	// counter (8 bytes, BE). Recovery replays advances in append order
	// interleaved with mutations so the recovered clock lands exactly on the
	// live high-water. Without this record, a foreign AdvanceLamportTo creates
	// an un-recorded counter gap and the recovered clock would under-shoot.
	WALRecClockAdvance WALRecordType = 0x03
	// WALRecMutationV2 (ADR-0045) is a committed local
	// mutation carrying the FULL 120-byte CRDTEntry (all ten fields), not the
	// legacy 80-byte subset. The legacy 0x01 record persists 5 of 10 fields;
	// ValidTimeStart/ValidTimeEnd/AssertionTime/DecisionTime/H3Index replayed
	// as ZEROS — silently, because the Merkle root folds only the dot. A NEW
	// type byte (not a walEntryLen bump, not a walVersion bump, not payloadLen
	// arithmetic) is the only upgrade that keeps every existing 0x01 WAL
	// readable: a new binary reads BOTH; the 0x01 path marks each record
	// LEGACY (witness-counted) rather than silently zero-filling. DOWNGRADE is
	// one-way: an OLD binary hard-errors on 0x04 at ReplayWAL's default case
	// (no silent misinterpretation — the accepted, disclosed trade at pre-1.0).
	WALRecMutationV2 WALRecordType = 0x04
	// WALRecCheckpointV2 (ADR-0045) is a
	// checkpoint record carrying the PRE-WALK sequence horizon (CutSeq) in
	// addition to root+watermark. The legacy 0x02 record's recovery tail cut
	// is the checkpoint record's OWN seq — but the image is walked BEFORE the
	// record is appended, and a mutation whose WAL append lands in the
	// walk→append window (insert landed after the walk passed its shard, WAL
	// record before the checkpoint record) sat BELOW the cut yet ABSENT from
	// the image: bounded recovery lost an ACKed write (caught live:
	// counter 94, seq 96, watermark 95, cut 104). CutSeq is captured as
	// NextSeq() BEFORE the walk, so every record below CutSeq completed its
	// append — hence its InsertLocal — before the walk began, and is therefore
	// IN the image by construction; the tail becomes Seq >= CutSeq and the
	// window is closed at the SOURCE. Payload: MerkleRoot(32) ||
	// LamportHigh(8) || CutSeq(8) || ClockHigh(8) = 56 bytes (ClockHigh added by
	// ADR-0045 — the live clock at checkpoint
	// time; the decode is length-discriminated so a legacy 48-byte record still
	// parses). A new binary reads BOTH 0x02 and 0x05; an old binary hard-errors
	// on 0x05 (the disclosed one-way downgrade, same trade as 0x04).
	WALRecCheckpointV2 WALRecordType = 0x05
	// WALRecChecksummed (0x06) is a CRC32C-framed
	// WRAPPER — the ONLY format change permitted here (the wal.go
	// format law: a per-record checksum rides a NEW type byte, never a
	// walVersion/walEntryLen bump nor payloadLen arithmetic). Its payload is
	// innerType(1) ‖ innerPayload(len) ‖ crc32c(4, big-endian, trailing)
	// where the CRC32C (Castagnoli) is computed over innerType‖innerPayload —
	// NOT the outer seq/payloadLen, which are framing already guarded by the
	// seq-contiguity check and the length bound. ONE wrapper type protects ALL
	// record kinds uniformly (mutation/checkpoint/clock) and lets ReplayWAL
	// reuse every EXISTING decode arm verbatim via inner-dispatch, keeping the
	// legacy set exactly 0x01–0x05. Production appends emit 0x06 by DEFAULT
	// (protection ON, not opt-in); the decoder accepts BOTH framed and legacy
	// records, so an existing on-disk WAL (0x01–0x05) still replays — legacy
	// records are disclosed-UNPROTECTED (retroactive protection is impossible).
	WALRecChecksummed WALRecordType = 0x06
)

// ErrWALCorrupt is returned by ReplayWAL when a WALRecChecksummed (0x06)
// record's CRC32C does not match its innerType‖innerPayload — i.e. a COMPLETE,
// length-consistent record whose CONTENT was corrupted (a bit-rot / bit-flip
// the framing guards cannot see). This is fail-LOUD: the WAL is the
// authoritative truth with NO fallback, so the error propagates to a
// boot-refusal exactly like ErrWALSeqGap (recovery.go's RecoverEngineWithSnapshot
// and the chaos supervisor both propagate it, never swallow). It is DISTINCT
// from a torn tail: a truncated FINAL record never reaches the CRC check (the
// short-read break drops it silently, the crash-recovery contract).
var ErrWALCorrupt = errors.New("chaos/wal: record content CRC32C mismatch (corrupt record)")

// castagnoliTable is the package-level CRC32C (Castagnoli) table — built ONCE,
// never per record (no crc32.New on the append/replay path, so the checksum
// adds ZERO allocations). On ARM64 (Graviton) Go's hash/crc32 for Castagnoli
// dispatches to the hardware CRC32 instruction; the measured cost is ns/record
// (see the zero-allocation benchmark). crc32.Checksum over the frame is the only op.
var castagnoliTable = crc32.MakeTable(crc32.Castagnoli)

// walCRC32Skip is a TEST-ONLY bug-injection seam used by the CRC-detection
// guards. When true, the 0x06 CRC COMPARISON is skipped (the CRC is still
// computed), so the
// corrupt-and-detect guards can prove the check is LOAD-BEARING: with the
// compare compiled out, a corrupted record replays SILENTLY and the guard goes
// RED. The zero value (false) is the secure default (verify ON); production
// code never sets it. Atomic so the -race verification battery sees no data race;
// it lives on the boot/replay path (ReplayWAL), never the CRDT hot loop.
var walCRC32Skip atomic.Bool

// WALMutation is the serializable form of one committed local mutation. The
// top-level NodeID/Counter are the mutation's dot (the recovery-restore
// identity — the embedded entry's dot fields cannot be trusted to exist in
// legacy records).
//
// Full (ADR-0045) is the complete 120-byte CRDTEntry — all ten fields.
// For a WALRecMutationV2 record it is persisted verbatim; for a legacy 0x01
// record it is SYNTHESIZED from the 5 persisted fields with the other five
// (ValidTimeStart/ValidTimeEnd/AssertionTime/DecisionTime/H3Index) zero — and
// Legacy is TRUE so no consumer can mistake those zeros for data. New appends
// are ALWAYS 0x04; NewWALMutation is the one construction site discipline.
//
// Entry is the legacy 80-byte subset, always populated (for V2 it is derived
// from Full) so readers written before the V2 record format keep working
// unchanged.
type WALMutation struct {
	EntityID string
	Full     eng.CRDTEntry
	NodeID   [16]byte
	Counter  uint64
	Entry    WALEntry
	Legacy   bool
}

// NewWALMutation is the ONE construction discipline for WALMutation (ADR-0045):
// the caller passes the engine-STAMPED CausalDot (InsertLocal's return)
// and the pre-insert entry; the dot + origin are stamped into the full entry
// exactly as InsertLocal stamped its internal copy (crdt.go:966-969: DotNodeID
// = dot.NodeID, DotCounter = dot.Counter, OriginNodeID = localNodeID — and
// NextDot's dot.NodeID IS localNodeID, crdt.go:853-862). The legacy Entry
// subset is derived, never independently built, so the two can never drift.
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

// validateV2 is the AppendMutation/AppendMutations gate: a mutation whose Full
// entry is missing or inconsistent with its top-level dot is a caller bug
// (a construction site that predates the V2 record format), and writing it would persist a zero-filled
// 120-byte entry that the Merkle root CANNOT see — the silent-corruption
// class ADR-0045 exists to kill. Fail LOUDLY at the append, never write it.
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

// WALEntry is the subset of CRDTEntry that participates in identity and the
// Merkle root (and must survive replay). The full 120-byte CRDTEntry adds
// valid-time and assertion-time fields that are reproduced by replaying the
// same (nodeID, counter) sequence, so only the identity-bearing fields are
// required for deterministic recovery. We persist OriginNodeID + DotNodeID +
// DotCounter so Merkle equality and CRDT-dot identity are both preserved.
type WALEntry struct {
	PayloadDigest [32]byte
	OriginNodeID  [16]byte
	DotNodeID     [16]byte
	DotCounter    uint64
	SystemTime    int64
}

// WALCheckpoint pairs a Merkle root with the Lamport counter at the point the
// checkpoint was recorded, so recovery can assert BOTH root equality AND
// that the worker resumes the Lamport clock from the correct high-water mark.
//
// CutSeq/HasCutSeq (ADR-0045): HasCutSeq selects the record type on
// append — 0x05 (horizon cut) when true, legacy 0x02 (record-seq cut) when
// false. CutSeq is the PRE-WALK NextSeq() horizon: every record below it is
// in the image by construction; the recovery tail is Seq >= CutSeq. Production
// (Bridge.AppendCheckpoint) always sets it; the zero value writes a legacy
// 0x02 record, preserving the legacy semantics for hand-built test logs and old
// on-disk WALs.
//
// ClockHigh (ADR-0045) is the engine's LIVE
// Lamport clock at checkpoint time — a DISTINCT field from LamportHigh (the
// image's local-dot watermark, which can never bound a foreign advance). The
// clock can be raised ABOVE every recorded value with NO 0x03 record on disk:
// the receiver raises it at admission BEFORE the verify gate (receiver.go:529
// → pkg/clock/admission.go), so a verify-failed frame leaves the clock raised
// durably nowhere. Persisted on every 0x05 this binary writes; recovery nails
// the clock to max(rep.LamportHigh, ClockHigh) via the CONSTRUCTOR seed (the
// EWMA-safe path). A legacy 48-byte 0x05 decodes with ClockHigh == 0.
//
// Fingerprint/HasFingerprint (ADR-0045) persist
// the STATE FINGERPRINT of the checkpoint image (the payload-folding second
// check — state_fingerprint.go), so bounded recovery can detect "same dots,
// wrong bytes" — the class the dot-only Merkle root is structurally blind to.
// HasFingerprint is FALSE when no image was captured (the snapshotter==nil
// back-compat path: stamping the EMPTY-state fingerprint beside the
// REAL root would poison every later boot's comparison) and FALSE on a decode
// of a fingerprint-less record (a legacy 48-byte 0x05 or the 56-byte
// snapshotter-less form).
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

	// syncHook is a TEST-ONLY fsync spy (ADR-0044). It is nil in the
	// production WAL, in which case sync() calls the real w.f.Sync() —
	// byte-identical to the un-spied path. A test-local WAL wrapper sets a
	// hook that increments a counter on each fsync (1 fsync per
	// AppendMutations batch vs 1000 per 1000 AppendMutation calls — the fsync-
	// COUNT physics) OR rigs a failure (a Sync that
	// errors on the Nth call → the batch-path 503-ALL honesty check). It is
	// NEVER shipped: OpenWAL leaves it nil; production code never sets it. The
	// indirection is the ONLY change to the single-fsync call sites — the
	// record encode/write/nextSeq++ bodies are byte-identical to the un-hooked form.
	syncHook func() error
}

// SetSyncHookForTest installs a TEST-ONLY fsync spy on the WAL (ADR-0044).
// It is the seam the fsync-count and fsync-failure regression tests use to COUNT
// fsync calls (1 fsync per AppendMutations batch vs 1000 per 1000 AppendMutation
// calls — the fsync-COUNT physics) and to RIG a Sync failure (a hook
// that errors on the first fsync → the batch-path 503-ALL honesty check). It is
// NEVER called by production code: OpenWAL leaves syncHook nil (the production path
// → w.f.Sync(), byte-identical to the un-hooked form); only a test-local harness sets the hook.
// The hook REPLACES the real fsync (it does NOT chain to w.f.Sync) — a counting
// hook returns nil (no real fsync, faster + deterministic); a rigging hook
// returns an error (the injected failure). Setting a nil hook clears it (back to
// the production path). NOT concurrency-safe with concurrent appends (the test
// harness sets the hook BEFORE the first append — the single-writer-before-reader
// discipline the SetBatchSize/SetStratifiedAntiEntropy mesh seams use).
func (w *WAL) SetSyncHookForTest(hook func() error) { w.syncHook = hook }

// sync routes the fsync through the test hook (ADR-0044): nil syncHook →
// w.f.Sync(); a test-local hook → the test's count-or-fail behavior. All four
// production append paths (AppendMutations/AppendMutation/AppendCheckpoint/
// AppendClockAdvance) fsync via syncFile(captured-fd) OUTSIDE w.mu — sync()'s only
// remaining callers are the TEST-ONLY constructors (AppendMutationV1ForTest,
// AppendCheckpointRawForTest) and the RedControl's over-hold helper, all of which
// hold w.mu. sync() reads w.f DIRECTLY, so it is only safe while holding w.mu
// (Close() nils w.f under the lock); never call it from an unlocked context — use
// syncFile(capturedFD) there.
func (w *WAL) sync() error {
	if w.syncHook != nil {
		return w.syncHook()
	}
	return w.f.Sync()
}

// syncFile fsyncs a CAPTURED *os.File handle (or routes to the test hook). It is
// the unlocked-fsync entry point (ADR-0045), used by ALL
// FOUR append paths (AppendMutations, AppendMutation, AppendCheckpoint,
// AppendClockAdvance): each releases w.mu before
// the fsync, so it CANNOT touch w.f at that moment — Close() sets `w.f = nil` under
// w.mu, and an unlocked `w.f.Sync()` racing a concurrent Close would nil-deref PANIC
// (and race-detector-flag the unsynchronized w.f read). The caller therefore
// captures f:= w.f while still holding the lock and passes it here.
//
// Passing the captured handle is not merely nil-safe, it is SEMANTICALLY the right
// object: the durability obligation is "the records I just wrote, through the fd I
// wrote them through". If Close() closes that fd concurrently, os.File.Sync returns
// os.ErrClosed (an error — NOT a panic), which propagates as a normal fsync failure;
// and Close() itself performs a final w.f.Sync() under the lock, so the tail is
// flushed on that path regardless. The syncHook branch is checked FIRST and ignores
// f, keeping the test seam byte-identical (a counting hook never touches the
// file; a rigging hook still injects its error).
func (w *WAL) syncFile(f *os.File) error {
	if w.syncHook != nil {
		return w.syncHook()
	}
	if f == nil {
		return errors.New("chaos/wal: fsync on a closed WAL")
	}
	return f.Sync()
}

// OpenWAL opens (or creates) the engine WAL at path. The header is written if
// the file is new; an existing file's header is verified and its tail is left
// at EOF for continued appends. Recovery uses OpenWAL for verification and a
// separate Replay path to rebuild the engine.
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
		// Snap the tail to the last clean record boundary BEFORE any
		// append. A crash can leave a torn trailing record; ReplayWAL tolerates
		// it (stops at the tear), but the append offset must NOT sit past it —
		// otherwise the next append lands after the torn bytes and the NEXT
		// replay parses [torn][new record] as one header, silently discarding
		// every record written since the tear (or tripping the unknown-type
		// hard-error). The fd is O_RDWR (not O_APPEND), so truncation + seek is
		// the caller's responsibility. A clean log has lastGood == size, so the
		// truncate is a no-op there.
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

// AppendMutation records a committed local mutation and returns after the fsync.
// Pre-mortem #1: synchronous fsync — the caller may ACK the client after this
// returns, no earlier, defeating the ACK-before-durability corruption.
func (w *WAL) AppendMutation(m WALMutation) error {
	w.mu.Lock()
	// NOTE: NO `defer w.mu.Unlock()` (the lock-scope split): the
	// success path releases w.mu BEFORE the fsync so a slow disk barrier never
	// serializes the WAL behind one caller's fsync; each error path unlocks
	// explicitly. Byte-identical in shape to AppendMutations.
	if err := validateV2(m); err != nil {
		w.mu.Unlock()
		return err
	}
	// Emit the CRC32C-framed 0x06 form by default — the record's
	// content is integrity-protected at rest. Single allocation; the inner payload
	// shares encodeMutationV2Record's layout (putMutationV2Payload), so byte-for-byte
	// it IS the 0x04 record, framed. The CRC never alters WHAT is recorded.
	rec, err := encodeMutationV2Checksummed(w.nextSeq, m)
	if err != nil {
		w.mu.Unlock()
		return err
	}
	if _, err := w.f.Write(rec); err != nil {
		w.mu.Unlock()
		return fmt.Errorf("chaos/wal: write mutation: %w", err)
	}
	// Advance-as-you-write (ADR-0045): the seq is consumed the instant the
	// record's bytes are in the file, NOT after the fsync. The bytes sit in the
	// page cache whether or not THIS fsync succeeds, and a neighbouring append's
	// fsync flushes the whole file (it can only flush MORE, never fewer) — so a
	// fsync failure must NOT leave the seq unconsumed, or the next append
	// re-stamps the SAME seq onto a DIFFERENT record and the recovery sequence
	// cut (seq > FinalCheckptSeq) silently absorbs the duplicate
	// (ReplayWAL:630-632). AppendMutations (wal.go:362) has always done it this
	// way; this aligns the single-append path so the seq is a unique key.
	w.nextSeq++
	// THE LOCK-SCOPE SPLIT: capture the fd under the lock, release w.mu, then
	// fsync the captured fd. The record is written + seq-stamped under the lock, so
	// its durable order is fixed; the fsync only persists it. A slow fsync no longer
	// holds the WAL mutex against a concurrent append (the reverse convoy).
	f := w.f
	w.mu.Unlock()
	if err := w.syncFile(f); err != nil {
		return fmt.Errorf("chaos/wal: fsync mutation: %w", err)
	}
	return nil
}

// AppendMutations is the ADR-0044 WAL group-commit: it writes N
// mutation records under ONE w.mu.Lock then issues ONE fsync for the whole
// batch (w.sync()), collapsing the per-mutation fsync COUNT that is the
// binding constraint (silicon: ~2.1ms/fsync × 10000 = ~21s > 10s SLO; ONE
// fsync × 2.1ms = 2.1ms — 1000× the count cut). It is the /v1/batch-insert path's
// durability primitive; AppendMutation (above) stays byte-identical for /v1/insert.
//
// NO SECOND WAL: this is ADDITIVE on the SAME WAL — one source of truth, NOT
// a second WAL. Both granularities append the SAME record format via the SAME
// encodeMutationV2Record + the SAME 13-byte header (seq+type+payloadLen) +
// WALRecMutationV2 type byte. ReplayWAL scans record-by-record via length-prefix
// — it sees N individual WALRecMutationV2 records, populates
// Mutations[] IDENTICALLY to N calls to AppendMutation. The determinism contract
// (ADR-0045: replay RESTORES each mutation at its WAL-recorded dot via the
// exact-dot route — it NEVER re-mints) is UNCHANGED: the SAME Mutations slice,
// the SAME replay. TestWALRecoveryDeterminism (which calls AppendMutation
// per entry) STAYS GREEN byte-identical; the batch-path determinism
// regression test proves AppendMutations preserves the contract.
//
// ATOMICITY (disclosed in ADR-0044): a Write failure at index i OR the final
// Sync failure → the WHOLE batch is treated as un-durable (returns (i, err) or
// (-1, syncErr)). The caller (Bridge.PutLocals) ACKs ALL entries as 503 — it
// cannot assert durability of any subset, because entries [0, i) sit in the OS
// page cache (may or may not survive a crash) and [i, N) were never written. This
// is the standard WAL atomic-batch model (a transaction commits all-or-none on the
// durable log). It is NOT silent data loss: the HTTP response has not been sent
// until PutLocals returns; a crash before that loses the un-ACKed entries, the
// client retries the WHOLE batch. /v1/insert keeps per-entry 503 byte-identical.
//
// nextSeq advances ONCE per successfully-WRITTEN record (advance as you write,
// NOT in a separate loop — same discipline as AppendMutation, so a Write failure
// stops advancing at the torn record; the next append stamps the next seq).
// ADR-0045 — THE LOCK IS RELEASED BEFORE THE FSYNC.
//
// The write loop runs under w.mu (page-cache writes: fast, microseconds); the
// fsync runs with w.mu RELEASED (a real disk barrier: on the 10K-key inject the
// measured cost is tens of seconds). Holding w.mu across the fsync serialized the
// ENTIRE WAL behind one batch's disk barrier — and AppendClockAdvance takes the
// SAME mutex (wal.go:323). On the 100-node silicon gate the seed's 10K-key inject
// therefore blocked the seed's OWN receive path: every inbound foreign delta needs
// AppendClockAdvance (the foreign-advance durability seed), so the receive
// path stalled for the whole inject window, cache.record populated late, and
// round-1 relay lookups missed — the "payload miss" storm.
//
// WHY THIS IS SAFE (three invariants, each load-bearing):
//
// 1. ORDERING is preserved. Record bytes reach the file via w.f.Write UNDER the
// lock, and w.nextSeq is bumped in the same critical section, so the byte
// order and the seq stamping are exactly as before. fsync is a DURABILITY
// barrier, not an ordering primitive: it cannot reorder bytes already written.
// The recovery contract (ADR-0045 — replay RESTORES the recorded dot,
// never re-mints; BOTH older seed formulas are refuted) reads records in
// seq order and is untouched; TestWALRecoveryDeterminism stays GREEN
// unchanged.
//
// 2. ATOMICITY of the ERROR contract is preserved byte-for-byte. A torn write
// still returns the failing index i (caller ACKs the whole batch 503); a sync
// failure still returns (-1, err). Same values, same call sites.
//
// 3. The CONCURRENT-fsync case is correct. Two batches may now fsync at once.
// fsync(2) on a shared fd flushes ALL dirty pages of the file, so a
// concurrent fsync can only flush MORE than its own records — never fewer.
// The guarantee "when AppendMutations returns nil, my records are durable"
// holds: our writes completed under the lock, strictly before our fsync began.
//
// The ONE behavioral delta: during the unlocked window the WAL tail sits in the
// page cache, not on the platter. That is the SAME un-durable posture a Sync
// failure already accepts (and which the caller already handles by 503-ing the
// batch) — the durability floor for a RETURNED-nil append is unchanged.
func (w *WAL) AppendMutations(ms []WALMutation) (firstFailIdx int, err error) {
	w.mu.Lock()
	// NOTE: NO `defer w.mu.Unlock()`. The unlock is explicit on every path,
	// because the success path MUST unlock BEFORE w.sync() (the whole point of
	// the split) while the two error paths must unlock and return immediately. A defer
	// here would either re-hold the lock across the fsync (the bug) or double-
	// unlock (a panic). Every `return` below is preceded by exactly one Unlock.
	for i, m := range ms {
		if e := validateV2(m); e != nil {
			// A caller-bug mutation (missing/inconsistent full entry) is the
			// same class as an encode error: the batch is un-durable as a unit.
			w.mu.Unlock()
			return i, fmt.Errorf("chaos/wal: validate mutation %d: %w", i, e)
		}
		// Emit the 0x06 CRC32C-framed form by default — single
		// allocation per record, byte-identical inner payload (putMutationV2Payload).
		rec, e := encodeMutationV2Checksummed(w.nextSeq, m)
		if e != nil {
			// An encode error (an oversized EntityID) is a caller bug; the WAL
			// tail is torn at this record — entries [0, i) are in the page cache
			// but NOT fsync'd. Treat the WHOLE batch as un-durable (the same
			// atomicity as a Sync failure): the caller ACKs all as 503.
			w.mu.Unlock()
			return i, fmt.Errorf("chaos/wal: encode mutation %d: %w", i, e)
		}
		if _, e := w.f.Write(rec); e != nil {
			w.mu.Unlock()
			return i, fmt.Errorf("chaos/wal: write mutation %d: %w", i, e)
		}
		w.nextSeq++
	}
	// THE LOCK-SCOPE SPLIT: the records are written + seq-stamped; capture the fd UNDER the
	// lock (Close() nils w.f under w.mu — an unlocked w.f read would be a data race
	// and a nil-deref panic), then release the mutex so a concurrent
	// AppendClockAdvance (the receive path) proceeds while our fsync waits on the
	// disk.
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
	// NOTE: NO `defer w.mu.Unlock()` (the lock-scope split): the fsync
	// moves out of the critical section; each error path unlocks explicitly.
	// Emit the 0x06 CRC32C-framed checkpoint by default. The
	// checkpoint's ClockHigh + fingerprint fields are now content-protected, so a
	// corrupted 0x05 is caught by the CRC BEFORE the clamp / fingerprint arms.
	rec := encodeCheckpointChecksummed(w.nextSeq, c)
	if _, err := w.f.Write(rec); err != nil {
		w.mu.Unlock()
		return fmt.Errorf("chaos/wal: write checkpoint: %w", err)
	}
	// Advance-as-you-write (ADR-0045): see AppendMutation. The seq is a
	// unique key only if it is consumed at write time, not after the fsync.
	w.nextSeq++
	// THE LOCK-SCOPE SPLIT: capture the fd under the lock, release w.mu, then
	// fsync the captured fd. Ordering is fixed by the write + nextSeq++ under the
	// lock; the fsync only persists it.
	f := w.f
	w.mu.Unlock()
	if err := w.syncFile(f); err != nil {
		return fmt.Errorf("chaos/wal: fsync checkpoint: %w", err)
	}
	return nil
}

// AppendClockAdvance records a peer-driven Lamport clock advance (the
// foreign-advance seed fix). It is fsync-on-commit — the same
// durability floor as AppendMutation/AppendCheckpoint. A clock advance that
// survives in memory but not on disk would re-introduce the gap on crash.
func (w *WAL) AppendClockAdvance(advancedTo uint64) error {
	w.mu.Lock()
	// NOTE: NO `defer w.mu.Unlock()` (the lock-scope split). This is the
	// RECEIVE path: previously it held w.mu ACROSS its fsync, so
	// one slow receive-path fsync serialized the origin's AppendMutations group-commit
	// behind the disk barrier (the reverse convoy). The
	// fsync now runs OUTSIDE the lock; each error path unlocks explicitly.
	// Emit the 0x06 CRC32C-framed clock-advance by default — a
	// corrupted advance counter is now caught at decode, not folded into the
	// Lamport high-water as valid state.
	rec := encodeClockAdvanceChecksummed(w.nextSeq, advancedTo)
	if _, err := w.f.Write(rec); err != nil {
		w.mu.Unlock()
		return fmt.Errorf("chaos/wal: write clock-advance: %w", err)
	}
	// Advance-as-you-write (ADR-0045): see AppendMutation.
	w.nextSeq++
	// THE LOCK-SCOPE SPLIT: capture the fd under the lock, release w.mu, then
	// fsync the captured fd. Ordering is fixed by the write + nextSeq++ under the
	// lock; the fsync only persists it.
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

// encodeMutationV2Record is the 0x04 (ADR-0045) form: identical framing to
// the legacy record, but the entry is the FULL 120-byte CRDTEntry written by
// the one shared codec (codec.go:encodeCRDTEntry — byte-identical to the
// snapshot image's layout, so a WAL tail entry and an image entry at the same
// dot are byte-equal). The top-level NodeID/Counter stay: the dot is the
// record's identity independent of the entry bytes.
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

// AppendMutationV1ForTest writes a LEGACY 0x01 record (the 80-byte format from
// before the V2 record format). TEST-ONLY (the SetSyncHookForTest precedent): production NEVER
// writes 0x01 after ADR-0045 — this seam exists so a test can build a real
// mixed-format log (an old binary's records next to a new binary's) and prove
// the replay reads both, marks the legacy ones, and never misinterprets them.
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
	w.nextSeq++ // advance-as-you-write (ADR-0045), byte-identical to the V2 path
	if err := w.sync(); err != nil {
		return fmt.Errorf("chaos/wal: fsync legacy mutation: %w", err)
	}
	return nil
}

// AppendMutationV2ForTest writes a BARE 0x04 record (the full-fidelity 120-byte
// mutation) with NO 0x06 CRC frame. TEST-ONLY (the AppendMutationV1ForTest
// precedent): now that the production AppendMutation path wraps every
// record in 0x06, so this seam exists to build a MIXED-FORMAT log (legacy
// 0x01/0x04/0x05 beside 0x06) proving the decoder reads BOTH, and to give the
// corrupt-and-detect guards a known-good UNFRAMED record to contrast against the
// framed one. It is byte-identical to the unframed production record.
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
	w.nextSeq++ // advance-as-you-write (ADR-0045), byte-identical to the wrapped path
	if err := w.sync(); err != nil {
		return fmt.Errorf("chaos/wal: fsync v2 mutation (test): %w", err)
	}
	return nil
}

// AppendCheckpointRawForTest writes a 0x05 checkpoint record whose payload is
// the EXACT byte slice given. This is the ONLY way to emit the legacy 48-byte
// form (root‖LamportHigh‖CutSeq — no ClockHigh, no Fingerprint) or a truncated
// <48-byte form: encodeCheckpointRecord only ever writes 56 bytes (snapshotter-
// less) or 88 (fingerprint-bearing). TEST-ONLY (the AppendMutationV1ForTest
// precedent): a regression test uses it to prove the 0x05 length-
// discriminating decoder boots a legacy 48-byte record with the fingerprint
// check DISARMED and HARD-REJECTS a truncated <48-byte record.
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
	w.nextSeq++ // advance-as-you-write (ADR-0045), byte-identical to AppendMutationV1ForTest
	if err := w.sync(); err != nil {
		return fmt.Errorf("chaos/wal: fsync raw checkpoint: %w", err)
	}
	return nil
}

func encodeCheckpointRecord(seq uint64, c WALCheckpoint) []byte {
	if c.HasCutSeq {
		// 0x05: root || watermark || pre-walk CutSeq horizon || ClockHigh
		// (the live clock at checkpoint time; closes the un-recorded
		// clock-raise hole) || StateFingerprint (the payload-folding
		// check, present only when an image was captured). 56 bytes
		// without a fingerprint, 88 with.
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

// frameChecksummed builds a WALRecChecksummed (0x06) record in a
// SINGLE allocation:
//
//	seq(8) ‖ 0x06(1) ‖ payloadLen(4) ‖ [ innerType(1) ‖ innerPayload(innerLen) ‖ crc32c(4) ]
//
// writeInner writes the inner payload at dst (rec[14:14+innerLen]); the payload
// layouts live in the shared put*Payload helpers below — used by BOTH the bare
// encoders (the test-only 0x04/0x05 forms) AND these framed (production 0x06)
// encoders — so the 0x04/0x05/0x03 byte layout, and its encodeCRDTEntry identity
// with the snapshot image, can never drift between the two forms. The CRC32C
// covers innerType‖innerPayload (contiguous at rec[13:14+innerLen]), NOT the
// outer seq/payloadLen framing (already guarded by seq-contiguity + the length
// bound). ONE allocation + a 0-alloc CRC (package-level castagnoliTable, no
// crc32.New): the checksummed append allocates EXACTLY what the bare append did
// (measured) — the "zero new allocations on the append path" invariant.
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

// putMutationV2Payload writes the 0x04 inner payload (entityIdLen‖entityId‖
// NodeID‖Counter‖entry) at dst[0:]. It is the SINGLE source of that layout,
// shared by encodeMutationV2Record (bare 0x04, test-only) and
// encodeMutationV2Checksummed (the production 0x06 form) so they can never drift.
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

// unwrapChecksummed verifies and unwraps a WALRecChecksummed
// (0x06) record's payload (innerType(1)‖innerPayload‖crc32c(4)). On a CRC
// mismatch — a COMPLETE record whose content was corrupted — it returns
// ErrWALCorrupt (fail LOUD). On a match it returns the inner type + inner
// payload so ReplayWAL dispatches to the SAME decode arms a legacy record uses
// (the CRC is metadata: it changes WHAT is rejected, never WHAT is replayed).
// A torn tail never reaches here (the short-payload read breaks first), so a
// short frame here is content corruption, not a crash boundary.
func unwrapChecksummed(payload []byte, seq uint64) (WALRecordType, []byte, error) {
	if len(payload) < 5 { // innerType(1) + crc32c(4) minimum
		return 0, nil, fmt.Errorf("%w: record seq %d checksummed frame too short (%d bytes)", ErrWALCorrupt, seq, len(payload))
	}
	body := payload[:len(payload)-4] // innerType ‖ innerPayload
	want := binary.BigEndian.Uint32(payload[len(payload)-4:])
	got := crc32.Checksum(body, castagnoliTable)
	// The compare is the load-bearing defense; walCRC32Skip (TEST-ONLY) compiles
	// it out so the corrupt-and-detect guards prove it is not decorative.
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

// scanRecords walks the record region (from byte 8, just after the fixed
// header) to EOF and returns the next sequence number to assign (one past the
// highest seen), the count of complete records read, and lastGood — the file
// offset of the first byte AFTER the last complete record (8 for an empty log).
// A torn final record stops the walk with lastGood at that record's first byte,
// so OpenWAL can truncate the tail there. Used by OpenWAL to keep nextSeq
// monotonic across reopen AND to snap a torn tail to a clean boundary
// (ADR-0045).
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

// WALRecord is a single record in the append-ordered replay stream. Exactly one
// of Mutation or Advance is populated; the Type field discriminates.
//
// Seq (ADR-0045) is the record's on-disk sequence number, decoded from the
// 8-byte header prefix every record already carries (wal.go:446/465/478). It is
// the ONLY totally-ordered identity the log has: scalar Lamport counters are a
// partial order across origins and cannot express "which records the checkpoint
// absorbed". The recovery tail cut is `Seq > FinalCheckptSeq` — a record-sequence
// cut, never a scalar-counter cut.
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
	// FinalCheckptSeq (ADR-0045) is the on-disk sequence number of the FINAL
	// checkpoint record — the seq of the WALRecCheckpoint that populated
	// FinalCheckpt. It is the recovery tail cut: records with Seq >
	// FinalCheckptSeq are the post-checkpoint tail. Zero when HasCheckpoint is
	// false. Because every record's seq is unique (advance-as-you-write, ADR-0045),
	// this cut is unambiguous even on a log that survived an fsync failure.
	FinalCheckptSeq uint64
	// LegacyCheckpoint (ADR-0045) is
	// TRUE iff the FINAL checkpoint record carries no fingerprint (a legacy
	// 0x02 record, a legacy 48-byte 0x05, or the 56-byte snapshotter-less
	// form). It is RE-ASSIGNED at every checkpoint record, so it tracks the
	// FINAL record's own form — previously it was a sticky OR set by ANY
	// fingerprint-less record (the witness claimed "final" and reported
	// "any"). For such an anchor the fingerprint half of the recovery
	// integrity check has nothing to compare against and is DISARMED — the
	// recovery witness surfaces this so the disarm is never silent.
	LegacyCheckpoint bool
	// SeqContiguityVerified is TRUE iff every
	// record's seq was checked against the unbroken-ascending-run law (the
	// record LOSS check that replaces the replay-only root assertion).
	// RecordsVerified is the number of records the run covered.
	SeqContiguityVerified bool
	RecordsVerified       int
	// ClockHighClamped is TRUE iff some 0x05
	// record carried a ClockHigh above maxCredibleClockHigh and was floored to
	// the log's durable high-water. ClockHighRaw is the largest raw value
	// clamped. FALSE/0 mean every ClockHigh decoded clean.
	ClockHighClamped bool
	ClockHighRaw     uint64
}

// ReplayWAL opens path fresh and returns every record in order. It is the
// single recovery entrypoint: hand the result to a fresh engine, replay the
// Mutations via InsertLocal-equivalent, and assert Merkle equality against
// FinalCheckpt (the determinism anchor). A torn tail record is silently
// truncated (the standard tail-tear handling); a mid-log corruption is reported
// as an error so recovery never rebuilds on a suspect log.
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
		// Bound the corruption-controlled length BEFORE allocating. A torn
		// tail is handled below by the short-read break; an over-large length on a
		// COMPLETE header is mid-log corruption and must be a loud error, never a
		// multi-GiB make() nor a silent skip.
		if payloadLen > maxRecordPayloadLen {
			return nil, fmt.Errorf("chaos/wal: record payload length %d exceeds max %d at seq %d (corrupt record)", payloadLen, maxRecordPayloadLen, seq)
		}
		// SEQ CONTIGUITY, the record-LOSS check. The
		// seqs must form an unbroken ascending run from the first record's seq.
		// SOUND (no false-positive path): the seq is consumed only after the
		// record's bytes are in the file (advance-as-you-write — a failed
		// Write returns before nextSeq++, and a failed fsync never unconsumes),
		// and the only Truncate is OpenWAL's torn-tail repair, which cuts the
		// END, never the middle. So a gap or a reorder means a record is
		// genuinely gone — refuse to rebuild on a log with a hole. This is
		// strictly stronger than the dot-fold root assertion it replaces on the
		// replay-only path: it detects the loss of ANY record type (mutations,
		// 0x03 advances, 0x05 checkpoints), not only a dot-set divergence. The
		// check sits AFTER the length guard so a length-corrupt record is
		// reported as the length corruption it is, and BEFORE the payload
		// read so a gapped record is reported without touching its bytes.
		// The CRC covers innerType‖innerPayload, NOT the outer
		// seq, and the contiguity check below skips the FIRST record. But a WAL
		// ALWAYS starts at seq 0 — writeHeader lays a fresh header and nextSeq is
		// zero-valued, and the only Truncate is OpenWAL's torn-TAIL repair (never
		// the front) — so a first record with a non-zero seq is a corrupted header
		// that neither the CRC nor the contiguity check would otherwise catch.
		if out.RecordsVerified == 0 && seq != 0 {
			return nil, fmt.Errorf("%w: first record seq is %d, want 0 (a WAL always starts at seq 0; a non-zero first seq is header corruption)", ErrWALSeqGap, seq)
		}
		if out.RecordsVerified > 0 && seq != prevSeq+1 {
			return nil, fmt.Errorf("%w: expected seq %d, observed %d (record #%d)", ErrWALSeqGap, prevSeq+1, seq, out.RecordsVerified)
		}
		payload := make([]byte, payloadLen)
		if _, err := io.ReadFull(f, payload); err != nil {
			if err == io.ErrUnexpectedEOF || err == io.EOF {
				// torn payload — truncate, stop. Do NOT include this record.
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
		// A 0x06 record is a CRC32C-framed wrapper. Verify the CRC
		// over innerType‖innerPayload BEFORE decoding; a mismatch is content
		// corruption → ErrWALCorrupt (fail LOUD, the WAL has no fallback). A torn
		// tail never reaches here (the short-payload read above already broke out),
		// so any 0x06 failure is corruption, NOT a crash boundary. On a match we
		// dispatch on the INNER type so every arm below runs verbatim and the
		// Replayed content (Mutations/Ordered/LamportHigh/…) is IDENTICAL to the
		// unframed form — the CRC is metadata, never a change to WHAT is replayed.
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
			// Fold the advance into
			// the high-water EXACTLY as the mutation and checkpoint cases do. The
			// recovery clock nail reads ONLY rep.LamportHigh (the constructor
			// seed + the final AdvanceLamportTo), so a 0x03 record that does not
			// fold is a clock the recovery never learns — the
			// under-shoot. A durable advance is the node's own promise that it
			// has observed logical time advancedTo; the folded high-water must
			// honor it. Monotone max, like the sibling folds.
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
			out.FinalCheckptSeq = seq // the legacy recovery tail cut is Seq > FinalCheckptSeq
			// Track the FINAL record's own form. A 0x02 record
			// carries no fingerprint field at all, so as the FINAL checkpoint it
			// leaves the fingerprint check with nothing to compare — legacy.
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
			// ClockHigh sits at [48:56] when the record carries it (the
			// 56-byte form). A legacy 48-byte 0x05 leaves it zero;
			// the recovery nail max(rep.LamportHigh, ClockHigh) then reduces to
			// rep.LamportHigh — the earlier behavior for that record, and
			// safe because every earlier 0x05 ever written lived on torn-down
			// test instances (ADR-0045).
			if len(payload) >= 56 {
				c.ClockHigh = binary.BigEndian.Uint64(payload[48:56])
				// CLAMP — decode is the sole authority on
				// this field; the record carries no checksum, so a corrupt
				// ClockHigh would otherwise seed the engine constructor verbatim
				// (recovery.go: rebuiltInitial) and NextDot's Add(1) would WRAP —
				// after a wrap every local dot re-issues a used counter and merge
				// keeps the existing entry on an equal dot, so every
				// post-recovery write is silently dropped on every peer while the
				// armed check certifies the boot (root and fingerprint fold
				// state, not the clock). FLOOR the incredible value to the log's
				// own durable high-water — the earlier seed semantics, safe
				// because a ClockHigh above every recorded value only ever covers
				// a raise that produced no mutation — and mark it LOUD
				// (witness fields + a recovery log line; never silent).
				// Do NOT remove the field: it is load-bearing
				// (receiver.go:529 raises the clock pre-verify with no 0x03).
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
			// The state fingerprint sits at [56:88] when
			// present. A fingerprint-less 0x05 (a legacy 48-byte record, or the
			// 56-byte snapshotter-less form) leaves HasFingerprint false — the
			// fingerprint half of the recovery integrity check DISARMS for that
			// anchor — and the replay MARKS it so the recovery witness discloses
			// that the fingerprint check never had a value to compare (the same
			// loud-disarm shape as the holesRepaired witness).
			if len(payload) >= 88 {
				copy(c.Fingerprint[:], payload[56:88])
				c.HasFingerprint = true
			}
			// Assign, don't OR — LegacyCheckpoint tracks the
			// FINAL checkpoint record's own form (each 0x05 overwrites
			// FinalCheckpt; the flag must follow it). Previously this was a
			// sticky `= true` in an else branch: ANY fingerprint-less record
			// pinned it for the whole replay while the docs promised "iff the
			// FINAL checkpoint".
			out.LegacyCheckpoint = !c.HasFingerprint
			out.FinalCheckpt = c
			out.HasCheckpoint = true
			out.FinalCheckptSeq = seq // the record's own seq; the tail cut is c.CutSeq (ADR-0045)
			if c.LamportHigh > out.LamportHigh {
				out.LamportHigh = c.LamportHigh
			}
		default:
			// Unknown record type. Per the no-silent-misinterpretation rule
			// this is an error rather than a skip.
			return nil, fmt.Errorf("chaos/wal: unknown record type 0x%x at seq %d", recType, seq)
		}
	}
	// Reaching here means the loop read every record to EOF (or a torn tail)
	// without a sequence violation — the contiguity check actually RAN. An
	// empty log verifies vacuously at RecordsVerified == 0 (honest: there was
	// nothing to lose).
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
	// Legacy marker: the 0x01 record persisted FIVE fields; the other five
	// are UNKNOWN, not "zero". Full is synthesized from the persisted five so
	// consumers never read a half-populated entry unawares, and Legacy=true is
	// the explicit marker the recovery witness counts ("N records replayed from
	// the legacy 80-byte format; tri-temporal and H3 fields are UNKNOWN").
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
// the FULL 120-byte CRDTEntry (all ten fields, byte-identical to the snapshot
// image's layout). The legacy Entry subset is derived so readers written
// before the V2 record format keep
// working. The dot is cross-checked against the entry at restore time
// (recovery's checkMutationRecord), not here — replay is byte-faithful.
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

// (The dead exported TruncateTail was deleted — it
// had ZERO callers and was cited as load-bearing while the real torn-tail
// truncation lives inline in OpenWAL's scanRecords→f.Truncate path above. Dead
// code cited as load-bearing is worse than absent code.)
