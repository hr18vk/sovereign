// ---------------------------------------------------------------------------
// Engine-side Write-Ahead Log (Stage 6 §2 recovery substrate)
// ---------------------------------------------------------------------------
//
// Stage 6 §2: "The supervisor identifies the dead connection, recovers the
// persistent database state via the write-ahead log, and spins up a pristine
// worker engine. This entire recovery cycle must execute without ever dropping
// the active HTTP connections."
//
// This WAL is the engine's OWN durability layer, NOT PostgreSQL's WAL (which
// DR3 sunsets). It records every committed local mutation with enough state to
// deterministically rebuild an equivalent engine whose Merkle root matches the
// root recorded at WAL-append time.
//
// DETERMINISM CONTRACT (pre-mortem #2 — the seed-defense):
//   The HAMT's MerkleRoot() folds only the CRDT causal dots (DotNodeID +
//   DotCounter) under SHA-256 — it does NOT depend on the maphash.Seed, which
//   Go marks "cannot be serialized or recreated in a different process." So a
//   recovered worker started from a fresh maphash.MakeSeed() reproduces an
//   IDENTICAL Merkle root for the same mutation sequence, provided it replays
//   the same (localNodeID, lamport) assignments. The WAL persists those
//   assignments exactly. Recovery replays into a fresh DeltaCRDTEngine and the
//   rebuild's final MerkleRoot MUST equal the root the WAL recorded at the
//   last checkpoint — else recovery is treated as data loss (the cl protect-then-no-loss invariant).
//
// DURABILITY CONTRACT (pre-mortem #1 — ACK-before-durability):
//   Append is SYNCHRONOUS: it writes then fsyncs before returning. The worker
//   MUST NOT ack a mutation to a client before Append returns. This is the
//   "crash-consistency, not liveness" rule: surviving is not enough if the
//   acknowledged state diverges.
// ---------------------------------------------------------------------------

package chaos

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
)

// WALMagic / WALVersion tag the log file so a corrupt or foreign file fails
// cleanly rather than being silently misinterpreted on recovery.
const (
	walMagic   uint32 = 0x57414C00 // "WAL\0"
	walVersion uint16 = 1
)

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
	// foreign-advance seed fix, Day 8.5). The payload is the advanced-to
	// counter (8 bytes, BE). Recovery replays advances in append order
	// interleaved with mutations so the re-minted dots match the recorded
	// dots exactly — the clock jumps are replayed at the exact point they
	// happened live. Without this record, a foreign AdvanceLamportTo creates
	// an un-recorded counter gap; the seed under-counts; replay re-mints
	// different dots; Merkle diverges.
	WALRecClockAdvance WALRecordType = 0x03
)

// WALMutation is the serializable form of one committed local mutation. The
// CRDTEntry fields required for Merkle-root equality are persisted: DotNodeID,
// DotCounter, and the payload-digest fields the engine sets in InsertLocal.
type WALMutation struct {
	EntityID string
	NodeID   [16]byte
	Counter  uint64
	Entry    WALEntry
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
type WALCheckpoint struct {
	MerkleRoot  [32]byte
	LamportHigh uint64
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

	// syncHook is a TEST-ONLY fsync spy (ADR-0044, Day 39). It is nil in the
	// production WAL, in which case sync() calls the real w.f.Sync() —
	// byte-identical to the pre-Day-39 path. A test-local WAL wrapper sets a
	// hook that increments a counter on each fsync (T-GROUP-COUNT: 1 fsync per
	// AppendMutations batch vs 1000 per 1000 AppendMutation calls — the fsync-
	// COUNT physics Day 39 closes) OR rigs a failure (T-GROUP-ACK: a Sync that
	// errors on the Nth call → the batch-path 503-ALL honesty tooth). It is
	// NEVER shipped: OpenWAL leaves it nil; production code never sets it. The
	// indirection is the ONLY change to the single-fsync call sites — the
	// record encode/write/nextSeq++ bodies are byte-identical to HEAD.
	syncHook func() error
}

// SetSyncHookForTest installs a TEST-ONLY fsync spy on the WAL (ADR-0044, Day 39).
// It is the seam the T-GROUP-COUNT + T-GROUP-ACK teeth use to COUNT fsync calls
// (T-GROUP-COUNT: 1 fsync per AppendMutations batch vs 1000 per 1000 AppendMutation
// calls — the fsync-COUNT physics) and to RIG a Sync failure (T-GROUP-ACK: a hook
// that errors on the first fsync → the batch-path 503-ALL honesty tooth). It is
// NEVER called by production code: OpenWAL leaves syncHook nil (the production path
// → w.f.Sync(), byte-identical to HEAD); only a test-local harness sets the hook.
// The hook REPLACES the real fsync (it does NOT chain to w.f.Sync) — a counting
// hook returns nil (no real fsync, faster + deterministic); a rigging hook
// returns an error (the injected failure). Setting a nil hook clears it (back to
// the production path). NOT concurrency-safe with concurrent appends (the test
// harness sets the hook BEFORE the first append — the single-writer-before-reader
// discipline the SetBatchSize/SetStratifiedAntiEntropy mesh seams use).
func (w *WAL) SetSyncHookForTest(hook func() error) { w.syncHook = hook }

// sync is the single fsync call site. It is the ADR-0044 (Day 39) indirection:
// nil syncHook → w.f.Sync() (the production path, byte-identical to HEAD); a
// test-local hook → the test's count-or-fail behavior. Consolidating the three
// per-record fsync call sites through ONE method is what lets T-GROUP-COUNT
// observe the fsync count without instrumenting the production WAL.
func (w *WAL) sync() error {
	if w.syncHook != nil {
		return w.syncHook()
	}
	return w.f.Sync()
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
		// Position at EOF for appends, AFTER the verified header.
		if _, err := f.Seek(0, io.SeekEnd); err != nil {
			f.Close()
			return nil, err
		}
		// Count existing records so nextSeq stays monotonic across reopens.
		seq, _, err := scanRecords(f)
		if err != nil {
			f.Close()
			return nil, err
		}
		w.nextSeq = seq
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
	defer w.mu.Unlock()
	rec, err := encodeMutationRecord(w.nextSeq, m)
	if err != nil {
		return err
	}
	if _, err := w.f.Write(rec); err != nil {
		return fmt.Errorf("chaos/wal: write mutation: %w", err)
	}
	if err := w.sync(); err != nil {
		return fmt.Errorf("chaos/wal: fsync mutation: %w", err)
	}
	w.nextSeq++
	return nil
}

// AppendMutations is the ADR-0044 (Day 39) WAL group-commit: it writes N
// mutation records under ONE w.mu.Lock then issues ONE fsync for the whole
// batch (w.sync()), collapsing the per-mutation fsync COUNT that is the GATE-1
// binding constraint (Day 38 silicon: ~2.1ms/fsync × 10000 = ~21s > 10s SLO; ONE
// fsync × 2.1ms = 2.1ms — 1000× the count cut). It is the /v1/batch-insert path's
// durability primitive; AppendMutation (above) stays byte-identical for /v1/insert.
//
// §8 ABSENCE-OF-FORK: this is ADDITIVE on the SAME WAL — one source of truth, NOT
// a second WAL. Both granularities append the SAME record format via the SAME
// encodeMutationRecord + the SAME 13-byte header (seq+type+payloadLen) +
// WALRecMutation type byte. ReplayWAL scans record-by-record via length-prefix
// (wal.go:432) — it sees N individual WALRecMutation records, populates
// Mutations[] IDENTICALLY to N calls to AppendMutation. The determinism contract
// (replay rebuiltInitial = LamportHigh - len(Mutations)) is UNCHANGED: the SAME
// Mutations slice, the SAME replay. TestStage6WALRecoveryDeterminism (which calls
// AppendMutation per entry) STAYS GREEN byte-identical; T-GROUP-DET (the batch-path
// determinism tooth) proves AppendMutations preserves the contract.
//
// ATOMICITY (disclosed in ADR-0044 §4): a Write failure at index i OR the final
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
func (w *WAL) AppendMutations(ms []WALMutation) (firstFailIdx int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for i, m := range ms {
		rec, e := encodeMutationRecord(w.nextSeq, m)
		if e != nil {
			// An encode error (an oversized EntityID) is a caller bug; the WAL
			// tail is torn at this record — entries [0, i) are in the page cache
			// but NOT fsync'd. Treat the WHOLE batch as un-durable (the same
			// atomicity as a Sync failure): the caller ACKs all as 503.
			return i, fmt.Errorf("chaos/wal: encode mutation %d: %w", i, e)
		}
		if _, e := w.f.Write(rec); e != nil {
			return i, fmt.Errorf("chaos/wal: write mutation %d: %w", i, e)
		}
		w.nextSeq++
	}
	if e := w.sync(); e != nil {
		return -1, fmt.Errorf("chaos/wal: fsync mutation batch: %w", e)
	}
	return -1, nil
}

// AppendCheckpoint records the current Merkle root + Lamport high-water mark.
// This is the determinism anchor: recovery asserts the replayed root equals
// the last checkpoint's root. Checkpoints are fsync'd for durability.
func (w *WAL) AppendCheckpoint(c WALCheckpoint) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	rec := encodeCheckpointRecord(w.nextSeq, c)
	if _, err := w.f.Write(rec); err != nil {
		return fmt.Errorf("chaos/wal: write checkpoint: %w", err)
	}
	if err := w.sync(); err != nil {
		return fmt.Errorf("chaos/wal: fsync checkpoint: %w", err)
	}
	w.nextSeq++
	return nil
}

// AppendClockAdvance records a peer-driven Lamport clock advance (the
// foreign-advance seed fix, Day 8.5). It is fsync-on-commit — the same
// durability floor as AppendMutation/AppendCheckpoint. A clock advance that
// survives in memory but not on disk would re-introduce the gap on crash.
func (w *WAL) AppendClockAdvance(advancedTo uint64) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	rec := encodeClockAdvanceRecord(w.nextSeq, advancedTo)
	if _, err := w.f.Write(rec); err != nil {
		return fmt.Errorf("chaos/wal: write clock-advance: %w", err)
	}
	if err := w.sync(); err != nil {
		return fmt.Errorf("chaos/wal: fsync clock-advance: %w", err)
	}
	w.nextSeq++
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

func encodeCheckpointRecord(seq uint64, c WALCheckpoint) []byte {
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
	binary.BigEndian.PutUint64(rec[13:21], advancedTo)
	return rec
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

// scanRecords walks the file from the current position to EOF and returns the
// next sequence number to assign (one past the highest seen), and the count of
// records read. Used by OpenWAL to keep nextSeq monotonic across reopen.
func scanRecords(f *os.File) (nextSeq uint64, count uint64, err error) {
	// Seek to right after the header.
	if _, err = f.Seek(8, io.SeekStart); err != nil {
		return 0, 0, err
	}
	hdr := make([]byte, 13)
	for {
		n, e := io.ReadFull(f, hdr)
		if e == io.EOF {
			return nextSeq, count, nil
		}
		if e == io.ErrUnexpectedEOF {
			// A torn final record (a crash left a partial record) — recovery
			// truncates it; we return the next sequence based on prior good
			// records. This is the standard WAL tail-tear handling.
			return nextSeq, count, nil
		}
		if e != nil {
			return 0, 0, e
		}
		if n != 13 {
			return 0, 0, errors.New("chaos/wal: short record header")
		}
		seq := binary.BigEndian.Uint64(hdr[0:8])
		// hdr[8] = type, ignored for scanning.
		payloadLen := binary.BigEndian.Uint32(hdr[9:13])
		if _, e := io.CopyN(io.Discard, f, int64(payloadLen)); e != nil {
			// Torn payload — same tail-tear handling.
			return nextSeq, count, nil
		}
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
type WALRecord struct {
	Type     WALRecordType
	Mutation WALMutation
	Advance  uint64
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
		payload := make([]byte, payloadLen)
		if _, err := io.ReadFull(f, payload); err != nil {
			if err == io.ErrUnexpectedEOF || err == io.EOF {
				// torn payload — truncate, stop. Do NOT include this record.
				break
			}
			return nil, fmt.Errorf("chaos/wal: replay payload: %w", err)
		}
		if seq >= out.NextSeq {
			out.NextSeq = seq + 1
		}
		switch recType {
		case WALRecMutation:
			m, err := decodeMutationPayload(payload)
			if err != nil {
				return nil, fmt.Errorf("chaos/wal: decode mutation at seq %d: %w", seq, err)
			}
			out.Mutations = append(out.Mutations, m)
			out.Ordered = append(out.Ordered, WALRecord{Type: WALRecMutation, Mutation: m})
			if m.Counter > out.LamportHigh {
				out.LamportHigh = m.Counter
			}
		case WALRecClockAdvance:
			if len(payload) < 8 {
				return nil, fmt.Errorf("chaos/wal: short clock-advance at seq %d", seq)
			}
			advancedTo := binary.BigEndian.Uint64(payload[0:8])
			out.Advances = append(out.Advances, advancedTo)
			out.Ordered = append(out.Ordered, WALRecord{Type: WALRecClockAdvance, Advance: advancedTo})
		case WALRecCheckpoint:
			if len(payload) < 40 {
				return nil, fmt.Errorf("chaos/wal: short checkpoint at seq %d", seq)
			}
			var c WALCheckpoint
			copy(c.MerkleRoot[:], payload[0:32])
			c.LamportHigh = binary.BigEndian.Uint64(payload[32:40])
			out.FinalCheckpt = c
			out.HasCheckpoint = true
			if c.LamportHigh > out.LamportHigh {
				out.LamportHigh = c.LamportHigh
			}
		default:
			// Unknown record type. Per the no-silent-misinterpretation rule
			// this is an error rather than a skip.
			return nil, fmt.Errorf("chaos/wal: unknown record type 0x%x at seq %d", recType, seq)
		}
	}
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
	return m, nil
}

// TruncateTail snaps the WAL back to `keep` bytes of record data (after the
// 8-byte header), dropping any torn final record. Called by recovery after a
// crash where scanRecords detected a partial trailing record.
func TruncateTail(path string, keep int) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Truncate(int64(8 + keep)); err != nil {
		return err
	}
	return f.Sync()
}
