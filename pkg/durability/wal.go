// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// Package durability provides the engine's write-ahead log and recovery path.
//
// The WAL types and functions alias their internal/chaos implementations. Both
// production recovery and the recovery tests therefore use the same binary
// codecs, append ordering, and fsync behaviour rather than separate copies.
package durability

import (
	"github.com/hr18vk/sovereign/internal/chaos"
	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// WAL is the append-only, fsync-on-commit engine write-ahead log. Re-exported
// from internal/chaos so production code depends on pkg/durability, not the
// chaos test harness package.
type WAL = chaos.WAL

// WALMutation is the serializable form of one committed local mutation.
type WALMutation = chaos.WALMutation

// WALEntry is the identity-bearing subset of CRDTEntry that participates in the
// Merkle root and must survive replay.
type WALEntry = chaos.WALEntry

// WALCheckpoint pairs a Merkle root with the Lamport high-water mark at the
// point the checkpoint was recorded — the determinism anchor.
type WALCheckpoint = chaos.WALCheckpoint

// WALRecordType identifies the kind of each appended record. Re-exported.
type WALRecordType = chaos.WALRecordType

// WALRecord is a single record in the append-ordered replay stream — the
// ordered mutation|advance stream the recovery replay walks. Re-exported.
type WALRecord = chaos.WALRecord

// WAL record types distinguish mutations, checkpoints, clock advances, and
// their full-fidelity or checksummed representations.
const (
	WALRecMutation     = chaos.WALRecMutation
	WALRecCheckpoint   = chaos.WALRecCheckpoint
	WALRecClockAdvance = chaos.WALRecClockAdvance
	// WALRecMutationV2 (ADR-0045 §4) is the full-fidelity 120-byte mutation
	// record — the only form new appends write.
	WALRecMutationV2 = chaos.WALRecMutationV2
	// WALRecCheckpointV2 (ADR-0045 §4) binds the root and watermark to the
	// pre-walk CutSeq used to select the replay tail. It is the checkpoint form
	// written by Bridge.AppendCheckpoint.
	WALRecCheckpointV2 = chaos.WALRecCheckpointV2
	// WALRecChecksummed (0x06, ADR-0053) wraps innerType, innerPayload, and a
	// CRC32C. ReplayWAL verifies the checksum before decoding the inner record.
	WALRecChecksummed = chaos.WALRecChecksummed
)

// Replayed is the result of a full WAL replay: the records seen, the final
// checkpoint (if any), and the highest Lamport counter observed.
type Replayed = chaos.Replayed

// OpenWAL opens (or creates) the engine WAL at path. Re-exported.
func OpenWAL(path string) (*WAL, error) { return chaos.OpenWAL(path) }

// NewWALMutation constructs a full 120-byte record from InsertLocal's dot and
// the caller's entry. It derives the legacy 80-byte subset from the same values
// rather than accepting an independently constructed copy (ADR-0045 §4).
func NewWALMutation(entityID string, dot eng.CausalDot, entry eng.CRDTEntry) WALMutation {
	return chaos.NewWALMutation(entityID, dot, entry)
}

// ReplayWAL opens path fresh and returns every record in order. It is the
// single recovery entrypoint. A torn tail record is silently truncated; a
// mid-log corruption is reported as an error so recovery never rebuilds on a
// suspect log. Re-exported.
func ReplayWAL(path string) (*Replayed, error) { return chaos.ReplayWAL(path) }

// ErrWALSeqGap reports a break in the WAL's ascending record sequence.
var ErrWALSeqGap = chaos.ErrWALSeqGap

// ErrWALCorrupt reports a complete 0x06 record whose contents do not match its
// CRC32C. Because the WAL is the authoritative recovery source, this error
// propagates to a boot refusal (ADR-0053).
var ErrWALCorrupt = chaos.ErrWALCorrupt

// MaxCredibleClockHigh is the credibility ceiling applied to a 0x05
// checkpoint's ClockHigh during WAL decoding (ADR-0053).
const MaxCredibleClockHigh = chaos.MaxCredibleClockHigh

// WALAsChaos exposes the aliased *chaos.WAL to tests that install sync hooks
// with SetSyncHookForTest (ADR-0044). It returns the same handle; production
// code does not call it.
func WALAsChaos(w *WAL) *chaos.WAL { return w }
