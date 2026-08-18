// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

// Package durability is the production write-ahead-log + recovery surface.
//
// wires the PROVEN WAL substrate (internal/chaos/wal.go) into the
// production origin path. The determinism property — replay a WAL into a
// fresh engine and the rebuilt Merkle root equals the checkpoint root — is
// PROVEN by internal/chaos.TestWALRecoveryDeterminism against
// internal/chaos/wal.go. This package does NOT fork that file: it re-exports
// the exact types and funcs so the bytes-under-test stay one source of truth.
// Forking would decouple production durability from the safety net and risk
// silent divergence (the §8 MEDIOCRITY attack).
//
// The re-export is a thin alias layer: every type/func below maps 1:1 to an
// internal/chaos symbol. Nothing is reinvented; the production surface is the
// proven surface.
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

// WALRecord is a single record in the append-ordered replay stream (—
// the ordered mutation|advance stream the recovery replay walks). Re-exported.
type WALRecord = chaos.WALRecord

// The three WAL record types. WALRecMutation + WALRecCheckpoint are the
// pair; WALRecClockAdvance (0x03) is the foreign-advance record (the
// clock jump a peer-driven Join performs, fsync-on-commit). Re-exported so
// recovery.go can switch on them without importing internal/chaos directly.
const (
	WALRecMutation     = chaos.WALRecMutation
	WALRecCheckpoint   = chaos.WALRecCheckpoint
	WALRecClockAdvance = chaos.WALRecClockAdvance
	// WALRecMutationV2 (ADR-0045) is the full-fidelity 120-byte mutation
	// record — the only form new appends write.
	WALRecMutationV2 = chaos.WALRecMutationV2
	// WALRecCheckpointV2 (ADR-0045) is the horizon-cut checkpoint
	// record (root || watermark || pre-walk CutSeq) — the only checkpoint
	// form Bridge.AppendCheckpoint writes.
	WALRecCheckpointV2 = chaos.WALRecCheckpointV2
	// WALRecChecksummed (0x06) is the CRC32C-framed
	// wrapper record — the only form new appends write. Its payload is
	// innerType(1) ‖ innerPayload ‖ crc32c(4); ReplayWAL verifies the CRC before
	// dispatching to the inner record's decode arm. Re-exported.
	WALRecChecksummed = chaos.WALRecChecksummed
)

// Replayed is the result of a full WAL replay: the records seen, the final
// checkpoint (if any), and the highest Lamport counter observed.
type Replayed = chaos.Replayed

// OpenWAL opens (or creates) the engine WAL at path. Re-exported.
func OpenWAL(path string) (*WAL, error) { return chaos.OpenWAL(path) }

// NewWALMutation is the ONE construction discipline for a WAL mutation
// (ADR-0045): the engine-STAMPED dot (InsertLocal's return) + the caller's
// entry become a full-fidelity 120-byte record with the legacy 80-byte subset
// derived, never independently built. Re-exported.
func NewWALMutation(entityID string, dot eng.CausalDot, entry eng.CRDTEntry) WALMutation {
	return chaos.NewWALMutation(entityID, dot, entry)
}

// ReplayWAL opens path fresh and returns every record in order. It is the
// single recovery entrypoint. A torn tail record is silently truncated; a
// mid-log corruption is reported as an error so recovery never rebuilds on a
// suspect log. Re-exported.
func ReplayWAL(path string) (*Replayed, error) { return chaos.ReplayWAL(path) }

// ErrWALSeqGap (Part B) is returned by ReplayWAL when the
// record seqs do not form an unbroken ascending run — a record is genuinely
// gone. Re-exported.
var ErrWALSeqGap = chaos.ErrWALSeqGap

// ErrWALCorrupt is returned by ReplayWAL when a 0x06
// record's CRC32C does not match its content — a COMPLETE record whose bytes
// were corrupted. The WAL is the authoritative truth with no fallback, so this
// propagates to a boot-refusal. Re-exported.
var ErrWALCorrupt = chaos.ErrWALCorrupt

// MaxCredibleClockHigh is the decode-time
// credibility ceiling for a 0x05 checkpoint's ClockHigh field. Re-exported.
const MaxCredibleClockHigh = chaos.MaxCredibleClockHigh

// WALAsChaos returns the underlying *chaos.WAL behind a durability WAL handle.
// It is a TEST-ONLY accessor (ADR-0044): the group-commit count and ack
// guards need to install the fsync-count / fsync-fail spy via
// chaos.WAL.SetSyncHookForTest, and durability.WAL is a type ALIAS for chaos.WAL
// (wal.go:22, the `=`), so the SAME instance underlies both views. The accessor
// is a no-op cast (the alias is the same type); it exists so the test does not
// reach into the alias with a raw type assertion (a reader-friendly seam). It is
// NEVER called by production code — only the test harness uses it to arm
// the spy on the WAL the Bridge holds.
func WALAsChaos(w *WAL) *chaos.WAL { return w }
