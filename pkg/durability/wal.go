// Package durability is the production write-ahead-log + recovery surface.
//
// Day 8 wires the PROVEN WAL substrate (internal/chaos/wal.go) into the
// production origin path. The determinism property — replay a WAL into a
// fresh engine and the rebuilt Merkle root equals the checkpoint root — is
// PROVEN by internal/chaos.TestStage6WALRecoveryDeterminism against
// internal/chaos/wal.go. This package does NOT fork that file: it re-exports
// the exact types and funcs so the bytes-under-test stay one source of truth.
// Forking would decouple production durability from the safety net and risk
// silent divergence (the §8 MEDIOCRITY attack).
//
// The re-export is a thin alias layer: every type/func below maps 1:1 to an
// internal/chaos symbol. Nothing is reinvented; the production surface is the
// proven surface.
package durability

import "github.com/hr18vk/supremum/internal/chaos"

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

// WALRecord is a single record in the append-ordered replay stream (Day 8.5 —
// the ordered mutation|advance stream the recovery replay walks). Re-exported.
type WALRecord = chaos.WALRecord

// The three WAL record types. WALRecMutation + WALRecCheckpoint are the Day-8
// pair; WALRecClockAdvance (0x03) is the Day-8.5 foreign-advance record (the
// clock jump a peer-driven Join performs, fsync-on-commit). Re-exported so
// recovery.go can switch on them without importing internal/chaos directly.
const (
	WALRecMutation     = chaos.WALRecMutation
	WALRecCheckpoint   = chaos.WALRecCheckpoint
	WALRecClockAdvance = chaos.WALRecClockAdvance
)

// Replayed is the result of a full WAL replay: the records seen, the final
// checkpoint (if any), and the highest Lamport counter observed.
type Replayed = chaos.Replayed

// OpenWAL opens (or creates) the engine WAL at path. Re-exported.
func OpenWAL(path string) (*WAL, error) { return chaos.OpenWAL(path) }

// ReplayWAL opens path fresh and returns every record in order. It is the
// single recovery entrypoint. A torn tail record is silently truncated; a
// mid-log corruption is reported as an error so recovery never rebuilds on a
// suspect log. Re-exported.
func ReplayWAL(path string) (*Replayed, error) { return chaos.ReplayWAL(path) }

// WALAsChaos returns the underlying *chaos.WAL behind a durability WAL handle.
// It is a TEST-ONLY accessor (ADR-0044, Day 39): the T-GROUP-COUNT + T-GROUP-ACK
// teeth need to install the fsync-count / fsync-fail spy via
// chaos.WAL.SetSyncHookForTest, and durability.WAL is a type ALIAS for chaos.WAL
// (wal.go:22, the `=`), so the SAME instance underlies both views. The accessor
// is a no-op cast (the alias is the same type); it exists so the test does not
// reach into the alias with a raw type assertion (a reader-friendly seam). It is
// NEVER called by production code — only the Day-39 test harness uses it to arm
// the spy on the WAL the Bridge holds.
func WALAsChaos(w *WAL) *chaos.WAL { return w }
