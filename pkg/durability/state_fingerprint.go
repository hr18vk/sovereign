// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package durability

// State fingerprints complement Merkle roots during recovery (ADR-0045 §5.1).
// A Merkle root contains only (DotNodeID, DotCounter) pairs, so it cannot detect
// equal dots carrying different entity IDs, payload digests, or temporal and H3
// fields. StateFingerprint includes the entity ID and all ten CRDTEntry fields
// in a canonical, order-independent fold.
//
// AppendCheckpoint computes the fingerprint over captured image records and
// stores it in the 0x05 checkpoint. Before replaying the tail, recovery computes
// it again over the joined image. Both sides use fingerprintEntryInto and
// foldEntryDigests so their preimages cannot drift apart.
//
// The reader walks shards through CaptureShardsPinned rather than State, which
// would duplicate every live entry into fresh arena nodes. On 20,000 records,
// the State-based walk added 33,323,280 bytes of arena while the shard walk
// added none. The writer reuses records from its existing pinned walk. Both
// paths allocate per-entry digests on the Go heap and run off the hot path.

import (
	"bytes"
	"crypto/sha256"
	"sort"

	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// fingerprintDomainSep separates this fingerprint from other uses of SHA-256.
// Its bytes are part of the persisted checkpoint format.
const fingerprintDomainSep = "SOVEREIGN-STATE-FINGERPRINT-v1\x00"

// fingerprintEntryInto hashes the domain separator, entity ID, a NUL, and the
// entry's canonical 120-byte encoding from encodeCRDTEntry. The caller owns and
// reuses the hasher and encoding buffer. Avoiding a new SHA-256 state per entry
// matters because checkpointing holds its EBR pin throughout the fold, delaying
// arena reclamation for that duration.
func fingerprintEntryInto(h hashWriter, buf *[crdtEntryWireSize]byte, entityID string, entry eng.CRDTEntry, out []byte) []byte {
	h.Reset()
	h.Write([]byte(fingerprintDomainSep))
	h.Write([]byte(entityID))
	h.Write([]byte{0})
	encodeCRDTEntry(entry, buf[:])
	h.Write(buf[:])
	return h.Sum(out)
}

// hashWriter is the subset of hash.Hash used by fingerprintEntryInto.
type hashWriter interface {
	Reset()
	Write(p []byte) (n int, err error)
	Sum(b []byte) []byte
}

// foldEntryDigests sorts the per-entry digests and hashes their concatenation.
// The result is a multiset hash: it depends on the entries, not their walk
// order.
func foldEntryDigests(perEntry [][]byte) [32]byte {
	sort.Slice(perEntry, func(a, b int) bool { return bytes.Compare(perEntry[a], perEntry[b]) < 0 })
	root := sha256.New()
	for _, d := range perEntry {
		root.Write(d)
	}
	var out [32]byte
	copy(out[:], root.Sum(nil))
	return out
}

// fingerprintRecords folds records captured by AppendCheckpoint's pinned walk.
// It avoids a second shard walk and arena allocation, while reusing the hasher
// and encode buffer to limit the time the checkpoint's EBR pin is held.
func fingerprintRecords(records []SnapshotRecord) [32]byte {
	h := sha256.New()
	var buf [crdtEntryWireSize]byte
	perEntry := make([][]byte, 0, len(records))
	for i := range records {
		perEntry = append(perEntry, fingerprintEntryInto(h, &buf, records[i].EntityID, records[i].Entry, nil))
	}
	return foldEntryDigests(perEntry)
}

// StateEntryCount returns the number of (entityID, entry) pairs held by the
// engine. It uses the same EBR-pinned shard walk as StateFingerprint and is
// intended for periodic telemetry rather than the hot path (ADR-0071). The pin
// delays arena reclamation until the count is complete.
func StateEntryCount(e *eng.DeltaCRDTEngine) int {
	n := 0
	ebr := e.EBR()
	participant := ebr.Acquire()
	participant.Enter(ebr)
	defer ebr.Release(participant)
	e.CaptureShardsPinned(func(entityID string, entries []eng.CRDTEntry) bool {
		n += len(entries)
		return true
	})
	return n
}

// StateFingerprint returns the SHA-256 fingerprint of every (entityID, entry)
// pair in the engine. It holds an EBR pin for the CaptureShardsPinned walk and
// uses the same canonical fold as the checkpoint writer, so the two fingerprints
// can be compared byte for byte. The walk does not grow the HAMT arena.
func StateFingerprint(e *eng.DeltaCRDTEngine) [32]byte {
	h := sha256.New()
	var buf [crdtEntryWireSize]byte
	var perEntry [][]byte
	// CaptureShardsPinned requires the caller to hold the pin for the whole
	// walk. Its entity IDs and entry slices are arena-backed views, which a
	// concurrent CAS could otherwise retire and free during the walk.
	ebr := e.EBR()
	participant := ebr.Acquire()
	participant.Enter(ebr)
	defer ebr.Release(participant)
	e.CaptureShardsPinned(func(entityID string, entries []eng.CRDTEntry) bool {
		for i := range entries {
			perEntry = append(perEntry, fingerprintEntryInto(h, &buf, entityID, entries[i], nil))
		}
		return true
	})
	return foldEntryDigests(perEntry)
}
