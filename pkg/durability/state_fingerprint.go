// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package durability

// state_fingerprint.go — the SECOND state-integrity verification (ADR-0045),
// WIRED into boot-time recovery by (ADR-0045, under the
// BINDING §15.16 Revision 1 §11.8).
//
// The Merkle root folds ONLY (DotNodeID, DotCounter) pairs (hamt.go:262-309):
// it is blind to the entityID, the payload digest, and every temporal/H3 byte.
// Root equality therefore CANNOT detect "same dots, wrong bytes" — which is
// exactly the failure mode of a lossy persistence format (the pre-§6 WAL
// replayed entries whose temporal fields were zeros, and the root still
// matched). StateFingerprint folds, for EVERY entry of every entity, the
// entityID AND all ten CRDTEntry fields, canonically ordered. Two states with
// equal Merkle roots but different bytes produce DIFFERENT fingerprints.
//
// WIRING: the checkpoint writer (bridge.go AppendCheckpoint) folds
// this fingerprint over the captured image records and persists it in the 0x05
// checkpoint record; recovery (recovery.go, the pre-tail check) recomputes it
// over the just-Joined image and compares. There is exactly ONE fold
// implementation — fingerprintEntry + foldEntryDigests — shared by both sides
// (two independent folds that must agree is a defect waiting for a silicon run
// to find it).
//
// THE FOLD IS SHARD-BASED, NOT State()-BASED: State() duplicates every
// live entry into fresh arena nodes (measured on 20,000 records:
// StateFingerprint via State() = +33,323,280 B arena, vs MerkleRootFromShards
// +0 B) — wiring that at boot would re-arm the N1 merged-view blowup
// removed from the checkpoint path. The reader side therefore walks the shards
// via CaptureShardsPinned (zero arena), under its own EBR pin (the walk's
// contract — merkle_sharded.go:199-209); the writer side folds the records its
// single pinned walk already captured (no second walk, no arena).
//
// SCOPE: a verification check, not a hot-path structure — it allocates Go-heap
// per-entry digests and walks the whole state, off the hot path.

import (
	"bytes"
	"crypto/sha256"
	"sort"

	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// fingerprintDomainSep is the per-entry domain separator (the exact bytes are
// load-bearing — writer and reader MUST hash the identical preimage).
const fingerprintDomainSep = "SOVEREIGN-STATE-FINGERPRINT-v1\x00"

// fingerprintEntryInto is THE canonical per-entry fold: SHA-256 over the domain
// separator, the entityID, a NUL, and the entry's canonical 120-byte encoding
// (the SAME codec the snapshot image uses, snapshot.go:encodeCRDTEntry). Writer
// and reader share this — see the file doc. The hasher and the encode buffer
// are caller-owned (reset+reused across entries) so the fold does not allocate
// a digest struct per entry — the fold runs INSIDE the checkpoint's EBR pin, so
// its wall-time is arena-reclamation time the pin holds back (the T21
// measurement: a per-entry sha256.New doubled the pin hold and OOMed the
// 64 MiB test arena under the State() hammer).
func fingerprintEntryInto(h hashWriter, buf *[crdtEntryWireSize]byte, entityID string, entry eng.CRDTEntry, out []byte) []byte {
	h.Reset()
	h.Write([]byte(fingerprintDomainSep))
	h.Write([]byte(entityID))
	h.Write([]byte{0})
	encodeCRDTEntry(entry, buf[:])
	h.Write(buf[:])
	return h.Sum(out)
}

// hashWriter is the sha256.Hash subset the fold uses (Reset/Write/Sum),
// declared so the fold's hot loop is explicit about the reuse discipline.
type hashWriter interface {
	Reset()
	Write(p []byte) (n int, err error)
	Sum(b []byte) []byte
}

// foldEntryDigests eliminates order: the per-entry digests are sorted ascending
// and folded by ONE SHA-256 over their concatenation (a multiset hash — the
// result depends on the SET of entries, never their walk order).
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

// fingerprintRecords folds a captured image's records — the WRITER side.
// bridge.go's AppendCheckpoint calls this on the records its ONE pinned
// CaptureShardsPinned walk already produced: no second walk, no arena. The
// hasher + the encode buffer are reused across entries (see
// fingerprintEntryInto) so the fold's wall-time stays small: it runs INSIDE the
// checkpoint's EBR pin, and pin time is arena-reclamation time.
func fingerprintRecords(records []SnapshotRecord) [32]byte {
	h := sha256.New()
	var buf [crdtEntryWireSize]byte
	perEntry := make([][]byte, 0, len(records))
	for i := range records {
		perEntry = append(perEntry, fingerprintEntryInto(h, &buf, records[i].EntityID, records[i].Entry, nil))
	}
	return foldEntryDigests(perEntry)
}

// StateFingerprint returns the 32-byte fingerprint of the engine's full state —
// the READER side. It walks the shards DIRECTLY via CaptureShardsPinned under
// its own EBR pin (zero arena growth — §11.8), folding every (entityID, entry)
// pair through the SAME canonical fold the writer uses, so the checkpoint's
// persisted fingerprint compares against it byte-exactly.
func StateFingerprint(e *eng.DeltaCRDTEngine) [32]byte {
	h := sha256.New()
	var buf [crdtEntryWireSize]byte
	var perEntry [][]byte
	// CaptureShardsPinned takes NO pin itself (merkle_sharded.go:199-209) — the
	// caller MUST hold one for the whole walk: the yielded entityID strings and
	// entries slices are arena-backed views, and a concurrent CAS that retires a
	// shard root mid-walk must not free them under us.
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
