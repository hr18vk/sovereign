// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package durability

// Tests for the bridge and recovery index-feed paths. They cover single and
// batched writes, feed placement before the WAL result is known, disabled-feed
// behavior, full replay, and legacy records with no H3 index.

import (
	"crypto/sha256"
	"path/filepath"
	"testing"

	eng "github.com/hr18vk/sovereign/pkg/sync"
)

type indexFeedFed struct {
	entityID string
	h3       uint64
	sys      int64
}

// indexFeedCollector observes the production SetIndexFeeder seam (the seam
// under test — never a manual emit). No lock: the feed fires synchronously
// on the caller's goroutine (the design contract — synchronous before
// return), so the collector is single-threaded by construction.
type indexFeedCollector struct {
	fed []indexFeedFed
}

func (c *indexFeedCollector) len() int { return len(c.fed) }

// indexFeedBridge builds a real Bridge over a real on-disk WAL, optionally
// wiring the production feeder to the collector (fed != nil).
func indexFeedBridge(t *testing.T, engine *eng.DeltaCRDTEngine, walPath string, fed *indexFeedCollector) *Bridge {
	t.Helper()
	wal, err := OpenWAL(walPath)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	b := NewBridge(engine, wal, 0)
	if fed != nil {
		b.SetIndexFeeder(func(entityID string, h3 uint64, sys int64) {
			fed.fed = append(fed.fed, indexFeedFed{entityID, h3, sys})
		})
	}
	t.Cleanup(func() { _ = b.Close() })
	return b
}

func indexFeedEngine(t *testing.T, id byte) *eng.DeltaCRDTEngine {
	t.Helper()
	engine, err := eng.NewDeltaCRDTEngine([16]byte{id}, 0, 64*1024*1024)
	if err != nil {
		t.Fatalf("NewDeltaCRDTEngine: %v", err)
	}
	engine.SetDataDir(t.TempDir())
	t.Cleanup(func() { _ = engine.Close() })
	return engine
}

// TestIndexFeedBridgeWrites checks that PutLocal feeds one record with the
// caller's entity ID, H3 index, and system time, and that PutLocals feeds each
// item in the batch.
func TestIndexFeedBridgeWrites(t *testing.T) {
	engine := indexFeedEngine(t, 0x25)
	fed := &indexFeedCollector{}
	b := indexFeedBridge(t, engine, filepath.Join(t.TempDir(), "wal"), fed)
	dg := sha256.Sum256([]byte("p"))
	if _, err := b.PutLocal("e1", "p", eng.CRDTEntry{PayloadDigest: dg, H3Index: 0xAA01, SystemTime: 1000, ValidTimeStart: 1, ValidTimeEnd: 2}); err != nil {
		t.Fatalf("PutLocal: %v", err)
	}
	if fed.len() != 1 {
		t.Fatalf("PutLocal fed %d records, want 1", fed.len())
	}
	items := []LocalItem{
		{EntityID: "b1", Payload: "p1", Entry: eng.CRDTEntry{PayloadDigest: dg, H3Index: 0xAA02, SystemTime: 1001, ValidTimeStart: 1, ValidTimeEnd: 2}},
		{EntityID: "b2", Payload: "p2", Entry: eng.CRDTEntry{PayloadDigest: dg, H3Index: 0xAA03, SystemTime: 1002, ValidTimeStart: 1, ValidTimeEnd: 2}},
	}
	if _, _, err := b.PutLocals(items); err != nil {
		t.Fatalf("PutLocals: %v", err)
	}
	if fed.len() != 3 {
		t.Fatalf("after PutLocals fed %d total, want 3 (1 + 2 per-item)", fed.len())
	}
	if fed.fed[0].entityID != "e1" || fed.fed[0].h3 != 0xAA01 || fed.fed[0].sys != 1000 {
		t.Fatalf("the fed record's fields diverged: %+v", fed.fed[0])
	}
}

// TestIndexFeedWALFailureStillFeeds checks feed placement after InsertLocal
// and before the WAL result is known. A failed append leaves the dot in engine
// state, so the index must receive the same entry even though PutLocal returns
// an error.
func TestIndexFeedWALFailureStillFeeds(t *testing.T) {
	engine := indexFeedEngine(t, 0x26)
	fed := &indexFeedCollector{}
	b := indexFeedBridge(t, engine, filepath.Join(t.TempDir(), "wal"), fed)
	dg := sha256.Sum256([]byte("p"))
	// Force the durability failure: pre-close the WAL (the control_test.go
	// precedent) — InsertLocal mints the dot; AppendMutation fails.
	if err := b.wal.Close(); err != nil {
		t.Fatalf("pre-close WAL: %v", err)
	}
	if _, err := b.PutLocal("e503", "p", eng.CRDTEntry{PayloadDigest: dg, H3Index: 0xAA04, SystemTime: 1003, ValidTimeStart: 1, ValidTimeEnd: 2}); err == nil {
		t.Fatalf("the pre-closed WAL must fail the PutLocal (the 503 shape)")
	}
	if fed.len() != 1 {
		t.Fatalf("the WAL-failed write still fed the index (InsertLocal already advanced the engine — the index mirrors it); fed=%d want 1", fed.len())
	}
}

// TestIndexFeedDisabledWrites checks that single and batched writes retain
// their normal behavior when no index feeder is configured.
func TestIndexFeedDisabledWrites(t *testing.T) {
	engine := indexFeedEngine(t, 0x27)
	b := indexFeedBridge(t, engine, filepath.Join(t.TempDir(), "wal"), nil)
	dg := sha256.Sum256([]byte("p"))
	if _, err := b.PutLocal("e-nil", "p", eng.CRDTEntry{PayloadDigest: dg, H3Index: 0xAA05, SystemTime: 1004, ValidTimeStart: 1, ValidTimeEnd: 2}); err != nil {
		t.Fatalf("a nil-feeder PutLocal must succeed: %v", err)
	}
	if _, _, err := b.PutLocals([]LocalItem{{EntityID: "e-nil2", Payload: "p", Entry: eng.CRDTEntry{PayloadDigest: dg, H3Index: 0xAA06, SystemTime: 1005, ValidTimeStart: 1, ValidTimeEnd: 2}}}); err != nil {
		t.Fatalf("a nil-feeder PutLocals must succeed: %v", err)
	}
}

// TestIndexFeedRecoveryReplay checks that RecoverEngineWithSnapshotFed emits
// every replayed record with the same entity ID, H3 index, and system time that
// recovery joins into the engine.
func TestIndexFeedRecoveryReplay(t *testing.T) {
	walPath := filepath.Join(t.TempDir(), "wal")
	engine := indexFeedEngine(t, 0x28)
	b := indexFeedBridge(t, engine, walPath, nil)
	dg := sha256.Sum256([]byte("p"))
	items := []LocalItem{
		{EntityID: "boot-1", Payload: "p1", Entry: eng.CRDTEntry{PayloadDigest: dg, H3Index: 0xBB01, SystemTime: 1100, ValidTimeStart: 1, ValidTimeEnd: 2}},
		{EntityID: "boot-2", Payload: "p2", Entry: eng.CRDTEntry{PayloadDigest: dg, H3Index: 0xBB02, SystemTime: 1101, ValidTimeStart: 1, ValidTimeEnd: 2}},
	}
	if _, _, err := b.PutLocals(items); err != nil {
		t.Fatalf("PutLocals: %v", err)
	}
	if err := b.Close(); err != nil {
		t.Fatalf("bridge.Close: %v", err)
	}
	if err := engine.Close(); err != nil {
		t.Fatalf("engine.Close: %v", err)
	}
	fed := &indexFeedCollector{}
	if _, _, _, _, err := RecoverEngineWithSnapshotFed([16]byte{0x28}, walPath, nil, 64*1024*1024, func(entityID string, h3 uint64, sys int64) {
		fed.fed = append(fed.fed, indexFeedFed{entityID, h3, sys})
	}); err != nil {
		t.Fatalf("RecoverEngineWithSnapshotFed: %v", err)
	}
	if fed.len() != 2 {
		t.Fatalf("recovery fed %d records, want 2 (every replayed record)", fed.len())
	}
	if fed.fed[0].entityID != "boot-1" || fed.fed[0].h3 != 0xBB01 || fed.fed[0].sys != 1100 {
		t.Fatalf("the fed record diverged from the WAL record: %+v", fed.fed[0])
	}
}

// TestIndexFeedLegacyRecoveryZeroH3 checks the fields emitted for a legacy 0x01
// record. The old format has no H3 index, so recovery emits zero while retaining
// the record's system time, matching the restored engine entry.
func TestIndexFeedLegacyRecoveryZeroH3(t *testing.T) {
	walPath := filepath.Join(t.TempDir(), "wal-legacy")
	wal, err := OpenWAL(walPath)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	dg := sha256.Sum256([]byte("legacy-p"))
	nodeID := [16]byte{0x29}
	entry := eng.CRDTEntry{PayloadDigest: dg, H3Index: 0xDEAD, SystemTime: 1200, ValidTimeStart: 1, ValidTimeEnd: 2}
	m := NewWALMutation("legacy-e", eng.CausalDot{NodeID: nodeID, Counter: 1}, entry)
	if err := wal.AppendMutationV1ForTest(m); err != nil {
		t.Fatalf("AppendMutationV1ForTest: %v", err)
	}
	if err := wal.Close(); err != nil {
		t.Fatalf("wal.Close: %v", err)
	}
	fed := &indexFeedCollector{}
	if _, _, _, _, err := RecoverEngineWithSnapshotFed(nodeID, walPath, nil, 64*1024*1024, func(entityID string, h3 uint64, sys int64) {
		fed.fed = append(fed.fed, indexFeedFed{entityID, h3, sys})
	}); err != nil {
		t.Fatalf("RecoverEngineWithSnapshotFed: %v", err)
	}
	if fed.len() != 1 {
		t.Fatalf("recovery fed %d records, want 1 (the legacy record is engine state)", fed.len())
	}
	if fed.fed[0].entityID != "legacy-e" || fed.fed[0].h3 != 0 || fed.fed[0].sys != 1200 {
		t.Fatalf("the legacy record must feed zeros (h3=0, sys verbatim), got %+v — the index mirrors the engine's actual restored state (restoreEntry), never the original write's fields", fed.fed[0])
	}
}

// TestRecoveryWithoutIndexFeed checks that RecoverEngine retains its existing
// behavior and restores the full entry when no feed callback is requested.
func TestRecoveryWithoutIndexFeed(t *testing.T) {
	walPath := filepath.Join(t.TempDir(), "wal-plain")
	engine := indexFeedEngine(t, 0x2a)
	b := indexFeedBridge(t, engine, walPath, nil)
	dg := sha256.Sum256([]byte("p"))
	if _, err := b.PutLocal("plain-e", "p", eng.CRDTEntry{PayloadDigest: dg, H3Index: 0xCC01, SystemTime: 1300, ValidTimeStart: 1, ValidTimeEnd: 2}); err != nil {
		t.Fatalf("PutLocal: %v", err)
	}
	if err := b.Close(); err != nil {
		t.Fatalf("bridge.Close: %v", err)
	}
	if err := engine.Close(); err != nil {
		t.Fatalf("engine.Close: %v", err)
	}
	rec, _, _, err := RecoverEngine([16]byte{0x2a}, walPath, 64*1024*1024)
	if err != nil {
		t.Fatalf("RecoverEngine: %v", err)
	}
	if entries := rec.PointGet("plain-e"); len(entries) != 1 || entries[0].H3Index != 0xCC01 {
		t.Fatalf("the plain recovery lost the record (entries=%d)", len(entries))
	}
	if cerr := rec.Close(); cerr != nil {
		t.Fatalf("recovered engine.Close: %v", cerr)
	}
}
