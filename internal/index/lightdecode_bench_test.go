// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package index

// These benchmarks measure remote-feed field extraction and index updates on
// the ingest path, separately from in-memory CRDT core throughput.
//
// They cover:
//   1. lightDecodeEvent, for per-frame extraction in HandleFrame;
//   2. lightDecodeBatch, for per-element extraction after one Unmarshal of a
//      verified batch wire in HandleBatchFrame or HandleHybridFrame;
//   3. Apply, for stale and move writes. BenchmarkIndexApply_Fresh covers
//      fresh inserts separately.

import (
	"crypto/sha256"
	"testing"

	capnp "capnproto.org/go/capnp/v3"
	capnp_schema "github.com/hr18vk/sovereign/api/capnp/api/capnp"
	mesh "github.com/hr18vk/sovereign/pkg/mesh"
	eng "github.com/hr18vk/sovereign/pkg/sync"
)

var benchOrigin = [16]byte{0xb1, 0x24, 0x0f, 0x24, 0x0a, 0xc1}

func benchEventWire(b *testing.B) []byte {
	b.Helper()
	dgst := sha256.Sum256([]byte("bench-payload"))
	entry := eng.CRDTEntry{
		PayloadDigest: dgst,
		OriginNodeID:  benchOrigin,
		DotNodeID:     benchOrigin,
		DotCounter:    7,
		H3Index:       0x8928308280fffff,
		SystemTime:    0x1111111111111111,
		ValidTimeEnd:  0x3333333333333333,
	}
	wire, err := eng.BuildCRDTDeltaEvent("bench-entity-0", "bench-payload", entry)
	if err != nil {
		b.Fatalf("BuildCRDTDeltaEvent: %v", err)
	}
	return wire
}

func benchBatchWire(b *testing.B, n int) []byte {
	b.Helper()
	events := make([]mesh.BuiltEvent, n)
	for i := range events {
		payload := "bench-payload"
		dgst := sha256.Sum256([]byte(payload))
		e := eng.CRDTEntry{
			PayloadDigest: dgst,
			OriginNodeID:  benchOrigin,
			DotNodeID:     benchOrigin,
			DotCounter:    uint64(100 + i),
			H3Index:       uint64(0x8900000000000000) + uint64(i),
			SystemTime:    int64(1_000_000 + i),
		}
		events[i] = mesh.BuiltEvent{EntityID: "bench-entity", Payload: payload, Entry: e}
	}
	wire, err := mesh.BuildCRDTDeltaBatch(events)
	if err != nil {
		b.Fatalf("BuildCRDTDeltaBatch: %v", err)
	}
	return wire
}

// lightDecodeEvent reads entityID, h3Index, and systemTime from a verified
// single-frame wire with one capnp.Unmarshal and three accessors. On the feed
// path, the receiver has already validated and applied the event, so decoding
// does not repeat digest validation, read the payload, or reconstruct the
// entry.
func lightDecodeEvent(wire []byte) (Record, error) {
	msg, err := capnp.Unmarshal(wire)
	if err != nil {
		return Record{}, err
	}
	defer msg.Release()
	ev, err := capnp_schema.ReadRootCRDTDeltaEvent(msg)
	if err != nil {
		return Record{}, err
	}
	id, err := ev.EntityId()
	if err != nil {
		return Record{}, err
	}
	return Record{EntityID: id, H3Index: ev.H3Index(), SystemTime: ev.SystemTime()}, nil
}

// lightDecodeBatch unmarshals a verified batch wire once and reads the feed
// fields from each element. The decoded values alias the message arena, which
// remains valid until the deferred Release at function exit.
func lightDecodeBatch(wire []byte) ([]Record, error) {
	msg, err := capnp.Unmarshal(wire)
	if err != nil {
		return nil, err
	}
	defer msg.Release()
	batch, err := capnp_schema.ReadRootCRDTDeltaBatch(msg)
	if err != nil {
		return nil, err
	}
	events, err := batch.Events()
	if err != nil {
		return nil, err
	}
	n := events.Len()
	out := make([]Record, 0, n)
	for i := 0; i < n; i++ {
		ev := events.At(i)
		id, err := ev.EntityId()
		if err != nil {
			return nil, err
		}
		out = append(out, Record{EntityID: id, H3Index: ev.H3Index(), SystemTime: ev.SystemTime()})
	}
	return out, nil
}

// BenchmarkLightDecode_Single measures the HandleFrame feed's field extraction
// in nanoseconds per frame.
func BenchmarkLightDecode_Single(b *testing.B) {
	wire := benchEventWire(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec, err := lightDecodeEvent(wire)
		if err != nil {
			b.Fatal(err)
		}
		if rec.EntityID != "bench-entity-0" {
			b.Fatal("light decode lost the entityID")
		}
	}
}

// BenchmarkLightDecode_Batch measures nanoseconds per 100-element batch.
// Dividing the result by 100 gives the per-delta cost; ReportAllocs reports
// transient bytes per batch.
func BenchmarkLightDecode_Batch(b *testing.B) {
	const n = 100
	wire := benchBatchWire(b, n)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		recs, err := lightDecodeBatch(wire)
		if err != nil {
			b.Fatal(err)
		}
		if len(recs) != n {
			b.Fatalf("light decode got %d records, want %d", len(recs), n)
		}
	}
}

// BenchmarkIndexApply_Stale measures duplicate and stale gossip arrivals for
// an entity whose index entry is already newer. TestIndex_MemoryBound checks
// that this shape performs no allocations; the benchmark measures its wall
// cost on the receive path.
func BenchmarkIndexApply_Stale(b *testing.B) {
	ix := NewWith(16, DefaultEpochNs)
	ix.Apply(Record{EntityID: "bench-e", H3Index: 1, SystemTime: 10_000})
	rec := Record{EntityID: "bench-e", H3Index: 1, SystemTime: 100}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ix.Apply(rec)
	}
}

// BenchmarkIndexApply_Move measures a strictly greater SystemTime moving an
// entity between cells, including removal and insertion of its memberships.
func BenchmarkIndexApply_Move(b *testing.B) {
	ix := NewWith(16, DefaultEpochNs)
	sys := int64(1_000_000)
	alt := [2]uint64{0x1, 0x2}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sys++
		ix.Apply(Record{EntityID: "bench-e", H3Index: alt[i&1], SystemTime: sys})
	}
}

// BenchmarkApplyCRDTDeltaBatch_Cost measures the ingest work for the same
// batch wire: capnp decoding, one reconstruction per element, and the Join
// walk on an engine. After the first iteration, exact-dot merging deduplicates
// the batch, so the result is the re-apply cost rather than the first-apply
// cost. The result is per batch; divide by the element count for per-delta
// cost.
func BenchmarkApplyCRDTDeltaBatch_Cost(b *testing.B) {
	const n = 100
	wire := benchBatchWire(b, n)
	e, err := eng.NewDeltaCRDTEngine(benchOrigin, 0, 64*1024*1024)
	if err != nil {
		b.Fatal(err)
	}
	e.SetDataDir(b.TempDir())
	defer e.Close()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := e.ApplyCRDTDeltaBatch(wire); err != nil {
			b.Fatal(err)
		}
	}
}
