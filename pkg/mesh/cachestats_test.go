// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package mesh

// cachestats_test.go — the guard for the
// /debug/memstats mesh-cache terms. The counters are RUNNING byte totals
// maintained O(1) at retain/record/delete; this test asserts the ARITHMETIC
// (not merely "the number moved") so a wrong add/subtract site cannot pass:
// every leg pins an exact integer.
//
//	go test -run TestCacheStats -count=1 -v ./pkg/mesh/

import (
	"testing"

	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// : payloadCache — record two payloads of known length; a re-record of
// the SAME key must replace (bytes = new length), not accumulate.
func TestCacheStatsPayloadArithmetic(t *testing.T) {
	g := NewGossiper(nil, nil, nil, nil)
	dot1 := eng.CausalDot{NodeID: [16]byte{1}, Counter: 1}
	dot2 := eng.CausalDot{NodeID: [16]byte{1}, Counter: 2}

	g.cache.record("entity-a", dot1, "12345")   // 5 bytes
	g.cache.record("entity-b", dot2, "1234567") // 7 bytes
	cs := g.CacheStats()
	if cs.PayloadEntries != 2 || cs.PayloadBytes != 12 {
		t.Fatalf("after two records: entries=%d bytes=%d, want 2/12", cs.PayloadEntries, cs.PayloadBytes)
	}

	g.cache.record("entity-a", dot1, "12") // SAME key, shorter payload: replace, 7+2
	cs = g.CacheStats()
	if cs.PayloadEntries != 2 || cs.PayloadBytes != 9 {
		t.Fatalf("re-record of the same key must replace not accumulate: entries=%d bytes=%d, want 2/9", cs.PayloadEntries, cs.PayloadBytes)
	}
}

// : relayCache per-frame layer — same replace-not-accumulate discipline.
func TestCacheStatsPerFrameArithmetic(t *testing.T) {
	g := NewGossiper(nil, nil, nil, nil)
	originA := [16]byte{0xA}

	g.relay.retain(originA, 1, make([]byte, 50))
	cs := g.CacheStats()
	if cs.RelayFrames != 1 || cs.RelayFrameBytes != 50 {
		t.Fatalf("after retain: frames=%d bytes=%d, want 1/50", cs.RelayFrames, cs.RelayFrameBytes)
	}

	g.relay.retain(originA, 1, make([]byte, 70)) // SAME dot, longer frame: replace
	cs = g.CacheStats()
	if cs.RelayFrames != 1 || cs.RelayFrameBytes != 70 {
		t.Fatalf("re-retain of the same dot must replace not accumulate: frames=%d bytes=%d, want 1/70", cs.RelayFrames, cs.RelayFrameBytes)
	}
}

// : relayCache batch layer — the refcount displacement must SUBTRACT
// the deleted frame's bytes exactly when its last referencing dot is displaced.
// Timeline (origin A, 100-byte frames):
//
//	seq1 {dots 1,2,3}  -> forward={s1:100}  bytes=100  reverse={1,2,3}  refs{s1:3}
//	seq2 {dots 2,3}    -> forward={s1,s2}   bytes=200  reverse={1,2,3}  refs{s1:1,s2:2}
//	seq3 {dot 1}       -> s1's last dot displaced -> forward={s2,s3} bytes=110
func TestCacheStatsBatchDisplacementSubtraction(t *testing.T) {
	g := NewGossiper(nil, nil, nil, nil)
	originA := [16]byte{0xA}
	frame := make([]byte, 100)

	g.relay.retainBatch(originA, 1, []uint64{1, 2, 3}, frame)
	cs := g.CacheStats()
	if cs.RelayBatchForward != 1 || cs.RelayBatchForwardBytes != 100 || cs.RelayBatchReverse != 3 {
		t.Fatalf("after seq1: forward=%d bytes=%d reverse=%d, want 1/100/3",
			cs.RelayBatchForward, cs.RelayBatchForwardBytes, cs.RelayBatchReverse)
	}

	g.relay.retainBatch(originA, 2, []uint64{2, 3}, frame) // displaces dots 2,3 from seq1; dot 1 keeps seq1 alive
	cs = g.CacheStats()
	if cs.RelayBatchForward != 2 || cs.RelayBatchForwardBytes != 200 || cs.RelayBatchReverse != 3 {
		t.Fatalf("after seq2 (partial displacement): forward=%d bytes=%d reverse=%d, want 2/200/3 — seq1 must SURVIVE while dot 1 still resolves through it",
			cs.RelayBatchForward, cs.RelayBatchForwardBytes, cs.RelayBatchReverse)
	}

	g.relay.retainBatch(originA, 3, []uint64{1}, frame) // displaces dot 1: seq1's refcount hits 0
	cs = g.CacheStats()
	if cs.RelayBatchForward != 2 || cs.RelayBatchForwardBytes != 200 || cs.RelayBatchReverse != 3 {
		t.Fatalf("after seq3 (seq1 evicted): forward=%d bytes=%d reverse=%d, want 2/200/3 — the displacement delete must subtract the evicted frame's 100 bytes",
			cs.RelayBatchForward, cs.RelayBatchForwardBytes, cs.RelayBatchReverse)
	}
}

// : nil safety — the /debug/memstats handler calls this unconditionally.
func TestCacheStatsNilGossiper(t *testing.T) {
	var g *Gossiper
	cs := g.CacheStats()
	if cs != (CacheStats{}) {
		t.Fatalf("nil gossiper must return the zero value, got %+v", cs)
	}
}
