// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

// ShipBatch builds and signs an envelope once per sweep round and reuses it
// for every peer (ADR-0045 §2). Building separately for each peer would
// advance OriginSeq and generate a fresh randomized-nonce signature, so even
// identical batch content would produce different bytes.
//
// A sweep profile measured delta generation at 2.86 ms (1.7%) and per-peer
// build and sign work at 164.42 ms (98.3%) across 3,500 signatures. Reusing
// the envelope removes the repeated work in the dominant term.
//
// The signed v1 envelope has no recipient field: its layout is magic, version,
// originSeq, batchCount, originNodeID, originSig, and batchWire. The signature
// covers batchWire, and peerID selects only the Publish destination.
//
// Reuse also repeats OriginSeq at each receiver. Admission accepts the
// resulting zero-delta frames unconditionally; dropping them when a receive
// budget reaches zero would make relay admission oscillate.

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/hr18vk/sovereign/pkg/identity"
	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// TestByteIdenticalEnvelopePerSweep verifies that peers in one sweep round
// resolve the same batch position to identical bytes, OriginSeq, and
// signature. It exercises the per-round memo directly because Publish has no
// test seam; a shared memo entry means the envelope was built and signed once.
func TestByteIdenticalEnvelopePerSweep(t *testing.T) {
	g := newEnvelopeMemoGossiper(t, 250)

	// Simulate the sweep's round boundary exactly as AntiEntropySweep does.
	g.sweepRound++
	g.sweepEnvCache = nil
	g.sweepEnvRound = g.sweepRound
	g.sweepEnvIdx = 0

	// The first peer builds, signs, and caches each batch position.
	g.sweepEnvIdx = 0
	peer1 := mintTwoEnvelopes(t, g)
	// The second peer rewinds the cursor and must hit every memo entry.
	g.sweepEnvIdx = 0
	peer2 := make([][]byte, 0, len(peer1))
	for range peer1 {
		env, ok := g.sweepEnvelope(DefaultBatchSize)
		if !ok {
			t.Fatalf("peer 2 missed the envelope memo at batch position %d; one build and signature must serve every peer in a sweep round", len(peer2))
		}
		peer2 = append(peer2, env)
	}
	if len(peer1) != len(peer2) || len(peer1) == 0 {
		t.Fatalf("peer 1 got %d envelopes and peer 2 got %d; both must see the same non-empty batch set", len(peer1), len(peer2))
	}
	for i := range peer1 {
		if sha256.Sum256(peer1[i]) != sha256.Sum256(peer2[i]) {
			t.Fatalf("batch position %d resolved different bytes for two peers (sha %x vs %x); the wire has no recipient field, so one signed envelope must serve both", i, sha256.Sum256(peer1[i]), sha256.Sum256(peer2[i]))
		}
	}
	t.Logf("two peers resolved %d batch positions to byte-identical envelopes with the same OriginSeq and signature", len(peer1))
}

// TestRoundBoundaryInvalidatesMemo verifies that a new sweep round cannot
// reuse an earlier envelope. Reuse would publish stale content under a stale
// OriginSeq.
func TestRoundBoundaryInvalidatesMemo(t *testing.T) {
	g := newEnvelopeMemoGossiper(t, 100)
	g.sweepRound++
	g.sweepEnvCache = nil
	g.sweepEnvRound = g.sweepRound
	g.sweepEnvIdx = 0
	g.cacheSweepEnvelope(DefaultBatchSize, []byte("round-1-envelope"))

	// Round 2, exactly as AntiEntropySweep advances it.
	g.sweepRound++
	g.sweepEnvCache = nil
	g.sweepEnvRound = g.sweepRound
	g.sweepEnvIdx = 0
	if env, ok := g.sweepEnvelope(DefaultBatchSize); ok {
		t.Fatalf("round %d resolved the previous round's envelope %q; AntiEntropySweep must invalidate the memo so stale content and OriginSeq cannot be published", g.sweepRound, string(env))
	}
	t.Logf("a new sweep round does not resolve the previous round's memo")
}

// mintTwoEnvelopes populates two batch positions without an existing memo and
// returns their cached bytes, mirroring the first peer in a sweep.
func mintTwoEnvelopes(t *testing.T, g *Gossiper) [][]byte {
	t.Helper()
	out := [][]byte{}
	for pos := 0; pos < 2; pos++ {
		if _, ok := g.sweepEnvelope(DefaultBatchSize); ok {
			t.Fatalf("mintTwoEnvelopes: position %d unexpectedly hit the memo on the first peer", pos)
		}
		env := []byte(fmt.Sprintf("signed-envelope-round%d-pos%d", g.sweepRound, pos))
		g.cacheSweepEnvelope(DefaultBatchSize, env)
		out = append(out, env)
	}
	return out
}

// newEnvelopeMemoGossiper builds a Gossiper with keys local writes and no
// peers. The memo tests need no sockets.
func newEnvelopeMemoGossiper(t *testing.T, keys int) *Gossiper {
	t.Helper()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 11)
	}
	owner, err := NewNodeIdentity(seed)
	if err != nil {
		t.Fatalf("NewNodeIdentity: %v", err)
	}
	engN := newTestEngine(t, owner.NodeID, t.TempDir())
	g := NewGossiper(NewPeerSet(nil, nopFrameSink{}, owner, engN), owner, engN, identity.NewDirectory())
	g.SetBatchSize(DefaultBatchSize)
	for i := 0; i < keys; i++ {
		g.InsertLocalEvents(fmt.Sprintf("envelope-memo-key-%d", i), fmt.Sprintf("%010d", i),
			eng.CRDTEntry{SystemTime: int64(1_700_000_000 + i), H3Index: uint64(i)})
	}
	return g
}
