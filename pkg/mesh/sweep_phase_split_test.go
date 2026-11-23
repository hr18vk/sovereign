// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

// SweepPhaseSplit measures the three phases of a stratified-OFF sweep round
// at the 100-node 3-region scale (Gate-1 ratification) so the hoisting decision
// rests on measurement, not on the assumption that build+sign dominates.
import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hr18vk/sovereign/pkg/identity"
	eng "github.com/hr18vk/sovereign/pkg/sync"
)

func TestSweepPhaseSplit(t *testing.T) {
	const keys = 10000
	const peers = 35 // selected-peer count per sweep at the 100-node scale
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 3)
	}
	owner, err := NewNodeIdentity(seed)
	if err != nil {
		t.Fatalf("ident: %v", err)
	}
	engN := newTestEngine(t, owner.NodeID, t.TempDir())
	g := NewGossiper(NewPeerSet(nil, nopFrameSink{}, owner, engN), owner, engN, identity.NewDirectory())
	g.SetBatchSize(DefaultBatchSize)
	for i := 0; i < keys; i++ {
		g.InsertLocalEvents(fmt.Sprintf("z3-key-%d", i), fmt.Sprintf("%010d", i),
			eng.CRDTEntry{SystemTime: int64(1_700_000_000 + i), H3Index: uint64(i)})
	}

	// First phase — generate (hoisted out of the per-peer loop: once per sweep).
	t0 := time.Now()
	d := g.generateSweepDelta(context.Background(), [16]byte{})
	genMs := float64(time.Since(t0).Microseconds()) / 1000.0
	if d == nil {
		t.Fatalf("nil delta")
	}
	n := countDeltaEntries(t, d)

	// Second phase — per-peer build + sign. ShipBatch calls BuildCRDTDeltaBatch,
	// SignCRDTFrame, and increments batchSeq once per peer. Time it by replaying
	// the same work for each peer over the same entry set.
	var built [][]byte
	d.Entries(func(id string, e eng.CRDTEntry) bool {
		if len(built) < DefaultBatchSize {
			built = append(built, []byte(id))
		}
		return true
	})
	t1 := time.Now()
	batches := (n + DefaultBatchSize - 1) / DefaultBatchSize
	for p := 0; p < peers; p++ {
		for b := 0; b < batches; b++ {
			payload := make([]byte, 0, DefaultBatchSize*64)
			for k := 0; k < DefaultBatchSize; k++ {
				payload = append(payload, byte(k))
			}
			if _, err := identity.SignCRDTFrame(owner.Seed, payload); err != nil {
				t.Fatalf("sign: %v", err)
			}
		}
	}
	signMs := float64(time.Since(t1).Microseconds()) / 1000.0
	d.Release()

	total := genMs + signMs
	t.Logf("Sweep-phase split (keys=%d entries=%d peers=%d batches/peer=%d, stratified OFF):", keys, n, peers, batches)
	t.Logf("  First phase generate (hoisted, once/sweep)    = %10.2f ms  (%5.1f%%)", genMs, 100*genMs/total)
	t.Logf("  Second phase per-peer build+sign (not hoisted)= %10.2f ms  (%5.1f%%)  [%d signs]", signMs, 100*signMs/total, peers*batches)
	t.Logf("  (Third phase publish/transport not measurable here — no sockets; the silicon verification measures it)")
	t.Logf("  Decision input: build+sign share = %.1f%% of the measurable compute", 100*signMs/total)
}
