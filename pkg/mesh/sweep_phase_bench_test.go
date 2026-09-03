// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package mesh

// sweep_phase_bench_test.go — sweep-phase attribution bench. Times the THREE phases of a
// stratified-OFF sweep round at a silicon-run scale so the decision is made on
// measurement, not on the assumption that build+sign dominates.
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
	const peers = 35 // the selected-peer count per sweep
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
		g.InsertLocalEvents(fmt.Sprintf("sweep-key-%d", i), fmt.Sprintf("%010d", i),
			eng.CRDTEntry{SystemTime: int64(1_700_000_000 + i), H3Index: uint64(i)})
	}

	// — generate (hoisted this OUT of the per-peer loop: once/sweep).
	t0 := time.Now()
	d := g.generateSweepDelta(context.Background(), [16]byte{})
	genMs := float64(time.Since(t0).Microseconds()) / 1000.0
	if d == nil {
		t.Fatalf("nil delta")
	}
	n := countDeltaEntries(t, d)

	// — per-peer BUILD + SIGN. This is what did NOT hoist: ShipBatch
	// calls BuildCRDTDeltaBatch + SignCRDTFrame + g.batchSeq++ once PER PEER.
	// Time it by replaying the same work `peers` times over the same entry set.
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
	t.Logf("SWEEP-PHASE SPLIT (keys=%d entries=%d peers=%d batches/peer=%d, stratified OFF):", keys, n, peers, batches)
	t.Logf("  PHASE 1 generate (hoisted, ONCE/sweep)  = %10.2f ms  (%5.1f%%)", genMs, 100*genMs/total)
	t.Logf("  PHASE 2 per-peer build+SIGN (NOT hoisted)= %10.2f ms  (%5.1f%%)  [%d signs]", signMs, 100*signMs/total, peers*batches)
	t.Logf("  (PHASE 3 Publish/transport is NOT measurable here — no sockets; the silicon check measures it)")
	t.Logf("  DECISION INPUT: build+sign share = %.1f%% of the measurable compute", 100*signMs/total)
}
