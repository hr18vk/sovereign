// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package chaos

// TestPartitionOracleArenaFlat drives partition.go's MerkleRoots on a diverged
// pair of 256MiB engines and verifies that repeated root comparisons via
// MerkleRootFromShards keep arena high-water flat (avoiding per-call State()
// snapshot allocations). The diverged pair must continue reporting
// converged=false each round so the root check actually executes.

import (
	"fmt"
	"testing"

	engsync "github.com/hr18vk/sovereign/pkg/sync"
)

func TestPartitionOracleArenaFlat(t *testing.T) {
	engsync.DataDir = t.TempDir()
	net := NewVirtualNet(ChaosProfile{})
	defer net.Stop() // no AddNode/BindNodes: no mailbox goroutines, clean Stop
	var idA, idB [16]byte
	idA[0], idB[0] = 0xC3, 0xD4
	eA, err := engsync.NewDeltaCRDTEngine(idA, 1, 256*1024*1024)
	if err != nil {
		t.Fatalf("NewDeltaCRDTEngine A: %v", err)
	}
	defer func() { _ = eA.Close() }()
	eB, err := engsync.NewDeltaCRDTEngine(idB, 1, 256*1024*1024)
	if err != nil {
		t.Fatalf("NewDeltaCRDTEngine B: %v", err)
	}
	defer func() { _ = eB.Close() }()
	// 500 entities on A only so the two engines remain diverged without deliveries.
	for i := 0; i < 500; i++ {
		eA.InsertLocal(fmt.Sprintf("oracle-div-%d", i), engsync.CRDTEntry{SystemTime: int64(i), H3Index: uint64(i)})
	}
	orch, err := NewOrchestrator(OrchestratorConfig{Net: net, Engines: map[[16]byte]*engsync.DeltaCRDTEngine{idA: eA, idB: eB}, Dedup: true})
	if err != nil {
		t.Fatalf("NewOrchestrator: %v", err)
	}
	hwA0, hwB0 := eA.Arena().HighWater(), eB.Arena().HighWater()
	const rounds = 200
	for i := 0; i < rounds; i++ {
		_, converged := orch.MerkleRoots()
		if converged {
			t.Fatalf("oracle: round %d reported converged on a permanently diverged pair — root comparison did not execute", i)
		}
	}
	hwA1, hwB1 := eA.Arena().HighWater(), eB.Arena().HighWater()
	t.Logf("%d churn rounds flat check — A high-water %d -> %d (delta %d), B %d -> %d (delta %d)", rounds, hwA0, hwA1, hwA1-hwA0, hwB0, hwB1, hwB1-hwB0)
	if hwA1 != hwA0 || hwB1 != hwB0 {
		t.Fatalf("oracle: MerkleRoots grew arena high-water (A +%d B +%d bytes over %d rounds); MerkleRootFromShards must allocate zero arena bytes", hwA1-hwA0, hwB1-hwB0, rounds)
	}
}
