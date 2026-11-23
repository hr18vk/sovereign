// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package chaos

// Digest release check over 10,000 orchestrator GossipOnce rounds.
//
// GenerateDigest allocates its IBLT buffer from the engine's bounded
// HamtArena. Calling dstDigest.Release() after GenerateDelta ensures each
// round retires the slab via EBR rather than exhausting the 32 MiB arena.
// Driving partition.go's real GossipOnce closure 10,000 times against a 2-node
// fabric verifies that the orchestrator releases every digest slab without an
// arena OOM under concurrent execution and -race.

import (
	"context"
	"strconv"
	"testing"
	"time"

	engsync "github.com/hr18vk/sovereign/pkg/sync"
)

// TestChaosDigestReleaseRoundTrip drives partition.go's GossipOnce closure
// 10,000 times against two 32 MiB engines and verifies all rounds complete
// without an arena panic.
func TestChaosDigestReleaseRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("digest release test runs 10K GossipOnce rounds; skip in -short")
	}

	// Two engines — the (from, to) pair partition.go exercises, mirrored to both
	// directions per RunGossipRound's full-mesh sweep.
	var srcID [16]byte
	srcID[0] = 0xA1
	var dstID [16]byte
	dstID[0] = 0xB2

	oldDir := engsync.DataDir
	t.Cleanup(func() { engsync.DataDir = oldDir })

	engsync.DataDir = t.TempDir()
	srcEng, err := engsync.NewDeltaCRDTEngine(srcID, 0, 32*1024*1024)
	if err != nil {
		t.Fatalf("NewDeltaCRDTEngine src: %v", err)
	}
	t.Cleanup(func() { _ = srcEng.Close() })

	engsync.DataDir = t.TempDir()
	dstEng, err := engsync.NewDeltaCRDTEngine(dstID, 0, 32*1024*1024)
	if err != nil {
		t.Fatalf("NewDeltaCRDTEngine dst: %v", err)
	}
	t.Cleanup(func() { _ = dstEng.Close() })

	// Seed a small fixed corpus on each engine so deltas are non-trivial but
	// the loop measures leak rate, not correctness — 50 entries is enough.
	// Stack-buffered keys (strconv on a 16-byte nodeID cap) keep setup zero-
	// fmt.Sprintf on the setup path.
	for k := 0; k < 50; k++ {
		key := "seed-event-" + strconv.Itoa(k)
		srcEng.InsertLocal(key, engsync.CRDTEntry{SystemTime: int64(k)})
	}
	for k := 0; k < 50; k++ {
		key := "dst-event-" + strconv.Itoa(k)
		dstEng.InsertLocal(key, engsync.CRDTEntry{SystemTime: int64(k + 50)})
	}

	// Tight, deterministic fabric: zero loss / zero duplicate / 0 jitter so the
	// loop measures pure leak-accumulation against the bounded arena. The
	// 100µs delivery base schedules the per-node goroutines off the inline
	// send path (Send enqueues to a mailbox processed by an AddNode goroutine);
	// the round call returns immediately after the makeDelta closure ships, so
	// 10K rounds are ~44µs each, not gated on delivery latency.
	profile := ChaosProfile{
		Drop:             0.0,
		Duplicate:        0.0,
		ReorderMaxJitter: 0,
		DeliveryBase:     100 * time.Microsecond,
	}
	net := NewVirtualNet(profile)
	t.Cleanup(net.Stop)

	orch, err := NewOrchestrator(OrchestratorConfig{
		Net:     net,
		Engines: map[[16]byte]*engsync.DeltaCRDTEngine{srcID: srcEng, dstID: dstEng},
		Dedup:   false, // CRDT Join idempotence is the safety net; no SeqNo dedup
	})
	if err != nil {
		t.Fatalf("NewOrchestrator: %v", err)
	}
	orch.BindNodes()

	// Run 10,000 GossipOnce sweeps across both (A->B) and (B->A) directions.
	ctx := context.Background()
	const rounds = 10000
	start := time.Now()
	for r := 0; r < rounds; r++ {
		if _, err := orch.GossipOnce(ctx); err != nil {
			t.Fatalf("release test: GossipOnce round %d failed: %v", r, err)
		}
	}
	elapsed := time.Since(start)

	// Drain in-flight deliveries so t.Cleanup's net.Stop sees a clean net state.
	_, _ = net.RunGossipRound(ctx, func(ctx context.Context, from, to [16]byte) ([]byte, error) {
		return nil, nil
	})

	t.Logf("completed %d GossipOnce rounds in %v (%v/round) without HamtArena panic",
		rounds, elapsed, elapsed/time.Duration(rounds))
}
