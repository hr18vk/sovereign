// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package chaos

// ---------------------------------------------------------------------------
// Chaos-Digest Release Discipline (the caller-leak closure).
// ---------------------------------------------------------------------------
//
// Forensic context: GenerateDigest()'s IBLT slab source was moved off the
// unbounded Go heap onto the per-engine bounded HamtArena. Before that move a
// caller that forgot to Release() its dstDigest leaked a ~24 KB bucket slab +
// ~48 B struct slab ON THE HEAP, where the GC silently reclaimed it; the leak
// was invisible. After the move the same forgotten Release draws the slab
// against the engine's 32 MiB arena and shows up as `HamtArena: OOM` at the
// round where the cumulative leak tips the bump pointer. The bug was ALWAYS in
// the callers; the bounded arena merely made it observable. This test closes
// the visible version by teaching the leaky caller (partition.go, the
// GossipOnce closure) the Release() discipline the engine always owed.
//
// This test is the 10K-round OOM drive. It drives partition.go's ACTUAL
// GossipOnce closure 10,000 times against a tight 2-engine fabric, NOT a
// hand-rolled replication. Driving the real orchestrator closure is
// load-bearing: a mutation that comments out partition.go's
// `defer dstDigest.Release()` bites BOTH this test AND the headline gate
// TestMerkleConvergenceAfterPartition RED via the SAME partition.go
// Release site. A hand-rolled inline replication would exercise its OWN
// release and could not bite on that mutation — defeating the two-axes safety
// net.
//
// The fabric is intentionally tiny and deterministic — zero drop, zero
// duplicate, 0 jitter, a 100µs delivery base just to schedule goroutines out
// of the inline path. Two engines keep the per-round cost at ~44µs (10K rounds
// in ~0.44s), so the forced-N=10000 fits comfortably under the -race gate's
// 15m timeout even with -race overhead. The arena is the SAME 32 MiB
// the chaos mesh uses at mesh_test.go — the size the regression originally
// tipped at the partition-heal round.
//
// Design rules:
// - the forced-N=10000 is non-negotiable; do NOT scale it back to 1000/100.
// - the loop gates on no-OOM-over-10K-rounds (do not gate on allocs/op here).
// - this test does NOT downgrade red and only t.Skip's under testing.Short().
// - it has NO raceEnabled guard (it is a forced-N drive small enough to fit
// in 15m under -race); it MUST PASS under -race at NumCPU cores.
//
// Each GossipOnce sweep drives RunGossipRound's full-mesh nested loop, so for
// a 2-engine net each round exchanges BOTH (A→B) and (B→A). That symmetry is
// the reclamation invariant: every engine takes BOTH the `from` role (its
// GenerateDelta advances its own EBR epoch via maybeAdvanceEpoch, crdt.go:1416)
// and the `to` role (its GenerateDigest allocates against its own arena; its
// dstDigest.Release retires the slab to its own EBR). A single fixed-direction
// loop would OOM the `to` engine on reclamation lag alone — NOT the leak this
// test exists to catch. The bidirectional sweep is exactly partition.go's
// real anti-entropy shape.
// ---------------------------------------------------------------------------

import (
	"context"
	"strconv"
	"testing"
	"time"

	engsync "github.com/hr18vk/sovereign/pkg/sync"
)

// TestChaosDigestReleaseRoundTrip is the 10K-round OOM drive.
// It drives partition.go's real GossipOnce closure 10,000 times against a
// 2-engine fabric on 32 MiB arenas. It PASSES iff all 10K rounds complete
// without a HamtArena panic — which they do iff partition.go's
// `defer dstDigest.Release()` is in place (dropping that line proves the converse).
func TestChaosDigestReleaseRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("digest-release OOM drive runs 10K GossipOnce rounds; skip in -short")
	}

	// Two engines — the (from, to) pair partition.go:221 exercises, mirrored
	// to both directions per RunGossipRound's full-mesh sweep.
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
	// the loop measures LEAK RATE, not correctness — 50 entries is enough.
	// Stack-buffered keys (strconv on a 16-byte nodeID cap) keep setup zero-
	// fmt.Sprintf on the test's own setup path (the hot-path discipline).
	for k := 0; k < 50; k++ {
		key := "seed-event-" + strconv.Itoa(k)
		srcEng.InsertLocal(key, engsync.CRDTEntry{SystemTime: int64(k)})
	}
	for k := 0; k < 50; k++ {
		key := "dst-event-" + strconv.Itoa(k)
		dstEng.InsertLocal(key, engsync.CRDTEntry{SystemTime: int64(k + 50)})
	}

	// Tight, deterministic fabric: zero loss / zero duplicate / 0 jitter so
	// the loop measures pure leak-accumulation against the bounded arena. The
	// 100µs delivery base schedules the per-node goroutines off the inline
	// send path (Send enqueues to a mailbox processed by an AddNode goroutine);
	// the round call returns immediately after the makeDelta closure ships,
	// so 10K rounds are ~44µs each at Tier-1, not gated on delivery latency.
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

	// The 10K-round forced-N drive. Each round is partition.go's real
	// GossipOnce: its closure calls dstEng.GenerateDigest() at line 221,
	// defers dstDigest.Release() at line 222, calls
	// srcEng.GenerateDelta(dstDigest), defers delta.Release(), and serializes
	// the delta's Entries. DROPPING that Release tips the
	// arena here; preserving it completes 10K rounds panic-free. This is the
	// two-axes safety net's runtime bite; the static source-side analysis is the other.
	ctx := context.Background()
	const rounds = 10000
	start := time.Now()
	for r := 0; r < rounds; r++ {
		if _, err := orch.GossipOnce(ctx); err != nil {
			t.Fatalf("digest-release OOM drive: GossipOnce round %d failed: %v", r, err)
		}
	}
	elapsed := time.Since(start)

	// Drain in-flight deliveries so t.Cleanup's net.Stop sees an honest net
	// state (the harness quiesces per-node goroutines; a noop RunGossipRound
	// tick advances the scheduler one last time without shipping traffic).
	_, _ = net.RunGossipRound(ctx, func(ctx context.Context, from, to [16]byte) ([]byte, error) {
		return nil, nil
	})

	t.Logf("digest-release OOM drive: %d GossipOnce rounds completed in %v (%v/round) without HamtArena panic — partition.go:222 dstDigest.Release held",
		rounds, elapsed, elapsed/time.Duration(rounds))
}
