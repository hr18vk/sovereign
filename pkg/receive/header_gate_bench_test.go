// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package receive

import (
	"testing"

	"github.com/hr18vk/sovereign/pkg/attribution"
)

// ---------------------------------------------------------------------------
// This file re-runs the Shape B reject benchmarks against the v3 receiver
// and reports the new accept/reject ratio. The Shape B benchmarks measured
// approximately 300x (the reject-path floor was a ~1 µs capnp decode in
// readGateFields); the v3 lift moves the gate fields to the header, so the
// reject-path floor drops to two fixed-offset slice reads (tens of ns).
// Whether the new ratio is ~500x or ~1000x is a number the benchmarks produce,
// not one this comment predicts. If the ratio is only 400x because
// UnmarshalRelayEnvelope's parsing cost now dominates the reject path, that
// is the finding — reported, not goalpost-tuned.
//
// The benchmarks drive the full HandleFrame composition over v3 frames (built
// via benchBuildFrame, which binds the v3 header mirrors). They do not bypass
// HandleFrame; a test that drives gates directly is not representative. The
// cheap rejects must run against the header dotCounter (the v3 mirror), not a
// capnp decode — asserted by the in-body VerifyHookCount==0 check.
//
// Gear tag: _4c. This box runs GOMAXPROCS=4 on a CPU part 0xd40
// (Graviton3-era). It is not a c8g.8xlarge at 32 cores. The "_4c" suffix is
// the gear tag; the 32-core figures cited separately are the proven
// publication numbers from the 32-core benchmark, not a 4-core re-measurement.
// ---------------------------------------------------------------------------

// BenchmarkDropDepth_4c measures the depth-exceed drop path against the v3
// receiver: a 3-hop frame under a 30 µs budget (MaxHopsForBudget=0) is dropped
// at the depth check with zero Verify calls. The v3 lift does not change the
// depth path's cost (the depth check reads the hop count, not the gate fields),
// so this benchmark is the control: it should match the previous DropDepth
// figure within noise. The headline is the rate and clock benchmarks below
// (those are the paths the v3 header read accelerates).
func BenchmarkDropDepth_4c(b *testing.B) {
	benchOverrideDataDirToTmpfs(b)
	originPub, originPriv := benchSetupOrigin(b)
	relayPubs, relayPrivs := benchFixedRelayKeys(b, benchHops)
	const budgetNS = int64(30 * 1000) // 30us -> MaxHopsForBudget=0
	r, _, _, _ := setupReceiver(b, benchWallBase, budgetNS, originPub)
	frame := benchBuildFrame(b, 7, originPriv, relayPrivs, relayPubs)

	count := new(attribution.VerifyHookCount)
	attribution.SetVerifyHook(count.Hook)
	defer attribution.ClearVerifyHook()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v := r.HandleFrame(frame)
		if v.Verdict != DropDepth {
			b.Fatalf("depth bench must DropDepth, got %v: %v", v.Verdict, v.Reason)
		}
	}
	b.StopTimer()
	if got := count.Load(); got != 0 {
		b.Fatalf("depth reject must issue zero Verify calls under bench load, got %d", got)
	}
	if ns := benchNsPerOp(b); ns > 0 {
		b.ReportMetric(float64(1e9)/float64(ns), "frames/sec")
	}
}

// BenchmarkDropRate_4c measures the rate-exceed drop path against the v3
// receiver: a MaxUint64 header dotCounter drains the peer bucket to zero, so
// Accept returns Drop before Open (zero Verifies). The v3 lift accelerates
// this path: the rate gate reads the header dotCounter (O(1)), not a capnp
// decode, so the reject-path floor drops from ~1 µs to tens of ns. The
// reported frames/sec is the v3 number; the ratio versus Shape A accept is the
// headline.
func BenchmarkDropRate_4c(b *testing.B) {
	benchOverrideDataDirToTmpfs(b)
	originPub, originPriv := benchSetupOrigin(b)
	relayPubs, relayPrivs := benchFixedRelayKeys(b, benchHops)
	r, _, _, _ := setupReceiver(b, benchWallBase, benchBudgetNS, originPub)
	frame := benchBuildFrame(b, MaxUint64DotCounter, originPriv, relayPrivs, relayPubs)

	count := new(attribution.VerifyHookCount)
	attribution.SetVerifyHook(count.Hook)
	defer attribution.ClearVerifyHook()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v := r.HandleFrame(frame)
		if v.Verdict != DropRate {
			b.Fatalf("rate bench must DropRate, got %v: %v", v.Verdict, v.Reason)
		}
	}
	b.StopTimer()
	if got := count.Load(); got != 0 {
		b.Fatalf("rate reject must issue zero Verify calls under bench load (cheap gate reads the header mirror, not a capnp decode), got %d", got)
	}
	if ns := benchNsPerOp(b); ns > 0 {
		b.ReportMetric(float64(1e9)/float64(ns), "frames/sec")
	}
}

// BenchmarkAcceptStream_4c measures the end-to-end accept cost of the v3
// receiver: a valid 3-hop frame with a valid dotCounter (7) passes all cheap
// gates, passes Open (Ed25519 Verify), passes VerifyCRDTFrame, and reaches
// Accept. This is the Shape A accept path against which the Shape B reject
// paths (DropRate, DropClock) are ratioed. The v3 lift does not accelerate
// the accept path (it still pays the capnp decode and Ed25519 Verify for the
// inner payload), so this number should be comparable to the previous
// AcceptStream figure (~300 µs/op on this box). The headline ratio is
// AcceptStream_ns / DropRate_ns (and DropClock_ns).
func BenchmarkAcceptStream_4c(b *testing.B) {
	benchOverrideDataDirToTmpfs(b)
	originPub, originPriv := benchSetupOrigin(b)
	relayPubs, relayPrivs := benchFixedRelayKeys(b, benchHops)
	r, _, _, _ := setupReceiver(b, benchWallBase, benchBudgetNS, originPub)
	frame := benchBuildFrame(b, 7, originPriv, relayPrivs, relayPubs)

	count := new(attribution.VerifyHookCount)
	attribution.SetVerifyHook(count.Hook)
	defer attribution.ClearVerifyHook()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v := r.HandleFrame(frame)
		if v.Verdict != Accept {
			b.Fatalf("accept bench must Accept, got %v: %v", v.Verdict, v.Reason)
		}
	}
	b.StopTimer()
	// Accept path must call Verify (Ed25519 on inner payload). The exact count
	// depends on hop count (3 hops = 3 verifies for the relay chain + 1 for
	// the origin = 4). We assert >= 1 to prove the accept path is real.
	if got := count.Load(); got < 1 {
		b.Fatalf("accept path must call Verify (Ed25519 on inner payload), got %d", got)
	}
	if ns := benchNsPerOp(b); ns > 0 {
		b.ReportMetric(float64(1e9)/float64(ns), "frames/sec")
	}
}

// BenchmarkDropClock_4c measures the clock-future drop path against the v3
// receiver: the last hop's WallUSec is 3000 µs ahead of the local clock
// (beyond the 2 ms epsilon), so IngressHLCScalarCap.Admit rejects before Open
// (zero Verifies). Like DropRate, the v3 lift accelerates this path (the clock
// gate reads the header dotCounter, O(1)).
func BenchmarkDropClock_4c(b *testing.B) {
	benchOverrideDataDirToTmpfs(b)
	originPub, originPriv := benchSetupOrigin(b)
	relayPubs, relayPrivs := benchFixedRelayKeys(b, benchHops)
	r, _, _, _ := setupReceiver(b, benchWallBase-3000, benchBudgetNS, originPub)
	frame := benchBuildFrame(b, 7, originPriv, relayPrivs, relayPubs)

	count := new(attribution.VerifyHookCount)
	attribution.SetVerifyHook(count.Hook)
	defer attribution.ClearVerifyHook()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v := r.HandleFrame(frame)
		if v.Verdict != DropClock {
			b.Fatalf("clock bench must DropClock, got %v: %v", v.Verdict, v.Reason)
		}
	}
	b.StopTimer()
	if got := count.Load(); got != 0 {
		b.Fatalf("clock reject must issue zero Verify calls under bench load (cheap gate reads the header mirror, not a capnp decode), got %d", got)
	}
	if ns := benchNsPerOp(b); ns > 0 {
		b.ReportMetric(float64(1e9)/float64(ns), "frames/sec")
	}
}
