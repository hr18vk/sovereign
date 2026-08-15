package receive

import (
	"testing"

	"github.com/hr18vk/supremum/pkg/attribution"
)

// ---------------------------------------------------------------------------
// Track 3.6 — G3.6.k RE-MEASURED RATIO (the track's headline output)
//
// This file re-runs the 3.5b Shape B reject benches against the v3 receiver
// and reports the new accept/reject ratio as a MEASURED number. The 3.5b
// bench MEASURED ~300x (the reject-path floor was a ~1 us capnp decode in
// readGateFields); the v3 lift moves the gate fields to the header, so the
// reject-path floor drops to two fixed-offset slice reads (tens of ns). The
// track's job is to convert "~300x" into a new measured figure; whether it is
// ~500x or hits ~1000x is a NUMBER this box PRODUCES, not one this doc
// predicts. If the new ratio is, say, only 400x because UnmarshalRelayEnvelope's
// parsing cost now dominates the reject path, that is the honest finding —
// reported, not goalpost-tuned.
//
// The benches drive the FULL HandleFrame composition over v3 frames (built via
// benchBuildFrame, which now binds the v3 header mirrors). They do NOT bypass
// HandleFrame (§0: a test that drives gates directly is BANNED). The cheap
// rejects MUST run against the HEADER dotCounter (the v3 mirror), NOT a capnp
// decode — asserted by the in-body VerifyHookCount==0 check (G3.6.f).
//
// GEAR TAG (HONEST): _4c. This box is GOMAXPROCS=4, CPU part 0xd40
// (Graviton3-era). It is NOT c8g.8xlarge at 32c. The "_4c" suffix is the
// HONEST gear tag; the 32c figures cited separately are Track 4's PROVEN
// publication numbers, NOT a 4c re-measurement.
// ---------------------------------------------------------------------------

// BenchmarkTrack36_DropDepth_4c re-measures the depth-exceed drop path against
// the v3 receiver: a 3-hop frame under a 30us budget (MaxHopsForBudget=0) is
// dropped at the 3.2 depth check with ZERO Verify calls. The v3 lift does NOT
// change the depth path's cost (the depth check reads the hop count, not the
// gate fields), so this bench is the control: it should match the 3.5b
// DropDepth figure within noise. The headline is the rate/clock benches below
// (those are the paths the v3 header read accelerates).
func BenchmarkTrack36_DropDepth_4c(b *testing.B) {
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
		b.Fatalf("G3.6.f: depth reject must issue ZERO Verify calls under bench load, got %d", got)
	}
	if ns := benchNsPerOp(b); ns > 0 {
		b.ReportMetric(float64(1e9)/float64(ns), "frames/sec")
	}
}

// BenchmarkTrack36_DropRate_4c re-measures the rate-exceed drop path against
// the v3 receiver: a MaxUint64 header dotCounter drains the peer bucket to 0,
// so Accept returns Drop BEFORE Open (zero Verifies). The v3 lift accelerates
// THIS path: the rate gate reads the HEADER dotCounter (O(1)), not a capnp
// decode, so the reject-path floor drops from ~1 us to tens of ns. The
// reported frames/sec is the v3 number; the ratio vs Shape A accept is the
// track's headline.
func BenchmarkTrack36_DropRate_4c(b *testing.B) {
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
		b.Fatalf("G3.6.f: rate reject must issue ZERO Verify calls under bench load (cheap gate reads the header mirror, not a capnp decode), got %d", got)
	}
	if ns := benchNsPerOp(b); ns > 0 {
		b.ReportMetric(float64(1e9)/float64(ns), "frames/sec")
	}
}

// BenchmarkTrack36_AcceptStream_4c measures the end-to-end ACCEPT cost of the
// v3 receiver: a valid 3-hop frame with a valid dotCounter (7) passes all
// cheap gates, passes Open (Ed25519 Verify), passes VerifyCRDTFrame, and
// reaches Accept. This is the Shape A accept path against which the Shape B
// reject paths (DropRate, DropClock) are ratioed. The v3 lift does NOT
// accelerate the accept path (it still pays the capnp decode + Ed25519 Verify
// for the inner payload), so this number should be comparable to the 3.5b
// AcceptStream figure (~300 us/op on this box). The headline ratio is
// AcceptStream_ns / DropRate_ns (and DropClock_ns).
func BenchmarkTrack36_AcceptStream_4c(b *testing.B) {
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
	// Accept path MUST call Verify (Ed25519 on inner payload). The exact count
	// depends on hop count (3 hops = 3 verifies for the relay chain + 1 for
	// the origin = 4). We assert >= 1 to prove the accept path is real.
	if got := count.Load(); got < 1 {
		b.Fatalf("G3.6.f: accept path MUST call Verify (Ed25519 on inner payload), got %d", got)
	}
	if ns := benchNsPerOp(b); ns > 0 {
		b.ReportMetric(float64(1e9)/float64(ns), "frames/sec")
	}
}

// BenchmarkTrack36_DropClock_4c re-measures the clock-future drop path
// against the v3 receiver: the last hop's WallUSec is 3000us ahead of the
// local clock (beyond the 2ms epsilon), so IngressHLCScalarCap.Admit rejects
// BEFORE Open (zero Verifies). Like DropRate, the v3 lift accelerates this
// path (the clock gate reads the HEADER dotCounter, O(1)).
func BenchmarkTrack36_DropClock_4c(b *testing.B) {
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
		b.Fatalf("G3.6.f: clock reject must issue ZERO Verify calls under bench load (cheap gate reads the header mirror, not a capnp decode), got %d", got)
	}
	if ns := benchNsPerOp(b); ns > 0 {
		b.ReportMetric(float64(1e9)/float64(ns), "frames/sec")
	}
}
