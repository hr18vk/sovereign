// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package receive

// The batch-accept cost of the index feed, measured ON vs OFF over the
// HandleBatchFrame path (the silicon 32c gate re-runs these; the estimate
// was +11.8% batch-accept from the light decode ~19.3 µs/batch over the
// ~163 µs the accept already pays). The OFF bench is the nil-feeder posture;
// the ON bench wires the SetIndexFeeder seam to a real index. Same signed
// frame, same receiver shape as BenchmarkBatchedVerifyParallel
// (bench_silicon_test.go). Layer: ingest (the 5.7M–6.0M deltas/sec @32c
// receive layer), not the core scaling-gate test — the index is off that path.

import (
	"fmt"
	"testing"

	"github.com/cloudflare/circl/sign/ed25519"
	"github.com/hr18vk/sovereign/internal/index"
)

// gateRun runs one ON-or-OFF accept-parallel leg at a fixed N (the
// benchSiliconBatchSizes shapes; the report judges the delta).
func gateRun(b *testing.B, n int, wire bool) {
	originPub, originPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		b.Fatalf("ed25519.GenerateKey: %v", err)
	}
	dataDir := b.TempDir()
	recv := newBenchReceiver(b, originPub, dataDir)
	if wire {
		ix := index.NewWith(index.DefaultShards, index.DefaultEpochNs)
		recv.SetIndexFeeder(func(entityID string, h3Index uint64, systemTime int64) {
			ix.Apply(index.Record{EntityID: entityID, H3Index: h3Index, SystemTime: systemTime})
		})
	}
	frame := makeSignedFrame(b, recv, originPriv.Seed(), n)
	b.ReportAllocs()
	b.SetBytes(int64(n))
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if v := recv.HandleBatchFrame(frame); v.Verdict != Accept {
				b.Fatalf("HandleBatchFrame: %s (%v)", v.Verdict, v.Reason)
			}
		}
	})
}

// BenchmarkIngestGateFeedOff — the base posture: nil feeder (one dead branch
// per accept). The baseline the ON legs are judged against.
func BenchmarkIngestGateFeedOff(b *testing.B) {
	for _, n := range []int{10, 100} {
		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) { gateRun(b, n, false) })
	}
}

// BenchmarkIngestGateFeedOn — the armed posture: the seam wired
// to a real index; every accepted batch light-decodes and folds N records.
func BenchmarkIngestGateFeedOn(b *testing.B) {
	for _, n := range []int{10, 100} {
		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) { gateRun(b, n, true) })
	}
}
