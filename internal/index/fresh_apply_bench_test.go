// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package index

// BenchmarkIndexApply_Fresh measures uncapped inserts of distinct entities.
// Each operation performs a global CAS reservation, a map insertion, and both
// cell and timestamp membership updates. Ingest benchmarks re-apply a fixed
// frame, so they reserve entities only during warmup and do not cover this
// cost. This is ingest-layer index maintenance, not CRDT core throughput.
// Every iteration adds an entity, so memory use grows as O(b.N).
import (
	"strconv"
	"sync/atomic"
	"testing"
)

func BenchmarkIndexApply_Fresh(b *testing.B) {
	ix := NewWith(DefaultShards, DefaultEpochNs)
	b.ReportAllocs()
	var n int64
	b.RunParallel(func(pb *testing.PB) {
		i := atomic.AddInt64(&n, 1) * 1_000_000_000
		for pb.Next() {
			i++
			ix.Apply(Record{EntityID: strconv.FormatInt(i, 10), H3Index: 0x8928308280fffff, SystemTime: i})
		}
	})
}
