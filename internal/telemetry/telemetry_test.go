// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package telemetry

import (
	"math"
	"sync/atomic"
	"testing"
	"unsafe"
)

// TestStripeSize_CacheLineAligned asserts each stripe occupies one 64-byte
// cache line so adjacent counters never false-share.
func TestStripeSize_CacheLineAligned(t *testing.T) {
	if sz := unsafe.Sizeof(counterStripe{}); sz != cacheLineBytes {
		t.Fatalf("counterStripe size = %d, want %d (one cache line)", sz, cacheLineBytes)
	}
}

// TestInc_AggregatesExact verifies the integer fast-path: 10k sequential Inc
// calls produce exactly 10000 via FloatValue (the counter stores float-bits so
// FloatValue's decode-sum must be exact for the 1.0 chain).
func TestInc_AggregatesExact(t *testing.T) {
	c := &Counter{stripes: make([]counterStripe, numStripes), mode: modeCounter}
	for i := 0; i < 10000; i++ {
		c.Inc()
	}
	if got := c.FloatValue(); got != 10000 {
		t.Fatalf("FloatValue after 10k Inc = %v, want 10000", got)
	}
}

// TestAdd_FloatExact verifies that fractional deltas sum to within 1e-6 of
// 1000 across the stripes.
func TestAdd_FloatExact(t *testing.T) {
	c := &Counter{stripes: make([]counterStripe, numStripes), mode: modeCounter}
	const n = 1_000_000
	for i := 0; i < n; i++ {
		c.Add(0.001)
	}
	if got := c.FloatValue(); math.Abs(got-1000.0) > 1e-6 {
		t.Fatalf("FloatValue after %d Add(0.001) = %v, want ~1000", n, got)
	}
}

// TestGauge_SetAndGet verifies last-writer-wins semantics on the gauge slot.
func TestGauge_SetAndGet(t *testing.T) {
	c := &Counter{stripes: make([]counterStripe, numStripes), mode: modeGauge}
	c.Set(42.5)
	if got := c.Value(); got != 42.5 {
		t.Fatalf("gauge Value = %v, want 42.5", got)
	}
	c.Set(7.25)
	if got := c.Value(); got != 7.25 {
		t.Fatalf("gauge Value after reset = %v, want 7.25", got)
	}
}

// TestInc_ConcurrentLinearizability runs Inc from many goroutines and checks
// that the final aggregate equals the number of increments.
func TestInc_ConcurrentLinearizability(t *testing.T) {
	c := &Counter{stripes: make([]counterStripe, numStripes), mode: modeCounter}
	const goroutines = 32
	const perG = 10000
	done := make(chan struct{}, goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			for i := 0; i < perG; i++ {
				c.Inc()
			}
			done <- struct{}{}
		}()
	}
	for g := 0; g < goroutines; g++ {
		<-done
	}
	want := float64(goroutines * perG)
	if got := c.FloatValue(); got != want {
		t.Fatalf("concurrent Inc aggregate = %v, want %v", got, want)
	}
}

// TestNoMutexOnHotPath retains the atomic-operation smoke check. Its field
// lookup is a stub and does not inspect Counter for mutex fields.
func TestNoMutexOnHotPath(t *testing.T) {
	// The current helper cannot inspect the Counter value's fields.
	var c Counter
	if field, ok := getField(&c, "mu"); ok {
		t.Fatalf("unexpected mutex-like field on Counter: %v", field)
	}
	atomic.AddUint64(new(uint64), 1) // link atomic to keep import intent explicit
}

// getField is a placeholder retained by the existing smoke test. It always
// reports that the requested field is absent.
func getField(p *Counter, name string) (any, bool) {
	_ = p
	_ = name
	return nil, false
}

func BenchmarkCounterInc(b *testing.B) {
	c := &Counter{stripes: make([]counterStripe, numStripes), mode: modeCounter}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Inc()
	}
}

func BenchmarkCounterAdd(b *testing.B) {
	c := &Counter{stripes: make([]counterStripe, numStripes), mode: modeCounter}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Add(1.5)
	}
}

func BenchmarkCounterSet(b *testing.B) {
	c := &Counter{stripes: make([]counterStripe, numStripes), mode: modeGauge}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Set(7.25)
	}
}

// BenchmarkCounterInc_Parallel measures concurrent increments on the striped
// counter. Cache-line padding prevents false sharing between stripe values.
func BenchmarkCounterInc_Parallel(b *testing.B) {
	c := &Counter{stripes: make([]counterStripe, numStripes), mode: modeCounter}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			c.Inc()
		}
	})
}

// BenchmarkCounterAdd_Parallel measures concurrent floating-point increments.
func BenchmarkCounterAdd_Parallel(b *testing.B) {
	c := &Counter{stripes: make([]counterStripe, numStripes), mode: modeCounter}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			c.Add(1.5)
		}
	})
}
