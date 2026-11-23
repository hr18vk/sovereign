// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package durability120

// The CDF helper shared by both halves (NVMe WAL + S3 Express).
//
// The p99 gate is a sub-millisecond bar, so the mean is not enough. This
// computes p50/p99/p99.9/pMax from a []time.Duration sample by sorting +
// indexed pick (no external dependency — a tiny vendored implementation).
//
// The percentile uses the nearest-rank method (no interpolation): for a sample of
// n sorted latencies, the p-th percentile is the value at index
// ceil(p/100 * n) - 1 (1-indexed rank r = ceil(p/100 * n), 0-indexed r-1). This
// is the standard nearest-rank CDF and is what the verdict table parses.

import (
	"sort"
	"time"
)

// cdfResult holds the four percentiles the verdict matrix reports.
type cdfResult struct {
	p50  time.Duration
	p99  time.Duration
	p999 time.Duration
	pMax time.Duration
	n    int
}

// computeCDF sorts the latency sample (in place — the caller's slice is
// reordered) and returns the nearest-rank p50/p99/p99.9/pMax. An empty sample
// returns all-zero durations (the caller must guard n>0 before publishing).
func computeCDF(latencies []time.Duration) cdfResult {
	if len(latencies) == 0 {
		return cdfResult{}
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	return cdfResult{
		p50:  percentile(latencies, 50),
		p99:  percentile(latencies, 99),
		p999: percentile(latencies, 99.9),
		pMax: latencies[len(latencies)-1],
		n:    len(latencies),
	}
}

// percentile returns the nearest-rank p-th percentile of a SORTED sample.
// rank r = ceil(p/100 * n), 0-indexed r-1, clamped to [0, n-1].
func percentile(sorted []time.Duration, p float64) time.Duration {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	rank := int(p/100.0*float64(n) + 0.999999) // ceil(p/100 * n)
	if rank < 1 {
		rank = 1
	}
	if rank > n {
		rank = n
	}
	return sorted[rank-1]
}
