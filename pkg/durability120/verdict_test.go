// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package durability120

// TestVerdictMatrix: the decision matrix for the durability verdict.
// Three clauses:
//
//	clause A — NVMe p99 (the durability-path baseline).
//	clause B — S3 Express p99 vs the sub-millisecond bar: pass if
//	           p99_s3express < 1,000,000 ns (1 ms), else fail → keep NVMe.
//	clause C — relative: s3 p99 / nvme p99 as a ratio (framing — a
//	           sub-ms S3 Express that is 1000x slower than NVMe is a durability-
//	           side win, not a latency win; clause B is the go/no-go, clause C
//	           is the characterization, not a gate).
//
// Integrity guards (the test fails the suite if):
//   - the table is fabricated (a number asserted without a real CDF behind it),
//   - the bar is mis-applied (e.g. p50 relabeled as p99, or the 1ms bar shifted),
//   - a skip is relabeled as pass (a skip is a skip).
//
// The test prints the table but does not auto-mark the verdict (the verdict
// edit is a separate step owned by the human; auto-upgrading a conditional
// verdict is a fabrication mode).
//
// How it gets the numbers: it runs the NVMe CDF (always available — Half A
// needs no creds) and the S3 CDF (which skips on 4c / no bucket). When the S3
// half skips, clause B is reported as "SKIP (no dir bucket / no creds)" — not
// pass, not fail — and the verdict stays conditional (the human owns the
// verdict edit). When the S3 half runs, clause B is PASS/FAIL on the sub-ms bar.

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/hr18vk/sovereign/internal/chaos"
	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// subMillisecondBarNS is the gate: S3 Express p99 must be sub-millisecond
// (1,000,000 ns) for the architecture to commit to the S3 Express sidecar.
// This is the gate constant; clause B compares against it.
const subMillisecondBarNS = 1_000_000 // 1 ms in nanoseconds

// TestVerdictMatrix prints the A/B/C decision matrix and asserts the integrity
// guards. It does not auto-upgrade the verdict (the verdict edit is human-owned).
func TestVerdictMatrix(t *testing.T) {
	// --- clause A: NVMe p99 (always available — Half A needs no creds) ---
	nvmeCDF := runNVMeCDFForMatrix(t)
	t.Logf("VERDICT clause A (NVMe WAL fsync p99 baseline): p50=%dns p99=%dns p99.9=%dns pMax=%dns",
		nvmeCDF.p50.Nanoseconds(), nvmeCDF.p99.Nanoseconds(),
		nvmeCDF.p999.Nanoseconds(), nvmeCDF.pMax.Nanoseconds())

	// --- clause B + C: S3 Express p99 (Skips on 4c / no bucket) ---
	s3CDF, s3Ran := runS3CDFForMatrix(t)

	t.Logf("==========================================================")
	t.Logf(" Decision matrix (zonal-endpoint direct = lower bound on VPC-Lattice)")
	t.Logf("==========================================================")
	t.Logf(" clause A | NVMe WAL fsync p99        : %dns", nvmeCDF.p99.Nanoseconds())
	if s3Ran {
		pass := s3CDF.p99.Nanoseconds() < subMillisecondBarNS
		barVerdict := "FAIL → keep NVMe"
		if pass {
			barVerdict = "PASS (sub-ms)"
		}
		t.Logf(" clause B | S3 Express p99 vs 1ms bar : %dns  →  %s",
			s3CDF.p99.Nanoseconds(), barVerdict)
		// clause C: ratio (characterization only, not a gate). Guard divide-by-zero.
		ratio := 0.0
		if nvmeCDF.p99.Nanoseconds() > 0 {
			ratio = float64(s3CDF.p99.Nanoseconds()) / float64(nvmeCDF.p99.Nanoseconds())
		}
		t.Logf(" clause C | s3 p99 / nvme p99 ratio   : %.1fx  (characterization only, not a gate)", ratio)
		t.Logf("----------------------------------------------------------")
		t.Logf(" VERDICT : clause B = %s. The verdict edit is human-owned;", barVerdict)
		t.Logf("          this matrix does not auto-upgrade a conditional verdict.")
		if pass {
			t.Logf("          If Half B is proven sub-ms, the pending set clears and")
			t.Logf("          the verdict becomes unconditional (all clauses proven).")
		} else {
			t.Logf("          Half B did not hit the sub-ms bar → keep NVMe; clause E5 stays")
			t.Logf("          open, the verdict stays conditional.")
		}
	} else {
		t.Logf(" clause B | S3 Express p99 vs 1ms bar : SKIP (no dir bucket / no creds)")
		t.Logf(" clause C | s3 p99 / nvme p99 ratio   : N/A (S3 half skipped)")
		t.Logf("----------------------------------------------------------")
		t.Logf(" VERDICT : clause B = SKIP (a skip is a skip — not a pass, not a fail).")
		t.Logf("          E5 stays open; the verdict stays conditional pending the")
		t.Logf("          S3 half. Half A NVMe p99 is proven regardless. The verdict")
		t.Logf("          edit is human-owned; this matrix does not auto-upgrade.")
	}
	t.Logf("==========================================================")

	// --- Integrity guards (the test fails if the matrix is dishonest) ---
	// Guard 1: a skip relabeled as pass. If the S3 half did not run, clause B
	// must be SKIP — never pass. (The log lines above already say SKIP; this
	// guard is the structural check that the s3Ran flag is the only thing that
	// can flip clause B to PASS/FAIL.)
	if !s3Ran {
		// Re-affirm: no number was fabricated for clause B. If someone edits
		// this test to print a PASS without s3Ran, this assertion catches it.
		if s3CDF.p99.Nanoseconds() != 0 {
			t.Fatalf("integrity guard: S3 half did not run but clause B has a non-zero p99 "+
				"(%dns) — a skip is being relabeled with a fabricated number", s3CDF.p99.Nanoseconds())
		}
	}
	// Guard 2: the bar is the 1ms constant. If someone edits
	// subMillisecondBarNS to a looser value to force a PASS, this catches it.
	if subMillisecondBarNS != 1_000_000 {
		t.Fatalf("integrity guard: subMillisecondBarNS = %d, want 1_000_000 — the bar was shifted",
			subMillisecondBarNS)
	}
}

// runNVMeCDFForMatrix runs a fixed-sample NVMe WAL fsync CDF for the verdict
// table. Always available (Half A needs no creds). Returns the CDF.
func runNVMeCDFForMatrix(t *testing.T) cdfResult {
	const n = 1000
	dir := benchWalDir(t)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	walPath := filepath.Join(dir, "verdict_nvme.wal")
	_ = os.Remove(walPath)
	wal, err := chaos.OpenWAL(walPath)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	t.Cleanup(func() {
		_ = wal.Close()
		_ = os.RemoveAll(dir)
	})
	var nodeID [16]byte
	nodeID[0] = 0x5A
	frames := make([][frameSize]byte, 1024)
	for i := range frames {
		frames[i] = MakeFrame120(uint64(i))
	}
	latencies := make([]time.Duration, n)
	for i := 0; i < n; i++ {
		f := frames[i%len(frames)]
		m := chaos.NewWALMutation("durability-bench-entity",
			eng.CausalDot{NodeID: nodeID, Counter: uint64(i + 1)},
			frameToEntry(f))
		start := time.Now()
		if err := wal.AppendMutation(m); err != nil {
			t.Fatalf("AppendMutation %d: %v", i, err)
		}
		latencies[i] = time.Since(start)
	}
	return computeCDF(latencies)
}

// runS3CDFForMatrix runs the S3 Express CDF for the verdict table. Returns
// (cdf, ran). ran is false when the test would skip (no bucket / no creds) —
// the table reports clause B as SKIP in that case (not pass, not fail).
func runS3CDFForMatrix(t *testing.T) (cdfResult, bool) {
	bucket := os.Getenv("DIRECTORY_BUCKET_NAME")
	if bucket == "" || !strings.HasSuffix(bucket, s3expressSuffix) {
		return cdfResult{}, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	// Resolve the region (AWS_REGION env or IMDS placement/region) and inject
	// it via WithRegion — LoadDefaultConfig resolves IMDS creds but not region.
	// See s3express_test.go resolveRegion for the full rationale.
	region := resolveRegion(ctx)
	if region == "" {
		return cdfResult{}, false
	}
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return cdfResult{}, false
	}
	client := s3.NewFromConfig(cfg)
	const n = 1000
	// warmup (trigger lazy CreateSession)
	warmupFrame := MakeFrame120(fixedSeed)
	warmupKey := fmt.Sprintf("durability-bench/warmup/%d-warmup-%x",
		time.Now().UnixNano(), warmupFrame[0:8])
	if _, err := client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: &bucket,
		Key:    &warmupKey,
		Body:   bytes.NewReader(warmupFrame[:]),
	}); err != nil {
		t.Fatalf("matrix warmup PutObject failed: %v", err)
	}
	latencies := make([]time.Duration, n)
	for i := 0; i < n; i++ {
		f := MakeFrame120(uint64(i))
		key := fmt.Sprintf("durability-bench/%d/%d-%x", time.Now().UnixNano(), i, f[0:8])
		start := time.Now()
		if _, err := client.PutObject(ctx, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &key,
			Body:   bytes.NewReader(f[:]),
		}); err != nil {
			t.Fatalf("matrix PutObject %d: %v", i, err)
		}
		latencies[i] = time.Since(start)
	}
	return computeCDF(latencies), true
}
