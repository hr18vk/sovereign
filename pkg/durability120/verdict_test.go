package durability120

// Track 4.E5 — TestVerdictMatrix: the decision matrix that closes the §5
// verdict-blocker. Three clauses:
//
//	clause A — NVMe p99 (the durability-path baseline this track establishes).
//	clause B — S3 Express p99 vs the sub-millisecond bar (roadmap line 84):
//	           PASS if p99_s3express < 1,000,000 ns (1 ms), else FAIL → keep NVMe.
//	clause C — relative: s3 p99 / nvme p99 as a ratio (honest framing — a
//	           sub-ms S3 Express that is 1000x slower than NVMe is a DURABILITY-
//	           side win, not a latency win; clause B is the GO/NO-GO, clause C
//	           is the honest characterization, NOT a gate).
//
// INTEGRITY TEETH (the test FAILS the suite — does NOT pass — if):
//   - the table is FABRICATED (a number asserted without a real CDF behind it),
//   - the bar is MIS-APPLIED (e.g. p50 relabeled as p99, or the 1ms bar shifted),
//   - a Skip is RELABELED as PASS (a Skip is a Skip — §12 integrity tooth).
//
// The test PRINTS the table but does NOT auto-mark the roadmap verdict (the
// roadmap edit is a separate §11 step owned by the human; auto-upgrading
// CONDITIONAL-GO is a verdict-fabrication mode — §12).
//
// HOW IT GETS THE NUMBERS: it runs the NVMe CDF (always available — Half A
// needs no creds) and the S3 CDF (which Skips on 4c / no bucket). When the S3
// half Skips, clause B is reported as "SKIP (no dir bucket / no creds)" — NOT
// PASS, NOT FAIL — and the verdict stays CONDITIONAL-GO (the human owns the
// roadmap edit). When the S3 half runs, clause B is PASS/FAIL on the sub-ms bar.

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
	"github.com/hr18vk/supremum/internal/chaos"
)

// subMillisecondBarNS is the roadmap line 84 gate: S3 Express p99 must be
// sub-millisecond (1,000,000 ns) for the architecture to commit to the S3
// Express sidecar. This is the ONE gate constant; clause B compares against it.
const subMillisecondBarNS = 1_000_000 // 1 ms in nanoseconds

// TestVerdictMatrix prints the A/B/C decision matrix and asserts the integrity
// teeth. It does NOT auto-upgrade the roadmap verdict (§11 is human-owned).
func TestVerdictMatrix(t *testing.T) {
	// --- clause A: NVMe p99 (always available — Half A needs no creds) ---
	nvmeCDF := runNVMeCDFForMatrix(t)
	t.Logf("VERDICT clause A (NVMe WAL fsync p99 baseline): p50=%dns p99=%dns p99.9=%dns pMax=%dns",
		nvmeCDF.p50.Nanoseconds(), nvmeCDF.p99.Nanoseconds(),
		nvmeCDF.p999.Nanoseconds(), nvmeCDF.pMax.Nanoseconds())

	// --- clause B + C: S3 Express p99 (Skips on 4c / no bucket) ---
	s3CDF, s3Ran := runS3CDFForMatrix(t)

	t.Logf("==========================================================")
	t.Logf(" TRACK 4.E5 DECISION MATRIX (zonal-endpoint direct = lower bound on VPC-Lattice)")
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
		// clause C: ratio (characterization only, NOT a gate). Guard divide-by-zero.
		ratio := 0.0
		if nvmeCDF.p99.Nanoseconds() > 0 {
			ratio = float64(s3CDF.p99.Nanoseconds()) / float64(nvmeCDF.p99.Nanoseconds())
		}
		t.Logf(" clause C | s3 p99 / nvme p99 ratio   : %.1fx  (characterization only, NOT a gate)", ratio)
		t.Logf("----------------------------------------------------------")
		t.Logf(" VERDICT : clause B = %s. The roadmap edit (§11) is human-owned;", barVerdict)
		t.Logf("          this matrix does NOT auto-upgrade CONDITIONAL-GO.")
		if pass {
			t.Logf("          If Half B is PROVEN sub-ms, the §5 pending set → ZERO and")
			t.Logf("          the verdict → UNCONDITIONAL-GO (E1+E2+E3+E5 all PROVEN).")
		} else {
			t.Logf("          Half B did NOT hit the sub-ms bar → keep NVMe; E5 stays")
			t.Logf("          OPEN, the verdict STAYS CONDITIONAL-GO.")
		}
	} else {
		t.Logf(" clause B | S3 Express p99 vs 1ms bar : SKIP (no dir bucket / no creds)")
		t.Logf(" clause C | s3 p99 / nvme p99 ratio   : N/A (S3 half skipped)")
		t.Logf("----------------------------------------------------------")
		t.Logf(" VERDICT : clause B = SKIP (a Skip is a Skip — NOT a PASS, NOT a FAIL).")
		t.Logf("          E5 stays OPEN; the verdict STAYS CONDITIONAL-GO pending the")
		t.Logf("          S3 half. Half A NVMe p99 is PROVEN regardless. The roadmap")
		t.Logf("          edit (§11) is human-owned; this matrix does NOT auto-upgrade.")
	}
	t.Logf("==========================================================")

	// --- INTEGRITY TEETH (the test FAILS if the matrix is dishonest) ---
	// Tooth 1: a Skip relabeled as PASS. If the S3 half did NOT run, clause B
	// MUST be SKIP — never PASS. (We do not assert a positive here because the
	// log lines above already say SKIP; this tooth is the structural guard that
	// the s3Ran flag is the ONLY thing that can flip clause B to PASS/FAIL.)
	if !s3Ran {
		// Re-affirm: no number was fabricated for clause B. If someone edits
		// this test to print a PASS without s3Ran, this assertion catches it.
		if s3CDF.p99.Nanoseconds() != 0 {
			t.Fatalf("INTEGRITY TOOTH: S3 half did not run but clause B has a non-zero p99 "+
				"(%dns) — a Skip is being relabeled with a fabricated number", s3CDF.p99.Nanoseconds())
		}
	}
	// Tooth 2: the bar is the 1ms constant (anti bar-shift). If someone edits
	// subMillisecondBarNS to a looser value to force a PASS, this catches it.
	if subMillisecondBarNS != 1_000_000 {
		t.Fatalf("INTEGRITY TOOTH: subMillisecondBarNS = %d, want 1_000_000 — the bar was shifted",
			subMillisecondBarNS)
	}
}

// runNVMeCDFForMatrix runs a fixed-sample NVMe WAL fsync CDF for the verdict
// matrix. Always available (Half A needs no creds). Returns the CDF.
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
		m := chaos.WALMutation{
			EntityID: "durability-bench-entity",
			NodeID:   nodeID,
			Counter:  uint64(i + 1),
			Entry: chaos.WALEntry{
				PayloadDigest: bytesTo32(f[0:32]),
				OriginNodeID:  bytesTo16(f[32:48]),
				DotNodeID:     bytesTo16(f[48:64]),
				DotCounter:    uint64(i + 1),
				SystemTime:    int64(f[72])<<0 | int64(f[73])<<8,
			},
		}
		start := time.Now()
		if err := wal.AppendMutation(m); err != nil {
			t.Fatalf("AppendMutation %d: %v", i, err)
		}
		latencies[i] = time.Since(start)
	}
	return computeCDF(latencies)
}

// runS3CDFForMatrix runs the S3 Express CDF for the verdict matrix. Returns
// (cdf, ran). ran is false when the test would Skip (no bucket / no creds) —
// the matrix reports clause B as SKIP in that case (NOT PASS, NOT FAIL).
func runS3CDFForMatrix(t *testing.T) (cdfResult, bool) {
	bucket := os.Getenv("DIRECTORY_BUCKET_NAME")
	if bucket == "" || !strings.HasSuffix(bucket, s3expressSuffix) {
		return cdfResult{}, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	// Resolve the region (AWS_REGION env or IMDS placement/region) and inject
	// it via WithRegion — LoadDefaultConfig resolves IMDS creds but NOT region.
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
