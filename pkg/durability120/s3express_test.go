package durability120

// Track 4.E5 Half B — TestS3ExpressPut_CDF: the S3 Express directory-bucket
// PutObject latency CDF, head-to-head against the NVMe WAL fsync (Half A).
//
// WHY A TEST, NOT A BENCHMARK (load-bearing idiom choice): a 100µs-1ms network
// RTT under testing.B's b.N mean re-stabilization is the WRONG idiom for a p99
// gate. b.N ramps to find a stable MEAN; a p99 gate needs a FIXED sample size
// so the tail is characterized, not averaged away. So this is a fixed 1000-
// sample Test (the same shape as TestFsyncWAL_CDF), NOT a Benchmark.
//
// GATING (the safe-on-4c contract): the test Skips (NOT fails) if
//   - os.Getenv("DIRECTORY_BUCKET_NAME") == "" (no dir bucket provisioned), OR
//   - config.LoadDefaultConfig fails to resolve creds (IMDS not available — the
//     4c canonical box has no instance profile).
// A plain t.Skip is the gate (NOT a build tag — the E3-precursor mistake was a
// build-tag asymmetry; this track uses a plain Skip so `go build ./pkg/
// durability120/` works on 4c without a tag and the test Skips cleanly).
//
// SDK ANTI-FAB (§5 — every symbol below was grep-verified in the module cache
// at $(go env GOMODCACHE)/github.com/aws/aws-sdk-go-v2/service/s3@v1.104.1 THIS
// TURN; the citations are pasted above each call site so the audit can
// re-verify without re-deriving):
//   api_op_PutObject.go:158  func (c *Client) PutObject(ctx, *PutObjectInput, ...func(*Options)) (*PutObjectOutput, error)
//   api_op_PutObject.go:173  type PutObjectInput struct { ... :211 Bucket *string; :216 Key *string; :248 Body io.Reader }
//   express_user_agent.go:27 const expressSuffix = "--x-s3"  // :30 HasSuffix(bucket, expressSuffix) auto-flags S3Express
//   express_resolve.go:10     func resolveExpressCredentials(o *Options)  // auto-provisions the express creds provider
//   express_default.go        // default provider calls CreateSession lazily + caches per-bucket creds (sessionCredsCache LRU)
//   endpoints.go:555          return "sigv4-s3express"  // endpoint resolver switches signing for dir buckets
//   endpoints.go:810         out.Set("backend", "S3Express")
//
// CONSEQUENCE (the right call site — do NOT over-build): the bench does NOT
// call CreateSession manually. It builds an s3.Client via s3.NewFromConfig(cfg)
// and calls PutObject with Bucket = the DIRECTORY BUCKET NAME (which MUST end
// in "--azid--x-s3"). The SDK (a) sees the "--x-s3" suffix, flags S3Express,
// (b) auto-provisions the express creds provider, (c) the provider calls
// CreateSession lazily on the first dir-bucket op and caches the ~5min
// s3express session creds, (d) the endpoint resolver routes to the ZONAL
// endpoint, (e) signs with sigv4-s3express. We pass NEITHER
// DisableS3ExpressSessionAuth (leave nil → auto-ENABLED) NOR a manual
// EndpointResolver (the V2 resolver handles the zonal endpoint from the
// bucket-name suffix). This mirrors internal/network/s3_uploader.go:65
// (cfg, err := config.LoadDefaultConfig(ctx); client := s3.NewFromConfig(cfg)).
//
// VPC-LATTICE HONEST FRAMING (§4 — a load-bearing anti-fab tooth): the roadmap
// line 84 says "S3 Express put-over-VPC-Lattice". VPC-Lattice can ONLY add
// latency, never subtract. This test measures the S3 Express ZONAL endpoint
// DIRECTLY (the floor). It is a LOWER BOUND on the VPC-Lattice path. The
// S3EXPRESS_CDF token and the verdict table MUST label the S3 number
// "zonal-endpoint direct (lower bound on the VPC-Lattice path)". We do NOT
// fabricate a VPC-Lattice number; VPC-Lattice forwarding is a SEPARATE future
// track (same status as Track-4.0 TF — see the honest-weakness log).

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// s3expressSuffix is the directory-bucket name suffix the SDK auto-detects
// (express_user_agent.go:27 const expressSuffix = "--x-s3"). Cited here so the
// gate can assert the user-provided bucket name is actually a dir bucket.
const s3expressSuffix = "--x-s3"

// TestS3ExpressPut_CDF measures the S3 Express zonal PutObject latency CDF
// (1000 samples) and emits the S3EXPRESS_CDF token. Skips cleanly on 4c (no
// creds / no bucket). The function name carries NEITHER a 4-core NOR a 32-core
// suffix (the 4.E1/4.E3 discipline; the 32c gear is in the .log header + flags).
func TestS3ExpressPut_CDF(t *testing.T) {
	bucket := os.Getenv("DIRECTORY_BUCKET_NAME")
	if bucket == "" {
		t.Skip("no DIRECTORY_BUCKET_NAME env: Half B S3 Express skipped (Half A NVMe still runs). " +
			"Provision a directory bucket in the same region+AZ as the c8g box and set DIRECTORY_BUCKET_NAME.")
	}
	if !strings.HasSuffix(bucket, s3expressSuffix) {
		t.Skipf("DIRECTORY_BUCKET_NAME %q lacks the %q suffix — not a directory bucket; the SDK would not auto-flag S3Express",
			bucket, s3expressSuffix)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// REGION RESOLUTION (load-bearing — the defect this fixes): config.
	// LoadDefaultConfig resolves the instance-profile CREDENTIALS from IMDS
	// automatically, but it does NOT auto-resolve the REGION from IMDS — the
	// region must be set explicitly (via AWS_REGION env or config.WithRegion).
	// Without it the SDK errors "A region must be set when sending requests to
	// S3" on the first PutObject (the c8g box has creds via IMDS but no
	// AWS_REGION env). So we resolve the region ourselves, in priority order:
	//   1. AWS_REGION / AWS_DEFAULT_REGION env (operator override), else
	//   2. the box's own IMDS placement/region (self-contained, no env needed),
	// and pass it via config.WithRegion. If neither resolves (the 4c box has no
	// IMDS), the test Skips cleanly (Half A NVMe still runs).
	region := resolveRegion(ctx)
	if region == "" {
		t.Skip("could not resolve AWS region (no AWS_REGION env and IMDS placement/region " +
			"unreachable — not on the c8g box): Half B skipped, Half A NVMe still runs")
	}
	t.Logf("S3EXPRESS_REGION resolved=%s (AWS_REGION env or IMDS placement/region)", region)

	// config.LoadDefaultConfig picks up IMDS instance-profile creds automatically
	// (same path as internal/network/s3_uploader.go:65); we inject the resolved
	// region via WithRegion. On the 4c canonical box there is no instance profile
	// → this fails → Skip.
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		t.Skipf("LoadDefaultConfig failed (no IMDS creds / not on the c8g box): %v — Half B skipped, Half A NVMe still runs", err)
	}

	// s3.NewFromConfig(cfg) — the ONLY client construction. The SDK auto-
	// detects the "--x-s3" suffix and switches to sigv4-s3express (see the
	// file header citations). No manual CreateSession, no manual EndpointResolver.
	client := s3.NewFromConfig(cfg)

	const n = 1000

	// WARMUP: PutObject ONCE before timing to trigger the lazy CreateSession
	// (express_default.go caches the ~5min session creds in a sessionCredsCache
	// LRU) so the first timed op is NOT poisoned by the ~RTT of session
	// bootstrap. The warmup latency is recorded SEPARATELY and excluded from
	// the CDF.
	warmupFrame := MakeFrame120(fixedSeed)
	warmupKey := fmt.Sprintf("durability-bench/warmup/%d-warmup-%x",
		time.Now().UnixNano(), warmupFrame[0:8])
	warmupStart := time.Now()
	_, warmupErr := client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: &bucket,
		Key:    &warmupKey,
		Body:   bytes.NewReader(warmupFrame[:]),
	})
	warmupLat := time.Since(warmupStart)
	if warmupErr != nil {
		t.Fatalf("warmup PutObject failed (the SDK auto-session path could not bootstrap — "+
			"check the dir bucket exists in the box's region+AZ and the instance profile has s3express perms): %v", warmupErr)
	}
	t.Logf("S3EXPRESS_WARMUP latency=%dns (excluded from CDF; this is the lazy CreateSession + first PutObject)",
		warmupLat.Nanoseconds())

	// AZ-MISMATCH FLAG (§3 Half B / honest-weakness #3): the dir bucket's AZ-id
	// is parsed from the "--azid--x-s3" suffix (e.g. "use1-az4"); the box's AZ-id
	// is read from IMDS placement/availability-zone-id. If they differ, the
	// measurement is a one-way CROSS-AZ put — a DIFFERENT number than a same-AZ
	// zonal put. We flag it honestly in t.Logf (same-AZ is the ideal; cross-AZ
	// is a different number, documented in the honest-weakness log).
	boxAZID := imdsGet(ctx, "placement/availability-zone-id")
	bucketAZID := parseBucketAZID(bucket)
	switch {
	case boxAZID != "" && bucketAZID != "" && boxAZID != bucketAZID:
		t.Logf("S3EXPRESS_AZ_MISMATCH boxAZID=%s bucketAZID=%s — this is a CROSS-AZ put, a "+
			"DIFFERENT number than a same-AZ zonal put; flag in the honest-weakness log", boxAZID, bucketAZID)
	case boxAZID != "" && bucketAZID != "" && boxAZID == bucketAZID:
		t.Logf("S3EXPRESS_AZ_MATCH boxAZID=%s bucketAZID=%s — same-AZ zonal put (the ideal measurement)", boxAZID, bucketAZID)
	default:
		t.Logf("S3EXPRESS_AZ bucketAZID=%s boxAZID=%s (AZ-id match not determinable)", bucketAZID, orEmpty(boxAZID))
	}

	latencies := make([]time.Duration, n)
	var firstErr error
	errCount := 0
	for i := 0; i < n; i++ {
		f := MakeFrame120(uint64(i))
		// Key: 120-byte-cost-symmetric to NVMe (the comparison is latency, NOT
		// bandwidth — E3 settled bandwidth). Key carries a nano-ts prefix for
		// uniqueness + the frame's first 8 bytes for shard spread.
		key := fmt.Sprintf("durability-bench/%d/%d-%x",
			time.Now().UnixNano(), i, f[0:8])
		start := time.Now()
		_, err := client.PutObject(ctx, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &key,
			Body:   bytes.NewReader(f[:]),
		})
		latencies[i] = time.Since(start)
		if err != nil {
			errCount++
			if firstErr == nil {
				firstErr = err
			}
		}
	}

	// A partial-CDF over a background of 503 Throttle is NOT a clean p99 — it
	// is a throttle condition. Surface ANY non-2xx error and FAIL (per §2.3).
	if firstErr != nil {
		t.Fatalf("S3 Express PutObject had %d/%d errors (first: %v) — the CDF is over a "+
			"throttle/error condition, NOT a clean p99; document separately", errCount, n, firstErr)
	}

	cdf := computeCDF(latencies)
	t.Logf("S3 Express zonal PutObject CDF (zonal-endpoint direct, lower bound on the VPC-Lattice path): "+
		"p50=%dns p99=%dns p99.9=%dns pMax=%dns n=%d",
		cdf.p50.Nanoseconds(), cdf.p99.Nanoseconds(),
		cdf.p999.Nanoseconds(), cdf.pMax.Nanoseconds(), n)
	// Machine-parsable token the harness greps into the .log; the verdict matrix
	// parses it. Single line, fixed key order, labeled zonal-direct (lower bound).
	t.Logf("S3EXPRESS_CDF p50=%dns p99=%dns p99.9=%dns pMax=%dns n=%d "+
		"(zonal-endpoint-direct-lower-bound-on-vpc-lattice)",
		cdf.p50.Nanoseconds(), cdf.p99.Nanoseconds(),
		cdf.p999.Nanoseconds(), cdf.pMax.Nanoseconds(), n)
}

// parseBucketAZID extracts the AZ-id from a directory-bucket name of the form
// "name--<azid>--x-s3" (e.g. "supremum-bench--use1-az4--x-s3" → "use1-az4").
// Returns "" if the name does not match the expected shape.
func parseBucketAZID(bucket string) string {
	s := strings.TrimSuffix(bucket, s3expressSuffix)
	// s is now "name--<azid>"; the AZ-id is the segment after the last "--".
	idx := strings.LastIndex(s, "--")
	if idx < 0 {
		return ""
	}
	az := s[idx+2:]
	if az == "" {
		return ""
	}
	return az
}

// resolveRegion returns the AWS region for the S3 client, in priority order:
//  1. AWS_REGION / AWS_DEFAULT_REGION env (operator override), else
//  2. the box's own IMDS placement/region (self-contained, no env needed).
//
// Returns "" if neither resolves (the 4c canonical box has no IMDS → the test
// Skips cleanly). This is the fix for the "A region must be set" defect:
// config.LoadDefaultConfig resolves IMDS CREDENTIALS but NOT the region.
func resolveRegion(ctx context.Context) string {
	for _, env := range []string{"AWS_REGION", "AWS_DEFAULT_REGION"} {
		if r := os.Getenv(env); r != "" {
			return r
		}
	}
	return imdsGet(ctx, "placement/region")
}

// imdsGet fetches a metadata value from the EC2 IMDSv2 endpoint
// (http://169.254.169.254/latest/meta-data/<path>) using a session token. It
// returns "" on any failure (no IMDS / not on EC2 / network error) so callers
// can treat the empty string as "not on the box" and Skip cleanly. The token
// TTL is 300s (same as c8g_run_bench.sh); the per-call timeout is 2s so a
// missing IMDS does not stall the test on the 4c box.
func imdsGet(ctx context.Context, path string) string {
	const imdsBase = "http://169.254.169.254/latest/meta-data/"
	tokenCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(tokenCtx, http.MethodPut,
		"http://169.254.169.254/latest/api/token", nil)
	if err != nil {
		return ""
	}
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "300")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ""
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		return ""
	}
	token := strings.TrimSpace(string(body))

	getCtx, cancel2 := context.WithTimeout(ctx, 2*time.Second)
	defer cancel2()
	getReq, err := http.NewRequestWithContext(getCtx, http.MethodGet, imdsBase+path, nil)
	if err != nil {
		return ""
	}
	getReq.Header.Set("X-aws-ec2-metadata-token", token)
	getResp, err := http.DefaultClient.Do(getReq)
	if err != nil {
		return ""
	}
	getBody, _ := io.ReadAll(getResp.Body)
	_ = getResp.Body.Close()
	if getResp.StatusCode != 200 {
		return ""
	}
	return strings.TrimSpace(string(getBody))
}

func orEmpty(s string) string {
	if s == "" {
		return "(unknown)"
	}
	return s
}
