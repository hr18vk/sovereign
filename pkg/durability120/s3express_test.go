// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package durability120

// TestS3ExpressPut_CDF: the S3 Express directory-bucket PutObject latency CDF,
// head-to-head against the NVMe WAL fsync baseline.
//
// This is a test, not a benchmark (load-bearing idiom choice): a 100µs-1ms network
// RTT under testing.B's b.N mean re-stabilization is the wrong idiom for a p99
// gate. b.N ramps to find a stable mean; a p99 gate needs a fixed sample size
// so the tail is characterized, not averaged away. This is a fixed 1000-sample
// test (the same shape as TestFsyncWAL_CDF), not a benchmark.
//
// Gating (the safe-on-4c contract): the test skips (not fails) if
//   - os.Getenv("DIRECTORY_BUCKET_NAME") == "" (no directory bucket provisioned), or
//   - config.LoadDefaultConfig fails to resolve creds (IMDS not available — the
//     4c canonical box has no instance profile).
// A plain t.Skip is the gate (not a build tag — a plain skip so `go build ./pkg/
// durability120/` works on 4c without a tag and the test skips cleanly).
//
// SDK anti-fabrication (every symbol below was grep-verified in the module cache
// at $(go env GOMODCACHE)/github.com/aws/aws-sdk-go-v2/service/s3@v1.104.1;
// the citations are pasted above each call site so they can be
// re-verified without re-deriving):
//   api_op_PutObject.go  func (c *Client) PutObject(ctx, *PutObjectInput, ...func(*Options)) (*PutObjectOutput, error)
//   api_op_PutObject.go  type PutObjectInput struct { ... :211 Bucket *string; :216 Key *string; :248 Body io.Reader }
//   express_user_agent.go  const expressSuffix = "--x-s3"  // :30 HasSuffix(bucket, expressSuffix) auto-flags S3Express
//   express_resolve.go  func resolveExpressCredentials(o *Options)  // auto-provisions the express creds provider
//   express_default.go  // default provider calls CreateSession lazily + caches per-bucket creds (sessionCredsCache LRU)
//   endpoints.go  return "sigv4-s3express"  // endpoint resolver switches signing for dir buckets
//   endpoints.go  out.Set("backend", "S3Express")
//
// Consequence (the right call site — do not over-build): the test does not
// call CreateSession manually. It builds an s3.Client via s3.NewFromConfig(cfg)
// and calls PutObject with Bucket = the directory bucket name (which must end
// in "--azid--x-s3"). The SDK (a) sees the "--x-s3" suffix, flags S3Express,
// (b) auto-provisions the express creds provider, (c) the provider calls
// CreateSession lazily on the first dir-bucket op and caches the ~5min
// s3express session creds, (d) the endpoint resolver routes to the zonal
// endpoint, (e) signs with sigv4-s3express. We pass neither
// DisableS3ExpressSessionAuth (leave nil → auto-enabled) nor a manual
// EndpointResolver (the V2 resolver handles the zonal endpoint from the
// bucket-name suffix). This mirrors internal/network/s3_uploader.go
// (cfg, err := config.LoadDefaultConfig(ctx); client := s3.NewFromConfig(cfg)).
//
// VPC-Lattice framing: the architecture doc says "S3 Express put-over-VPC-Lattice".
// VPC-Lattice can only add latency, never subtract. This test measures the S3 Express
// zonal endpoint directly (the floor). It is a lower bound on the VPC-Lattice path.
// The S3EXPRESS_CDF token and the verdict table must label the S3 number
// "zonal-endpoint direct (lower bound on the VPC-Lattice path)". We do not
// fabricate a VPC-Lattice number; VPC-Lattice forwarding is a separate future
// track.

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
// (express_user_agent.go const expressSuffix = "--x-s3"). Cited here so the
// gate can assert the user-provided bucket name is actually a directory bucket.
const s3expressSuffix = "--x-s3"

// TestS3ExpressPut_CDF measures the S3 Express zonal PutObject latency CDF
// (1000 samples) and emits the S3EXPRESS_CDF token. Skips cleanly on 4c (no
// creds / no bucket). The function name carries neither a 4-core nor a 32-core
// suffix; the 32c gear is in the log header and flags.
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

	// Region resolution (load-bearing — the defect this fixes): config.
	// LoadDefaultConfig resolves the instance-profile credentials from IMDS
	// automatically, but it does not auto-resolve the region from IMDS — the
	// region must be set explicitly (via AWS_REGION env or config.WithRegion).
	// Without it the SDK errors "A region must be set when sending requests to
	// S3" on the first PutObject (the c8g box has creds via IMDS but no
	// AWS_REGION env). So we resolve the region ourselves, in priority order:
	//   1. AWS_REGION / AWS_DEFAULT_REGION env (operator override), else
	//   2. the box's own IMDS placement/region (self-contained, no env needed),
	// and pass it via config.WithRegion. If neither resolves (the 4c box has no
	// IMDS), the test skips cleanly (Half A NVMe still runs).
	region := resolveRegion(ctx)
	if region == "" {
		t.Skip("could not resolve AWS region (no AWS_REGION env and IMDS placement/region " +
			"unreachable — not on the c8g box): Half B skipped, Half A NVMe still runs")
	}
	t.Logf("S3EXPRESS_REGION resolved=%s (AWS_REGION env or IMDS placement/region)", region)

	// config.LoadDefaultConfig picks up IMDS instance-profile creds automatically
	// (same path as internal/network/s3_uploader.go); we inject the resolved
	// region via WithRegion. On the 4c canonical box there is no instance profile,
	// so this fails and the test skips.
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		t.Skipf("LoadDefaultConfig failed (no IMDS creds / not on the c8g box): %v — Half B skipped, Half A NVMe still runs", err)
	}

	// s3.NewFromConfig(cfg) — the only client construction. The SDK auto-
	// detects the "--x-s3" suffix and switches to sigv4-s3express (see the
	// file header citations). No manual CreateSession, no manual EndpointResolver.
	client := s3.NewFromConfig(cfg)

	const n = 1000

	// Warmup: PutObject once before timing to trigger the lazy CreateSession
	// (express_default.go caches the ~5min session creds in a sessionCredsCache
	// LRU) so the first timed op is not poisoned by the ~RTT of session
	// bootstrap. The warmup latency is recorded separately and excluded from
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

	// AZ mismatch flag: the dir bucket's AZ-id is parsed from the "--azid--x-s3"
	// suffix (e.g. the us-east-1 AZ identifier); the box's AZ-id is read from
	// IMDS placement/availability-zone-id. If they differ, the measurement is a
	// one-way cross-AZ put — a different number than a same-AZ zonal put. We flag
	// it in t.Logf (same-AZ is the ideal; cross-AZ is a different number).
	boxAZID := imdsGet(ctx, "placement/availability-zone-id")
	bucketAZID := parseBucketAZID(bucket)
	switch {
	case boxAZID != "" && bucketAZID != "" && boxAZID != bucketAZID:
		t.Logf("S3EXPRESS_AZ_MISMATCH boxAZID=%s bucketAZID=%s — this is a cross-AZ put, a "+
			"different number than a same-AZ zonal put", boxAZID, bucketAZID)
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
		// Key: 120-byte-cost-symmetric to NVMe (the comparison is latency, not
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

	// A partial-CDF over a background of 503 Throttle is not a clean p99 — it
	// is a throttle condition. Surface any non-2xx error and fail (per §2.3).
	if firstErr != nil {
		t.Fatalf("S3 Express PutObject had %d/%d errors (first: %v) — the CDF is over a "+
			"throttle/error condition, not a clean p99; document separately", errCount, n, firstErr)
	}

	cdf := computeCDF(latencies)
	t.Logf("S3 Express zonal PutObject CDF (zonal-endpoint direct, lower bound on the VPC-Lattice path): "+
		"p50=%dns p99=%dns p99.9=%dns pMax=%dns n=%d",
		cdf.p50.Nanoseconds(), cdf.p99.Nanoseconds(),
		cdf.p999.Nanoseconds(), cdf.pMax.Nanoseconds(), n)
	// Machine-parsable token the harness greps into the log; the verdict table
	// parses it. Single line, fixed key order, labeled zonal-direct (lower bound).
	t.Logf("S3EXPRESS_CDF p50=%dns p99=%dns p99.9=%dns pMax=%dns n=%d "+
		"(zonal-endpoint-direct-lower-bound-on-vpc-lattice)",
		cdf.p50.Nanoseconds(), cdf.p99.Nanoseconds(),
		cdf.p999.Nanoseconds(), cdf.pMax.Nanoseconds(), n)
}

// parseBucketAZID extracts the AZ-id from a directory-bucket name of the form
// "name--<azid>--x-s3" (e.g. "bucket--usew2-az1--x-s3" → "usew2-az1").
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
// skips cleanly). This is the fix for the "A region must be set" defect:
// config.LoadDefaultConfig resolves IMDS credentials but not the region.
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
// can treat the empty string as "not on the box" and skip cleanly. The token
// TTL is 300s (same as the c8g benchmark script); the per-call timeout is 2s so a
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
