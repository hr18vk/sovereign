// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package metrics

import (
	"crypto/rand"
	"crypto/sha256"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	capnp "capnproto.org/go/capnp/v3"
	"github.com/cloudflare/circl/sign/ed25519"
	capnp_schema "github.com/hr18vk/sovereign/api/capnp/api/capnp"
	"github.com/hr18vk/sovereign/pkg/admission"
	"github.com/hr18vk/sovereign/pkg/attribution"
	"github.com/hr18vk/sovereign/pkg/clock"
	"github.com/hr18vk/sovereign/pkg/identity"
	"github.com/hr18vk/sovereign/pkg/receive"
	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// The ingest-latency test constructs valid and malformed frames using exported
// attribution, receive, and sync APIs. Its frame builders are local so this
// package does not depend on receive's test helpers. Benchmarks measure the
// recorder instruments independently of frame processing.

const (
	testEntityID = "tenant=acme;ledger=txn;id=0a1b2c3d4e5f60718293a4b5c6d7e8f9"
	testPayload  = "this-is-recoverable-payload-bytes-not-its-digest"
	testWallBase = int64(1_700_000_000_000_000)
	testBudgetNS = int64(1_000_000_000) // 1ms -> MaxHopsForBudget=15, admits 1 hop
)

var (
	testOriginNodeID = [16]byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	}
	testPayloadDigest [32]byte
)

func init() {
	d := sha256.Sum256([]byte(testPayload))
	copy(testPayloadDigest[:], d[:])
}

// testEntityIDFor varies the entity ID's final four hexadecimal digits. Each
// generated frame then has a distinct causal dot and is applied rather than
// deduplicated.
func testEntityIDFor(i uint64) string {
	return testEntityID[:len(testEntityID)-4] + entityIDSuffix(i)
}

func entityIDSuffix(i uint64) string {
	const hex = "0123456789abcdef"
	var b [4]byte
	for j := 0; j < 4; j++ {
		b[3-j] = hex[(i>>(uint(j)*4))&0xf]
	}
	return string(b[:])
}

// buildInnerWire marshals a single CRDTDeltaEvent capnp frame the engine's
// ApplyCRDTDeltaEvent accepts: DotNodeID == OriginNodeID (the attribution
// check), PayloadDigest == SHA-256(payload) (the digest check), and the
// compiled wire version. It mirrors pkg/receive.buildCRDTDeltaWire against the
// exported capnp schema + eng.CRDTDeltaEventWireVersion.
func buildInnerWire(t testing.TB, entityID string, dotCounter uint64) []byte {
	t.Helper()
	msg, seg, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		t.Fatalf("capnp.NewMessage: %v", err)
	}
	ev, err := capnp_schema.NewRootCRDTDeltaEvent(seg)
	if err != nil {
		t.Fatalf("NewRootCRDTDeltaEvent: %v", err)
	}
	ev.SetVersion(eng.CRDTDeltaEventWireVersion)
	if err := ev.SetPayloadDigest(testPayloadDigest[:]); err != nil {
		t.Fatalf("SetPayloadDigest: %v", err)
	}
	if err := ev.SetOriginNodeID(testOriginNodeID[:]); err != nil {
		t.Fatalf("SetOriginNodeID: %v", err)
	}
	if err := ev.SetDotNodeID(testOriginNodeID[:]); err != nil {
		t.Fatalf("SetDotNodeID: %v", err)
	}
	ev.SetDotCounter(dotCounter)
	ev.SetH3Index(0x8928308280fffff)
	ev.SetSystemTime(0x1111111111111111)
	ev.SetValidTimeStart(0x2222222222222222)
	ev.SetValidTimeEnd(0x3333333333333333)
	ev.SetAssertionTime(0x4444444444444444)
	ev.SetDecisionTime(0x5555555555555555)
	if err := ev.SetEntityId(entityID); err != nil {
		t.Fatalf("SetEntityId: %v", err)
	}
	if err := ev.SetPayload(testPayload); err != nil {
		t.Fatalf("SetPayload: %v", err)
	}
	data, err := msg.Marshal()
	if err != nil {
		t.Fatalf("msg.Marshal: %v", err)
	}
	return data
}

// TestIngestLatencyRecorded drives malformed frames and valid signed frames
// through HandleFrame, recording every verdict. The scrape must contain both
// the early-rejection and signature-verification latency populations, as well
// as a sample for every input frame.
//
// Valid frames have an origin signature and no relay hops. They therefore need
// one VerifyCRDTFrame call and no outer relay verification. A relay hop would
// add another signature verification and could move samples above the bucket
// boundary used to identify the single-verification population.
func TestIngestLatencyRecorded(t *testing.T) {
	const total = 100_000
	const honest = 200 // enough signed frames to populate the verify-path bucket
	const forged = total - honest
	_ = forged

	// Valid frames share one registered keypair but have unique causal dots, so
	// each one is accepted rather than deduplicated. Building and signing the
	// frames before the loop keeps setup out of the recorded latency samples.
	originPub, originPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("origin GenerateKey: %v", err)
	}
	recv := setupTestReceiverWithOriginPub(t, originPub, originPriv)

	exp := NewExporter()
	rec := exp.Recorder()

	honestFrames := make([][]byte, honest)
	for i := 0; i < honest; i++ {
		honestFrames[i] = buildZeroHopHonestFrame(t, uint64(i+1), originPriv)
	}
	forgedFrame := []byte("not-a-valid-relay-envelope-just-garbage-bytes")

	for i := 0; i < total; i++ {
		start := time.Now()
		var av receive.AcceptVerdict
		if i < honest {
			av = recv.HandleFrame(honestFrames[i])
		} else {
			av = recv.HandleFrame(forgedFrame)
		}
		rec.RecordIngest(time.Since(start), av.Verdict)
	}

	body := scrapeMetrics(t, exp)
	countLine := extractHistogramCount(t, body, "sovereign_ingest_latency_seconds")
	if countLine < total {
		t.Fatalf("ingest histogram count = %d, want at least %d", countLine, total)
	}
	// Signed-frame samples must reach the 100us bucket, emitted as 0.0001 by
	// the Prometheus text format. Signature verification keeps this population
	// separate from early rejection under the race detector as well.
	if !bucketHasSamples(t, body, "sovereign_ingest_latency_seconds_bucket", "0.0001") {
		t.Fatalf("the 0.0001 bucket has no samples; verify-path observations are missing")
	}
	// Race instrumentation shifts malformed-frame observations into higher
	// buckets. Check a wider early-rejection bucket there while retaining the
	// tighter boundary in an ordinary test run.
	if raceEnabled {
		if !bucketHasSamples(t, body, "sovereign_ingest_latency_seconds_bucket", "1e-05") {
			t.Fatalf("under -race, the 1e-05 bucket has no early-rejection samples")
		}
		t.Logf("race run: count=%d; early-rejection and verify-path buckets populated", countLine)
	} else {
		if !bucketHasSamples(t, body, "sovereign_ingest_latency_seconds_bucket", "1e-06") {
			t.Fatalf("the 1e-06 bucket has no early-rejection samples")
		}
		t.Logf("count=%d; early-rejection and verify-path buckets populated", countLine)
	}
}

// setupTestReceiverWithOriginPub constructs a Receiver with a registered origin
// key, a synthetic clock, and a temporary engine data directory. Sharing the
// origin public key lets all valid frames in the stream use one Directory entry.
func setupTestReceiverWithOriginPub(t testing.TB, originPub ed25519.PublicKey, originPriv ed25519.PrivateKey) *receive.Receiver {
	t.Helper()
	_ = originPriv
	oldDataDir := eng.DataDir
	eng.DataDir = t.TempDir()
	t.Cleanup(func() { eng.DataDir = oldDataDir })
	engine, err := eng.NewDeltaCRDTEngine(testOriginNodeID, 0, 64*1024*1024)
	if err != nil {
		t.Fatalf("NewDeltaCRDTEngine: %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	sc := clock.NewSyntheticClock(testWallBase)
	cap := clock.NewIngressHLCScalarCap(sc, engine)
	bucket := admission.NewPeerBucket()
	dir := identity.NewDirectory()
	var originNodeIDArr [16]byte
	copy(originNodeIDArr[:], testOriginNodeID[:])
	if err := dir.Register(originNodeIDArr, originPub); err != nil {
		t.Fatalf("Directory.Register: %v", err)
	}
	return receive.NewReceiver(bucket, cap, sc, dir, engine, testBudgetNS)
}

// buildZeroHopHonestFrame signs an inner CRDT event and wraps it in a v3
// envelope with no relay hops. The unique entity ID and dot counter make each
// frame a new causal update rather than a duplicate application.
func buildZeroHopHonestFrame(t testing.TB, dotCounter uint64, originPriv ed25519.PrivateKey) []byte {
	t.Helper()
	innerWire := buildInnerWire(t, testEntityIDFor(dotCounter), dotCounter)
	originSig := ed25519.Sign(originPriv, innerWire)
	var sigArr [attribution.OriginSigSize]byte
	copy(sigArr[:], originSig)
	env := attribution.NewSignedRelayEnvelopeV3(innerWire, sigArr, dotCounter, testOriginNodeID, nil)
	return env.Marshal()
}

// BenchmarkRecordIngest measures histogram observation plus a cached verdict
// counter increment for one accepted frame.
func BenchmarkRecordIngest(b *testing.B) {
	exp := NewExporter()
	rec := exp.Recorder()
	latency := 60 * time.Microsecond
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec.RecordIngest(latency, receive.Accept)
	}
}

// BenchmarkRecordVerify measures a verification-latency observation on its own.
func BenchmarkRecordVerify(b *testing.B) {
	exp := NewExporter()
	rec := exp.Recorder()
	latency := 60 * time.Microsecond
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec.RecordVerify(latency)
	}
}

// BenchmarkHistogramObserve isolates histogram bucket selection and sample
// updates from the counter increment in RecordIngest.
func BenchmarkHistogramObserve(b *testing.B) {
	exp := NewExporter()
	rec := exp.Recorder()
	latency := 60 * time.Microsecond
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec.ingestHist.Observe(latency.Seconds())
	}
}

// BenchmarkVerdictCounterInc isolates an increment through the cached counter
// for Accept, without a CounterVec label lookup.
func BenchmarkVerdictCounterInc(b *testing.B) {
	exp := NewExporter()
	rec := exp.Recorder()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec.verdictCounters[0].Inc()
	}
}

// scrapeMetrics drives the Exporter's /metrics handler and returns the body.
func scrapeMetrics(t testing.TB, exp *Exporter) string {
	t.Helper()
	srv := httptest.NewServer(exp.Handler())
	t.Cleanup(srv.Close)
	resp, err := srv.Client().Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatalf("scrape /metrics: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read scrape body: %v", err)
	}
	return string(body)
}

// extractHistogramCount reads the integer sample count from a histogram's
// _count line in the Prometheus text response.
func extractHistogramCount(t testing.TB, body, name string) uint64 {
	t.Helper()
	// The histogram count line is `sovereign_ingest_latency_seconds_count N`.
	needle := name + "_count"
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, needle+" ") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				var n uint64
				for _, ch := range fields[1] {
					if ch < '0' || ch > '9' {
						break
					}
					n = n*10 + uint64(ch-'0')
				}
				return n
			}
		}
	}
	t.Fatalf("histogram %s _count line not found in scrape", name)
	return 0
}

// bucketHasSamples reports whether the named histogram bucket (le=label) has a
// nonzero sample count in the scraped text.
func bucketHasSamples(t testing.TB, body, name, le string) bool {
	t.Helper()
	needle := name + "{le=\"" + le + "\"} "
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, needle) {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[1] != "0" {
				return true
			}
			return false
		}
	}
	return false
}
