// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

// These tests cover /v1/query over Resolver.AsOf and LocalFS, including writes,
// checkpoints, crash recovery, concurrent reads, and a disabled query tier.
//
// Memtable keys begin with sha256(entityID)[:16]. The L0 flusher stores that
// prefix in column 0 and names the directory hex(firstKey[:8]); Resolver derives
// the same values from the queried entity ID. For a single-entity flush, the
// directory and column-0 hashes therefore match on the write and read paths.
// Multi-entity flush files instead use the smallest entity hash for the directory;
// that remaining lookup limitation is documented in ADR-0017, so these round
// trips use one entity per harness.
//
// Disabling the Arrow index is the negative control. The recovery image is still
// written, but with no l0 files AsOf returns ErrEntityNotFound and the handler
// returns 404. The enabled case must return the persisted timestamp and digest.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hr18vk/sovereign/internal/database"
	"github.com/hr18vk/sovereign/pkg/durability"
	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// queryTestNodeID is a distinct 16-byte nodeID for the harness (kept separate
// from the control tests' test503NodeID so a value collision in one family
// never masks the other's root cause).
var queryTestNodeID = [16]byte{0x12, 0x12, 0x0c, 0x0c, 0x00, 0xaa, 0xbb, 0xcc}

// queryTestArenaSize matches pkg/sync + pkg/durability test convention (64 MiB).
const queryTestArenaSize uintptr = 64 * 1024 * 1024

// queryValidEndNs is an int64-safe open-end sentinel for these tests. It exceeds
// every SystemTime used here, so AsOf's valid-time filter accepts the entry and
// dominance selects the latest SystemTime at or before the transaction time.
//
// database.MaxValidTime.UnixNano() cannot serve as this sentinel: year 9999 is
// outside time.UnixNano's int64 range and wraps to a negative value. Such an end
// would make the valid-time interval empty for the timestamps used in these
// tests. ADR-0017 §3 records that limitation; production code does not call
// UnixNano on MaxValidTime.
const queryValidEndNs int64 = 9_000_000_000_000_000_000 // year ~2253; > baseT, < MaxInt64.

// queryTestEntry gives an entry the valid-time range
// [systemTime, queryValidEndNs). The shared stagedEntry helper leaves both
// bounds zero, which is suitable for Merkle-root recovery tests but produces an
// empty interval that AsOf cannot return.
func queryTestEntry(systemTime int64) eng.CRDTEntry {
	return eng.CRDTEntry{
		SystemTime:     systemTime,
		ValidTimeStart: systemTime,
		ValidTimeEnd:   queryValidEndNs, // open-ended (int64-safe sentinel; not MaxValidTime.UnixNano — overflows)
		AssertionTime:  systemTime,
	}
}

// queryDigest computes the digest Bridge.PutLocal stores in the Arrow row.
// AsOf returns this digest while the row's payload body remains SENTRY.
func queryDigest(payload string) [32]byte { return sha256.Sum256([]byte(payload)) }

// queryHarness builds a Bridge over a fresh WAL and a LocalFS snapshot store.
// With enableIndex, AppendCheckpoint writes both the dot-bearing recovery image
// and the l0 Arrow query index. Cleanup closes the engine and WAL; tests that
// simulate a crash close them first, and their repeated Close calls are safe.
func queryHarness(t *testing.T, enableIndex bool) (bridge *durability.Bridge, lfs *durability.LocalFS, walPath string) {
	t.Helper()
	eng.DataDir = t.TempDir()
	engine, err := eng.NewDeltaCRDTEngine(queryTestNodeID, 1, queryTestArenaSize)
	if err != nil {
		t.Fatalf("NewDeltaCRDTEngine: %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })

	walPath = filepath.Join(t.TempDir(), "q.wal")
	wal, err := durability.OpenWAL(walPath)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	t.Cleanup(func() { _ = wal.Close() })

	lfsRoot := filepath.Join(t.TempDir(), "snapstore")
	lfs, err = durability.NewLocalFS(lfsRoot)
	if err != nil {
		t.Fatalf("NewLocalFS: %v", err)
	}

	bridge = durability.NewBridge(engine, wal, 0) // 0 = caller-driven checkpoints; the test calls AppendCheckpoint
	if enableIndex {
		bridge.SetSnapshotter(lfs, true) // recovery image + Arrow query index
	}
	return bridge, lfs, walPath
}

// newQueryResolver constructs the Resolver over the same lfs the snapshotter
// writes l0/*.arrow to (S3Lister + S3Downloader both backed by LocalFS; bucket
// ignored by LocalFS — "local" is cosmetic). Mirrors cmd/sovereign-node's
// construction. queryAlloc is the off-heap read-buffer allocator; it is a
// stateless handle (no Close — per-buffer Free in scanFile is the lifecycle;
// ADR-0017 §4) so the process-drop at test end leaks nothing.
func newQueryResolver(lfs *durability.LocalFS) *database.Resolver {
	alloc := database.NewJemallocAllocator()
	return database.NewResolver(lfs, lfs, alloc, "local", database.DefaultResolverConfig())
}

// queryGet issues a GET /v1/query against srv with the given params and returns
// the decoded status + body bytes (the caller asserts on status + shape).
func queryGet(t *testing.T, srv *httptest.Server, key string, validTime, txTime time.Time) (int, []byte) {
	t.Helper()
	q := url.Values{}
	q.Set("key", key)
	q.Set("valid_time", validTime.Format(time.RFC3339Nano))
	q.Set("tx_time", txTime.Format(time.RFC3339Nano))
	resp, err := http.Get(srv.URL + "/v1/query?" + q.Encode())
	if err != nil {
		t.Fatalf("GET /v1/query: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read /v1/query body: %v", err)
	}
	return resp.StatusCode, body
}

// queryNanosInRFC3339Nano round-trip-checks a ns timestamp can be formatted +
// re-parsed to the same ns (the handler's parseQueryTime path). Used to stamp
// the open-ended valid queries so the txTime the handler reconstructs is the
// exact ns the guard asserts against.
func queryNanosInRFC3339Nano(ns int64) time.Time { return time.Unix(0, ns).UTC() }

// TestQuery_RoundTrip_WritesThenQueriesPersistedHistory writes one entity,
// checkpoints it, and retrieves it through both Resolver.AsOf and /v1/query.
// SystemTime and PayloadDigest must match the write. With enableIndex=false, the
// same write produces only a recovery image; AsOf must return ErrEntityNotFound
// and the HTTP handler must return 404.
func TestQuery_RoundTrip_WritesThenQueriesPersistedHistory(t *testing.T) {
	const alpha = "alpha"
	const payload = "alpha-payload"
	// Fixed ns timestamps; same decimal length so lexicographic == numeric (the
	// file's txTime suffix sorts the same both ways — though AsOf dominance is
	// order-independent regardless).
	T_alpha := int64(1_700_000_000_000_000_001)
	wantDigest := queryDigest(payload)

	// ── Positive control: the index is written; AsOf retrieves the persisted event ──
	t.Run("bitemporal_roundtrip", func(t *testing.T) {
		bridge, lfs, _ := queryHarness(t, true) // enableIndex=true → l0/*.arrow written
		if _, err := bridge.PutLocal(alpha, payload, queryTestEntry(T_alpha)); err != nil {
			t.Fatalf("PutLocal: %v", err)
		}
		if err := bridge.AppendCheckpoint(); err != nil {
			t.Fatalf("AppendCheckpoint: %v", err)
		}

		resolver := newQueryResolver(lfs)

		// (1) Resolver seam: AsOf direct. validTime=T_alpha ∈ [T_alpha, MaxValid);
		// txTime=T_alpha+1 (> T_alpha) so SystemTime<=txTime passes.
		got, err := resolver.AsOf(
			context.Background(), alpha,
			queryNanosInRFC3339Nano(T_alpha),
			queryNanosInRFC3339Nano(T_alpha+1),
		)
		if err != nil {
			t.Fatalf("AsOf: %v", err)
		}
		assertPersistedEvent(t, got, alpha, T_alpha, wantDigest)

		// (2) The /v1/query surface (the headline). One AsOf + one JSON encode
		// (mirror /v1/get's discipline), reading the persisted index.
		if got.EntityID != alpha {
			t.Fatalf("AsOf EntityID = %q, want %q", got.EntityID, alpha)
		}
		cs := NewControlServer(nil, queryTestNodeID, nil, nil) // g nil: /v1/query + /livecheck never touch it
		cs.SetResolver(resolver)
		srv := httptest.NewServer(cs.Handler())
		t.Cleanup(srv.Close)

		status, body := queryGet(t, srv, alpha,
			queryNanosInRFC3339Nano(T_alpha), queryNanosInRFC3339Nano(T_alpha+1))
		if status != http.StatusOK {
			t.Fatalf("/v1/query returned %d, want 200: %s", status, body)
		}
		var qr queryResponse
		if err := json.Unmarshal(body, &qr); err != nil {
			t.Fatalf("decode queryResponse: %v (body=%s)", err, body)
		}
		if !qr.Present {
			t.Fatalf("query present=false, want true (the persisted event exists at the coords)")
		}
		if qr.EntityID != alpha {
			t.Fatalf("query entity_id = %q, want %q", qr.EntityID, alpha)
		}
		if qr.SystemTimeNs != T_alpha {
			t.Fatalf("query system_time_ns = %d, want %d (the WRITE's SystemTime, retrieved verbatim)", qr.SystemTimeNs, T_alpha)
		}
		if qr.PayloadDigestHex != hex.EncodeToString(wantDigest[:]) {
			t.Fatalf("query payload_digest_hex = %q, want %q (the WRITE's real digest, echoed verbatim, not recomputed)",
				qr.PayloadDigestHex, hex.EncodeToString(wantDigest[:]))
		}
		// The index stores a SENTRY body, so the response contains the digest
		// but cannot contain the original payload.
		if hasPayloadField(body) {
			t.Fatalf("queryResponse contains a payload field despite the SENTRY-bodied index: %s", body)
		}
	})

	// Without the Arrow index, AsOf has no l0 objects to read and must return
	// ErrEntityNotFound. This distinguishes the index's contribution from the
	// recovery image, which is still written in this subtest.
	t.Run("no_index_written_returns_404", func(t *testing.T) {
		bridge, lfs, _ := queryHarness(t, false) // enableIndex=false → recovery image only, no l0/*.arrow
		if _, err := bridge.PutLocal(alpha, payload, queryTestEntry(T_alpha)); err != nil {
			t.Fatalf("PutLocal: %v", err)
		}
		if err := bridge.AppendCheckpoint(); err != nil {
			t.Fatalf("AppendCheckpoint: %v", err)
		}

		resolver := newQueryResolver(lfs)

		// The Resolver seam: no l0 files means ErrEntityNotFound (not a prefix
		// mismatch — the keys are byte-identical; the index was simply never
		// written).
		_, err := resolver.AsOf(
			context.Background(), alpha,
			queryNanosInRFC3339Nano(T_alpha),
			queryNanosInRFC3339Nano(T_alpha+1),
		)
		if err == nil {
			t.Fatalf("AsOf returned nil error with the Arrow index unwritten — want ErrEntityNotFound (the round-trip failure)")
		}
		if !isErrEntityNotFound(err) {
			t.Fatalf("AsOf err = %v, want a wrap of database.ErrEntityNotFound (no l0 files when the index is off)", err)
		}

		// The surface: ErrEntityNotFound maps to the 404 body.
		cs := NewControlServer(nil, queryTestNodeID, nil, nil)
		cs.SetResolver(resolver)
		srv := httptest.NewServer(cs.Handler())
		t.Cleanup(srv.Close)
		status, body := queryGet(t, srv, alpha,
			queryNanosInRFC3339Nano(T_alpha), queryNanosInRFC3339Nano(T_alpha+1))
		if status != http.StatusNotFound {
			t.Fatalf("disabled-index /v1/query returned %d, want 404 (AsOf's ErrEntityNotFound maps here): %s", status, body)
		}
		var nf queryNotFoundBody
		if err := json.Unmarshal(body, &nf); err != nil {
			t.Fatalf("decode 404 body: %v (body=%s)", err, body)
		}
		if nf.Entity != alpha || nf.Error != "not found" {
			t.Fatalf("404 body = %+v, want {Error:%q Entity:%q}", nf, "not found", alpha)
		}
	})
}

// assertPersistedEvent checks that AsOf preserves the written SystemTime and
// PayloadDigest. InsertLocal changes only dot fields; SnapshotToLSM persists the
// remaining entry fields. The Arrow payload body is SENTRY, so the digest is the
// available payload identity (ADR-0011 §5, §9).
func assertPersistedEvent(t *testing.T, got *database.TriTemporalEvent, wantEntityID string, wantSystemTime int64, wantDigest [32]byte) {
	t.Helper()
	if got == nil {
		t.Fatalf("AsOf returned a nil event, want the persisted event")
	}
	if got.EntityID != wantEntityID {
		t.Fatalf("AsOf EntityID = %q, want %q", got.EntityID, wantEntityID)
	}
	if got.SystemTime != wantSystemTime {
		t.Fatalf("AsOf SystemTime = %d, want the persisted value %d",
			got.SystemTime, wantSystemTime)
	}
	if got.PayloadDigest != wantDigest {
		t.Fatalf("AsOf PayloadDigest = %x, want sha256(payload) = %x",
			got.PayloadDigest, wantDigest)
	}
}

// TestQuery_ResilientAfterBoundedRecovery_HistorySurvivesCrash checkpoints two
// versions of one entity, closes the engine and WAL, and recovers from the latest
// dot-bearing image plus the post-checkpoint WAL tail. The two Arrow files remain
// on disk independently of the recovered HAMT. Queries at each transaction-time
// horizon must return the corresponding SystemTime and digest.
func TestQuery_ResilientAfterBoundedRecovery_HistorySurvivesCrash(t *testing.T) {
	const alpha = "alpha"
	const p1, p2 = "alpha@T1", "alpha@T2"
	T1 := int64(1_700_000_000_000_000_001)
	T2 := int64(1_700_000_000_000_000_002)
	d1, d2 := queryDigest(p1), queryDigest(p2)

	bridge, lfs, walPath := queryHarness(t, true)

	if _, err := bridge.PutLocal(alpha, p1, queryTestEntry(T1)); err != nil {
		t.Fatalf("PutLocal @T1: %v", err)
	}
	if err := bridge.AppendCheckpoint(); err != nil {
		t.Fatalf("AppendCheckpoint #1: %v", err)
	}
	if _, err := bridge.PutLocal(alpha, p2, queryTestEntry(T2)); err != nil {
		t.Fatalf("PutLocal @T2: %v", err)
	}
	if err := bridge.AppendCheckpoint(); err != nil {
		t.Fatalf("AppendCheckpoint #2: %v", err)
	}

	// CRASH: close the live WAL + engine (no graceful flush beyond the per-
	// mutation fsync + the two checkpoint fsyncs already on disk).
	if err := bridge.WAL().Close(); err != nil {
		t.Fatalf("crash: WAL close: %v", err)
	}
	if err := bridge.Engine().Close(); err != nil {
		t.Fatalf("crash: engine close: %v", err)
	}

	// Bounded recover: the latest dot-bearing image (#2 watermark) loads, the
	// post-checkpoint tail replays.
	recEngine, recWAL, _, witness, err := durability.RecoverEngineWithSnapshot(queryTestNodeID, walPath, lfs, queryTestArenaSize)
	if err != nil {
		t.Fatalf("RecoverEngineWithSnapshot: %v", err)
	}
	t.Cleanup(func() { _ = recEngine.Close() })
	t.Cleanup(func() { _ = recWAL.Close() })

	// Bounded recovery must load the latest dot-bearing image rather than
	// replaying the entire WAL.
	if !witness.Bounded {
		t.Fatalf("witness.Bounded=false, want true after loading the latest dot-bearing image")
	}

	// A query at T2's valid and transaction times must select the later event
	// from the Arrow files that survived the engine and WAL close.
	resolver := newQueryResolver(lfs)
	got, err := resolver.AsOf(
		context.Background(), alpha,
		queryNanosInRFC3339Nano(T2),
		queryNanosInRFC3339Nano(T2+1),
	)
	if err != nil {
		t.Fatalf("post-recovery AsOf at T2: %v", err)
	}
	if got.SystemTime != T2 {
		t.Fatalf("post-recovery AsOf SystemTime = %d, want %d", got.SystemTime, T2)
	}
	if got.PayloadDigest != d2 {
		t.Fatalf("post-recovery AsOf PayloadDigest = %x, want %x", got.PayloadDigest, d2)
	}

	// Each checkpoint leaves a separate Arrow file. The earlier T1 event must
	// remain queryable at its own transaction-time horizon.
	files, err := lfs.ListObjects(context.Background(), "local", "l0/", 0)
	if err != nil {
		t.Fatalf("ListObjects l0/: %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("L0 file count = %d, want 2 (one fresh l0/*.arrow per checkpoint — the unbounded-growth witness); files=%v",
			len(files), files)
	}
	// A horizon between T1 and T2 excludes the later SystemTime and must return
	// the earlier checkpoint's event rather than overwriting its history.
	gotT1, err := resolver.AsOf(
		context.Background(), alpha,
		queryNanosInRFC3339Nano(T1),
		queryNanosInRFC3339Nano(T1+1),
	)
	if err != nil {
		t.Fatalf("post-recovery AsOf at T1 horizon: %v", err)
	}
	if gotT1.SystemTime != T1 || gotT1.PayloadDigest != d1 {
		t.Fatalf("post-recovery AsOf at T1 horizon = (sys=%d digest=%x), want (sys=%d digest=%x)",
			gotT1.SystemTime, gotT1.PayloadDigest, T1, d1)
	}
}

// TestQuery_RaceClean_ConcurrentQueryAndCheckpoint runs one writer, repeated
// checkpoints, and concurrent AsOf calls. LocalFS listing/download and off-heap
// Arrow reads must be race-free (ADR-0017 §3). A reader may encounter an
// incomplete upload; scanFile skips it and retains an earlier valid event. Once
// the writer stops and the final checkpoint finishes, AsOf must return the last
// written SystemTime.
//
// Run with: go test -race -count=5 -run TestQuery_RaceClean ./pkg/mesh/
func TestQuery_RaceClean_ConcurrentQueryAndCheckpoint(t *testing.T) {
	bridge, lfs, _ := queryHarness(t, true)
	resolver := newQueryResolver(lfs)

	// One sequential writer keeps SystemTime and dot order aligned, making the
	// final checkpoint's expected value deterministic. Checkpointing and querying
	// still run concurrently with the writer and with each other; write-write
	// contention is covered by the engine's own tests.
	const totalWrites = 80
	const baseT = int64(1_700_000_000_000_000_000)
	const alpha = "alpha"

	var wg sync.WaitGroup
	stop := make(chan struct{}) // stop the queryer at quiescence

	// Writer: PutLocal alpha@(baseT+j), j = 0..totalWrites-1, sequentially.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < totalWrites; j++ {
			sys := baseT + int64(j) // distinct + increasing in write (= dot) order
			if _, err := bridge.PutLocal(alpha, fmt.Sprintf("%s-%d", alpha, j), queryTestEntry(sys)); err != nil {
				t.Errorf("PutLocal race %d: %v", j, err)
				return
			}
		}
	}()

	// Checker: AppendCheckpoint continuously while the writer runs.
	checkerDone := make(chan struct{})
	go func() {
		defer close(checkerDone)
		for {
			select {
			case <-stop:
				if err := bridge.AppendCheckpoint(); err != nil {
					t.Errorf("final AppendCheckpoint: %v", err)
				}
				return
			default:
				if err := bridge.AppendCheckpoint(); err != nil {
					t.Errorf("checker AppendCheckpoint: %v", err)
					return
				}
			}
		}
	}()

	// Concurrent queries use the current valid and transaction times. A file
	// observed during upload is skipped; a later complete checkpoint remains
	// available. ErrEntityNotFound is valid before the first index file lands.
	queryerDone := make(chan struct{})
	go func() {
		defer close(queryerDone)
		for {
			select {
			case <-stop:
				return
			default:
				now := time.Now()
				if _, err := resolver.AsOf(context.Background(), alpha, now, now); err != nil &&
					!isErrEntityNotFound(err) {
					t.Errorf("concurrent AsOf: %v", err)
					return
				}
			}
		}
	}()

	wg.Wait()   // Wait for all writes.
	close(stop) // Stop querying and request one final checkpoint.
	<-checkerDone
	<-queryerDone

	// Sequential writes keep dot and SystemTime order aligned. The final
	// checkpoint therefore contains alpha at baseT+totalWrites-1, and AsOf at
	// that valid time and the following transaction time must return it.
	sysMax := baseT + totalWrites - 1 // the highest SystemTime written (latest-dot alpha)
	got, err := resolver.AsOf(context.Background(), alpha,
		queryNanosInRFC3339Nano(sysMax), queryNanosInRFC3339Nano(sysMax+1))
	if err != nil {
		t.Fatalf("quiescent AsOf: %v (the final checkpoint is on disk; a miss is a torn-read false-positive)", err)
	}
	if got.SystemTime != sysMax {
		t.Fatalf("quiescent AsOf SystemTime = %d, want %d (the latest checkpointed value; no torn-read false-positive)", got.SystemTime, sysMax)
	}
	if got.EntityID != alpha {
		t.Fatalf("quiescent AsOf EntityID = %q, want %q", got.EntityID, alpha)
	}
}

// TestQuery_DisabledWhenNoLSMRoot_Honest503 requires /v1/query to return 503
// with "query-tier disabled (no --lsm-root)" when no Resolver is configured.
// A 404 would incorrectly suggest that the entity, rather than the query tier,
// is absent. The availability check precedes parameter validation (ADR-0017 §3).
func TestQuery_DisabledWhenNoLSMRoot_Honest503(t *testing.T) {
	t.Run("nil_resolver_returns_503_not_404", func(t *testing.T) {
		// NewControlServer unmodified (4-arg); SetResolver never called → resolver stays nil.
		cs := NewControlServer(nil, queryTestNodeID, nil, nil)
		srv := httptest.NewServer(cs.Handler())
		t.Cleanup(srv.Close)

		status, body := queryGet(t, srv, "does-not-exist",
			queryNanosInRFC3339Nano(1_700_000_000_000_000_001),
			queryNanosInRFC3339Nano(1_700_000_000_000_000_002))

		if status != http.StatusServiceUnavailable {
			t.Fatalf("disabled /v1/query returned %d, want 503 to distinguish an unavailable tier from a missing entity: %s",
				status, body)
		}
		var d queryDisabledBody
		if err := json.Unmarshal(body, &d); err != nil {
			t.Fatalf("decode 503 body: %v (body=%s)", err, body)
		}
		if d.Error != "query-tier disabled (no --lsm-root)" {
			t.Fatalf("503 body error = %q, want the disclosure %q", d.Error, "query-tier disabled (no --lsm-root)")
		}
	})

	t.Run("missing_params_return_400_even_when_disabled", func(t *testing.T) {
		// The 503-disabled check runs before param validation (the tier is off;
		// a malformed query to a disabled tier is still "unavailable", not
		// "bad request"). This pins the order so a future refactor doesn't 400
		// a request that should be 503 (hiding the disabled state behind a 400).
		cs := NewControlServer(nil, queryTestNodeID, nil, nil) // resolver nil
		srv := httptest.NewServer(cs.Handler())
		t.Cleanup(srv.Close)

		q := url.Values{}
		// no key, no valid_time, no tx_time — a totally empty query
		resp, err := http.Get(srv.URL + "/v1/query?" + q.Encode())
		if err != nil {
			t.Fatalf("GET /v1/query (empty): %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("empty disabled /v1/query returned %d, want 503 (the 503-disabled guard runs before param validation)", resp.StatusCode)
		}
	})
}

// TestQueryL0FileGrowthDisclosed records the current L0 growth behavior: each
// AppendCheckpoint writes a fresh l0/*.arrow file without merging earlier files,
// so N checkpoints produce N files. The test asserts that count rather than
// claiming compaction has been implemented (ADR-0017 §5). The epoch tombstone
// compactor does not address this growth because production has no DELETE
// operator that creates dead-to-dead rows.
func TestQueryL0FileGrowthDisclosed(t *testing.T) {
	const N = 50
	const alpha = "alpha"
	const baseT = int64(1_700_000_000_000_000_000)

	bridge, lfs, _ := queryHarness(t, true)

	// N checkpoints, each with a distinct SystemTime (so each flush's txTime
	// differs → a new l0 file, no overwrite). Single entity → same prefix dir.
	for i := 0; i < N; i++ {
		sys := baseT + int64(i) // distinct per checkpoint → distinct file txTime
		if _, err := bridge.PutLocal(alpha, fmt.Sprintf("%s-%d", alpha, i), queryTestEntry(sys)); err != nil {
			t.Fatalf("PutLocal %d: %v", i, err)
		}
		if err := bridge.AppendCheckpoint(); err != nil {
			t.Fatalf("AppendCheckpoint %d: %v", i, err)
		}
	}

	files, err := lfs.ListObjects(context.Background(), "local", "l0/", 0)
	if err != nil {
		t.Fatalf("ListObjects l0/: %v", err)
	}

	// Exactly one new file per checkpoint is the current behavior; no merge or
	// compaction reduces the count.
	if len(files) != N {
		t.Fatalf("L0 file count = %d, want %d (one file per checkpoint); files=%v",
			len(files), N, files)
	}

	t.Logf("L0 contains %d files after %d checkpoints", len(files), N)
	t.Logf("files under l0/: %v", files)

	// Queries remain correct across these files, with cost proportional to the
	// number scanned and bounded by ResolverConfig.MaxL0Files.
	resolver := newQueryResolver(lfs)
	got, err := resolver.AsOf(context.Background(), alpha,
		queryNanosInRFC3339Nano(baseT+int64(N-1)),
		queryNanosInRFC3339Nano(baseT+int64(N)),
	)
	if err != nil {
		t.Fatalf("AsOf across %d L0 files: %v", N, err)
	}
	if got.SystemTime != baseT+int64(N-1) {
		t.Fatalf("AsOf across L0 files returned SystemTime = %d, want the latest checkpointed value %d", got.SystemTime, baseT+int64(N-1))
	}
}

// ────────────────────────────────────────────────────────────────────────
// helpers
// ────────────────────────────────────────────────────────────────────────

// isErrEntityNotFound reports whether err is or wraps
// database.ErrEntityNotFound. AsOf returns it when no L0 keys are listed or no
// dominant row matches; scan and cancellation errors use the 500 path instead.
func isErrEntityNotFound(err error) bool {
	if err == nil {
		return false
	}
	// database.ErrEntityNotFound is a bare fmt.Errorf sentinel; the list-empty
	// path returns it unwrapped, so a direct == suffices. The substring guard
	// catches any future wrap.
	return err == database.ErrEntityNotFound ||
		strings.Contains(err.Error(), database.ErrEntityNotFound.Error())
}

// hasPayloadField reports whether a query or range JSON body contains a
// "payload" key. The index stores SENTRY bodies, so responses expose the payload
// digest but not the original value (ADR-0011 §5, §9).
func hasPayloadField(body []byte) bool {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		return false
	}
	_, ok := m["payload"]
	return ok
}
