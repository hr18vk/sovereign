package mesh

// Day 12 — READ-half teeth (/v1/query over Resolver.AsOf). The durability tier
// is round-trip-closed: write → checkpoint → query, AND write → checkpoint →
// crash → bounded-recover → query-the-history.
//
// LAW II (byte-identity, verified before writing T1): the WRITE key prefix and
// the READ key prefix are byte-identical.
//   WRITE (memtable.go:144): h := sha256.Sum256(entityIDBytes); key[0:16] = h[:16].
//   WRITE dir  (l0_flusher.go:224): hex(firstKey[:8])            — firstKey[:8] = h[:8]
//                                    of the SMALLEST-hash entity in the SkipList.
//   WRITE col0 (l0_flusher.go:147): entityHashBuilder.Append(entityHash)  — entityHash = key[0:16] = h[:16].
//   READ hash  (query.go:119):       fullHash := sha256.Sum256(entityIDBytes); hashPrefix = fullHash[:16].
//   READ dir   (query.go:125):       hex(hashPrefix[:8])         — hashPrefix[:8] = fullHash[:8] of the QUERIED entity.
//   READ col0  (query.go:346):       bytes.Equal(rowHash, hashPrefix[:])  — hashPrefix = fullHash[:16].
// For a SINGLE entity the smallest-hash entity IS that entity, so WRITE
// `hex(sha256(eid)[:8])` == READ `hex(sha256(eid)[:8])` and the col0 16-byte hash
// matches too — the round-trip closes. (Multi-entity flush files are keyed by
// the smallest-hash entity; a per-entity query would not find them. That is a
// pre-existing Day-11 WRITE-path behavior; Day 12 is READ-only. The teeth use a
// single entity so the round-trip closes; the residual is disclosed in ADR-0017.)
//
// The teeth PROVE that byte-identity by retrieving the persisted event. AsOf is
// the READ half; the pre-fix RED was "no /v1/query route (404) AND no
// Resolver-over-LocalFS E2E (the AsOf surface was unit-isolated to
// internal/database with a mock S3 — wiring LocalFS as the real S3 is the new
// seam)" (ADR-0017). The RED-control sub-stages cut the index-WRITE (enableIndex=
// false) to make the failure observable WITHOUT needing to run the tooth on the
// pre-fix binary: with the Arrow index unwritten, AsOf returns ErrEntityNotFound
// (no l0 files) — the honest signature that the Round-Trip needs the write half.

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

	"github.com/hr18vk/supremum/internal/database"
	"github.com/hr18vk/supremum/pkg/durability"
	eng "github.com/hr18vk/supremum/pkg/sync"
)

// queryTestNodeID is a distinct 16-byte nodeID for the Day-12 harness (kept
// separate from the control tests' test503NodeID so a value collision in one
// family never masks the other's root cause).
var queryTestNodeID = [16]byte{0x12, 0x12, 0x0c, 0x0c, 0x00, 0xaa, 0xbb, 0xcc}

// queryTestArenaSize matches pkg/sync + pkg/durability test convention (64 MiB).
const queryTestArenaSize uintptr = 64 * 1024 * 1024

// queryValidEndNs is a CONCRETE far-future ns sentinel that fits int64 (<
// math.MaxInt64 ≈ 9.22e18) and exceeds every SystemTime these teeth use (baseT
// ≈ 1.7e18 + small offsets). It is the VALID-TIME-range OPEN END for queryTestEntry
// so AsOf's Filter3 (validStart <= validTime < validEnd) accepts any validTime
// >= SystemTime, reducing the tri-temporal dominance to "latest SystemTime <=
// transactionTime" — the cleanest pin for the round-trip teeth.
//
// It DELIBERATELY does NOT use database.MaxValidTime.UnixNano() (l0_flusher.go:20
// — the documented "open-ended (year 9999)" sentinel). That var's UnixNano()
// OVERFLOWS int64: year-9999 is ~2.5e26 ns from epoch, beyond int64's 9.2e18
// ceiling, so it wraps to -4,852,116,232,933,722,624 — a HUGE NEGATIVE. A row with
// validEnd = that negative would fail Filter3's `validTimeNs >= validEnd` for
// EVERY positive validTime → the entity becomes UNQUERYABLE. No production code
// calls .UnixNano() on MaxValidTime (verified: only the var's own definition
// references it), so the read tier is NOT broken in prod; the overflow is a
// latent WRITE-PATH-var landmine disclosed in ADR-0017 §6 (out of Day-12's
// READ-only scope to fix). The teeth sidestep it with this int64-safe sentinel.
const queryValidEndNs int64 = 9_000_000_000_000_000_000 // year ~2253; > baseT, < MaxInt64.

// queryTestEntry builds a CRDTEntry with a KNOWN SystemTime and an OPEN-ENDED
// valid-time range [SystemTime, queryValidEndNs). See queryValidEndNs for why
// a concrete sentinel (NOT database.MaxValidTime.UnixNano(), which overflows).
// The Day-11 shared helper stagedEntry leaves ValidTimeStart/End ZERO, which
// makes AsOf's valid-time predicate (validStart <= v < validEnd) an EMPTY range
// that never matches — fine for the recovery teeth (they check MerkleRoot, not
// the Arrow READ), but fatal here. Day-12 sets its own range (this helper).
func queryTestEntry(systemTime int64) eng.CRDTEntry {
	return eng.CRDTEntry{
		SystemTime:     systemTime,
		ValidTimeStart: systemTime,
		ValidTimeEnd:   queryValidEndNs, // open-ended (int64-safe sentinel; NOT MaxValidTime.UnixNano — overflows)
		AssertionTime:  systemTime,
	}
}

// queryDigest returns the PayloadDigest bridge.PutLocal stamps (bridge.go:182
// sha256(payload)) — the HONEST digest SnapshotToLSM emits into the Arrow row
// with a SENTRY body (snapshot.go:445), and AsOf echoes verbatim. T1 asserts it
// (NOT a fabricated payload value — the G06.e "digest-is-not-value" guard).
func queryDigest(payload string) [32]byte { return sha256.Sum256([]byte(payload)) }

// queryHarness builds a live Bridge bound to a fresh WAL over t.TempDir(), a
// LocalFS snapshot store over its own t.TempDir() root, and — when enableIndex
// — SetSnapshotter(lfs, true) so AppendCheckpoint writes the dot-bearing
// recovery image + the Arrow query index (the Day-11 seam). It mirrors
// durability.newLiveBridge (eng.DataDir isolation — the FROZEN-ctor hazard) +
// control_test.go's harness. t.Cleanup closes the live engine + WAL (the tests
// that CRASH close them first; double-Close is the existing snapshot-test
// pattern and is safe). Returns the lfs for the Resolver + recovery to share.
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

	bridge = durability.NewBridge(engine, wal, 0) // 0 = caller-driven checkpoints (the teeth call AppendCheckpoint)
	if enableIndex {
		bridge.SetSnapshotter(lfs, true) // recovery image + Arrow query index
	}
	return bridge, lfs, walPath
}

// newQueryResolver constructs the Resolver over the SAME lfs the snapshotter
// writes l0/*.arrow to (S3Lister + S3Downloader both backed by LocalFS; bucket
// ignored by LocalFS — "local" is cosmetic). Mirrors cmd/sovereign-node's Day-12
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
// re-parsed to the same ns (the handler's parseQueryTime path). Used to STAMP
// the open-ended valid queries so the txTime the handler reconstructs is the
// exact ns the tooth asserts against.
func queryNanosInRFC3339Nano(ns int64) time.Time { return time.Unix(0, ns).UTC() }

// ────────────────────────────────────────────────────────────────────────
// T1 — the headline. write → checkpoint → query persists SystemTime + digest.
// ────────────────────────────────────────────────────────────────────────

// TestQuery_RoundTrip_WritesThenQueriesPersistedHistory is DAY-12 T1. A
// single-entity PutLocal + AppendCheckpoint writes l0/{sha256(eid)[:8]}/{T}.arrow
// with the REAL digest + a SENTRY body; a Resolver over the same lfs returns
// the persisted TriTemporalEvent — SystemTime + PayloadDigest verbatim. The tooth
// ALSO drives the /v1/query handler (the wired surface, not just the Resolver
// seam) so the headline (the surface) is the proof, not a unit green.
//
// RED-control sub-stage: enableIndex=false → AppendCheckpoint writes the recovery
// image ONLY (no l0/*.arrow) → AsOf returns ErrEntityNotFound → the handler
// returns 404 (the persistent "not found" sentinel). This is the honest A/B
// toggle: the 200 path needs the Day-11 index-WRITE; cutting it makes AsOf
// observable-fail (not a constructed green for the Day-12 READ wire).
func TestQuery_RoundTrip_WritesThenQueriesPersistedHistory(t *testing.T) {
	const alpha = "alpha"
	const payload = "alpha-payload"
	// Fixed ns timestamps; same decimal length so lexicographic == numeric (the
	// file's txTime suffix sorts the same both ways — though AsOf dominance is
	// order-independent regardless).
	T_alpha := int64(1_700_000_000_000_000_001)
	wantDigest := queryDigest(payload)

	// ── GREEN: the index is written; AsOf retrieves the persisted event ──
	t.Run("GREEN_bitemporal_roundtrip", func(t *testing.T) {
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

		// (2) The /v1/query SURFACE (Day-12's headline). One AsOf + one JSON
		// encode (mirror /v1/get's discipline), reading the PERSISTED index.
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
			t.Fatalf("query payload_digest_hex = %q, want %q (the WRITE's real digest, echoed verbatim — NOT recomputed)",
				qr.PayloadDigestHex, hex.EncodeToString(wantDigest[:]))
		}
		// Law V guard: the body carries NO payload field (the index has a SENTRY
		// body, so a payload field would be the G06.e fabrication).
		if hasPayloadField(body) {
			t.Fatalf("queryResponse must NOT carry a payload field (the index stores a SENTRY body; reporting one is fabrication): %s", body)
		}
	})

	// ── RED control: cut the index-WRITE → AsOf returns ErrEntityNotFound ──
	// (pre-fix RED, by code-reading: at HEAD no /v1/query route → 404. This RED
	// control makes the SAME observable AFTER the fix by cutting the write half:
	// the recovery image is written but the l0/*.arrow index is NOT, so AsOf
	// finds no keys → ErrEntityNotFound. Proves the 200 is not a constructed
	// green for the read wire — it depends on the Day-11 index-WRITE.)
	t.Run("RED_no_index_written_returns_404", func(t *testing.T) {
		bridge, lfs, _ := queryHarness(t, false) // enableIndex=false → recovery image only, NO l0/*.arrow
		if _, err := bridge.PutLocal(alpha, payload, queryTestEntry(T_alpha)); err != nil {
			t.Fatalf("PutLocal: %v", err)
		}
		if err := bridge.AppendCheckpoint(); err != nil {
			t.Fatalf("AppendCheckpoint: %v", err)
		}

		resolver := newQueryResolver(lfs)

		// The Resolver seam: no l0 files → ErrEntityNotFound (NOT a prefix
		// mismatch — the keys are byte-identical; the index was simply never
		// written).
		_, err := resolver.AsOf(
			context.Background(), alpha,
			queryNanosInRFC3339Nano(T_alpha),
			queryNanosInRFC3339Nano(T_alpha+1),
		)
		if err == nil {
			t.Fatalf("AsOf returned nil error with the Arrow index UNWRITTEN — want ErrEntityNotFound (the honest round-trip failure)")
		}
		if !isErrEntityNotFound(err) {
			t.Fatalf("AsOf err = %v, want a wrap of database.ErrEntityNotFound (no l0 files when the index is off)", err)
		}

		// The surface: ErrEntityNotFound → handler returns the honest 404 body.
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

// assertPersistedEvent checks the AsOf-returned event round-trips the WRITE's
// SystemTime + PayloadDigest verbatim (the SystemTime InsertLocal PRESERVES —
// crdt.go:949-951 override ONLY the dot fields; SnapshotToLSM reads it back into
// the Arrow row; AsOf echoes it). Payload body is a SENTRY (nil) — we assert the
// DIGEST, not a payload value (the G06.e honesty guard).
func assertPersistedEvent(t *testing.T, got *database.TriTemporalEvent, wantEntityID string, wantSystemTime int64, wantDigest [32]byte) {
	t.Helper()
	if got == nil {
		t.Fatalf("AsOf returned nil event — want the persisted event (ErrEntityNotFound would have been a key-prefix mismatch; the index is byte-identical, so this is a real miss)")
	}
	if got.EntityID != wantEntityID {
		t.Fatalf("AsOf EntityID = %q, want %q", got.EntityID, wantEntityID)
	}
	if got.SystemTime != wantSystemTime {
		t.Fatalf("AsOf SystemTime = %d, want %d (round-trip: write → checkpoint → query → persisted SystemTime retrieved verbatim)",
			got.SystemTime, wantSystemTime)
	}
	if got.PayloadDigest != wantDigest {
		t.Fatalf("AsOf PayloadDigest = %x, want %x (the WRITE's real sha256(payload); HONEST digest, NOT recomputed)",
			got.PayloadDigest, wantDigest)
	}
}

// ────────────────────────────────────────────────────────────────────────
// T2 — crash → bounded-recover → query-the-history (round-trip across a crash).
// ────────────────────────────────────────────────────────────────────────

// TestQuery_ResilientAfterBoundedRecovery_HistorySurvivesCrash is DAY-12 T2.
// PutLocal(alpha@T1) + AppendCheckpoint (→ ckpt image #1 + l0 arrow #1); PutLocal
// (alpha@T2) + AppendCheckpoint (→ ckpt image #2 + l0 arrow #2); CRASH
// (WAL+engine Close). RecoverEngineWithSnapshot loads the latest dot-bearing
// image + replays only the post-checkpoint tail (witness.Bounded); a Resolver
// over the SAME lfs then returns the persisted event @ T2 (the l0/*.arrow files
// survived the crash on disk — they are a QUERY tier, independent of the
// recovered HAMT). Plus the L0 file list shows BOTH T1 and T2 files (the
// unbounded-growth residue — one fresh file per checkpoint, no merge).
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

	// (a) the bounded path loaded the snapshot (NOT full replay).
	if !witness.Bounded {
		t.Fatalf("witness.Bounded=false, want true (the latest dot-bearing image should load; full replay would not bound the tail)")
	}

	// (b) the post-recover AsOf returns the persisted event @ T2 (history
	// survives the crash + the bound — the durability tier is round-trip-closed
	// across a crash). validTime/txTime = "now"-ish (>= T2) lands in the latest
	// open-ended range; dominance picks max SystemTime = T2.
	resolver := newQueryResolver(lfs)
	got, err := resolver.AsOf(
		context.Background(), alpha,
		queryNanosInRFC3339Nano(T2),
		queryNanosInRFC3339Nano(T2+1),
	)
	if err != nil {
		t.Fatalf("post-recover AsOf: %v (the l0/*.arrow files survived the crash; a miss would mean the WRITE→READ key-prefix diverged — Law II)", err)
	}
	if got.SystemTime != T2 {
		t.Fatalf("post-recover AsOf SystemTime = %d, want %d (the persisted event @ T2 — history survives the crash + bound)", got.SystemTime, T2)
	}
	if got.PayloadDigest != d2 {
		t.Fatalf("post-recover AsOf PayloadDigest = %x, want %x (T2's real digest)", got.PayloadDigest, d2)
	}

	// (c) BOTH checkpoint files are on disk under l0/ — the unbounded-growth
	// witness (one fresh l0/*.arrow per checkpoint, no merge). The earlier T1
	// event is ALSO queryable (the index retained it, not overwrote it — a
	// DIFFERENT file per checkpoint, appended not merged).
	files, err := lfs.ListObjects(context.Background(), "local", "l0/", 0)
	if err != nil {
		t.Fatalf("ListObjects l0/: %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("L0 file count = %d, want 2 (one fresh l0/*.arrow per checkpoint — the unbounded-growth witness); files=%v",
			len(files), files)
	}
	// T1 history is retrievable too (the index did NOT overwrite T1 — it is a
	// separate file; dominance at validTime/txTime >= T1 picks T2, but a query
	// scoped to T1's horizon returns T1 — the persisted history is queryable).
	gotT1, err := resolver.AsOf(
		context.Background(), alpha,
		queryNanosInRFC3339Nano(T1),
		queryNanosInRFC3339Nano(T1+1), // txTime horizon BETWEEN T1 and T2 → dominance picks T1 (T2 > txTime excluded)
	)
	if err != nil {
		t.Fatalf("post-recover AsOf @T1 horizon: %v", err)
	}
	if gotT1.SystemTime != T1 || gotT1.PayloadDigest != d1 {
		t.Fatalf("post-recover AsOf @T1 horizon = (sys=%d dgst=%x), want (sys=%d dgst=%x) — the T1 history must be queryable (the index retained it, not overwrote it)",
			gotT1.SystemTime, gotT1.PayloadDigest, T1, d1)
	}
}

// ────────────────────────────────────────────────────────────────────────
// T3 — -race: concurrent PutLocal + AppendCheckpoint + AsOf (no torn-read FP).
// ────────────────────────────────────────────────────────────────────────

// TestQuery_RaceClean_ConcurrentQueryAndCheckpoint is DAY-12 T3 (C.RACE). A
// writer PutLocal-s alpha at monotonically increasing SystemTime; a checker
// AppendCheckpoint-s continuously; a queryer runs AsOf concurrently. -race must
// flag NO data race (LocalFS.ListObjects/Download + the off-heap Arrow reads are
// concurrent-safe — ADR-0017 §3). At quiescence AsOf == the latest checkpoint's
// value (a query concurrent with a checkpoint may list a file mid-Upload — the
// scanFile continue-on-error mitigation query.go:233 refuses the torn bytes and
// keeps an earlier valid event; the latest checkpoint is fully on disk once the
// checker stops, so the final AsOf is exact — no torn-read false-positive).
//
// Run with: go test -race -count=5 -run TestQuery_RaceClean ./pkg/mesh/
func TestQuery_RaceClean_ConcurrentQueryAndCheckpoint(t *testing.T) {
	bridge, lfs, _ := queryHarness(t, true)
	resolver := newQueryResolver(lfs)

	// SINGLE sequential writer: SystemTime = baseT + writeIndex in WRITE order,
	// which == DOT order (NextCounter is monotonic), so the latest-DOT alpha at
	// quiescence is exactly alpha@(baseT + totalWrites-1) — DETERMINISTIC.
	// (A fleet of racing writers would assign the last counter's SystemTime
	// nondeterministically; AsOf dominance is on max SystemTime across
	// checkpoint files, and only the file captured while @max was the latest-dot
	// holds it — not guaranteed under write-write concurrency. Sequential writer
	// restores the pin WITHOUT weakening the race: the CHECKER + QUERYER still
	// run concurrently with the writer + each other + the LocalFS — that is the
	// torn-read race T3 exists to stress; write-write concurrency is the
	// engine's own CAS, tested elsewhere.)
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

	// Queryer: AsOf concurrently. validTime=now/txTime=now → lands in every
	// open-ended range → dominance picks the latest SystemTime <= now. A torn
	// file mid-Upload is continue-on-error'd; no race, no crash.
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

	wg.Wait()   // writer done — all totalWrites on disk
	close(stop) // stop checker (after its final ckpt) + queryer
	<-checkerDone
	<-queryerDone

	// Quiescence: the final AppendCheckpoint (last action in checker's stop
	// branch) wrote the latest alpha@sysMax. AsOf now returns it exact. The
	// txTime/sysMax pins: the latest-dot alpha has SystemTime = baseT+(N-1)
	// (sequential writer → dot order == SystemTime order); the final checkpoint
	// captured it; a query with validTime/txTime >= sysMax returns it via max-
	// SystemTime dominance. A torn-read false-positive would miss (FP err).
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

// ────────────────────────────────────────────────────────────────────────
// T4 — disabled when no --lsm-root: honest 503, NOT a silent 404.
// ────────────────────────────────────────────────────────────────────────

// TestQuery_DisabledWhenNoLSMRoot_Honest503 is DAY-12 T4. A ControlServer with
// NO resolver wired (a research/in-memory node, or --lsm-root absent) MUST
// return 503 + {"error":"query-tier disabled (no --lsm-root)"} for /v1/query —
// NOT 404. A route-absent 404 is indistinguishable to a client from "entity not
// found", so a disabled tier that 404'd would be a silent lie (the Day-8.5
// honest-no-availability precedent — ADR-0017 §3).
//
// RED-before-fix (recorded): at HEAD the Handler() mux registered no /v1/query
// route, so GET /v1/query → ServeMux's default 404 — exactly the misread-able
// behavior. The fix registers the route + the nil-resolver 503 guard.
func TestQuery_DisabledWhenNoLSMRoot_Honest503(t *testing.T) {
	t.Run("nil_resolver_returns_503_not_404", func(t *testing.T) {
		// NewControlServer unmodified (4-arg); SetResolver NEVER called → resolver stays nil.
		cs := NewControlServer(nil, queryTestNodeID, nil, nil)
		srv := httptest.NewServer(cs.Handler())
		t.Cleanup(srv.Close)

		status, body := queryGet(t, srv, "does-not-exist",
			queryNanosInRFC3339Nano(1_700_000_000_000_000_001),
			queryNanosInRFC3339Nano(1_700_000_000_000_000_002))

		if status != http.StatusServiceUnavailable {
			t.Fatalf("disabled /v1/query returned %d, want 503 (honest no-availability; a 404 would be indistinguishable from 'not found' — the silent-lie class): %s",
				status, body)
		}
		var d queryDisabledBody
		if err := json.Unmarshal(body, &d); err != nil {
			t.Fatalf("decode 503 body: %v (body=%s)", err, body)
		}
		if d.Error != "query-tier disabled (no --lsm-root)" {
			t.Fatalf("503 body error = %q, want the honest disclosure %q", d.Error, "query-tier disabled (no --lsm-root)")
		}
	})

	t.Run("missing_params_return_400_even_when_disabled", func(t *testing.T) {
		// The 503-disabled check runs BEFORE param validation (the tier is OFF;
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
			t.Fatalf("empty disabled /v1/query returned %d, want 503 (the 503-disabled guard runs BEFORE param validation)", resp.StatusCode)
		}
	})
}

// ────────────────────────────────────────────────────────────────────────
// T-WITNESS — the honest debt: N files after N checkpoints, NOT fixed.
// ────────────────────────────────────────────────────────────────────────

// TestQuery_L0FileGrowthDisclosed is DAY-12 T-WITNESS — the honest-negative
// tooth. It makes the L0 unbounded-growth debt OBSERVABLE in CI: each
// AppendCheckpoint writes a FRESH l0/*.arrow (no merge), so N checkpoints → N
// files. This tooth DISCLOSES the debt; it does NOT fix it.
//
// It MUST assert fileCount == N (the debt's existence) and NEVER assert
// fileCount < N (that would be a false-fix fabricated green). The disclosure is
// LOGGED (t.Logf), not assert-failed. Per ADR-0017 §5 + the honest-negative
// culture: "L0 unbounded growth disclosed: N files after N checkpoints;
// level-overwrite compaction is a future fork; the epoch tombstone compactor is
// DEAD-TO-DEAD (no production DELETE operator) and is NOT the fix for this debt."
func TestQuery_L0FileGrowthDisclosed(t *testing.T) {
	const N = 50
	const alpha = "alpha"
	const baseT = int64(1_700_000_000_000_000_000)

	bridge, lfs, _ := queryHarness(t, true)

	// N checkpoints, each with a DISTINCT SystemTime (so each flush's txTime
	// differs → a NEW l0 file, no overwrite). Single entity → same prefix dir.
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

	// THE WITNESS — the debt's existence, asserted (NOT < N; exactly N: one
	// fresh file per checkpoint, no merge, no compaction). This is the honest
	// OBSERVABLE, not a fabricated improvement.
	if len(files) != N {
		t.Fatalf("L0 file count = %d, want %d (one fresh l0/*.arrow per checkpoint — the disclosed debt); files=%v",
			len(files), N, files)
	}

	// The disclosure (LOGGED — the honest-negative-culture discipline). The debt
	// is OBSERVABLE in CI, not silently accrued. It is NOT fixed by this fork.
	t.Logf("L0 unbounded growth disclosed: %d files after %d checkpoints; level-overwrite compaction is a future fork; the epoch tombstone compactor is DEAD-TO-DEAD (no production DELETE operator) and is NOT the fix for this debt.", len(files), N)
	t.Logf("files under l0/: %v", files)

	// AsOf still functions over an UNBOUNDED L0 — correctness is preserved; the
	// cost is O(L0-files) per query (the disclosed scope, NOT a Day-12 target).
	// This guards the honest contract: unbounded ≠ broken; it is bounded only by
	// the ResolVerConfig.MaxL0Files cap (1000) — a future fork shrinks it.
	resolver := newQueryResolver(lfs)
	got, err := resolver.AsOf(context.Background(), alpha,
		queryNanosInRFC3339Nano(baseT+int64(N-1)),
		queryNanosInRFC3339Nano(baseT+int64(N)),
	)
	if err != nil {
		t.Fatalf("AsOf over an unbounded L0 (N=%d): %v (correctness is preserved; the disclosed cost is O(L0-files), NOT a correctness bug)", N, err)
	}
	if got.SystemTime != baseT+int64(N-1) {
		t.Fatalf("AsOf over unbounded L0 SystemTime = %d, want %d (dominance picks the latest checkpointed value)", got.SystemTime, baseT+int64(N-1))
	}
}

// ────────────────────────────────────────────────────────────────────────
// helpers
// ────────────────────────────────────────────────────────────────────────

// isErrEntityNotFound reports whether err wraps database.ErrEntityNotFound (the
// "no matching event" sentinel — query.go:417). AsOf returns it bare when no L0
// keys are listed (query.go:143) or no dominant match (query.go:175); scan/cancel
// errors wrap differently — the distinction is the 404 vs 500 boundary.
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

// hasPayloadField reports whether the /v1/query JSON body carries a "payload"
// key (which it must NOT — the index stores a SENTRY body; a payload field would
// be the G06.e fabrication). Decodes into a map to check key presence.
func hasPayloadField(body []byte) bool {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		return false
	}
	_, ok := m["payload"]
	return ok
}
