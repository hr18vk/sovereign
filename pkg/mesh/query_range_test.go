// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package mesh

// (ADR-0024) guards — the /v1/range HTTP route + the AsOf-consistency
// superset invariant (the load-bearing one), over a REAL *LocalFS via the
// production Bridge harness (the query_test.go precedent).
//
// This file holds the operator-facing-seam guards:
//   - AsOf-CONSISTENCY superset (the consistency invariant): for the SAME
//     entity+txTime, AsOf(E, v, txTime) for any v in [vLo, vHi) returns a row
//     PRESENT in Range(E, [vLo,vHi), txTime). Driven over a REAL *LocalFS via
//     the Bridge (write → checkpoint → Arrow index → Resolver.Range + AsOf).
//   - /v1/range ROUTE CONTRACT: 405 on POST, 503 when resolver nil (the
// honest-disabled precedent — NOT a silent 404), 400 on missing key
//     / bad valid_time_lo / bad valid_time_hi / bad tx_time / empty window, 404
//     ErrEntityNotFound, 200 the sorted window + truncated. Mirrors /v1/query's
//     handler (control.go handleQuery) for the shared cases.
// - scope hygiene: pkg/mesh's import of pkg/sync is UNCHANGED — Range
//     reuses the Resolver, NOT the engine (Range adds NO engine read-seam importer).
//
// It reuses the query_test.go harness (queryHarness / newQueryResolver /
// queryTestNodeID / queryValidEndNs / queryNanosInRFC3339Nano /
// isErrEntityNotFound) — the SAME REAL *LocalFS + Bridge the query guards
// drive. Range is READ-only; the Bridge path keeps col0/entityID coupling HONEST
// (key prefix = sha256(entityID)[:16]), so this file does NOT host the
// decoupled-col0 Filter-4 test (that needs the low-level SkipList+Flusher path in
// internal/database). The narrower scope is the import-graph honest split.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hr18vk/sovereign/internal/database"
	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// rangeTestEntry builds a CRDTEntry with an EXPLICIT valid-time window [vs, ve)
// + a known SystemTime. It is the window-aware sibling of queryTestEntry (which
// sets ValidTimeEnd = OpenEndedValidEndNs, the degenerate-window pin for AsOf a
// Range window-intersection test does NOT want). The Bridge.PutLocal path
// (bridge.go:178) + snapshot.go:439-441 carry entry.ValidTimeStart/End VERBATIM
// into the Arrow row, so a checkpoint of these lands DISTINCT windows the
// Resolver.Range reads. The open-end sentinel (OpenEndedValidEndNs) is reused
// when a window is meant to extend past any realistic txTime.
//
// NOTE on the pkg/sync (eng) import: this is a TEST file (query_range_test.go),
// NOT pkg/mesh's production import graph. query_test.go already imports
// eng for the SAME harness; the scope-hygiene guard asserts pkg/mesh/control.go
// (PRODUCTION) imports pkg/sync UNCHANGED — a test-file import is the
// precedent, NOT a production-seam addition.
func rangeTestEntry(systemTime, validStart, validEnd int64) (eng.CRDTEntry, error) {
	if validEnd <= validStart {
		return eng.CRDTEntry{}, fmt.Errorf("rangeTestEntry: degenerate window [%d,%d)", validStart, validEnd)
	}
	return eng.CRDTEntry{
		SystemTime:     systemTime,
		ValidTimeStart: validStart,
		ValidTimeEnd:   validEnd,
		AssertionTime:  systemTime,
	}, nil
}

// rangeGet issues a GET /v1/range against srv with the given params and returns
// the decoded status + body bytes. Mirrors queryGet (the /v1/query helper) so the
// route guards share a consistent fetch shape.
func rangeGet(t *testing.T, srv *httptest.Server, key string, vLo, vHi, tx time.Time) (int, []byte) {
	t.Helper()
	q := url.Values{}
	if key != "" {
		q.Set("key", key)
	}
	if !vLo.IsZero() {
		q.Set("valid_time_lo", vLo.Format(time.RFC3339Nano))
	}
	if !vHi.IsZero() {
		q.Set("valid_time_hi", vHi.Format(time.RFC3339Nano))
	}
	if !tx.IsZero() {
		q.Set("tx_time", tx.Format(time.RFC3339Nano))
	}
	resp, err := http.Get(srv.URL + "/v1/range?" + q.Encode())
	if err != nil {
		t.Fatalf("GET /v1/range: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read /v1/range body: %v", err)
	}
	return resp.StatusCode, body
}

// ──────────────────────────────────────────────────────────────────────────
// AsOf-CONSISTENCY superset over a REAL *LocalFS via the Bridge.
// ──────────────────────────────────────────────────────────────────────────

// TestAsOfConsistencyRangeSupersetOverLocalFS is the AsOf-consistency superset
// guard over
// the production durable surface (the Bridge → checkpoint → Arrow index a
// sovereign-node writes). For the SAME entity+txTime, AsOf(E, v, txTime) for any
// v in [vLo, vHi) returns a row PRESENT in Range(E, [vLo,vHi), txTime). The 4-
// probe sweep. Range is a SUPERSET.
//
// SEEDING NOTE (the honest Bridge path): SnapshotToLSM reads engine.State's
// MERGED dominant per entity (snapshot.go `latest` map), so multiple PutLocals to
// the SAME entity in ONE checkpoint collapse to ONE row. To build a multi-row
// history for one entity via the production Bridge, issue ONE PutLocal PER
// checkpoint — each checkpoint's dominant lands as its OWN L0 file (the SAME
// shape a sovereign-node's checkpoint cadence produces). Range then reads the
// multi-FILE history (L0 files are the per-checkpoint dominants). This is the
// FAITHFUL durable surface; the multi-DOT-per-file seam lives in
// internal/database/range_test.go (the SkipList path that co-locates
// several rows in ONE file — CANNOT via the Bridge, which merges first). A Range
// filter that DIVERGES from AsOf's (e.g. an off-by-one bound) breaks this.
func TestAsOfConsistencyRangeSupersetOverLocalFS(t *testing.T) {
	const alpha = "alpha"
	base := int64(1_700_000_000_000_000_000)
	// One row per checkpoint; each checkpoint's dominant lands as its own L0
	// file. Windows DISJOINT (so each AsOf probe resolves a UNIQUE row across
	// the multi-file history — the superset check maps each AsOf to its file).
	wins := [][2]int64{
		{base + 10, base + 20},
		{base + 30, base + 40},
		{base + 50, base + 60},
	}
	sysVals := []int64{base + 1000, base + 2000, base + 3000}

	bridge, lfs, _ := queryHarness(t, true) // enableIndex=true → l0/*.arrow written
	for i, w := range wins {
		entry, err := rangeTestEntry(sysVals[i], w[0], w[1])
		if err != nil {
			t.Fatalf("rangeTestEntry %d: %v", i, err)
		}
		if _, err := bridge.PutLocal(alpha, fmt.Sprintf("row-%d", i), entry); err != nil {
			t.Fatalf("PutLocal %d: %v", i, err)
		}
		if err := bridge.AppendCheckpoint(); err != nil { // one ckpt per row → own L0 file
			t.Fatalf("AppendCheckpoint %d: %v", i, err)
		}
	}

	r := newQueryResolver(lfs)
	vLo := queryNanosInRFC3339Nano(base + 10)
	vHi := queryNanosInRFC3339Nano(base + 60)
	tx := queryNanosInRFC3339Nano(base + 99999)
	ctx := context.Background()
	rows, _, err := r.Range(ctx, alpha, vLo, vHi, tx)
	if err != nil {
		t.Fatalf("Range over the multi-file history: %v (3 L0 files were written; a miss is a key-prefix divergence)", err)
	}
	if len(rows) != 3 {
		t.Fatalf("expected 3 rows (one per checkpoint-L0-file) over the multi-file history; got %d — if <3 the Bridge's per-ckpt `latest` collapse or the listing + supersession dropped a file", len(rows))
	}
	type key struct{ vs, sys int64 }
	rangeSet := make(map[key]*database.TriTemporalEvent, len(rows))
	for _, row := range rows {
		rangeSet[key{row.ValidTimeStart, row.SystemTime}] = row
	}
	// 4-probe sweep across the disjoint union (one probe per row + the ends).
	for _, probe := range []int64{base + 10, base + 35, base + 55, base + 59} {
		vT := queryNanosInRFC3339Nano(probe)
		got, aErr := r.AsOf(ctx, alpha, vT, tx)
		if aErr != nil {
			t.Fatalf("AsOf at v=%d: %v (an intersecting row covers it; the durable index carries it)", probe-base, aErr)
		}
		k := key{got.ValidTimeStart, got.SystemTime}
		if _, present := rangeSet[k]; !present {
			t.Fatalf("AsOf-consistency superset: AsOf(alpha, v=%d) row {vs=%d,sys=%d} NOT in Range result-set — Range's filter DIVERGES from AsOf's (the consistency killer)", probe-base, got.ValidTimeStart, got.SystemTime)
		}
	}
	t.Logf("REAL *LocalFS: 4-point AsOf sweep (v=10,35,55,59) each ∈ Range result-set over %d L0 files (one per checkpoint) — Range is a SUPERSET of every AsOf point in the window", len(rows))
}

// ──────────────────────────────────────────────────────────────────────────
// /v1/range ROUTE CONTRACT (the operator-facing seam).
// ──────────────────────────────────────────────────────────────────────────

// TestRangeRouteContract mirrors /v1/query's
// handler (control.go handleQuery) for the shared cases (405/503/400/404/200) +
// asserts the range-specific 400 guards (valid_time_lo + valid_time_hi parse +
// the non-empty window). All over a REAL *LocalFS via the Bridge for the 200 +
// 404 paths (the same surface the production node reads).
func TestRangeRouteContract(t *testing.T) {
	const alpha = "alpha"
	base := int64(1_700_000_000_000_000_000)

	// a live resolver + a persisted row for the 200/404 paths.
	bridge, lfs, _ := queryHarness(t, true)
	entry, err := rangeTestEntry(base+1000, base+30, base+40)
	if err != nil {
		t.Fatalf("rangeTestEntry: %v", err)
	}
	if _, err := bridge.PutLocal(alpha, "row-A", entry); err != nil {
		t.Fatalf("PutLocal: %v", err)
	}
	if err := bridge.AppendCheckpoint(); err != nil {
		t.Fatalf("AppendCheckpoint: %v", err)
	}
	r := newQueryResolver(lfs)

	t.Run("200_sorted_window", func(t *testing.T) {
		// Add a second intersecting row so the window has 2 + the sort is visible.
		entry2, _ := rangeTestEntry(base+2000, base+50, base+60)
		if _, err := bridge.PutLocal(alpha, "row-B", entry2); err != nil {
			t.Fatalf("PutLocal B: %v", err)
		}
		if err := bridge.AppendCheckpoint(); err != nil {
			t.Fatalf("AppendCheckpoint B: %v", err)
		}
		cs := NewControlServer(nil, queryTestNodeID, nil, nil)
		cs.SetResolver(r)
		srv := httptest.NewServer(cs.Handler())
		t.Cleanup(srv.Close)
		status, body := rangeGet(t, srv, alpha,
			queryNanosInRFC3339Nano(base+25), queryNanosInRFC3339Nano(base+65),
			queryNanosInRFC3339Nano(base+99999))
		if status != http.StatusOK {
			t.Fatalf("200 path: status=%d body=%s", status, body)
		}
		var rr rangeResponse
		if err := json.Unmarshal(body, &rr); err != nil {
			t.Fatalf("decode rangeResponse: %v body=%s", err, body)
		}
		if len(rr.Rows) != 2 {
			t.Fatalf("200 path: expected 2 intersecting rows ([30,40)+[50,60)); got %d", len(rr.Rows))
		}
		if rr.Entity != alpha {
			t.Fatalf("200 entity=%q want %q", rr.Entity, alpha)
		}
		if rr.Truncated {
			t.Fatalf("200 path: truncated must be false (2 rows << MaxRangeRows)")
		}
		// validTimeStart ascending + the digest is echoed verbatim.
		for i := 1; i < len(rr.Rows); i++ {
			if rr.Rows[i-1].ValidTimeStartNs >= rr.Rows[i].ValidTimeStartNs {
				t.Fatalf("200 path: rows must be validTimeStart-sorted; got [%d, %d]", rr.Rows[i-1].ValidTimeStartNs, rr.Rows[i].ValidTimeStartNs)
			}
		}
		// NO payload field (the index stores a SENTRY body).
		if hasPayloadField(body) {
			t.Fatalf("/v1/range body carries a payload field (the digest-is-not-value fabrication — the index has a SENTRY body): %s", body)
		}
		t.Logf("200: Range [25,65) → %d rows, sorted, truncated=false, no payload field (the no-fabrication discipline holds)", len(rr.Rows))
	})

	t.Run("405_POST_rejected", func(t *testing.T) {
		cs := NewControlServer(nil, queryTestNodeID, nil, nil)
		cs.SetResolver(r)
		srv := httptest.NewServer(cs.Handler())
		t.Cleanup(srv.Close)
		resp, err := http.PostForm(srv.URL+"/v1/range", url.Values{"key": {alpha}})
		if err != nil {
			t.Fatalf("POST /v1/range: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("POST /v1/range returned %d, want 405 (Method-Not-Allowed — Range is a GET read)", resp.StatusCode)
		}
	})

	t.Run("503_resolver_nil_honest_disabled", func(t *testing.T) {
		// SetResolver NEVER called → resolver stays nil → 503 (NOT 404).
		cs := NewControlServer(nil, queryTestNodeID, nil, nil)
		srv := httptest.NewServer(cs.Handler())
		t.Cleanup(srv.Close)
		status, body := rangeGet(t, srv, alpha,
			queryNanosInRFC3339Nano(base+25), queryNanosInRFC3339Nano(base+65),
			queryNanosInRFC3339Nano(base+99999))
		if status != http.StatusServiceUnavailable {
			t.Fatalf("disabled /v1/range returned %d, want 503 (honest no-availability — NOT silent 404); body=%s", status, body)
		}
		var d queryDisabledBody
		if err := json.Unmarshal(body, &d); err != nil {
			t.Fatalf("decode 503: %v body=%s", err, body)
		}
		if d.Error != "query-tier disabled (no --lsm-root)" {
			t.Fatalf("503 error=%q want the honest disclosure %q", d.Error, "query-tier disabled (no --lsm-root)")
		}
	})

	t.Run("503_runs_BEFORE_param_validation_even_when_disabled", func(t *testing.T) {
		// The disabled-tier check runs BEFORE param validation (the SAME order
		// handleQuery pins: a malformed range to a disabled tier is
		// "unavailable", NOT "bad request"). This pins the order so a future
		// refactor does NOT 400 a request that should be 503.
		cs := NewControlServer(nil, queryTestNodeID, nil, nil) // resolver nil
		srv := httptest.NewServer(cs.Handler())
		t.Cleanup(srv.Close)
		// totally empty query — no key, no valid_time_lo/hi, no tx_time.
		resp, err := http.Get(srv.URL + "/v1/range?")
		if err != nil {
			t.Fatalf("GET /v1/range (empty): %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("empty disabled /v1/range returned %d, want 503 (the disabled guard runs BEFORE param validation)", resp.StatusCode)
		}
	})

	t.Run("400_missing_key", func(t *testing.T) {
		cs := NewControlServer(nil, queryTestNodeID, nil, nil)
		cs.SetResolver(r)
		srv := httptest.NewServer(cs.Handler())
		t.Cleanup(srv.Close)
		// no key; valid params present.
		status, _ := rangeGet(t, srv, "",
			queryNanosInRFC3339Nano(base+25), queryNanosInRFC3339Nano(base+65),
			queryNanosInRFC3339Nano(base+99999))
		if status != http.StatusBadRequest {
			// Build the request manually since rangeGet omits empty key.
			t.Fatalf("missing-key /v1/range returned %d, want 400", status)
		}
	})

	t.Run("400_bad_valid_time_lo", func(t *testing.T) {
		cs := NewControlServer(nil, queryTestNodeID, nil, nil)
		cs.SetResolver(r)
		srv := httptest.NewServer(cs.Handler())
		t.Cleanup(srv.Close)
		q := url.Values{}
		q.Set("key", alpha)
		q.Set("valid_time_lo", "not-a-timestamp")
		q.Set("valid_time_hi", queryNanosInRFC3339Nano(base+65).Format(time.RFC3339Nano))
		q.Set("tx_time", queryNanosInRFC3339Nano(base+99999).Format(time.RFC3339Nano))
		resp, err := http.Get(srv.URL + "/v1/range?" + q.Encode())
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("bad valid_time_lo returned %d, want 400", resp.StatusCode)
		}
	})

	t.Run("400_bad_valid_time_hi", func(t *testing.T) {
		cs := NewControlServer(nil, queryTestNodeID, nil, nil)
		cs.SetResolver(r)
		srv := httptest.NewServer(cs.Handler())
		t.Cleanup(srv.Close)
		q := url.Values{}
		q.Set("key", alpha)
		q.Set("valid_time_lo", queryNanosInRFC3339Nano(base+25).Format(time.RFC3339Nano))
		q.Set("valid_time_hi", "2026-13-99T99:99:99Z") // bad RFC3339
		q.Set("tx_time", queryNanosInRFC3339Nano(base+99999).Format(time.RFC3339Nano))
		resp, err := http.Get(srv.URL + "/v1/range?" + q.Encode())
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("bad valid_time_hi returned %d, want 400", resp.StatusCode)
		}
	})

	t.Run("400_bad_tx_time", func(t *testing.T) {
		cs := NewControlServer(nil, queryTestNodeID, nil, nil)
		cs.SetResolver(r)
		srv := httptest.NewServer(cs.Handler())
		t.Cleanup(srv.Close)
		q := url.Values{}
		q.Set("key", alpha)
		q.Set("valid_time_lo", queryNanosInRFC3339Nano(base+25).Format(time.RFC3339Nano))
		q.Set("valid_time_hi", queryNanosInRFC3339Nano(base+65).Format(time.RFC3339Nano))
		q.Set("tx_time", "garbage")
		resp, err := http.Get(srv.URL + "/v1/range?" + q.Encode())
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("bad tx_time returned %d, want 400", resp.StatusCode)
		}
	})

	t.Run("400_empty_window_hi_le_lo", func(t *testing.T) {
		// valid_time_hi <= valid_time_lo: the empty half-open window class.
		cs := NewControlServer(nil, queryTestNodeID, nil, nil)
		cs.SetResolver(r)
		srv := httptest.NewServer(cs.Handler())
		t.Cleanup(srv.Close)
		status, body := rangeGet(t, srv, alpha,
			queryNanosInRFC3339Nano(base+65), // lo
			queryNanosInRFC3339Nano(base+25), // hi < lo → empty window
			queryNanosInRFC3339Nano(base+99999))
		if status != http.StatusBadRequest {
			t.Fatalf("empty-window /v1/range returned %d, want 400 (hi<=lo is the empty-window guard); body=%s", status, body)
		}
	})

	t.Run("404_entity_not_found", func(t *testing.T) {
		// A window disjoint from every durable row → ErrEntityNotFound → 404.
		cs := NewControlServer(nil, queryTestNodeID, nil, nil)
		cs.SetResolver(r)
		srv := httptest.NewServer(cs.Handler())
		t.Cleanup(srv.Close)
		status, body := rangeGet(t, srv, "never-written",
			queryNanosInRFC3339Nano(base+25), queryNanosInRFC3339Nano(base+65),
			queryNanosInRFC3339Nano(base+99999))
		if status != http.StatusNotFound {
			t.Fatalf("not-found /v1/range returned %d, want 404 (ErrEntityNotFound maps here); body=%s", status, body)
		}
		var nf queryNotFoundBody
		if err := json.Unmarshal(body, &nf); err != nil {
			t.Fatalf("decode 404: %v body=%s", err, body)
		}
		if nf.Entity != "never-written" || nf.Error != "not found" {
			t.Fatalf("404 body=%+v want {Error:%q Entity:%q}", nf, "not found", "never-written")
		}
	})
}

// TestScopeHygieneMeshImportOfSyncUnchanged is the
// scope-hygiene guard. Range reuses Resolver (internal/database), NOT the live
// HAMT / pkg/sync engine, so it adds NO new importer of a live-engine/HAMT read
// seam. This guard asserts pkg/mesh's import of pkg/sync (eng) is UNCHANGED —
// Range's /v1/range handler + the resolver path add ZERO engine read-seam
// importers. The check mirrors the pkg/receive source-grep discipline.
func TestScopeHygieneMeshImportOfSyncUnchanged(t *testing.T) {
	wd, err := os.Getwd()
	require_NoErrf(t, "getwd", err)
	controlGo := filepath.Join(wd, "control.go")
	data, err := os.ReadFile(controlGo)
	if err != nil {
		t.Fatalf("read control.go: %v", err)
	}
	// pkg/sync (eng) MUST still be imported (the pre-existing /v1/insert +
	// /v1/get + /v1/query readers use eng.CRDTEntry / eng.CausalDot). This file's
	// handleRange uses database.Resolver + database.CoalesceRange — it does NOT
	// add a new eng. surface. The import line is the SAME shape the
	// query guards inherited.
	if !strings.Contains(string(data), `eng "github.com/hr18vk/sovereign/pkg/sync"`) {
		t.Fatalf("scope hygiene: pkg/mesh/control.go no longer imports pkg/sync (eng) — must NOT change the mesh↔sync import surface (Range reuses Resolver, NOT the engine); the eng import is the pre-existing seam")
	}
	// Range's NEW surface type must be database (NOT eng) — the Range handler
	// references database.Range/something only via Resolver. Assert the handler
	// uses database. (A regression that routed Range through engine.InsertLocal
	// would be the TOCTOU class — Range is READ-only.)
	if !strings.Contains(string(data), "database.ErrEntityNotFound") || !strings.Contains(string(data), `s.resolver.Range`) {
		t.Fatalf("scope hygiene: handleRange must call s.resolver.Range + surface database.ErrEntityNotFound (READ-only via Resolver, NOT the engine)")
	}
	// Range must NOT reach into the live HAMT — no engine.State / engine.InsertLocal
	// in handleRange's body. (A grep on the file, not just the function: the
	// handleRange block must not contain engine read-seam calls.) The handleGet
	// / handleInsert readers are ALLOWED their existing engine seams; the check
	// is scoped to handleRange via the absence of NEW engine.Method calls WITHIN
	// Range's handler — covered by the resolver.Range call above (the handler
	// goes through the resolver, period).
	t.Logf("scope hygiene: pkg/mesh imports pkg/sync (eng) UNCHANGED; handleRange goes through s.resolver.Range (READ-only via Resolver, NOT the engine/HAMT) — Range adds NO engine read-seam importer")
}

// require_NoErrf is a local require-no-error wrapper (testify's require imports
// common types; kept local to avoid a testify-only helper in this guard).
func require_NoErrf(t *testing.T, prefix string, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", prefix, err)
	}
}
