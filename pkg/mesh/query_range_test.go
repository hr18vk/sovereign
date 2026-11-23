// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

// These tests cover /v1/range and its consistency with Resolver.AsOf using the
// production Bridge and a real LocalFS. For one entity and transaction time,
// every row returned by AsOf within [vLo, vHi) must also appear in Range over
// that window.
//
// The route checks cover method and parameter errors, a disabled resolver,
// missing entities, sorted results, and truncation. The tests reuse the query
// harness and its Arrow-index setup. Multi-row files produced below the Bridge
// are covered in internal/database because the Bridge snapshots only the
// dominant row for an entity at each checkpoint.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/hr18vk/sovereign/internal/database"
	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// rangeTestEntry builds an entry with an explicit non-empty valid-time window
// [validStart, validEnd) and a known SystemTime. Bridge.PutLocal preserves both
// bounds in the Arrow row, allowing the test to construct disjoint windows and
// check Range's intersection rules.
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
// AsOf-consistency superset over a real *LocalFS via the Bridge.
// ──────────────────────────────────────────────────────────────────────────

// TestAsOfConsistencyRangeSupersetOverLocalFS checks four AsOf probes against a
// Range result over the same entity, valid-time window, and transaction time.
// Every selected row must be present in the Range set.
//
// SnapshotToLSM keeps only the dominant row for an entity in a checkpoint. The
// test therefore performs one PutLocal and AppendCheckpoint per disjoint window,
// producing three L0 files for Range to read. Multi-row files below the Bridge
// are covered by internal/database/range_test.go.
func TestAsOfConsistencyRangeSupersetOverLocalFS(t *testing.T) {
	const alpha = "alpha"
	base := int64(1_700_000_000_000_000_000)
	// One row per checkpoint; each checkpoint's dominant lands as its own L0
	// file. Windows are disjoint (so each AsOf probe resolves a unique row across
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
			t.Fatalf("AsOf(alpha, v=%d) returned {vs=%d,sys=%d}, which is absent from Range; their filters disagree", probe-base, got.ValidTimeStart, got.SystemTime)
		}
	}
	t.Logf("4-point AsOf sweep (v=10,35,55,59) each in Range result-set over %d L0 files (one per checkpoint) — Range is a superset of every AsOf point in the window", len(rows))
}

// /v1/range route contract.

// TestRangeRouteContract checks the /v1/range responses for success, unsupported
// methods, a missing resolver, malformed parameters, an empty window, and an
// unknown entity. Successful and not-found requests read a real LocalFS index.
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
		// Rows are ordered by validTimeStart. The index stores SENTRY bodies,
		// so the response can return digests but not original payload values.
		for i := 1; i < len(rr.Rows); i++ {
			if rr.Rows[i-1].ValidTimeStartNs >= rr.Rows[i].ValidTimeStartNs {
				t.Fatalf("200 path: rows must be validTimeStart-sorted; got [%d, %d]", rr.Rows[i-1].ValidTimeStartNs, rr.Rows[i].ValidTimeStartNs)
			}
		}
		if hasPayloadField(body) {
			t.Fatalf("/v1/range body contains a payload field, but the index stores SENTRY bodies: %s", body)
		}
		t.Logf("Range [25,65) returned %d sorted rows with truncated=false and no payload field", len(rr.Rows))
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

	t.Run("503_resolver_nil_disabled", func(t *testing.T) {
		// SetResolver never called → resolver stays nil → 503 (not 404).
		cs := NewControlServer(nil, queryTestNodeID, nil, nil)
		srv := httptest.NewServer(cs.Handler())
		t.Cleanup(srv.Close)
		status, body := rangeGet(t, srv, alpha,
			queryNanosInRFC3339Nano(base+25), queryNanosInRFC3339Nano(base+65),
			queryNanosInRFC3339Nano(base+99999))
		if status != http.StatusServiceUnavailable {
			t.Fatalf("disabled /v1/range returned %d, want 503 (no-availability — not silent 404); body=%s", status, body)
		}
		var d queryDisabledBody
		if err := json.Unmarshal(body, &d); err != nil {
			t.Fatalf("decode 503: %v body=%s", err, body)
		}
		if d.Error != "query-tier disabled (no --lsm-root)" {
			t.Fatalf("503 error=%q want the disclosure %q", d.Error, "query-tier disabled (no --lsm-root)")
		}
	})

	t.Run("503_runs_before_param_validation_even_when_disabled", func(t *testing.T) {
		// The disabled-tier check runs before param validation (the same order
		// handleQuery pins: a malformed range to a disabled tier is
		// "unavailable", not "bad request"). This pins the order so a future
		// refactor does not 400 a request that should be 503.
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
			t.Fatalf("empty disabled /v1/range returned %d, want 503 (the disabled guard runs before param validation)", resp.StatusCode)
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
