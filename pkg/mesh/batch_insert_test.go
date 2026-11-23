// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

// Tests for /v1/batch-insert (pkg/mesh/control.go).
//
// These tests use package mesh so they can decode the unexported JSON response
// types returned by the handler. The in-process harness mirrors control_test.go:
// eng.DataDir, NewDeltaCRDTEngine, durability.OpenWAL, NewBridge, NewGossiper,
// SetBridge, NewControlServer, and httptest.NewServer. Requests go directly to
// ControlServer.Handler through httptest, without a TLS listener.
//
// The successful-insert case anchors two negative controls:
//   TestBatchInsertPartialBatch reports 400 for an empty-key entry and 200 for
//     the valid entries, rather than reporting success for the whole batch.
//   TestBatchInsertWALFailPerEntry reports 503 for entries whose WAL fsync
//     fails. The durability contract from ADR-0014 and ADR-0015 applies to each
//     entry, not to the batch as a whole.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/hr18vk/sovereign/pkg/durability"
	"github.com/hr18vk/sovereign/pkg/identity"
	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// batchItemReq mirrors the per-entry request accepted by POST
// /v1/batch-insert. Key and Val leave the bitemporal timestamps at their
// defaults: valid from the write time and open-ended.
type batchItemReq struct {
	Key string `json:"key"`
	Val string `json:"val"`
}

// newBatchControlServer builds the same in-process harness as
// TestControlInsert_DurableWriteReturns200. The caller supplies an open WAL;
// the failure test closes it after the first entry to force fsync errors.
func newBatchControlServer(t *testing.T, nodeID [16]byte, wal *durability.WAL) (*httptest.Server, *eng.DeltaCRDTEngine, *Gossiper) {
	t.Helper()
	eng.DataDir = t.TempDir()
	engine, err := eng.NewDeltaCRDTEngine(nodeID, 1, 64*1024*1024)
	if err != nil {
		t.Fatalf("NewDeltaCRDTEngine: %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	bridge := durability.NewBridge(engine, wal, 0)
	g := NewGossiper(nil, nil, engine, identity.NewDirectory())
	g.SetBridge(bridge)
	cs := NewControlServer(g, nodeID, nil, nil)
	srv := httptest.NewServer(cs.Handler())
	t.Cleanup(srv.Close)
	return srv, engine, g
}

// postBatch POSTs items to /v1/batch-insert and returns the decoded
// batchInsertResponse with one status per entry.
func postBatch(t *testing.T, srv *httptest.Server, items []batchItemReq) batchInsertResponse {
	t.Helper()
	body, _ := json.Marshal(struct {
		Items []batchItemReq `json:"items"`
	}{Items: items})
	resp, err := http.Post(srv.URL+"/v1/batch-insert", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /v1/batch-insert: %v", err)
	}
	defer resp.Body.Close()
	// A partial batch is 200 at the HTTP layer (per-entry failures are in the
	// JSON body, not the HTTP status) — so a 4xx/5xx here is a transport/handler
	// error, not a partial-batch signal.
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /v1/batch-insert returned HTTP %d (want 200 — partial-batch failures are per-entry in the body, not the HTTP status); body=%s", resp.StatusCode, readBodyForTest(resp))
	}
	var r batchInsertResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		t.Fatalf("decode batch response: %v", err)
	}
	return r
}

// TestBatchInsertHappy inserts 100 entries and requires Inserted == 100,
// Failed == 0, and a nonzero DotHex with status 200 for every item. PointGet
// checks each key's count, origin, and dot counter; HTTP reads then verify that
// three inserted values are visible through /v1/get.
func TestBatchInsertHappy(t *testing.T) {
	walPath := filepath.Join(t.TempDir(), "batch-ok.wal")
	wal, err := durability.OpenWAL(walPath)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	t.Cleanup(func() { _ = wal.Close() })
	srv, engine, _ := newBatchControlServer(t, test503NodeID, wal)

	const n = 100
	items := make([]batchItemReq, n)
	for i := 0; i < n; i++ {
		items[i] = batchItemReq{Key: batchKey(i), Val: batchVal(i)}
	}
	r := postBatch(t, srv, items)

	if r.Inserted != n {
		t.Fatalf("batch insert: Inserted=%d, want %d durable entries", r.Inserted, n)
	}
	if r.Failed != 0 {
		t.Fatalf("batch insert: Failed=%d, want 0; statuses: %+v", r.Failed, r.Items)
	}
	if len(r.Items) != n {
		t.Fatalf("batch insert: len(Items)=%d, want %d statuses", len(r.Items), n)
	}
	for i, st := range r.Items {
		if st.Code != http.StatusOK {
			t.Fatalf("batch insert: item %d Code=%d, want 200", i, st.Code)
		}
		if st.DotHex == "" || st.DotHex == allZeroHex() {
			t.Fatalf("batch insert: item %d DotHex=%q, want a nonzero receipt", i, st.DotHex)
		}
	}

	// Checking only that keys are present would miss count drift. Require one
	// entry per key, attributed to the local node with a nonzero dot counter.
	for i := 0; i < n; i++ {
		entries := engine.PointGet(batchKey(i))
		if len(entries) != 1 {
			t.Fatalf("batch insert: key %q has %d entries, want exactly 1", batchKey(i), len(entries))
		}
		if entries[0].DotNodeID != test503NodeID {
			t.Fatalf("batch insert: key %q DotNodeID=%x, want local node %x", batchKey(i), entries[0].DotNodeID, test503NodeID)
		}
		if entries[0].DotCounter == 0 {
			t.Fatalf("batch insert: key %q has zero DotCounter after a 200 response", batchKey(i))
		}
	}

	// Read the first, middle, and last keys through the production HTTP
	// endpoint. On the originator, the cache returns the payload as well as
	// presence, so compare the complete value.
	for _, i := range []int{0, n / 2, n - 1} {
		resp, err := http.Get(srv.URL + "/v1/get?key=" + batchKey(i))
		if err != nil {
			t.Fatalf("GET /v1/get?key=%s: %v", batchKey(i), err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET /v1/get?key=%s returned HTTP %d, want 200", batchKey(i), resp.StatusCode)
		}
		var gr getResponse
		if err := json.NewDecoder(resp.Body).Decode(&gr); err != nil {
			t.Fatalf("decode /v1/get body for key %s: %v", batchKey(i), err)
		}
		resp.Body.Close()
		if !gr.Present {
			t.Fatalf("GET /v1/get?key=%s Present=false, want true", batchKey(i))
		}
		if gr.Payload != batchVal(i) {
			t.Fatalf("GET /v1/get?key=%s Payload=%q, want %q", batchKey(i), gr.Payload, batchVal(i))
		}
	}
	t.Logf("batch insert: %d entries inserted with nonzero receipts; all %d keys have one local, nonzero dot; three values matched through /v1/get", n, n)
}

// TestBatchInsertPartialBatch submits one empty key among valid entries. The
// rejected item must return 400 without a receipt; the other items must retain
// their own 200 statuses and receipts rather than inheriting a batch-wide
// result.
func TestBatchInsertPartialBatch(t *testing.T) {
	walPath := filepath.Join(t.TempDir(), "batch-partial.wal")
	wal, err := durability.OpenWAL(walPath)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	t.Cleanup(func() { _ = wal.Close() })
	srv, _, _ := newBatchControlServer(t, test503NodeID, wal)

	// 3 entries: index 1 has an empty key (the bad one). The rest are valid.
	items := []batchItemReq{
		{Key: batchKey(0), Val: batchVal(0)},
		{Key: "", Val: batchVal(1)}, // bad: empty key
		{Key: batchKey(2), Val: batchVal(2)},
	}
	r := postBatch(t, srv, items)

	if r.Inserted != 2 {
		t.Fatalf("partial batch: Inserted=%d, want 2 valid entries", r.Inserted)
	}
	if r.Failed != 1 {
		t.Fatalf("partial batch: Failed=%d, want 1 empty-key failure", r.Failed)
	}
	if len(r.Items) != 3 {
		t.Fatalf("partial batch: len(Items)=%d, want 3", len(r.Items))
	}
	for _, st := range r.Items {
		switch st.Index {
		case 1:
			if st.Code != http.StatusBadRequest {
				t.Fatalf("empty-key entry (index %d, key=%q) Code=%d, want 400", st.Index, st.Key, st.Code)
			}
			if st.DotHex != "" {
				t.Fatalf("empty-key entry DotHex=%q, want no receipt", st.DotHex)
			}
		default:
			if st.Code != http.StatusOK {
				t.Fatalf("valid entry (index %d) Code=%d, want 200 despite another entry's failure", st.Index, st.Code)
			}
			if st.DotHex == "" || st.DotHex == allZeroHex() {
				t.Fatalf("valid entry (index %d) DotHex=%q, want a nonzero receipt", st.Index, st.DotHex)
			}
		}
	}
	t.Logf("partial batch: empty key returned 400 without a receipt; two valid entries returned 200 with receipts")
}

// TestBatchInsertWALFailPerEntry closes the WAL after one successful insert,
// then submits two more entries. Each failed write must return 503 without a
// DotHex receipt, while the earlier durable write remains present. This extends
// the durability checks in ADR-0014 and ADR-0015 to the batch endpoint.
//
// Closing the WAL makes PutLocal's fsync fail and InsertLocalEvents return the
// zero CausalDot. The active bridge makes that sentinel trigger the handler's
// 503 response instead of acknowledging an undurable write.
func TestBatchInsertWALFailPerEntry(t *testing.T) {
	walPath := filepath.Join(t.TempDir(), "batch-walfail.wal")
	wal, err := durability.OpenWAL(walPath)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	srv, engine, g := newBatchControlServer(t, test503NodeID, wal)

	// Entry 0 is durable. Entries 1 and 2 are submitted after the WAL closes and
	// must each report 503 without affecting the earlier receipt.
	items := []batchItemReq{
		{Key: batchKey(0), Val: batchVal(0)}, // durable (WAL open)
		{Key: batchKey(1), Val: batchVal(1)}, // WAL closed below → 503
		{Key: batchKey(2), Val: batchVal(2)}, // WAL still closed → 503
	}
	// The synchronous httptest server completes and fsyncs this request before
	// the test closes the WAL.
	first := postBatch(t, srv, items[:1])
	if first.Items[0].Code != http.StatusOK {
		t.Fatalf("WAL-failure setup: entry 0 Code=%d, want 200 with the WAL open", first.Items[0].Code)
	}
	if err := wal.Close(); err != nil {
		t.Fatalf("close WAL to force write failures: %v", err)
	}

	// The bridge remains active, so each zero-dot result returns 503.
	rest := postBatch(t, srv, items[1:])
	if rest.Inserted != 0 {
		t.Fatalf("WAL-failure writes: Inserted=%d, want 0 because both fsyncs failed", rest.Inserted)
	}
	if rest.Failed != 2 {
		t.Fatalf("WAL-failure writes: Failed=%d, want 2", rest.Failed)
	}
	for _, st := range rest.Items {
		if st.Code != http.StatusServiceUnavailable {
			t.Fatalf("WAL-failed entry index %d Code=%d, want 503", st.Index, st.Code)
		}
		if st.DotHex != "" {
			t.Fatalf("WAL-failed entry index %d DotHex=%q, want no durable receipt", st.Index, st.DotHex)
		}
	}
	// InsertLocal can retain an in-memory dot before its WAL append fails, so
	// presence alone is not the durability contract. The earlier successful
	// entry must remain present, and the failed entries' 503 responses carry the
	// durability result.
	if entries := engine.State().Get(batchKey(0)); len(entries) == 0 {
		t.Fatalf("durable entry 0 is absent after later WAL failures")
	}
	_ = g // SetBridge keeps BridgeActive true for the zero-dot 503 guard.
	t.Logf("entry 0 returned 200 with the WAL open; entries 1 and 2 returned 503 without receipts after it closed")
}

// batchKey and batchVal produce deterministic, distinct fixture keys and
// values using the same zero-padded index shape as the mesh write tests.
func batchKey(i int) string { return "batch-key-" + batchIdx(i) }
func batchVal(i int) string { return batchIdx(i) }

// batchIdx returns a zero-padded three-digit index, sufficient for 100 entries.
func batchIdx(i int) string {
	const hexd = "0123456789"
	b := make([]byte, 3)
	b[0] = hexd[(i/100)%10]
	b[1] = hexd[(i/10)%10]
	b[2] = hexd[i%10]
	return string(b)
}

// readBodyForTest reads the response body for an error message (test-only helper
// — the handler tests need the body on a non-200 to diagnose).
func readBodyForTest(resp *http.Response) string {
	b := make([]byte, 4096)
	n, _ := resp.Body.Read(b)
	return string(b[:n])
}
