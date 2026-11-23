// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

// These tests cover control-port route opt-in, disabled H3 indexing, H3 cell
// syntax, and read-your-writes behavior (ADR-0070). Their fault-injection
// harness checks that each assertion fails when the behavior under test is
// disabled. Tests may import internal packages; a separate import-boundary
// test prevents production packages from doing so.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hr18vk/sovereign/internal/database"
	"github.com/hr18vk/sovereign/internal/index"
	"github.com/hr18vk/sovereign/pkg/identity"
	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// ProdRoutesNode builds the production stack the routes need: a real engine
// and gossiper (in-memory, no bridge), a real index, a real resolver over a
// noop durable tier with the live adapter, and a real ControlServer armed or
// unarmed per the flag. Checkpointing is off (no LocalFS), so read-your-writes
// proves the live feed path, not a durable flush.
type ProdRoutesNode struct {
	engine *eng.DeltaCRDTEngine
	ix     *index.Index
	cs     *ControlServer
	srv    *httptest.Server
}

// ProdRoutesLiveAdapter is the engine HAMT adapter discipline re-derived for
// the mesh test (PointGet + Filter2 — the same pattern used in main).
type ProdRoutesLiveAdapter struct{ engine *eng.DeltaCRDTEngine }

func (a ProdRoutesLiveAdapter) LiveRead(ctx context.Context, entityID string, txTimeNs int64) ([]database.LiveEvent, error) {
	entries := a.engine.PointGet(entityID)
	out := make([]database.LiveEvent, 0, len(entries))
	for i := range entries {
		e := entries[i]
		if e.SystemTime > txTimeNs {
			continue // Filter2: the visibility bound
		}
		out = append(out, database.LiveEvent{
			SystemTime:     e.SystemTime,
			ValidTimeStart: e.ValidTimeStart,
			ValidTimeEnd:   e.ValidTimeEnd,
			AssertionTime:  e.AssertionTime,
			H3Index:        e.H3Index,
			PayloadDigest:  e.PayloadDigest,
		})
	}
	return out, nil
}

// ProdRoutesNoop is the empty durable tier (the noop lister precedent).
type ProdRoutesNoop struct{}

func (ProdRoutesNoop) ListObjects(ctx context.Context, bucket, prefix string, maxKeys int) ([]string, error) {
	return nil, nil
}

func (ProdRoutesNoop) Download(ctx context.Context, bucket, key string) (io.ReadCloser, error) {
	return io.NopCloser(nil), errors.New("prod-routes: empty durable tier never downloads")
}

func newProdRoutesNode(t *testing.T, armed bool) *ProdRoutesNode {
	t.Helper()
	nodeID := [16]byte{0x25, 0x25}
	engine, err := eng.NewDeltaCRDTEngine(nodeID, 0, 64*1024*1024)
	if err != nil {
		t.Fatalf("NewDeltaCRDTEngine: %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	g := NewGossiper(nil, nil, engine, identity.NewDirectory())
	var ix *index.Index
	var resolver *database.Resolver
	if armed {
		ix = index.NewWith(index.DefaultShards, index.DefaultEpochNs)
		g.SetIndexFeeder(func(entityID string, h3 uint64, sys int64) {
			ix.Apply(index.Record{EntityID: entityID, H3Index: h3, SystemTime: sys})
		})
		cfg := database.DefaultResolverConfig()
		cfg.LiveSource = ProdRoutesLiveAdapter{engine: engine}
		resolver = database.NewResolver(ProdRoutesNoop{}, ProdRoutesNoop{}, database.NewJemallocAllocator(), "prod-routes", cfg)
		resolver.SetSecondaryIndexSource(ix)
	}
	cs := NewControlServer(g, nodeID, nil, nil)
	if armed {
		cs.SetResolver(resolver)
		cs.SetSecondaryIndex(true)
	}
	srv := httptest.NewServer(cs.Handler())
	t.Cleanup(srv.Close)
	return &ProdRoutesNode{engine: engine, ix: ix, cs: cs, srv: srv}
}

// TestProdRoutes_OptIn checks that a disabled H3 route is absent from the mux
// and returns 404, while an enabled route reaches its handler and reports 400
// for a missing cell. Registering routes unconditionally makes the disabled
// assertion fail.
func TestProdRoutes_OptIn(t *testing.T) {
	off := newProdRoutesNode(t, false)
	resp, err := http.Get(off.srv.URL + "/v1/querybyh3")
	if err != nil {
		t.Fatalf("GET (unarmed): %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("disabled H3 route returned %d, want 404 because no route is registered", resp.StatusCode)
	}
	on := newProdRoutesNode(t, true)
	resp2, err := http.Get(on.srv.URL + "/v1/querybyh3")
	if err != nil {
		t.Fatalf("GET (armed): %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("enabled H3 route returned %d for a missing cell, want 400", resp2.StatusCode)
	}
}

// TestProdRoutes_H3DisabledIgnoresCell checks that an insert carrying
// h3_index stores H3Index zero while secondary indexing is disabled. Honoring
// the requested cell in that configuration makes the test fail.
func TestProdRoutes_H3DisabledIgnoresCell(t *testing.T) {
	off := newProdRoutesNode(t, false)
	body, _ := json.Marshal(map[string]interface{}{"key": "h3off", "val": "v", "h3_index": 0x8928308280fffff})
	resp, err := http.Post(off.srv.URL+"/v1/insert", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /v1/insert: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("insert with h3_index while indexing is disabled returned %d, want 200", resp.StatusCode)
	}
	entries := off.engine.PointGet("h3off")
	if len(entries) == 0 {
		t.Fatalf("insert did not create an entry")
	}
	if entries[0].H3Index != 0 {
		t.Fatalf("disabled H3 indexing stored cell %x; h3_index must be ignored", entries[0].H3Index)
	}
}

// TestProdRoutes_H3Syntax checks that a nonzero h3_index with mode bits
// [59,63) other than 1 is rejected with 400, while a valid mode-1 cell is
// accepted. Disabling plausibleH3Cell makes the rejection assertions fail.
func TestProdRoutes_H3Syntax(t *testing.T) {
	on := newProdRoutesNode(t, true)
	for _, bad := range []uint64{0x1, 0x2000000000000000, 0xFFFFFFFFFFFFFFFF} {
		body, _ := json.Marshal(map[string]interface{}{"key": "h3bad", "val": "v", "h3_index": bad})
		resp, err := http.Post(on.srv.URL+"/v1/insert", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("POST /v1/insert: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("h3_index=%#x with mode nibble %d returned %d, want 400 for a non-1 mode", bad, (bad>>59)&0xF, resp.StatusCode)
		}
	}
	// The boundary check: a well-formed cell is accepted (mode nibble 1).
	body, _ := json.Marshal(map[string]interface{}{"key": "h3good", "val": "v", "h3_index": 0x8928308280fffff})
	resp, err := http.Post(on.srv.URL+"/v1/insert", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /v1/insert: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("well-formed mode-1 H3 cell returned %d, want 200", resp.StatusCode)
	}
}

// TestProdRoutes_ReadYourWrites inserts an H3-tagged entity and immediately
// queries it over HTTP. The durable tier is empty and checkpointing is off, so
// only the live index feed can answer. Removing the gossiper's feeder call
// makes the query miss and fails the test.
func TestProdRoutes_ReadYourWrites(t *testing.T) {
	on := newProdRoutesNode(t, true)
	const cell = uint64(0x8928308280fffff)
	body, _ := json.Marshal(map[string]interface{}{"key": "ryw-e", "val": "v", "h3_index": cell})
	resp, err := http.Post(on.srv.URL+"/v1/insert", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /v1/insert: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("read-your-writes: insert failed: %d", resp.StatusCode)
	}
	now := time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
	q := fmt.Sprintf("/v1/querybyh3?cell=0x%x&valid_time=%s&tx_time=%s", cell, now, now)
	resp2, err := http.Get(on.srv.URL + q)
	if err != nil {
		t.Fatalf("GET /v1/querybyh3: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("read-your-writes: the immediate query got %d — read-your-writes is broken (a delayed or absent feed)", resp2.StatusCode)
	}
	var out struct {
		Rows []struct {
			EntityID string `json:"entity_id"`
		} `json:"rows"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Rows) != 1 || out.Rows[0].EntityID != "ryw-e" {
		t.Fatalf("read-your-writes: want exactly ryw-e, got %+v", out.Rows)
	}
}

// TestProdRoutes_GossiperFeedsIndex checks that single and batch inserts with
// no durability bridge (--wal-path="") both reach the index through
// SetIndexFeeder. Removing either feeder call leaves its writes missing from
// the index and fails the corresponding assertion.
func TestProdRoutes_GossiperFeedsIndex(t *testing.T) {
	nodeID := [16]byte{0x25, 0x26}
	engine, err := eng.NewDeltaCRDTEngine(nodeID, 0, 64*1024*1024)
	if err != nil {
		t.Fatalf("NewDeltaCRDTEngine: %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	g := NewGossiper(nil, nil, engine, identity.NewDirectory())
	ix := index.NewWith(index.DefaultShards, index.DefaultEpochNs)
	g.SetIndexFeeder(func(entityID string, h3 uint64, sys int64) {
		ix.Apply(index.Record{EntityID: entityID, H3Index: h3, SystemTime: sys})
	})
	dg := [32]byte{} // InsertLocalEvents stamps the digest from the payload itself
	// The single in-memory insert (InsertLocalEvents bridge==nil branch).
	g.InsertLocalEvents("goss-single", "v", eng.CRDTEntry{PayloadDigest: dg, H3Index: 0xDD01, SystemTime: 1400, ValidTimeStart: 1, ValidTimeEnd: 2})
	// The batch in-memory insert (InsertLocalEventsBatch bridge==nil loop).
	if _, _, err := g.InsertLocalEventsBatch([]BatchItem{
		{EntityID: "goss-b1", Payload: "v1", Entry: eng.CRDTEntry{PayloadDigest: dg, H3Index: 0xDD02, SystemTime: 1401, ValidTimeStart: 1, ValidTimeEnd: 2}},
		{EntityID: "goss-b2", Payload: "v2", Entry: eng.CRDTEntry{PayloadDigest: dg, H3Index: 0xDD03, SystemTime: 1402, ValidTimeStart: 1, ValidTimeEnd: 2}},
	}); err != nil {
		t.Fatalf("InsertLocalEventsBatch: %v", err)
	}
	for cell, want := range map[uint64]int{0xDD01: 1, 0xDD02: 1, 0xDD03: 1} {
		if got := ix.CandidatesByH3(cell); len(got) != want {
			t.Fatalf("gossiper taps: cell %#x candidates=%v, want %d — an in-memory branch's write did not reach the feed", cell, got, want)
		}
	}
	if st := ix.Stats(); st.Entities != 3 {
		t.Fatalf("gossiper taps: indexed %d entities, want 3", st.Entities)
	}
}
