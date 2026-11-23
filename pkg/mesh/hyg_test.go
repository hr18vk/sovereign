// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"
)

// TestT_HYG_UncappedCountRoute checks the HTTP form of the uncapped entity
// count. The route's indexed_entities value comes from IndexHealth().entities,
// while Stats().Entities independently walks the index for /metrics.
//
// The harness uses the engine, gossip feed, index, resolver, and HTTP route.
// This matters because a stub with a hard-coded IndexHealth response would pass
// even if the route stopped reading the real count. Three live entities must
// produce a count of three without ceiling drops or a degraded health result.
func TestT_HYG_UncappedCountRoute(t *testing.T) {
	on := newProdRoutesNode(t, true)
	cells := []uint64{0x8928308280fffff, 0x8928308280ffffe, 0x8928308280ffffd}
	for i, cell := range cells {
		body, _ := json.Marshal(map[string]interface{}{"key": fmt.Sprintf("hyg-%d", i), "val": "v", "h3_index": cell})
		resp, err := http.Post(on.srv.URL+"/v1/insert", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("POST /v1/insert: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("insert %d failed: %d", i, resp.StatusCode)
		}
	}
	// Check the index walk used by /metrics before reading the route counter.
	st := on.ix.Stats()
	if st.Entities != len(cells) {
		t.Fatalf("Stats().Entities=%d, want %d — the feed did not land", st.Entities, len(cells))
	}
	// IndexHealth supplies the route's indexed_entities value.
	hEnt, _, cd, degraded := on.ix.IndexHealth()
	if hEnt != len(cells) {
		t.Fatalf("IndexHealth().entities=%d at the uncapped default, want %d", hEnt, len(cells))
	}
	if cd != 0 || degraded {
		t.Fatalf("ceilingDrops=%d degraded=%v at the uncapped default, want 0/false", cd, degraded)
	}
	now := time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
	q := fmt.Sprintf("/v1/querybyh3?cell=0x%x&valid_time=%s&tx_time=%s", cells[0], now, now)
	resp, err := http.Get(on.srv.URL + q)
	if err != nil {
		t.Fatalf("GET /v1/querybyh3: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the query got %d", resp.StatusCode)
	}
	var out struct {
		Rows []struct {
			EntityID string `json:"entity_id"`
		} `json:"rows"`
		IndexedEntities int `json:"indexed_entities"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// The HTTP response must report the same distinct-entity count as the walk.
	if out.IndexedEntities != len(cells) {
		t.Fatalf("indexed_entities=%d at the uncapped default, want %d; /metrics reports %d", out.IndexedEntities, len(cells), st.Entities)
	}
	// Each queried cell contains its own entity, so the rows must remain exact.
	if len(out.Rows) != 1 || out.Rows[0].EntityID != "hyg-0" {
		t.Fatalf("query returned incorrect rows: %v", out.Rows)
	}
}

// TestT_HYG_CaveatFieldRoute requires both cross-entity routes to return
// current_state: true because the index contains current placements. The route
// contracts differ for historical queries: /v1/querybyh3 can omit an entity
// that moved out of a cell, but cannot return a false positive;
// /v1/querybysystime remains exact for its >= after_time threshold because the
// latest system time dominates every resolved system time. The field is part of
// every complete answer.
func TestT_HYG_CaveatFieldRoute(t *testing.T) {
	on := newProdRoutesNode(t, true)
	const cell = uint64(0x8928308280fffff)
	body, _ := json.Marshal(map[string]interface{}{"key": "hyg-cav", "val": "v", "h3_index": cell})
	resp, err := http.Post(on.srv.URL+"/v1/insert", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /v1/insert: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("insert failed: %d", resp.StatusCode)
	}
	now := time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
	get := func(path string) (bool, int) {
		resp, err := http.Get(on.srv.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s got %d", path, resp.StatusCode)
		}
		var out struct {
			Rows         []struct{} `json:"rows"`
			CurrentState bool       `json:"current_state"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
		return out.CurrentState, len(out.Rows)
	}
	have, rows := get(fmt.Sprintf("/v1/querybyh3?cell=0x%x&valid_time=%s&tx_time=%s", cell, now, now))
	if !have || rows != 1 {
		t.Fatalf("/v1/querybyh3 current_state=%v rows=%d, want true/1 (the field must accompany a complete answer)", have, rows)
	}
	have2, rows2 := get(fmt.Sprintf("/v1/querybysystime?after_time=%s&valid_time=%s&tx_time=%s", past, now, now))
	if !have2 || rows2 != 1 {
		t.Fatalf("/v1/querybysystime current_state=%v rows=%d, want true/1", have2, rows2)
	}
}
