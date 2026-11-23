// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hr18vk/sovereign/pkg/identity"
	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// TestHandleGetSustainedReadsNoOOM checks that repeated point reads do not
// retain intermediate HAMT roots. State().Get rebuilds the merged HAMT, and the
// functional path copies made by Set are not retired after the call. Routing
// handleGet through State().Get therefore grew the arena on every request; the
// default 64 MiB arena panicked after roughly 2,000 sequential reads.
//
// handleGet instead uses engine.PointGet, an O(log N) read within each shard
// that allocates no arena bytes. This test drives 5,000 requests through the
// ControlServer handler and requires every response to succeed while the arena
// high-water mark remains unchanged. Routing handleGet back to State().Get
// makes the assertion fail. TestPointGet_StateLeakNegativeControl separately
// checks that the high-water measurement detects growth.
func TestHandleGetSustainedReadsNoOOM(t *testing.T) {
	var nodeID [16]byte
	copy(nodeID[:], "pointget-t4-node")
	engine, err := eng.NewDeltaCRDTEngine(nodeID, 1, 64*1024*1024) // the production default arena
	if err != nil {
		t.Fatalf("NewDeltaCRDTEngine: %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })

	// Seed a realistic live set (the read path's only dependency is the shards).
	const seedN = 1000
	for i := 0; i < seedN; i++ {
		engine.InsertLocal(fmt.Sprintf("pointget-t4-%d", i), eng.CRDTEntry{H3Index: uint64(i)})
	}

	g := NewGossiper(nil, nil, engine, identity.NewDirectory())
	cs := NewControlServer(g, nodeID, nil, nil)
	handler := cs.Handler()

	doGet := func(key string) int {
		req := httptest.NewRequest(http.MethodGet, "/v1/get?key="+key, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}

	// Warm up (absorb any one-time lazy init), then measure.
	for i := 0; i < 100; i++ {
		if code := doGet(fmt.Sprintf("pointget-t4-%d", i%seedN)); code != http.StatusOK {
			t.Fatalf("warmup /v1/get #%d returned %d, want 200", i, code)
		}
	}

	hw0 := engine.Arena().HighWater()
	const reads = 5000
	for i := 0; i < reads; i++ {
		if code := doGet(fmt.Sprintf("pointget-t4-%d", i%seedN)); code != http.StatusOK {
			t.Fatalf("/v1/get #%d returned %d, want 200", i, code)
		}
	}
	hw1 := engine.Arena().HighWater()

	if hw1 != hw0 {
		t.Fatalf("%d sustained /v1/get reads grew the arena high-water from %d to %d bytes (+%d); PointGet must not retain intermediate HAMT roots", reads, hw0, hw1, hw1-hw0)
	}
	t.Logf("%d sustained /v1/get reads over %d entities left the arena high-water at %d bytes", reads, seedN, hw1)
}
