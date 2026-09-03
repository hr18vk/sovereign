// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package mesh

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hr18vk/sovereign/pkg/identity"
	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// ═══════════════════════════════════════════════════════════════════════════
// TestHandleGetSustainedReadsNoOOM — the sustained point-get read guard: the
// killer defect on the PRODUCTION read path.
//
// THE DEFECT: pre-fix, handleGet called engine.State.Get(key) — State
// (crdt.go:1457) rebuilds the FULL merged HAMT per call and LEAKS O(N·log N)
// arena bytes per call (Set's functional path-copying never retires its
// intermediate roots). The /verify crash-harness OOM'd the default 64 MiB arena
// at ~2000 sequential /v1/gets — an allocation PANIC, not a graceful error.
//
// THE FIX: handleGet now calls engine.PointGet (point_get.go) — an O(log N)
// per-shard pure read that allocates ZERO arena bytes.
//
// THIS guard: drive THOUSANDS of sequential /v1/get requests through the REAL
// ControlServer handler (the exact function the HTTP server invokes) and assert
// (a) every read returns 200 and (b) the arena high-water stays EXACTLY flat.
// Pre-fix this loop grows the arena monotonically toward the OOM; post-fix it
// is flat. (The pre-fix failure is demonstrated by a bug-injection run —
// routing handleGet back to State.Get makes the arena climb — plus
// pkg/sync's TestPointGet_StateLeakNegativeControl, which proves the leak
// gauge detects growth so this "flat" assertion is not vacuous.)
// ═══════════════════════════════════════════════════════════════════════════
func TestHandleGetSustainedReadsNoOOM(t *testing.T) {
	var nodeID [16]byte
	copy(nodeID[:], "sustained-node")
	engine, err := eng.NewDeltaCRDTEngine(nodeID, 1, 64*1024*1024) // the production default arena
	if err != nil {
		t.Fatalf("NewDeltaCRDTEngine: %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })

	// Seed a realistic live set (the read path's only dependency is the shards).
	const seedN = 1000
	for i := 0; i < seedN; i++ {
		engine.InsertLocal(fmt.Sprintf("sustained-key-%d", i), eng.CRDTEntry{H3Index: uint64(i)})
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
		if code := doGet(fmt.Sprintf("sustained-key-%d", i%seedN)); code != http.StatusOK {
			t.Fatalf("warmup /v1/get #%d returned %d, want 200", i, code)
		}
	}

	hw0 := engine.Arena().HighWater()
	const reads = 5000
	for i := 0; i < reads; i++ {
		if code := doGet(fmt.Sprintf("sustained-key-%d", i%seedN)); code != http.StatusOK {
			t.Fatalf("/v1/get #%d returned %d, want 200", i, code)
		}
	}
	hw1 := engine.Arena().HighWater()

	if hw1 != hw0 {
		t.Fatalf(" regression on the PRODUCTION read path: %d sustained /v1/get reads grew the arena high-water %d -> %d (+%d bytes); the pre-fix State().Get path OOM'd at ~2000 reads", reads, hw0, hw1, hw1-hw0)
	}
	t.Logf(" KILLED: %d sustained /v1/get reads over %d entities left the arena high-water EXACTLY flat at %d bytes (the pre-fix State().Get path OOM'd at ~2000)", reads, seedN, hw1)
}
