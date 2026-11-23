// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package main

// The memstats route accounts for both directions of relay batch retention.
// This test checks that relay_batch_reverse_bytes is present and included in
// mesh_cache_bytes. The mesh package tests the byte counter's retain/delete
// behavior and its per-entry footprint.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/hr18vk/sovereign/pkg/identity"
	"github.com/hr18vk/sovereign/pkg/mesh"
)

func TestMemstats_RelayReverseBytes(t *testing.T) {
	// RetainForeignBatch dereferences the owner while filtering self-originated
	// dots. Three foreign dots give the reverse index a nonzero footprint.
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 3)
	}
	owner, err := mesh.NewNodeIdentity(seed)
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	g := mesh.NewGossiper(nil, owner, nil, identity.NewDirectory())
	var foreign [16]byte
	for i := range foreign {
		foreign[i] = 0xF2
	}
	frame := make([]byte, 137)
	for i := range frame {
		frame[i] = byte(i)
	}
	g.RetainForeignBatch(foreign, 7, []uint64{101, 102, 103}, frame)
	port := fpRouteFreePort(t)
	srv := startLivecheck(fmt.Sprintf("127.0.0.1:%d", port), fpRouteNodeID(0xA5), nil, nil, g, nil, nil, nil)
	defer func() { _ = srv.Shutdown(context.Background()) }()
	fpRouteSettle(t, port)
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/debug/memstats", port))
	if err != nil {
		t.Fatalf("the memstats probe failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/debug/memstats returned %d, want 200", resp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode memstats response: %v", err)
	}
	if _, ok := body["relay_batch_reverse_bytes"]; !ok {
		t.Fatalf("/debug/memstats omitted relay_batch_reverse_bytes")
	}
	// Recompute mesh_cache_bytes from the route's exposed terms.
	get := func(k string) float64 { v, _ := body[k].(float64); return v }
	sum := get("payload_bytes") + get("relay_frame_bytes") + get("relay_batch_forward_bytes") + get("relay_batch_reverse_bytes")
	if get("mesh_cache_bytes") != sum {
		t.Fatalf("mesh_cache_bytes=%v, want four-term sum %v", get("mesh_cache_bytes"), sum)
	}
	if _, ok := body["relay_batch_reverse"]; !ok {
		t.Fatalf("/debug/memstats omitted the relay_batch_reverse count")
	}
}
