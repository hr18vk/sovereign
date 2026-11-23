// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package main

// TestResponderIndegreeRoute verifies the /debug/responder-indegree route.
// When enabled, the route returns 200 and mirrors mesh.RespondIndegSnapshot:
// the enabled state, 17-bucket occupancy histogram, arrival count, and cap.
// The route returns 404 by default. pkg/mesh tests cover arrival recording and
// occupancy sampling; these tests cover the HTTP contract.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"

	"github.com/hr18vk/sovereign/pkg/identity"
	"github.com/hr18vk/sovereign/pkg/mesh"
)

func TestResponderIndegreeRoute_ArmedRouteMirrorsSnapshot(t *testing.T) {
	t.Setenv("SOVEREIGN_RESPOND_INDEG_DEBUG", "1")
	os.Unsetenv("SOVEREIGN_TEST_FAULT_FINGERPRINT")
	g := mesh.NewGossiper(nil, nil, nil, identity.NewDirectory())
	g.SetStratifiedAntiEntropy(true) // allocates the responder seam
	g.SetRespondIndegArmed(true)     // arms the tracker
	port := fpRouteFreePort(t)
	srv := startLivecheck(fmt.Sprintf("127.0.0.1:%d", port), fpRouteNodeID(0xA2), nil, nil, g, nil, nil, nil)
	defer func() { _ = srv.Shutdown(context.Background()) }()
	fpRouteSettle(t, port)
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/debug/responder-indegree", port))
	if err != nil {
		t.Fatalf("probe failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/debug/responder-indegree returned %d (want 200 on the armed route)", resp.StatusCode)
	}
	var body struct {
		NodeID   string   `json:"node_id"`
		Armed    bool     `json:"armed"`
		Arrivals uint64   `json:"arrivals"`
		Hist     []uint64 `json:"occupancy_hist"`
		Cap      int      `json:"cap"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	snap := g.RespondIndegSnapshot()
	if !body.Armed {
		t.Fatalf("the armed route reported armed=false — the tracker was armed in-process")
	}
	if len(body.Hist) != snap.Cap+1 || len(body.Hist) != 17 {
		t.Fatalf("occupancy_hist len=%d (want 17 = cap+1) — the distributional shape, not a flat max", len(body.Hist))
	}
	if body.Cap != snap.Cap || body.Arrivals != snap.Arrivals {
		t.Fatalf("the route (arrivals=%d cap=%d) does not mirror RespondIndegSnapshot() (arrivals=%d cap=%d)", body.Arrivals, body.Cap, snap.Arrivals, snap.Cap)
	}
}

func TestResponderIndegreeRoute_UnarmedControl(t *testing.T) {
	os.Unsetenv("SOVEREIGN_RESPOND_INDEG_DEBUG")
	os.Unsetenv("SOVEREIGN_TEST_FAULT_FINGERPRINT")
	g := mesh.NewGossiper(nil, nil, nil, identity.NewDirectory())
	port := fpRouteFreePort(t)
	srv := startLivecheck(fmt.Sprintf("127.0.0.1:%d", port), fpRouteNodeID(0xA2), nil, nil, g, nil, nil, nil)
	defer func() { _ = srv.Shutdown(context.Background()) }()
	fpRouteSettle(t, port)
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/debug/responder-indegree", port))
	if err != nil {
		t.Fatalf("the unarmed probe failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("route returned %d with debugging disabled, want 404", resp.StatusCode)
	}
}
