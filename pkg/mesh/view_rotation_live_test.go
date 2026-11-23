// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

// TestViewRotationBidirectionalLive proves that the rotating view makes every
// intra-region pair bidirectionally live within bounded rounds: both
// directions fire, with the fire following the rotating view membership every
// round. The StarveViewPeerOf seam (the test-only fault injection in
// TopologyManager.StarveViewPeerOf) reproduces the permanently-directed
// shape; that capture is committed with the evidence. The mirror managers
// reproduce the shipped draw from the same bytes and are validated per round
// against the sweep's viewXor observable — a drifting mirror fails loudly
// instead of lying.
// Fault-injectable: (1) the starve seam → one direction never fires → FAIL;
// (2) a non-rotating seed → fires collapse to never/all → FAIL.

import (
	"context"
	"fmt"
	"testing"
	"time"

	"encoding/binary"
	eng "github.com/hr18vk/sovereign/pkg/sync"
)

func TestViewRotationBidirectionalLive(t *testing.T) {
	m := buildCensusMesh(t, 42)
	defer m.close()
	finishCensusMesh(t, m) // accept loops + full-mesh dials — without it every Publish hits "no live peer"
	n := len(m.nodes)
	ids := make([][16]byte, n)
	regions := make([]RegionTag, n)
	for i, nd := range m.nodes {
		ids[i] = nd.ident.NodeID
		regions[i] = nd.region
	}
	for _, nd := range m.nodes {
		nd.g.SetPartialIntraView(true) // the shipped setter, every node
	}
	idTag := make(map[[16]byte]RegionTag, n)
	for i := range ids {
		idTag[ids[i]] = regions[i]
	}
	region1Size := 0
	for _, r := range regions {
		if r == regions[0] {
			region1Size++
		}
	}
	wantDrawn := minInt(intraViewSize, region1Size-1)
	wantElig := region1Size - 1
	ctx := context.Background()
	// the prediction mirrors — the same shipped Select bytes, driven with
	// the same per-sweep seed chain (sweepRound ^ LE(nodeID[:8]), first
	// sweep = round 1; validated per round against st.viewXor below)
	mA := buildArmedManager(0, ids, regions)
	mB := buildArmedManager(1, ids, regions)

	// probe drives `rounds` A-only (or B-only) probe rounds: the sweeper
	// inserts one fresh key per round (so every selected peer's exchange
	// fires, never gated), sweeps alone, and the responder's
	// digestRespondSent delta must equal the mirror's membership
	// prediction exactly — one request → one response, pair-attributable.
	probe := func(sweeper, responder int, mgr *TopologyManager, tag string) int {
		snd, rsp := m.nodes[sweeper], m.nodes[responder]
		prev := rsp.g.digestRespondSent.Load()
		fires := 0
		for round := 1; round <= 40; round++ {
			snd.g.InsertLocalEvents(fmt.Sprintf("k21-%s-%d", tag, round), fmt.Sprintf("v-%d", round), eng.CRDTEntry{
				SystemTime: int64(1_700_100_000 + round),
				H3Index:    uint64(round),
			})
			mgr.SetSeed(selectorRoundSeed(uint64(round), ids[sweeper]))
			pred := false
			wantXor := uint64(0)
			for _, p := range mgr.Select(ctx) {
				if idTag[p] == regions[sweeper] {
					if p == ids[responder] {
						pred = true
					}
					wantXor ^= binary.LittleEndian.Uint64(p[:8])
				}
			}
			st := snd.g.AntiEntropySweep(m.ctx)
			if st.viewXor != wantXor || st.viewDrawn != wantDrawn || st.viewEligible != wantElig {
				t.Fatalf("view rotation: %s round %d: the mirror does not reproduce the shipped draw (mirror xor=%x vs sweep xor=%x, drawn=%d/%d) — the prediction instrument is unvalidated", tag, round, wantXor, st.viewXor, st.viewDrawn, st.viewEligible)
			}
			// Poll, never a fixed sleep (a fixed 250 ms window
			// turned a >250 ms responder deschedule into a false negative on
			// pred=true rounds, and a late prior-round response could
			// double-credit the next round — the poll waits until this
			// round's response lands, so every response is consumed within
			// its own round; the 2s deadline is real-pathology territory,
			// far past any loopback response under load).
			if pred {
				deadline := time.Now().Add(2 * time.Second)
				for rsp.g.digestRespondSent.Load()-prev < 1 && time.Now().Before(deadline) {
					time.Sleep(5 * time.Millisecond)
				}
				if got := rsp.g.digestRespondSent.Load() - prev; got > 1 {
					t.Fatalf("view rotation: %s round %d: %d responses in one round — the one-request-one-response pair-attribution assumption is broken", tag, round, got)
				} else if got != 1 {
					t.Fatalf("view rotation: %s round %d: the selected round's response never arrived within the 2 s deadline — the fire does not follow the view (the directed-fire defect class)", tag, round)
				}
			} else {
				time.Sleep(50 * time.Millisecond) // the grace window: a response here means the responder fired without selection
				if got := rsp.g.digestRespondSent.Load() - prev; got != 0 {
					t.Fatalf("view rotation: %s round %d: responder's response (%d) does not match the rotating-view membership prediction (%v) — the fire does not follow the view (the directed-fire defect class)", tag, round, got, pred)
				}
			}
			prev = rsp.g.digestRespondSent.Load()
			if pred {
				fires++
			}
		}
		return fires
	}

	firesAtoB := probe(0, 1, mA, "AtoB")
	firesBtoA := probe(1, 0, mB, "BtoA")
	if firesAtoB == 0 || firesBtoA == 0 {
		t.Fatalf("view rotation: the pair is not bidirectionally live (A→B=%d/40, B→A=%d/40) — a one-directional pair at p=8/13 is the directed-fire kill condition (the rotation does not heal the directed shape)", firesAtoB, firesBtoA)
	}
	t.Logf("view rotation: A→B fired %d/40 rounds, B→A fired %d/40 rounds — the pair is bidirectionally live with the fire exactly following the rotating view (the rotation closes the directed-fire defect class at zero cost; the fault injection arms B's starve seam and fails here)", firesAtoB, firesBtoA)
}

// TestViewStarveDegenerate verifies the starve seam's contract at a
// degenerate region: at n_r-1 <= f the starved peer must be excluded
// from every intra view drawn by this manager. A 3-node region (n_r-1=2 <= f=8)
// with the starve armed must draw exactly the one non-starved peer.
func TestViewStarveDegenerate(t *testing.T) {
	l := SelectorLayout{name: "starve-degenerate-3", counts: []int{3, 3, 3}}
	ids, regions := buildSelectorPopulation(&l)
	mgr := buildArmedManager(0, ids, regions)
	mgr.StarveViewPeerOf(ids[1])
	ctx := context.Background()
	for round := uint64(1); round <= 12; round++ {
		mgr.SetSeed(selectorRoundSeed(round, ids[0]))
		view := mgr.Select(ctx)
		for _, p := range view {
			if p == ids[1] {
				t.Fatalf("view starve degenerate: round %d drew the starved peer in a degenerate region (view=%d peers) — the seam contract 'excluded from every intra view' is broken at n_r-1=%d <= f=%d", round, len(view), 2, intraViewSize)
			}
		}
		drw, elig, _ := mgr.LastIntraView()
		if drw != 1 || elig != 2 {
			t.Fatalf("view starve degenerate: round %d stats (%d/%d), want drawn=1 (the starved peer removed, the one peer kept) eligible=2", round, drw, elig)
		}
	}
}
