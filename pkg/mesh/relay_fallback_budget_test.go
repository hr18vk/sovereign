// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// This test checks the per-frame fallback budget in shipDelta's foreign batch
// path (ADR-0067). Three nodes form a line: O originates batches, A relays
// them one frame at a time, and C is the destination. C has no digest sink, so
// A's digest request times out and starts defer handling without fault
// injection.
//
// O originates 700 dots in seven 100-entry batches, and A originates 20 dots.
// After A retains O's envelopes, the O-A edge closes so foreignReceived
// measures only the A-C sweep. Two rounds defer, the third arms the ship
// window with sEst=720, and later rounds walk a window covering about 56% of
// the hash ring.
//
// Each escalation round must satisfy foreignReceived <=
// deferSliceMaxEntries (608). Seven full batches contain 700 entries, so the
// pre-check must reject the seventh and leave at most 600 charged entries.
// Charging one per offered entry instead of each entry's actual cost would
// admit all seven batches and breach the budget.
//
// The test does not assert C's final held count. Resuming a capped round from
// lastHash makes window composition depend on walk order: observed runs held
// either 600 or 700 of O's entries with the same per-round budget. The defer
// escalation tests cover delivery; this test covers only charging.
package mesh

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/hr18vk/sovereign/pkg/crypto"
)

func TestRelayFallbackOneBudgetPerFramePath(t *testing.T) {
	ca, err := crypto.NewMeshCA()
	if err != nil {
		t.Fatalf("NewMeshCA: %v", err)
	}
	root := t.TempDir()
	caPath, err := ca.WriteCAPEM(root)
	if err != nil {
		t.Fatalf("WriteCAPEM: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// O ships full deltas without stratification. A owns the stratified defer
	// path. C never sweeps and has no digest sink, so its silence starts the
	// escalation.
	o := newEclipseNode(t, ca, caPath, root, "O", 0xE1, false, false)
	a := newEclipseNode(t, ca, caPath, root, "A", 0xE2, true, false)
	cm := newEclipseNode(t, ca, caPath, root, "C", 0xE3, false, false)

	// All-pair Directory registrations C needs: C verifies O's origin on
	// A's re-published batches and A's origin on A's per-frame self ships.
	reg := func(x, y *EclipseNode) {
		if err := x.dir.Register(y.ident.NodeID, y.ident.Pub); err != nil {
			t.Fatalf("register %x in %x: %v", y.ident.NodeID, x.ident.NodeID, err)
		}
	}
	reg(a, o)
	reg(o, a)
	reg(cm, o)
	reg(cm, a)
	// A needs C's key to verify C's challenge response (ADR-0068). Without
	// this registration the A-C edge remains ineligible for egress and the
	// test cannot reach its defer and ship windows.
	reg(a, cm)

	const mintO = 700
	const mintSelf = 20
	o.g.SetBatchSize(100) // 700 dots -> 7 origin-signed 100-element batches
	eclipseMint(o, "relay-origin", mintO)
	eclipseMint(a, "relay-self", mintSelf)

	// O's sweeps deliver all seven batches. A joins the 700 dots and retains
	// their envelopes through WireRelayHooks. A does not sweep yet, avoiding
	// an A-O request and premature defer state on that edge.
	eclipseWire(t, ctx, o, a)
	for round := 1; round <= 3; round++ {
		o.g.AntiEntropySweep(ctx)
	}
	eclipseDrain(t, a)
	if got := eclipseCount(a, "relay-origin", mintO); got != mintO {
		t.Fatalf("setup: A holds %d of %d origin dots before the relay fallback rounds", got, mintO)
	}

	// Kill the O-A edge: st.foreignReceived aggregates every edge of the
	// sweep — a live O edge would double the round's counts and void the
	// per-round bound. O's state is already joined at A; the retained
	// envelopes live in A's relayCache, not the edge.
	if err := a.ps.ClosePeer(o.ident.NodeID); err != nil {
		t.Fatalf("kill A->O: %v", err)
	}
	if err := o.ps.ClosePeer(a.ident.NodeID); err != nil {
		t.Fatalf("kill O->A: %v", err)
	}
	eclipseAwaitAbsent(t, a.ps, o.ident.NodeID)
	eclipseAwaitAbsent(t, o.ps, a.ident.NodeID)

	// C drops A's request at its nil-digester accept loop. After the 250 ms
	// wait, noteDeferTrigger records the timeout. Rounds 1-2 defer, round 3
	// arms shipWindow with sEst=720, and later rounds charge shipDelta's ring
	// walk. With O disconnected, foreignReceived measures only C.
	a.g.SetDeferHandler(true)
	a.g.SetDigestWaitTimeout(250 * time.Millisecond)
	eclipseWire(t, ctx, a, cm)

	maxEnvs, maxRecv := 0, 0
	perRound := make([]string, 0, 8)
	for round := 1; round <= 8; round++ {
		st := a.g.AntiEntropySweep(ctx)
		if st.foreignEnvelopes > maxEnvs {
			maxEnvs = st.foreignEnvelopes
		}
		if st.foreignReceived > maxRecv {
			maxRecv = st.foreignReceived
		}
		perRound = append(perRound, fmt.Sprintf("r%d:env=%d,recv=%d,relayMiss=%d", round, st.foreignEnvelopes, st.foreignReceived, st.relayMisses))
	}
	eclipseDrain(t, cm)
	t.Logf("relay fallback: perRound=[%v] maxRecv=%d maxEnvs=%d C.heldOrigin=%d/%d C.heldSelf=%d/%d",
		strings.Join(perRound, " "), maxRecv, maxEnvs,
		eclipseCount(cm, "relay-origin", mintO), mintO,
		eclipseCount(cm, "relay-self", mintSelf), mintSelf)

	// A budget check is meaningful only if the walk offered foreign batches.
	// The window covers about 56% of the ring and each batch's 100 keys hash
	// uniformly, so at least four distinct batches in some round is a
	// conservative lower bound. Fewer means escalation or retention failed.
	if maxEnvs < 4 {
		t.Fatalf("empty assertion guard: only %d distinct foreign envelopes published across 8 driven rounds — the escalation arm or the batch retain is broken (perRound=[%v])", maxEnvs, strings.Join(perRound, " "))
	}
	// Every escalation round must stay within the single received-cost
	// budget. The pre-check refuses the seventh batch because 600+100 > 608.
	if maxRecv > 608 {
		t.Errorf("one-budget breach: an escalation round published %d received elements > deferSliceMaxEntries=608 — the per-frame fallback is not charging its batches (the nil-costOf regression class; perRound=[%v])", maxRecv, strings.Join(perRound, " "))
	}
}
