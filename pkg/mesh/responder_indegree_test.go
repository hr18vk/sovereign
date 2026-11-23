// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

// These tests exercise the responder in-degree histogram through
// enqueueDigestResponse and its semaphore acquire/drop path. Holding
// respondSem tokens makes the occupancy samples deterministic. The command
// tests separately cover the /debug/responder-indegree route.
//
// The fixture has a real engine and owner but no peers. A spawned digest build
// therefore runs, fails the egress verification for the missing peer, and
// releases its slot without dialing (ADR-0068).

import (
	"hash/maphash"
	"testing"
	"time"

	"github.com/hr18vk/sovereign/pkg/identity"
	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// P1BiiGossiper builds a gossiper with one engine entry, an owner identity, an
// empty PeerSet, and a directory. Stratified anti-entropy allocates respondSem,
// and SetRespondIndegArmed enables occupancy tracking.
func P1BiiGossiper(t *testing.T) (*Gossiper, *eng.DeltaCRDTEngine) {
	t.Helper()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	owner, err := NewNodeIdentity(seed)
	if err != nil {
		t.Fatalf("create owner identity: %v", err)
	}
	var nid [16]byte
	for i := range nid {
		nid[i] = 0xA3
	}
	engine, err := eng.NewDeltaCRDTEngine(nid, 1, 16*1024*1024)
	if err != nil {
		t.Fatalf("create engine: %v", err)
	}
	entry := eng.CRDTEntry{
		SystemTime:     1789000000000000000,
		ValidTimeStart: 1,
		ValidTimeEnd:   2,
		AssertionTime:  3,
		DecisionTime:   4,
	}
	engine.InsertLocal("p1bii-key", entry)
	peers := NewPeerSet(nil, nil, owner, engine)
	g := NewGossiper(peers, owner, engine, identity.NewDirectory())
	g.SetStratifiedAntiEntropy(true)
	g.SetRespondIndegArmed(true)
	return g, engine
}

// TestP1BiiTrackerRecordsOccupancy checks three cases. With all 16 slots held,
// an arrival increments the full bucket and digestRespondDropped. With five
// slots held, it increments hist[5], then releases its acquired slot when the
// missing peer fails egress verification. The blind control counts the arrival
// without adding histogram mass.
func TestP1BiiTrackerRecordsOccupancy(t *testing.T) {
	g, engine := P1BiiGossiper(t)
	defer func() { _ = engine.Close() }()
	sem := g.respondSem
	var victim [16]byte
	victim[15] = 0xB

	// Occupy every slot so the next arrival is dropped.
	for i := 0; i < digestRespondMaxConcurrent; i++ {
		sem <- struct{}{}
	}
	g.enqueueDigestResponse(victim, maphash.Seed{}, 100)
	snap := g.RespondIndegSnapshot()
	if !snap.Armed || snap.Arrivals != 1 || snap.Hist[digestRespondMaxConcurrent] != 1 {
		t.Fatalf("drop bucket: armed=%v arrivals=%d hist[16]=%d, want true, 1, and 1", snap.Armed, snap.Arrivals, snap.Hist[digestRespondMaxConcurrent])
	}
	if drops := g.digestRespondDropped.Load(); drops != 1 {
		t.Fatalf("drop bucket: digestRespondDropped=%d, want 1", drops)
	}

	// Drain 11 of the 16 held tokens to leave five in flight.
	for i := 0; i < 11; i++ {
		<-sem
	}
	g.enqueueDigestResponse(victim, maphash.Seed{}, 100)
	deadline := time.Now().Add(5 * time.Second)
	for len(sem) != 5 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if len(sem) != 5 {
		t.Fatalf("mid occupancy: spawned build did not release its slot; held slots=%d, want 5", len(sem))
	}
	snap = g.RespondIndegSnapshot()
	if snap.Arrivals != 2 || snap.Hist[5] != 1 {
		t.Fatalf("mid occupancy: arrivals=%d hist[5]=%d, want 2 and 1", snap.Arrivals, snap.Hist[5])
	}

	// The blind control suppresses histogram mass but still counts arrivals.
	g.respondIndeg.blind.Store(true)
	g.enqueueDigestResponse(victim, maphash.Seed{}, 100)
	for len(sem) != 5 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	g.respondIndeg.blind.Store(false)
	snap = g.RespondIndegSnapshot()
	if snap.Arrivals != 3 || snap.Hist[5] != 1 {
		t.Fatalf("blind control: arrivals=%d hist[5]=%d, want 3 and the previous count of 1", snap.Arrivals, snap.Hist[5])
	}
	for i := 0; i < 5; i++ {
		<-sem
	}
}
