// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

import (
	"testing"
	"time"

	cryptorand "crypto/rand"
	"github.com/cloudflare/circl/sign/ed25519"

	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// TestConvergenceLagRecorded holds the engine's Merkle root stable across two
// stampConvergence calls. The second call must set LastConvergedAt and
// LastConvergedRoot, with ConvergenceLag near zero immediately afterward.
// A later unchanged stamp must leave the timestamp fixed so the lag can grow.
//
// No peers are needed. The gauge measures how long the local root has been
// stable; it does not compare roots across nodes.
func TestConvergenceLagRecorded(t *testing.T) {
	// Isolate the engine DataDir per test (mirrors newTestEngine).
	oldDataDir := eng.DataDir
	eng.DataDir = t.TempDir()
	t.Cleanup(func() { eng.DataDir = oldDataDir })

	var nodeID [16]byte
	for i := range nodeID {
		nodeID[i] = byte(i + 1)
	}
	engine, err := eng.NewDeltaCRDTEngine(nodeID, 0, 64*1024*1024)
	if err != nil {
		t.Fatalf("NewDeltaCRDTEngine: %v", err)
	}
	defer engine.Close()

	// A NodeIdentity and no peers are sufficient; convergence stamping does
	// not depend on peer count.
	seed := make([]byte, ed25519.SeedSize)
	if _, err := cryptorand.Read(seed); err != nil {
		t.Fatalf("rand seed: %v", err)
	}
	ident, err := NewNodeIdentity(seed)
	if err != nil {
		t.Fatalf("NewNodeIdentity: %v", err)
	}
	// Construct the Gossiper directly. The stamping path reads only the engine
	// and convergence fields, so a PeerSet, frame sink, dialer, and receiver
	// would add unused setup.
	g := &Gossiper{
		peers:   nil, // no peers: AntiEntropySweep is a no-op; stampConvergence runs
		cache:   newPayloadCache(),
		owner:   ident,
		engine:  engine,
		domains: nil,
	}

	// No convergence timestamp exists before the first sweep.
	if !g.LastConvergedAt().IsZero() {
		t.Fatalf("LastConvergedAt must be zero before any sweep, got %v", g.LastConvergedAt())
	}
	if g.ConvergenceLag() != 0 {
		t.Fatalf("ConvergenceLag must be 0 when never converged, got %v", g.ConvergenceLag())
	}

	// Insert events to make the root nonzero. The first stamp only advances
	// prevRoot from zero; convergence requires a second matching root.
	for i := 0; i < 10; i++ {
		eid := "civic-" + itoa(i)
		entry := eng.CRDTEntry{
			SystemTime: int64(1_700_000_000 + i),
			H3Index:    uint64(i),
		}
		g.InsertLocalEvents(eid, "value-"+itoa(i), entry)
	}
	g.stampConvergence()
	if !g.LastConvergedAt().IsZero() {
		t.Fatalf("after sweep 1 (root changed, no match): LastConvergedAt must still be zero, got %v", g.LastConvergedAt())
	}

	// With no new events, this root matches prevRoot but differs from the zero
	// lastConvergedRoot, so the second stamp records convergence.
	g.stampConvergence()
	if g.LastConvergedAt().IsZero() {
		t.Fatalf("after sweep 2 (root stable across two sweeps): LastConvergedAt must advance, still zero")
	}
	stableRoot := engine.State().MerkleRoot()
	if got := g.LastConvergedRoot(); got != stableRoot {
		t.Fatalf("LastConvergedRoot = %x, want the stable root %x", got, stableRoot)
	}

	// The lag should be small immediately after the converging stamp. The 5 ms
	// threshold leaves room for race-detector scheduling overhead; this is not
	// intended as a precise latency bound.
	lag := g.ConvergenceLag()
	if lag > 5*time.Millisecond {
		t.Fatalf("ConvergenceLag right after convergence = %v, want ~0 (sub-5ms)", lag)
	}
	t.Logf("convergence-lag seed: LastConvergedAt advanced, root=%x, lag=%v", stableRoot, lag)

	// Sweep 3: root still stable. It matches prevRoot but equals
	// lastConvergedRoot now, so it does not re-stamp (no new convergence event).
	// LastConvergedAt stays at the sweep-2 timestamp; the lag grows.
	beforeSweep3 := g.LastConvergedAt()
	time.Sleep(5 * time.Millisecond)
	g.stampConvergence()
	if g.LastConvergedAt() != beforeSweep3 {
		t.Fatalf("after sweep 3 (root stable, already converged): LastConvergedAt must not re-stamp, changed from %v to %v", beforeSweep3, g.LastConvergedAt())
	}
	// A 2 ms lower bound after the 5 ms sleep checks that staleness grows
	// while leaving margin for timer granularity and race-detector overhead.
	if lag := g.ConvergenceLag(); lag < 2*time.Millisecond {
		t.Fatalf("after 5ms sleep + stable sweep 3: ConvergenceLag = %v, want >= 2ms (the staleness grows)", lag)
	}
	t.Logf("convergence-lag staleness after 5ms: lag=%v (grows while stable, no re-stamp)", g.ConvergenceLag())
}

// itoa formats an integer without adding a strconv import for this test.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	pos := len(b)
	neg := i < 0
	if neg {
		i = -i
	}
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		b[pos] = '-'
	}
	return string(b[pos:])
}
