package mesh

import (
	"testing"
	"time"

	cryptorand "crypto/rand"
	"github.com/cloudflare/circl/sign/ed25519"

	eng "github.com/hr18vk/supremum/pkg/sync"
)

// TestConvergenceLagRecorded drives a Gossiper's engine to a stable MerkleRoot
// across two consecutive stampConvergence calls and asserts the convergence-lag
// seed advances: LastConvergedAt moves from the zero Time to a real timestamp,
// LastConvergedRoot equals the stable root, and ConvergenceLag is ~0 right
// after the converging stamp. Race-clean.
//
// The test does NOT need live peers: stampConvergence computes the engine's
// MerkleRoot unconditionally after every sweep (the gauge reads the LOCAL
// engine's root stability, not a cross-node compare — the 2-node roots-equal
// GAUGE is the binary indicator; the lag is the staleness since the local root
// last stabilized). A single-node gossiper therefore exercises the seed.
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

	// Minimal gossiper: a NodeIdentity + an empty PeerSet (no peers — the
	// convergence seed runs regardless of peer count).
	seed := make([]byte, ed25519.SeedSize)
	if _, err := cryptorand.Read(seed); err != nil {
		t.Fatalf("rand seed: %v", err)
	}
	ident, err := NewNodeIdentity(seed)
	if err != nil {
		t.Fatalf("NewNodeIdentity: %v", err)
	}
	// An empty PeerSet needs a frameSink + dialer; the convergence seed does
	// not touch peers, so a nil-safe construction via the real NewPeerSet with
	// a no-op receiver is overkill. Instead build the Gossiper struct directly
	// (the fields the seed reads are engine + the convergence fields, all zero
	// by default).
	g := &Gossiper{
		peers:   nil, // no peers: AntiEntropySweep is a no-op; stampConvergence runs
		cache:   newPayloadCache(),
		owner:   ident,
		engine:  engine,
		domains: nil,
	}

	// Before any sweep: never converged.
	if !g.LastConvergedAt().IsZero() {
		t.Fatalf("LastConvergedAt must be zero before any sweep, got %v", g.LastConvergedAt())
	}
	if g.ConvergenceLag() != 0 {
		t.Fatalf("ConvergenceLag must be 0 when never converged, got %v", g.ConvergenceLag())
	}

	// Sweep 1: insert events so the root is NON-zero, then stamp. The root
	// changed from the zero prevRoot, but it does NOT match prevRoot (prevRoot
	// is still zero), so this sweep does NOT stamp convergence — it just
	// advances prevRoot. This is correct: convergence requires TWO consecutive
	// sweeps with the SAME root.
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

	// Sweep 2: no new events, so the root is STABLE (== sweep 1's root). This
	// sweep matches prevRoot AND differs from lastConvergedRoot (zero) →
	// convergence stamps.
	g.stampConvergence()
	if g.LastConvergedAt().IsZero() {
		t.Fatalf("after sweep 2 (root stable across two sweeps): LastConvergedAt must advance, still zero")
	}
	stableRoot := engine.State().MerkleRoot()
	if got := g.LastConvergedRoot(); got != stableRoot {
		t.Fatalf("LastConvergedRoot = %x, want the stable root %x", got, stableRoot)
	}

	// Right after the converging stamp, the lag is ~0 (small). The threshold
	// is 5ms (not 1ms) so the assertion is robust under -race, where the race
	// detector perturbs time.Since bookkeeping; the invariant under test is
	// "the lag is small right after convergence," not a precise bound.
	lag := g.ConvergenceLag()
	if lag > 5*time.Millisecond {
		t.Fatalf("ConvergenceLag right after convergence = %v, want ~0 (sub-5ms)", lag)
	}
	t.Logf("convergence-lag seed: LastConvergedAt advanced, root=%x, lag=%v", stableRoot, lag)

	// Sweep 3: root still stable. It matches prevRoot but EQUALS
	// lastConvergedRoot now, so it does NOT re-stamp (no new convergence event).
	// LastConvergedAt stays at the sweep-2 timestamp; the lag grows.
	beforeSweep3 := g.LastConvergedAt()
	time.Sleep(5 * time.Millisecond)
	g.stampConvergence()
	if g.LastConvergedAt() != beforeSweep3 {
		t.Fatalf("after sweep 3 (root stable, already converged): LastConvergedAt must NOT re-stamp, changed from %v to %v", beforeSweep3, g.LastConvergedAt())
	}
	// After a 5ms sleep the lag must exceed the post-convergence small-lag
	// regime (the staleness grows while the root stays stable). 2ms is a
	// robust lower bound under -race.
	if lag := g.ConvergenceLag(); lag < 2*time.Millisecond {
		t.Fatalf("after 5ms sleep + stable sweep 3: ConvergenceLag = %v, want >= 2ms (the staleness grows)", lag)
	}
	t.Logf("convergence-lag staleness after 2ms: lag=%v (grows while stable, no re-stamp)", g.ConvergenceLag())
}

// itoa is a tiny dependency-free int->string (avoids strconv for a test helper).
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
