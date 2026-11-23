// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

// These tests cover challenge-answer budgets, hash-order healing, and defensive
// handling of a Gossiper with no PeerSet.
//
// Connected connections answer at most 16 challenges per connection. Declined
// connections have a per-suspect-key cap of 64 and a PeerSet-wide reservation
// ceiling of 65,536, which remains effective when remote addresses rotate.
// Fresh connections must still complete the handshake. The tests observe answer
// frames, server-side reservation counters, skew refusals, convergence, and
// nil-peer drops directly.

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hr18vk/sovereign/pkg/crypto"
	"github.com/hr18vk/sovereign/pkg/receive"
)

// quintetLeafPair issues a CA-signed leaf and writes its PEM pair under root.
// A CN containing a valid node ID lets RegisterInbound install the connection;
// an invalid node ID leaves it on the declined, stateless path. TLS accepts both
// certificates because CN interpretation happens after certificate verification.
func quintetLeafPair(t *testing.T, ca *crypto.MeshCA, root, cn, name string) (certPath, keyPath string) {
	t.Helper()
	leaf, err := ca.IssueLeaf(cn)
	if err != nil {
		t.Fatalf("IssueLeaf(%s): %v", name, err)
	}
	certPath, keyPath, err = leaf.WritePEM(filepath.Join(root, "quintet-leaf-"+name))
	if err != nil {
		t.Fatalf("WritePEM(%s): %v", name, err)
	}
	return certPath, keyPath
}

// quintetChallengerDial opens a client TLS connection with the supplied leaf.
// The client deliberately skips server verification because the test exercises
// the server's responder; the server still requires and verifies the client
// certificate.
func quintetChallengerDial(t *testing.T, caPath, addr, certPath, keyPath string) *tls.Conn {
	t.Helper()
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatalf("read CA PEM: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatalf("AppendCertsFromPEM: the mesh CA PEM did not parse")
	}
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadX509KeyPair: %v", err)
	}
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		RootCAs:      pool,
		Certificates: []tls.Certificate{pair},
		//nolint:gosec // the test client intentionally skips server verification to exercise the responder
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("tls.Dial(%s): %v", addr, err)
	}
	return conn
}

// quintetSendChallenges writes n distinct well-formed 53-byte CHALLENGE
// frames over conn — fresh crypto/rand nonces (the expected wire shape),
// length-prefixed exactly as the serve loop's FrameReader expects.
func quintetSendChallenges(t *testing.T, conn *tls.Conn, challengerID [16]byte, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		var nonce [32]byte
		if _, err := crand.Read(nonce[:]); err != nil {
			t.Fatalf("nonce mint: %v", err)
		}
		if _, err := conn.Write(receive.LengthPrefixFrame(buildChallengeFrame(challengerID, nonce))); err != nil {
			t.Fatalf("challenge %d write: %v", i, err)
		}
	}
}

// quintetCountResponses counts the 133-byte RESPONSE-role challenge frames
// that arrive on conn until the wire goes quiet for two consecutive 300 ms
// windows (the drain sink poll-until-stable pattern — never a fixed sleep:
// a late answer resets the quiet count, so the count stays falsifiable).
func quintetCountResponses(t *testing.T, conn *tls.Conn) int {
	t.Helper()
	fr := receive.NewFrameReader(conn)
	count := 0
	quiet := 0
	for quiet < 2 {
		_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		frame, err := fr.ReadFrame()
		if err != nil {
			quiet++
			continue
		}
		if IsChallengeFrame(frame) && challengeFrameRole(frame) == challengeRoleResponse {
			count++
		}
		quiet = 0
	}
	return count
}

// quintetSeed mints a NodeIdentity seed from crypto/rand (the fresh-key
// shape — the challenger is not a configured mesh member; only its leaf's
// CN decodes, which is exactly the surface the two arms split on).
func quintetSeed(t *testing.T) []byte {
	t.Helper()
	buf := make([]byte, 32)
	if _, err := crand.Read(buf); err != nil {
		t.Fatalf("seed mint: %v", err)
	}
	return buf
}

// TestQ5AnswerBudgetConnectedArm sends 100 well-formed challenges over one
// installed connection. The responder must answer 16 and record 84 budget drops.
// A second connection with a fresh identity must still receive its first answer,
// showing that each connection has an independent handshake budget.
func TestQ5AnswerBudgetConnectedArm(t *testing.T) {
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

	a := newEclipseNode(t, ca, caPath, root, "quintet-connected", 0xA5, false, false)
	var wg sync.WaitGroup
	wg.Add(1)
	go runAcceptLoopWithPeerSet(ctx, a.ln, a.sink, nil, &wg, a.ps)

	chIdent, err := NewNodeIdentity(quintetSeed(t))
	if err != nil {
		t.Fatalf("NewNodeIdentity: %v", err)
	}
	certPath, keyPath := quintetLeafPair(t, ca, root, identHex(chIdent.NodeID), "connected")
	conn := quintetChallengerDial(t, caPath, a.addr, certPath, keyPath)
	defer conn.Close()

	quintetSendChallenges(t, conn, chIdent.NodeID, 100)
	answers := quintetCountResponses(t, conn)
	if answers > 16 {
		t.Errorf("connected arm answered %d of 100 challenges, want at most 16", answers)
	}
	if got := a.ps.challengeAnswerBudgetDrops.Load(); got != 84 {
		t.Errorf("connected arm recorded %d budget drops, want 84", got)
	}

	// Use a fresh identity so RegisterInbound installs the second connection.
	// Reusing the first identity would decline it and exercise the other arm.
	chIdent2, err := NewNodeIdentity(quintetSeed(t))
	if err != nil {
		t.Fatalf("NewNodeIdentity (margin): %v", err)
	}
	certPath2, keyPath2 := quintetLeafPair(t, ca, root, identHex(chIdent2.NodeID), "connected-margin")
	conn2 := quintetChallengerDial(t, caPath, a.addr, certPath2, keyPath2)
	defer conn2.Close()
	quintetSendChallenges(t, conn2, chIdent2.NodeID, 1)
	if m := quintetCountResponsesBounded(t, conn2, 10*time.Second); m != 1 {
		t.Errorf("fresh connected identity received %d answers to one challenge, want 1", m)
	}
}

// quintetDeclinedWave opens conns declined connections and sends perConn
// challenges on each. Reaching the 65,536 global ceiling with per-key caps of 64
// requires at least 1,024 rotating connections. Concurrent readers keep the
// wave's settle time independent of the connection count and return both the
// observed answers and the open connections for the caller to close later.
func quintetDeclinedWave(t *testing.T, caPath, addr, certPath, keyPath string, challengerID [16]byte, conns, perConn int) (int, []*tls.Conn) {
	t.Helper()
	cs := make([]*tls.Conn, conns)
	for i := range cs {
		cs[i] = quintetChallengerDial(t, caPath, addr, certPath, keyPath)
	}
	for _, c := range cs {
		quintetSendChallenges(t, c, challengerID, perConn)
	}
	// Each reader has a rolling quiet window. A shared absolute deadline could
	// expire later readers even while earlier answers were still arriving.
	res := make(chan int, conns)
	for _, c := range cs {
		go func(c *tls.Conn) {
			fr := receive.NewFrameReader(c)
			n := 0
			for {
				_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
				frame, err := fr.ReadFrame()
				if err != nil {
					break // the quiet window closed — this conn is drained
				}
				if IsChallengeFrame(frame) && challengeFrameRole(frame) == challengeRoleResponse {
					n++
				}
			}
			res <- n
			// The caller closes connections after the reservation counters settle.
			// Closing at reader exit could discard challenges still queued on the
			// server's per-connection pipeline.
		}(c)
	}
	total := 0
	for i := 0; i < conns; i++ {
		total += <-res
	}
	return total, cs
}

// TestQ5AnswerBudgetDeclinedArm exercises the stateless responder with a
// CA-signed leaf whose CN is not a node ID. RegisterInbound declines that
// connection, and the responder keys its reservation by remote address.
//
// The checks proceed in order: one challenge on a fresh connection receives one
// answer; 70 challenges on one address reserve exactly 64; and 1,024 rotating
// connections drive the PeerSet-wide reservation total to its 65,536 ceiling.
// The global limit is necessary because rotating addresses would otherwise
// obtain fresh per-key budgets.
func TestQ5AnswerBudgetDeclinedArm(t *testing.T) {
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

	a := newEclipseNode(t, ca, caPath, root, "quintet-declined", 0xA6, false, false)
	var wg sync.WaitGroup
	wg.Add(1)
	go runAcceptLoopWithPeerSet(ctx, a.ln, a.sink, nil, &wg, a.ps)

	chIdent, err := NewNodeIdentity(quintetSeed(t))
	if err != nil {
		t.Fatalf("NewNodeIdentity: %v", err)
	}
	declCert, declKey := quintetLeafPair(t, ca, root, "quintet-declined-not-a-nodeid", "declined")

	// A fresh declined connection must still answer its first challenge.
	c1 := quintetChallengerDial(t, caPath, a.addr, declCert, declKey)
	defer c1.Close()
	quintetSendChallenges(t, c1, chIdent.NodeID, 1)
	margin := quintetCountResponsesBounded(t, c1, 10*time.Second)
	if margin != 1 {
		t.Errorf("fresh declined connection received %d answers to one challenge, want 1", margin)
	}

	c2 := quintetChallengerDial(t, caPath, a.addr, declCert, declKey)
	defer c2.Close()
	quintetSendChallenges(t, c2, chIdent.NodeID, 70)
	perKey := quintetCountResponses(t, c2)
	if perKey > 64 {
		t.Errorf("one declined connection received %d answers to 70 challenges, want at most 64", perKey)
	}
	// Poll the server-side counters until in-flight reservations settle. The
	// wire count is bounded; these counters provide the exact expected totals.
	pkServer, gServer := uint64(0), uint64(0)
	pollDL := time.Now().Add(60 * time.Second)
	for {
		a.ps.challengeDeclinedMu.Lock()
		pkServer = a.ps.challengeDeclinedByKey[c2.LocalAddr().String()].count
		gServer = a.ps.challengeDeclinedGlobal
		a.ps.challengeDeclinedMu.Unlock()
		if (pkServer == 64 && gServer == 65) || time.Now().After(pollDL) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if pkServer != 64 || gServer != 65 {
		t.Errorf("declined reservations are per-key=%d and global=%d, want 64 and 65", pkServer, gServer)
	}

	// Race instrumentation makes the full global wave too slow for the readers'
	// rolling windows. Retain a concurrent mini-wave to exercise reservation
	// synchronization, and run the exact global composition without -race.
	if quintetRaceBuild {
		mini, mcs := quintetDeclinedWave(t, caPath, a.addr, declCert, declKey, chIdent.NodeID, 4, 70)
		defer func() {
			for _, c := range mcs {
				_ = c.Close()
			}
		}()
		if mini > 4*64 {
			t.Errorf("four concurrent declined connections received %d answers, want at most 256", mini)
		}
		if got := a.ps.challengeAnswerBudgetDrops.Load(); got < 6 {
			t.Errorf("race build recorded %d budget drops, want at least 6", got)
		}
		t.Skipf("full declined-arm composition is too slow under -race; margin, per-key, and concurrent cases ran")
	}

	// Sixteen waves of 64 connections send 65 challenges each. Keep every
	// connection open until the counters settle: closing early can discard queued
	// challenges, and ephemeral-port reuse can assign an old address's budget to
	// a later connection. Server-side counters, unlike reader-window wire counts,
	// have an exact terminal state.
	var waveConns []*tls.Conn
	global := 0
	for w := 0; w < 16; w++ {
		n, cs := quintetDeclinedWave(t, caPath, a.addr, declCert, declKey, chIdent.NodeID, 64, 65)
		global += n
		waveConns = append(waveConns, cs...)
	}
	defer func() {
		for _, c := range waveConns {
			_ = c.Close()
		}
	}()
	// Across all three cases, 66,631 challenges must produce 65,536 reservations
	// and 1,095 drops. Poll until the serve loops finish their queued work.
	deadlineW := time.Now().Add(60 * time.Second)
	g := uint64(0)
	drops := uint64(0)
	for time.Now().Before(deadlineW) {
		a.ps.challengeDeclinedMu.Lock()
		g = a.ps.challengeDeclinedGlobal
		a.ps.challengeDeclinedMu.Unlock()
		drops = a.ps.challengeAnswerBudgetDrops.Load()
		if g == challengeAnswerGlobalCeiling && drops == 1095 {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if g != challengeAnswerGlobalCeiling {
		t.Errorf("global declined reservation count is %d after settling, want 65536", g)
	}
	if drops != 1095 {
		t.Errorf("declined-arm budget drops = %d after settling, want 1095 (66,631 challenges minus 65,536 reservations)", drops)
	}
	if total := margin + perKey + global; total > int(challengeAnswerGlobalCeiling) {
		t.Errorf("declined-arm wire total is %d (margin=%d per-key=%d global=%d), above the 65536 ceiling", total, margin, perKey, global)
	}
	t.Logf("declined-arm wire counts: margin=%d per-key=%d global=%d total=%d; exact assertions use server counters", margin, perKey, global, margin+perKey+global)
}

// TestQ1HashOrderHealBoundedRefusals models a version-skew sender by restoring
// delta-walk hash order with disableShipOrderBugInject. B mints 3,000 keys while
// partitioned, reconnects to A, and must converge within four driven rounds.
// A must hold every key and reach Lamport counter 3,001.
//
// Skew-refusal totals vary with delta-walk order and the time-dependent
// admission envelope. Pre-apply clock advancement can also hide a refusal by
// presenting the bound with a clock already at the arrival's dot. The count is
// therefore diagnostic; convergence, key cardinality, and the final clock are
// the deterministic assertions. Separate admission tests exercise the bound
// itself, and the fault control verifies the arrival-order injection.
func TestQ1HashOrderHealBoundedRefusals(t *testing.T) {
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

	a := newEclipseNode(t, ca, caPath, root, "hash-order-a", 0xA7, false, false)
	b := newEclipseNode(t, ca, caPath, root, "hash-order-b", 0xB8, false, false)
	if err := a.dir.Register(b.ident.NodeID, b.ident.Pub); err != nil {
		t.Fatalf("register B in A: %v", err)
	}
	if err := b.dir.Register(a.ident.NodeID, a.ident.Pub); err != nil {
		t.Fatalf("register A in B: %v", err)
	}
	const mint = 3000
	eclipseMint(b, "hash-order-key-", mint)
	eclipseWire(t, ctx, a, b)
	// Restore hash-order shipping to model a peer without sorted delivery.
	b.g.disableShipOrderBugInject.Store(true)

	convergedRound := 0
	for round := 1; round <= 8; round++ {
		var sweepWG sync.WaitGroup
		sweepWG.Add(2)
		go func() { defer sweepWG.Done(); a.g.AntiEntropySweep(ctx) }()
		go func() { defer sweepWG.Done(); b.g.AntiEntropySweep(ctx) }()
		sweepWG.Wait()
		eclipseDrain(t, a)
		if a.engine.MerkleRootFromShards() == b.engine.MerkleRootFromShards() {
			convergedRound = round
			break
		}
	}
	_, skew, _, _ := eclipseDrain(t, a)
	// Refused frames can be shipped again. Convergence and final state are the
	// deterministic result; the timing-sensitive refusal count is diagnostic.
	t.Logf("hash-order arrival produced %d skew refusals and converged on round %d", skew, convergedRound)
	if convergedRound == 0 || convergedRound > 4 {
		t.Errorf("hash-order healing did not converge within four rounds (convergedRound=%d)", convergedRound)
	}
	if got := eclipseCount(a, "hash-order-key-", mint); got != mint {
		t.Errorf("A holds %d of %d minted keys after healing", got, mint)
	}
	if clockA := a.engine.LamportCounter(); clockA != uint64(mint+1) {
		t.Errorf("A Lamport counter is %d after healing, want %d (genesis plus applied dots)", clockA, mint+1)
	}
}

// TestI7NilPeersGossiperDeliverDigestNoPanic passes a nonzero connection ID and
// a zero-filled frame to a zero-value Gossiper. The frame is long enough for the
// bounded sender and role reads, so delivery reaches the admission gate. A nil
// PeerSet must produce a gate drop rather than an egressVerified dereference
// panic. A recovered panic identifies the missing guard directly.
func TestI7NilPeersGossiperDeliverDigestNoPanic(t *testing.T) {
	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("DeliverDigest panicked with a nil PeerSet and nonzero connection ID: %v", rec)
		}
	}()
	g := &Gossiper{}
	frame := make([]byte, 512) // past every fixed offset; zero bytes — the gate derefs before any role routing
	g.DeliverDigest([16]byte{0x01}, frame)
}

// quintetCountResponsesBounded polls the drain window until at least one
// response lands or the deadline expires — the load-independence pattern
// (a starved settle window is a flake, never a verdict). The upper bound
// stays exact: a second answer in any window still fails the == 1 check.
func quintetCountResponsesBounded(t *testing.T, conn *tls.Conn, deadline time.Duration) int {
	t.Helper()
	total := 0
	end := time.Now().Add(deadline)
	for total < 1 && time.Now().Before(end) {
		total += quintetCountResponses(t, conn)
		if total < 1 {
			time.Sleep(50 * time.Millisecond)
		}
	}
	return total
}

// TestQ5bSignFailBurnConnectedArm forces challenge signatures to fail. Failed
// attempts must not consume connected or declined budgets, and a successful
// challenge after the fault is cleared must still receive an answer.
func TestQ5bSignFailBurnConnectedArm(t *testing.T) {
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
	a := newEclipseNode(t, ca, caPath, root, "sign-fail-node", 0xB5, false, false)
	var wg sync.WaitGroup
	wg.Add(1)
	go runAcceptLoopWithPeerSet(ctx, a.ln, a.sink, nil, &wg, a.ps)
	chIdent, err := NewNodeIdentity(quintetSeed(t))
	if err != nil {
		t.Fatalf("NewNodeIdentity: %v", err)
	}
	certPath, keyPath := quintetLeafPair(t, ca, root, identHex(chIdent.NodeID), "q5b")
	conn := quintetChallengerDial(t, caPath, a.addr, certPath, keyPath)
	defer conn.Close()
	a.ps.signFailBugInject.Store(true)
	defer a.ps.signFailBugInject.Store(false)
	quintetSendChallenges(t, conn, chIdent.NodeID, 17)
	_ = quintetCountResponses(t, conn) // No answers arrive while signing fails.
	if got := a.ps.challengeAnswerBudgetDrops.Load(); got != 0 {
		t.Errorf("17 failed signatures produced %d connected budget drops, want 0", got)
	}
	// Clearing the fault on the same connection must restore the handshake.
	a.ps.signFailBugInject.Store(false)
	quintetSendChallenges(t, conn, chIdent.NodeID, 1)
	if m := quintetCountResponsesBounded(t, conn, 10*time.Second); m != 1 {
		t.Errorf("after clearing the signature fault, one challenge received %d answers, want 1", m)
	}
	// Failed signatures on the declined arm must likewise refund reservations.
	declCert, declKey := quintetLeafPair(t, ca, root, "quintet-declined-not-a-nodeid", "q5bdecl")
	dc := quintetChallengerDial(t, caPath, a.addr, declCert, declKey)
	defer dc.Close()
	a.ps.challengeDeclinedMu.Lock()
	pre := a.ps.challengeDeclinedGlobal
	a.ps.challengeDeclinedMu.Unlock()
	a.ps.signFailBugInject.Store(true)
	quintetSendChallenges(t, dc, chIdent.NodeID, 5)
	_ = quintetCountResponses(t, dc)
	a.ps.signFailBugInject.Store(false)
	a.ps.challengeDeclinedMu.Lock()
	post := a.ps.challengeDeclinedGlobal
	a.ps.challengeDeclinedMu.Unlock()
	if post != pre {
		t.Errorf("declined reservation global changed from %d to %d across five failed signatures, want unchanged", pre, post)
	}
}

// quintetLogBuf serializes logger writes with the test's substring counts.
// Serve goroutines can log while the test is reading, so a bare bytes.Buffer
// would race.
type quintetLogBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *quintetLogBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *quintetLogBuf) count(sub string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return strings.Count(b.buf.String(), sub)
}

// TestQ5cPreBudgetNoiseCap sends 100 malformed challenges. Signature budgets do
// not limit parse-failure logging, so the separate noise cap must emit at most
// eight lines while challengeNoiseLogSeq still counts every frame. Waiting for
// the sequence to reach 100 ensures the line-count assertion runs after the
// complete drive rather than during a quiet but incomplete drain.
func TestQ5cPreBudgetNoiseCap(t *testing.T) {
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

	a := newEclipseNode(t, ca, caPath, root, "noise-cap-node", 0xD4, false, false)
	var wg sync.WaitGroup
	wg.Add(1)
	go runAcceptLoopWithPeerSet(ctx, a.ln, a.sink, nil, &wg, a.ps)

	chIdent, err := NewNodeIdentity(quintetSeed(t))
	if err != nil {
		t.Fatalf("NewNodeIdentity: %v", err)
	}
	certPath, keyPath := quintetLeafPair(t, ca, root, identHex(chIdent.NodeID), "q5c")
	conn := quintetChallengerDial(t, caPath, a.addr, certPath, keyPath)
	defer conn.Close()

	// Truncate each challenge below the fixed 53-byte shape so parsing fails
	// before signature verification or answer-budget accounting.
	good := buildChallengeFrame(chIdent.NodeID, [32]byte{7})
	prefixed := receive.LengthPrefixFrame(good[:40])
	var buf quintetLogBuf
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	for i := 0; i < 100; i++ {
		if _, werr := conn.Write(prefixed); werr != nil {
			t.Fatalf("write malformed challenge %d: %v", i, werr)
		}
	}
	count := func() int {
		return buf.count("malformed frame or no owner identity")
	}
	// The capped line count reaches eight before all frames are necessarily
	// processed. The sequence counter is the complete-drain signal because it
	// advances for both printed and suppressed messages.
	drainDL := time.Now().Add(6 * time.Second)
	for a.ps.challengeNoiseLogSeq.Load() < 100 && time.Now().Before(drainDL) {
		time.Sleep(50 * time.Millisecond)
	}
	if got := a.ps.challengeNoiseLogSeq.Load(); got < 100 {
		t.Fatalf("noise sequence reached %d of 100 within 6s; the malformed-frame drive did not finish", got)
	}
	if got := count(); got > 8 {
		t.Errorf("100 malformed challenges produced %d parse-failure log lines, want at most 8", got)
	}
}

// TestI7bNilGuardCounterSplit sends 100 frames to a zero-value Gossiper. Every
// frame must increment deliverDigestNilGuardDrops without changing
// digestUnverifiedDrops, keeping missing-peer drops distinct from verification
// failures. The shared log cap emits the first eight messages.
func TestI7bNilGuardCounterSplit(t *testing.T) {
	g := &Gossiper{}
	frame := make([]byte, 512)
	var buf quintetLogBuf
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	for i := 0; i < 100; i++ {
		g.DeliverDigest([16]byte{byte(i)}, frame)
	}
	if got := g.deliverDigestNilGuardDrops.Load(); got != 100 {
		t.Errorf("100 nil-peer deliveries produced %d dedicated drops, want 100", got)
	}
	if got := g.digestUnverifiedDrops.Load(); got != 0 {
		t.Errorf("nil-peer deliveries produced %d unverified drops, want 0", got)
	}
	if got := buf.count("nil-peers 0-value Gossiper"); got != 8 {
		t.Errorf("100 nil-peer deliveries produced %d log lines, want 8", got)
	}
}
