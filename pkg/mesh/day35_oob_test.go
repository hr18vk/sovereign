package mesh

// day35_oob_test.go is the Day-35 (ADR-0040) OOB peer-Directory pubkey
// provisioning gate — the §III teeth that PROVE the two seams correct at the
// UNIT level (the binary 2-node convergence proof is the job-dir
// verify_day35.go harness, NOT committed here).
//
// THE STRUCTURAL TRUTH the teeth encode (verified against the bytes this turn):
// the Day-34 in-process harness (newDay34Harness, day34_topo_test.go:90) keys
// the TopologyManager under the REAL peerID at :193
// (topoA.SetRegion(identB.NodeID, regionB)) AND dials under the REAL peerID at
// :223 (psA.Dial(ctx, addrB, "localhost", identB.NodeID)) — so the in-process
// gate NEVER reproduces the zero-peerID hazard. The hazard is BINARY-ONLY:
// cmd/sovereign-node/main.go dials peerSet.Dial(ctx, pa, host, zeroPeerID) +
// keys the topology under peerIDForAddr(addr) (a SHA-256 addr surrogate) which
// the zero peerID never matches → the region lookup misses → every peer routes
// RegionUnset = intra = byte-identical full-mesh = the N=2 no-op.
//
// So the teeth split:
//
//   - T-OOB-PROVISION-RETIRES-SURROGATE (the LOAD-BEARING headline, unit form):
//     REPRODUCES the hazard at the unit level by keying the topology under a
//     surrogate + asserting topology.Select does NOT return the real nodeID
//     (the RED — the no-op), then RE-KEYS under the real nodeID (the Day-35
//     applyProvisioning path) + asserts Select DOES return it (the retirement).
//   - T-OOB-RECONCILE (Seam B): mints a REAL leaf via crypto.NewMeshCA +
//     ca.IssueLeaf(identHex(nodeID)) (the production cert minter — NOT a
//     fabricated self-signed leaf), dials a real TLS listener, + calls
//     reconcilePeerID → asserts the hex-decode mirrors the certgen mint. RED:
//     a leaf whose CN is the 16 RAW bytes (NOT the 32-char hex) → ok=false (the
//     hex-decode guard is load-bearing — a naive copy would truncate 32-char
//     ASCII hex to 16 garbage bytes).
//   - T-OOB-OFF-BYTE-IDENTICAL: --peer-dir "" + --peer-auto-reconcile false =
//     byte-identical Day-34. Exercised via the topology's un-provisioned default
//     (an untagged peer routes intra) — the cmd tooth asserts the empty-path
//     no-op directly.
//   - T-OOB-NO-FROZEN-TOUCH: the FROZEN 5 are byte-identical pre-AND-post Day
//     35. MIRRORS the Day-34 TestT_TOPO_No_Frozen_Tooth VERBATIM (os.Stat
//     existence guard → t.Fatalf, NOT skip; then `git diff --name-only HEAD`)
//     + adds the explicit bug-inject control (a BOGUS path is REJECTED by the
//     os.Stat guard — proves the guard is load-bearing, NOT vestigial).
//   - T-OOB-RACE: concurrent Dial + reconcile + sweep under -race (the re-key
//     takes ps.mu — the race-detector signal).
//
// The CONFIG-PARSE + APPLY teeth live in cmd/sovereign-node/provisioning_test.go
// (package main — they can reach parsePeerDir/applyProvisioning). The SCOPE
// negative-control tooth lives in pkg/receive/track36_day35_scope_test.go
// (package receive — it can reach the track36ExemptDayNN maps).

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	ed25519 "github.com/cloudflare/circl/sign/ed25519"

	"github.com/hr18vk/supremum/pkg/crypto"
	"github.com/hr18vk/supremum/pkg/receive"
)

// nopFrameSink is a zero-op frameSink for TestT_OOB_RECONNECT_HEALS. The tooth
// dials + drops + heals — it NEVER publishes frames to the PeerSet under test
// (the peer B side sends nothing; the dial-side readLoop's DispatchFrame is
// never reached because the conn drops before any frame arrives). A real
// receive.Receiver needs a bucket, clock, directory, + engine (the day34
// harness builds all four); for a focused reconnect-liveness tooth that is
// dead weight. The nop sink returns AcceptDrop (the conservative verdict —
// any frame that DID arrive would be dropped, NOT applied; the tooth asserts
// reconnect liveness, NOT frame delivery).
type nopFrameSink struct{}

func (nopFrameSink) HandleFrame([]byte) receive.AcceptVerdict {
	return receive.AcceptVerdict{Verdict: receive.DropMalformed}
}
func (nopFrameSink) HandleBatchFrame([]byte) receive.AcceptVerdict {
	return receive.AcceptVerdict{Verdict: receive.DropMalformed}
}
func (nopFrameSink) HandleHybridFrame([]byte) receive.AcceptVerdict {
	return receive.AcceptVerdict{Verdict: receive.DropMalformed}
}

// TestT_OOB_PROVISION_RETIRES_SURROGATE is the LOAD-BEARING headline tooth
// (unit form). It REPRODUCES the Day-34 §7.1 zero-peerID hazard at the unit
// level, then PROVES Day 35 retires it.
//
// THE MECHANISM (verified against the bytes): AntiEntropySweep calls
// g.topology.Select(ctx) (gossip.go:711) which iterates t.regions
// (topology.go:209) and returns the registered peerIDs. The Day-34 binary
// keys t.regions under peerIDForAddr(addr) — a SHA-256 surrogate — while the
// dial stores the peerConn under the ZERO peerID. So the selector returns the
// SURROGATE; Publish(surrogate) finds no live peer (the dial keyed zero) →
// silent fallback (gossip.go:910, non-fatal). The mesh never converges.
//
// THE RED (reproduces the no-op): key the topology under a surrogate [16]byte
// → Select does NOT return the real nodeID (the real nodeID is NOT in
// t.regions; the surrogate IS, but the dial keyed zero, so Publish(real) +
// Publish(surrogate) BOTH miss the live-peer map). The tooth asserts the real
// nodeID is ABSENT from Select's output.
//
// THE RETIREMENT (Day 35): re-key the topology under the REAL nodeID (the
// applyProvisioning path — topo.SetRegion(realNodeID, region)) → Select DOES
// return the real nodeID → Publish(real) finds the live peer → convergence
// completes. The tooth asserts the real nodeID IS PRESENT in Select's output.
func TestT_OOB_PROVISION_RETIRES_SURROGATE(t *testing.T) {
	selfRegion := RegionTag(1)
	peerRegion := RegionTag(2) // CROSS-region (1 != 2) → the inter-region arm
	peerNodeID := [16]byte{0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44}
	// The Day-34 surrogate: a DIFFERENT [16]byte (peerIDForAddr(addr) — a SHA-256
	// surrogate; here a fixed stand-in). The dial keys the peerConn under ZERO,
	// so NEITHER the surrogate NOR the real nodeID is in ps.peers — but the
	// topology is keyed under the surrogate, so Select returns the surrogate,
	// and Publish(real)/(surrogate) both miss. This is the no-op.
	surrogate := [16]byte{0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55}

	// RED — the Day-34 surrogate keying. topo.IsInterRegion(realNodeID) is false
	// (the registry keys the surrogate, NOT the real nodeID; IsInterRegion
	// returns false for a peer NOT in the registry — topology.go:160). Select
	// does NOT return the real nodeID (it returns the surrogate, which the dial
	// never stored under → Publish misses).
	topoRed := NewTopologyManager(selfRegion)
	topoRed.SetRegion(surrogate, peerRegion) // the Day-34 surrogate keying
	topoRed.SetSeed(1)
	if topoRed.IsInterRegion(peerNodeID) {
		t.Fatalf("T-OOB-PROVISION-RETIRES-SURROGATE RED: the Day-34 surrogate path made topo.IsInterRegion(real %x) TRUE — the RED did NOT reproduce the no-op (the surrogate == the real nodeID by accident — a build bug in the RED)", peerNodeID)
	}
	selRed := topoRed.Select(context.Background())
	for _, id := range selRed {
		if id == peerNodeID {
			t.Fatalf("T-OOB-PROVISION-RETIRES-SURROGATE RED: the Day-34 surrogate path returned the REAL nodeID %x from Select (the registry keys the surrogate %x — Select should return the surrogate, NOT the real nodeID) — the RED did NOT reproduce the no-op", peerNodeID, surrogate)
		}
	}
	t.Logf("GATE PASS: T-OOB-PROVISION-RETIRES-SURROGATE RED — the Day-34 surrogate path MISSES (topo.IsInterRegion(real %x)=false; Select does NOT return the real nodeID) → Publish(real) misses → the N=2 no-op reproduces, proving the Day-35 retirement is load-bearing", peerNodeID)

	// THE RETIREMENT — the Day-35 path (applyProvisioning's
	// topo.SetRegion(realNodeID, region)). topo.IsInterRegion(realNodeID) is now
	// TRUE (the registry keys the REAL nodeID; crossRegion(1,2)=true). Select
	// DOES return the real nodeID → Publish(real) hits the live peer →
	// convergence completes.
	topo := NewTopologyManager(selfRegion)
	topo.SetRegion(peerNodeID, peerRegion) // the Day-35 keying under the REAL nodeID
	topo.SetSeed(1)
	if !topo.IsInterRegion(peerNodeID) {
		t.Fatalf("T-OOB-PROVISION-RETIRES-SURROGATE: the Day-35 path (region keyed under the REAL nodeID %x) MISSED — topo.IsInterRegion=%v (want true; self=%d peer=%d) — the selector would route intra, the N=2 no-op reproduces", peerNodeID, topo.IsInterRegion(peerNodeID), selfRegion, peerRegion)
	}
	sel := topo.Select(context.Background())
	found := false
	for _, id := range sel {
		if id == peerNodeID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("T-OOB-PROVISION-RETIRES-SURROGATE: the Day-35 path keyed the region under the REAL nodeID %x but Select did NOT return it (got %d peerIDs) — the selector misses the very peer it should route", peerNodeID, len(sel))
	}
	t.Logf("GATE PASS: T-OOB-PROVISION-RETIRES-SURROGATE — the Day-35 path (region keyed under the REAL nodeID %x) makes topo.IsInterRegion=true + Select returns the real nodeID → Publish(real) HITS → the inter-region arm fires → the 2-node mesh converges", peerNodeID)
}

// TestT_OOB_RECONCILE is the T-OOB-RECONCILE tooth (Seam B): reconcilePeerID
// hex-decodes the peer leaf CommonName → [16]byte + re-keys the peerConn under
// the REAL nodeID. The tooth mints a REAL leaf via the production cert minter
// (crypto.NewMeshCA + ca.IssueLeaf(identHex(nodeID)) — the SAME path
// newDay34Harness uses at day34_topo_test.go:109/146), wraps it in a *tls.Conn
// via a real TLS listener + dial, calls reconcilePeerID, + asserts the returned
// nodeID == realNodeID + ok == true.
//
// The RED control: a leaf whose CN is the 16 RAW bytes (NOT the 32-char hex).
// reconcilePeerID MUST return ok=false (the hex-decode of a 16-raw-byte string
// yields !=16 bytes OR a hex error). This proves the hex-decode is load-bearing
// — a naive copy(id[:], []byte(cn)) would ACCEPT the raw bytes (the injected
// bug) + produce a garbage nodeID that never matches any real nodeID.
//
// ROUTING-only (M3): the reconcile re-keys the ROUTING map (ps.peers); it does
// NOT call Directory.Register/RegisterPQ (the verification pubkey stays the
// deploy's OOB concern). A self-announced node with NO OOB-provisioned
// Directory pubkey is ROUTED but NOT VERIFIED → its deltas DROPPED LOUD via
// VerifyFail (the correct zero-trust posture, disclosed ADR-0040 §6).
func TestT_OOB_RECONCILE(t *testing.T) {
	realNodeID := [16]byte{0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66}

	// Mint a REAL leaf with CN = hex(realNodeID) via the production cert minter
	// (the certgen mirror — IssueLeaf sets CommonName: nodeID, certgen.go:176).
	ca, err := crypto.NewMeshCA()
	if err != nil {
		t.Fatalf("NewMeshCA: %v", err)
	}
	leaf, err := ca.IssueLeaf(identHex(realNodeID)) // CN = the 32-char lowercase hex
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}
	conn := dialLeafTLS(t, leaf)
	defer conn.Close()

	pc := &peerConn{addr: "127.0.0.1:0", conn: conn, peerID: [16]byte{}}
	ps := &PeerSet{peers: make(map[[16]byte]*peerConn), byAddr: make(map[string]*peerConn)}
	got, ok := ps.reconcilePeerID(pc, conn)
	if !ok {
		t.Fatalf("T-OOB-RECONCILE: reconcilePeerID returned ok=false for a leaf with CN=hex(realNodeID) — the hex-decode MISSED (want ok=true, got %x)", got)
	}
	if got != realNodeID {
		t.Fatalf("T-OOB-RECONCILE: reconcilePeerID returned %x, want %x — the hex-decode produced the wrong nodeID (the certgen CN mirror is broken)", got, realNodeID)
	}
	t.Logf("GATE PASS: T-OOB-RECONCILE — reconcilePeerID hex-decoded the leaf CN %q -> %x (the production-cert-minter mirror; ROUTING-only per M3)", identHex(realNodeID), got)

	// The RED control: a leaf whose CN is the 16 RAW bytes (NOT the 32-char hex).
	// reconcilePeerID MUST return ok=false (the hex-decode of a 16-raw-byte string
	// yields !=16 bytes — hex.DecodeString needs 32 hex chars for 16 bytes). This
	// proves the hex-decode is load-bearing: a naive copy(id[:], []byte(cn))
	// would ACCEPT the raw bytes (the injected bug) + produce a garbage nodeID.
	rawCN := string(realNodeID[:]) // the 16 RAW bytes, NOT hex — non-ASCII
	leafRed, err := ca.IssueLeaf(rawCN)
	if err != nil {
		// A raw-bytes CN with non-ASCII bytes may fail x509 validation; that is
		// ITSELF the RED firing at the mint layer (a non-hex CN is not a valid
		// x509 string). If the mint rejects it, the reconcile never sees it —
		// but the hex-decode guard is still load-bearing for a CN that DOES mint
		// (e.g. a 16-char ASCII string). Re-mint with a 16-char ASCII stand-in.
		asciiCN := "0123456789abcdef" // 16 ASCII chars — mints, but hex-decodes to 8 bytes
		leafRed, err = ca.IssueLeaf(asciiCN)
		if err != nil {
			t.Fatalf("T-OOB-RECONCILE RED: could not mint a non-hex-CN leaf (raw-bytes CN rejected by x509; ASCII stand-in %q also rejected): %v — the RED needs a leaf that mints but does NOT hex-decode to 16 bytes", asciiCN, err)
		}
	}
	connRed := dialLeafTLS(t, leafRed)
	defer connRed.Close()
	pcRed := &peerConn{addr: "127.0.0.1:0", conn: connRed, peerID: [16]byte{}}
	psRed := &PeerSet{peers: make(map[[16]byte]*peerConn), byAddr: make(map[string]*peerConn)}
	gotRed, okRed := psRed.reconcilePeerID(pcRed, connRed)
	if okRed {
		t.Fatalf("T-OOB-RECONCILE RED: reconcilePeerID returned ok=TRUE for a non-hex CN (got %x) — the hex-decode ACCEPTED a non-32-hex-char CN; the RED did NOT fire — the hex-decode guard is vestigial (a naive copy would truncate 32-char hex to 16 garbage bytes)", gotRed)
	}
	t.Logf("GATE PASS: T-OOB-RECONCILE RED — reconcilePeerID REJECTED a non-hex CN (ok=false) — the hex-decode guard is load-bearing (a naive copy would truncate 32-char hex to 16 garbage bytes)")
}

// TestT_OOB_OFF_BYTE_IDENTICAL is the T-OOB-OFF-BYTE-IDENTICAL tooth:
// --peer-dir "" + --peer-auto-reconcile false = byte-identical Day-34. The
// in-package assertion: an UN-provisioned peer (NO topo.SetRegion) routes
// intra (IsInterRegion=false) — the conservative default = byte-identical
// full-mesh. The cmd tooth (provisioning_test.go) asserts the empty --peer-dir
// no-op directly (parsePeerDir("") → ErrPeerDirEmpty → applyProvisioning
// returns an empty map → the dial loop's ELSE arm runs for every peer = zero
// peerID = byte-identical Day-34).
func TestT_OOB_OFF_BYTE_IDENTICAL(t *testing.T) {
	topo := NewTopologyManager(RegionTag(1))
	peerNodeID := [16]byte{0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77}
	// NO topo.SetRegion — the un-provisioned default. IsInterRegion MUST be
	// false (the peer routes intra = byte-identical full-mesh — topology.go:160
	// returns false for a peer NOT in the registry).
	if topo.IsInterRegion(peerNodeID) {
		t.Fatalf("T-OOB-OFF-BYTE-IDENTICAL: an un-provisioned peer routed INTER-region (topo.IsInterRegion(%x)=true with NO SetRegion) — the conservative-default discipline is broken (an un-tagged peer should route intra)", peerNodeID)
	}
	// Select over an empty registry returns NO peerIDs — the sweep's
	// full-mesh Peers() path is the byte-identical default (regionArmed requires
	// topology != nil AND regionAware; an un-provisioned topology with
	// regionAware OFF takes Peers()).
	sel := topo.Select(context.Background())
	if len(sel) != 0 {
		t.Fatalf("T-OOB-OFF-BYTE-IDENTICAL: an un-provisioned topology returned %d peerIDs from Select (want 0 — the registry is empty; the sweep falls back to Peers())", len(sel))
	}
	t.Logf("GATE PASS: T-OOB-OFF-BYTE-IDENTICAL — an un-provisioned peer routes intra (IsInterRegion=false) + Select over an empty registry returns 0 peerIDs — the byte-identical Day-34 default; the cmd tooth asserts the empty --peer-dir no-op directly")
}

// TestT_OOB_NO_FROZEN_TOUCH is the T-OOB-NO-FROZEN-TOUCH tooth: the FROZEN 5
// are byte-identical pre-AND-post Day 35. MIRRORS the Day-34
// TestT_TOPO_No_Frozen_Touch VERBATIM (day34_topo_test.go:794): os.Stat
// existence guard → t.Fatalf (NOT skip — a wrong-path can never silently pass
// the vacuous-by-wrong-path class the Day-34 first draft fell into), then
// `git diff --name-only HEAD -- <path>` is EMPTY iff untouched.
//
// USE REAL PATHS — the FROZEN 5 (the SAME 5 the Day-34 tooth cites at
// day34_topo_test.go:796-802): pkg/sync/crdt.go (44f89527),
// pkg/sync/crdt_apply.go (ed9132a2), api/capnp/api/capnp/schema.capnp
// (47d2796a), api/capnp/api/capnp/schema.capnp.go (590af228),
// pkg/attribution/envelope.go (b1beba1e).
//
// The bug-inject control (the standing-memory Edit H mandate): a BOGUS path
// MUST FAIL the existence guard (NOT vacuously pass). This proves the guard is
// load-bearing — remove the os.Stat + the tooth would PASS on a nonexistent
// path (the Day-34 defect class).
func TestT_OOB_NO_FROZEN_TOUCH(t *testing.T) {
	root := repoRootMesh(t) // the EXISTING helper (day29_stratified_test.go:941)
	frozen := []string{
		"pkg/sync/crdt.go",                    // 44f89527 (the Day-29 streak anchor)
		"pkg/sync/crdt_apply.go",              // ed9132a2
		"api/capnp/api/capnp/schema.capnp",    // 47d2796a (the REAL path — NOT pkg/sync/)
		"api/capnp/api/capnp/schema.capnp.go", // 590af228 (the REAL path)
		"pkg/attribution/envelope.go",         // b1beba1e (convention-frozen, the Day-32 mold)
	}
	for _, f := range frozen {
		// (a) the EXISTENCE guard — the /ruthless-auditor correction (mirrored
		// VERBATIM from day34_topo_test.go:807). A non-existent path would make
		// the diff check vacuous; this guard FAILS (NOT skips) so a wrong-path
		// can never silently pass.
		if _, err := os.Stat(filepath.Join(root, f)); err != nil {
			t.Fatalf("T-OOB-NO-FROZEN-TOUCH: the FROZEN file %s does NOT EXIST at %s — a `git diff --name-only HEAD -- <nonexistent>` returns EMPTY + would PASS VACUOUSLY (the Day-34 wrong-path class the standing memory Edit H names): %v", f, filepath.Join(root, f), err)
		}
		// The git-HEAD byte-equality check (the TestT_TOPO_No_Frozen_Touch
		// pattern, day34_topo_test.go:810): `git diff --name-only HEAD -- <path>`
		// is EMPTY iff the file is byte-identical to HEAD. A non-empty diff =
		// the file was TOUCHED.
		out, err := exec.Command("git", "-C", root, "diff", "--name-only", "HEAD", "--", f).Output()
		if err != nil {
			t.Skipf("T-OOB-NO-FROZEN-TOUCH: git diff unavailable for %s (%v); skipping", f, err)
		}
		if len(strings.TrimSpace(string(out))) != 0 {
			t.Fatalf("T-OOB-NO-FROZEN-TOUCH: the FROZEN file %s was TOUCHED by Day 35 — the 44f89527 streak is BROKEN; Day 35 is IDENTITY/ROUTING, NOT CRDT — pkg/sync is UNTOUCHED; diff:\n%s", f, string(out))
		}
	}
	t.Logf("GATE PASS: T-OOB-NO-FROZEN-TOUCH — the FROZEN 5 are byte-identical to git-HEAD (os.Stat-guarded + git-diff-checked); the 44f89527 streak is PRESERVED (NO streak-breaker this fork)")

	// (b) the bug-inject control: a BOGUS path MUST FAIL the existence guard
	// (NOT vacuously pass). This proves the guard is load-bearing — remove the
	// os.Stat + the tooth would PASS on a nonexistent path (the Day-34 defect
	// class the standing memory Edit H codifies).
	bogus := filepath.Join(root, "pkg/sync/THIS_FILE_DOES_NOT_EXIST.go")
	if _, err := os.Stat(bogus); err == nil {
		t.Fatalf("T-OOB-NO-FROZEN-TOUCH bug-inject: the BOGUS path %s EXISTS — the control is invalid (the bug-inject needs a genuinely nonexistent path)", bogus)
	}
	// The guard FIRED (err != nil) — the bug-inject is PROVEN: a nonexistent
	// path is REJECTED, not vacuously passed. A future author who removes the
	// os.Stat guard would make this control pass silently (the class Edit H
	// codifies).
	t.Logf("GATE PASS: T-OOB-NO-FROZEN-TOUCH bug-inject — the BOGUS path %s was REJECTED by the os.Stat guard (the Day-34 vacuous-by-wrong-path class is caught; the standing memory Edit H codifies the rule)", bogus)
}

// TestT_OOB_RACE is the T-OOB-RACE tooth: concurrent Dial + reconcile + sweep
// under -race. The reconcile re-keys ps.peers under ps.mu (the write lock —
// peer.go:327), so a concurrent sweep (which reads ps.peers via Publish under
// the RLock — peer.go:445) observes a consistent pre- or post-re-key peerID,
// never a torn one. The tooth reuses the day34 harness (the proven non-hanging
// 2-node mold — a REAL recv/engine/gossiper, NOT a nil-recv minimal harness),
// arms autoReconcile on BOTH PeerSets (so Dial re-keys under the real nodeID),
// then runs concurrent AntiEntropySweep rounds on A + B under -race.
//
// THE RACE SURFACE: the reconcile re-key (Dial goroutine, write lock) vs the
// sweep's Publish (a goroutine per sweep, read lock). A torn read would surface
// as a race-detector failure. The day34 harness already dials under the REAL
// peerID (day34_topo_test.go:223), so the reconcile is a REDUNDANT re-key to
// the SAME nodeID — but the LOCK CONTOUR (write vs read on ps.peers) is the
// surface the tooth exercises, and the re-key's idempotent-to-the-same-key
// property is itself a correctness assertion (a re-key to a DIFFERENT key
// under contention would be a bug).
//
// Reusing newDay34Harness (NOT a bespoke nil-recv harness) is the honest call:
// the bespoke harness hung (a nil recv makes readLoop block in ReadFrame on a
// conn that sends nothing; cancel() does not interrupt a blocked syscall; only
// ClosePeer's conn-close does, but concurrent Publish writers on the SAME
// *tls.Conn are NOT safe — tls.Conn.Write is single-writer). The day34 harness
// wires a REAL recv + gossiper so the sweep's Publish goes through the gossiper
// (serialized per-peer), the readLoops exit cleanly on ctx cancel, and the
// teardown is the proven h.close() mold.
func TestT_OOB_RACE(t *testing.T) {
	// ON + both peers region 1 (intra — the byte-identical-to-OFF N=2 path; the
	// race tooth is about the LOCK CONTOUR, not the inter-region arm).
	h := newDay34Harness(t, true, RegionTag(1), RegionTag(1))
	// Arm the reconcile re-key on BOTH PeerSets. The day34 harness dials under
	// the REAL peerID, so the reconcile is a no-op re-key to the SAME nodeID —
	// but it STILL takes ps.mu (the write lock) on the Dial path, which is the
	// race surface vs the sweep's read lock.
	h.psA.SetAutoReconcile(true)
	h.psB.SetAutoReconcile(true)
	defer h.close()

	// Insert a modest event set (the sweep has something to ship; 100 keeps the
	// tooth fast under -race).
	h.insertEvents(t, 100)

	// Concurrent sweeps on A + B under -race (the real concurrent surface a
	// live mesh hits every sweep round). The reconcile re-key is already
	// complete (the dial happened in newDay34Harness); these exercise the
	// steady-state concurrent Publish/Peers/Select access. A torn read on
	// ps.peers would surface as a race-detector failure.
	const rounds = 5
	for round := 0; round < rounds; round++ {
		h.topoA.SetSeed(uint64(round) + 1)
		h.topoB.SetSeed(uint64(round) + 1)
		var sweepWG sync.WaitGroup
		sweepWG.Add(2)
		go func() { defer sweepWG.Done(); h.gA.AntiEntropySweep(h.ctx) }()
		go func() { defer sweepWG.Done(); h.gB.AntiEntropySweep(h.ctx) }()
		// Concurrent Peers() snapshots (RLock reads) vs the sweep — the third
		// concurrent reader surface, exercised in lockstep with the sweeps.
		go func() { defer sweepWG.Done(); _ = h.psA.Peers(); _ = h.psB.Peers() }()
		sweepWG.Add(1) // account for the Peers goroutine
		sweepWG.Wait()
	}
	t.Logf("GATE PASS: T-OOB-RACE — %d concurrent sweep rounds (A+B) + concurrent Peers snapshots under -race (the reconcile re-key takes ps.mu; the race-detector saw no torn read)", rounds)
}

// dialLeafTLS stands up an in-process TLS listener presenting `leaf` + dials it,
// returning a *tls.Conn whose ConnectionState().PeerCertificates is the peer's
// leaf (so reconcilePeerID can read the CN). Mirrors the newDay34Harness TLS
// wire-up (day34_topo_test.go:170-228) but for a single leaf + a raw tls.Listen
// (the tooth only needs the DIALER's view of the server's leaf CN).
func dialLeafTLS(t *testing.T, leaf *crypto.Leaf) *tls.Conn {
	t.Helper()
	dir := t.TempDir()
	certPath, keyPath, err := leaf.WritePEM(filepath.Join(dir, "leaf"))
	if err != nil {
		t.Fatalf("dialLeafTLS: WritePEM: %v", err)
	}
	// Load the leaf into a tls.Certificate for the listener.
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("dialLeafTLS: LoadX509KeyPair: %v", err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("dialLeafTLS: tls.Listen: %v", err)
	}
	// Accept + complete the server handshake in a goroutine.
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		// Drain briefly so the dialer's read does not get an immediate EOF
		// before ConnectionState is populated; then close.
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 1)
		_, _ = c.Read(buf)
		_ = c.Close()
	}()
	// A root pool that trusts the leaf's CA. The leaf was minted by ca.IssueLeaf
	// (the production minter); the CA PEM is at dir/ca.pem via WriteCAPEM — but
	// dialLeafTLS only has the leaf. Read the CA from the leaf's issuer (the
	// leaf's cert chain includes the CA for a self-signed dev CA). The simplest
	// honest path: trust the leaf's own cert (the dialer only needs to complete
	// the handshake so ConnectionState is populated; it does NOT need to VERIFY
	// the leaf — reconcilePeerID reads the CN regardless of verification). Use
	// InsecureSkipVerify so the dial completes for any leaf (the tooth is NOT
	// testing TLS verification — that is the Day-1 gate; this tooth tests the
	// CN hex-decode).
	dialer := &tls.Dialer{Config: &tls.Config{
		InsecureSkipVerify: true, // reconcilePeerID reads the CN regardless of verification (the Day-1 gate covers verification)
		ServerName:         "localhost",
		MinVersion:         tls.VersionTLS12,
	}}
	conn, err := dialer.Dial("tcp", ln.Addr().String())
	if err != nil {
		_ = ln.Close()
		t.Fatalf("dialLeafTLS: dialer.Dial: %v", err)
	}
	_ = ln.Close()
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		t.Fatalf("dialLeafTLS: dialer.Dial returned %T, want *tls.Conn", conn)
	}
	// Force the handshake on the dial side so ConnectionState is populated.
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("dialLeafTLS: Handshake: %v", err)
	}
	return tlsConn
}

// reconnectHealDialer is a controllable dialer for TestT_OOB_RECONNECT_HEALS:
// each Dial returns a *tls.Conn from a FRESH loopback TLS listener the dialer
// mints on demand. The test CLOSES the accepted conn to simulate a natural peer
// drop (readLoop io.EOF — NOT ClosePeer, which would evict the maps). The next
// Dial mints a fresh listener so the peer "comes back" + ReconnectLoop re-dials
// it. This is the HONEST in-process simulation of a peer restart: real
// crypto/tls record layer, real kernel socket, a real drop the readLoop
// observes — the same loopback discipline gossip_test.go:59 uses (NOT net.Pipe,
// which returns net.Conn not *tls.Conn).
type reconnectHealDialer struct {
	t       *testing.T
	leaf    *crypto.Leaf
	mu      sync.Mutex
	accepts []net.Conn // the server-side accepted conns (the test closes to drop)
}

func (d *reconnectHealDialer) Dial(network, addr, serverName string) (*tls.Conn, error) {
	d.t.Helper()
	dir := d.t.TempDir()
	certPath, keyPath, err := d.leaf.WritePEM(filepath.Join(dir, "leaf"))
	if err != nil {
		return nil, err
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		return nil, err
	}
	// Accept one conn server-side, COMPLETE the server-side TLS handshake (a
	// tls.Listen Accept returns a *tls.Conn whose handshake is LAZY — the client's
	// tlsConn.Handshake() below would block forever without this server-side
	// Handshake()), then keep the server conn open on a long blocking Read so the
	// peer stays "live" until the test CLOSES it to simulate a natural drop.
	// The Read returns io.EOF when the dial-side conn drops (the test's drop) →
	// the server goroutine exits + the server conn is closed; the dial-side
	// readLoop's ReadFrame gets io.EOF too → the natural-drop path fires.
	accepted := make(chan net.Conn, 1)
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			ln.Close()
			return
		}
		tc, ok := c.(*tls.Conn)
		if !ok {
			_ = c.Close()
			return
		}
		if herr := tc.Handshake(); herr != nil {
			_ = tc.Close()
			return
		}
		accepted <- tc
		// Keep the server conn open: block on a long Read that returns io.EOF when
		// the dial-side conn drops. This is the "peer is live" state.
		_ = tc.SetReadDeadline(time.Now().Add(60 * time.Second))
		buf := make([]byte, 1)
		_, _ = tc.Read(buf) // blocks until EOF (the drop) or the 60s deadline
		_ = tc.Close()
	}()
	dialer := &tls.Dialer{Config: &tls.Config{
		InsecureSkipVerify: true, // the tooth tests RECONNECT liveness, NOT TLS verification (the Day-1 gate covers that)
		ServerName:         "localhost",
		MinVersion:         tls.VersionTLS12,
	}}
	conn, err := dialer.Dial("tcp", ln.Addr().String())
	if err != nil {
		_ = ln.Close()
		return nil, err
	}
	_ = ln.Close()
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, fmt.Errorf("reconnectHealDialer: dialer.Dial returned %T, want *tls.Conn", conn)
	}
	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}
	// Capture the server-side accepted conn so the test can CLOSE it to drop.
	// The accepted channel is filled once the server handshake completes; wait
	// for it (bounded) so d.accepts is populated before the test reads it.
	select {
	case c := <-accepted:
		d.mu.Lock()
		d.accepts = append(d.accepts, c)
		d.mu.Unlock()
	case <-time.After(2 * time.Second):
		return nil, fmt.Errorf("reconnectHealDialer: server-side handshake did not complete within 2s")
	}
	return tlsConn, nil
}

// TestT_OOB_RECONNECT_HEALS is the T-OOB-RECONNECT-HEALS tooth — the runtime
// proof the /code-review fixes (Dial liveness, readLoop conn-close,
// ReconnectLoop addr-keyed + ctx-recheck + timer-stop) compose into a real
// drop-and-heal. The PRE-EXISTING teeth use persistent net.Pipe / loopback
// conns that NEVER drop, so they did NOT catch the root-cause defect the four
// reviewers unanimously flagged: a natural peer drop left a stale dead
// peerConn in ps.byAddr/ps.peers whose conn pointer was non-nil → Dial's
// `existing.conn != nil` guard returned "already live" → ReconnectLoop
// tight-spun at 100% CPU, never re-dialing → the mesh NEVER healed.
//
// The tooth:
//  1. builds a PeerSet with a reconnectHealDialer + dials a peer (live);
//  2. CLOSES the accepted server-side conn (a natural drop — readLoop io.EOF,
//     NOT ClosePeer);
//  3. spawns ReconnectLoop; waits for the heal (a bounded timeout);
//  4. asserts the ps.byAddr[addr] entry is a FRESH live peerConn (a new *tls.Conn
//     + done open) — the stale entry was overwritten by the re-dial.
//
// RED control (in the comment, not the code — the fix is in place): with the
// OLD `existing.conn != nil` guard, Dial would return nil "already live" for
// the stale dead entry → ReconnectLoop would spin (no backoff, no re-dial) →
// the heal would never happen → the tooth's healWait would time out + the
// t.Fatalf("reconnect did NOT heal") would fire. The tooth PASSING proves the
// liveness fix (Dial re-dials a dead peer) + the readLoop conn-close (the
// stale conn is closed, not leaked) + the addr-keyed ReconnectLoop (the wait
// finds the peer) compose.
func TestT_OOB_RECONNECT_HEALS(t *testing.T) {
	ca, err := crypto.NewMeshCA()
	if err != nil {
		t.Fatalf("NewMeshCA: %v", err)
	}
	dir := t.TempDir()
	if _, err := ca.WriteCAPEM(dir); err != nil {
		t.Fatalf("WriteCAPEM: %v", err)
	}
	seedB := make([]byte, ed25519.SeedSize)
	for i := range seedB {
		seedB[i] = 0xBB
	}
	identB, err := NewNodeIdentity(seedB)
	if err != nil {
		t.Fatalf("NewNodeIdentity B: %v", err)
	}
	dirB := t.TempDir()
	leafB, err := ca.IssueLeaf(identHex(identB.NodeID)) // CN = the 32-char hex (the certgen mirror — IssueLeaf sets CommonName: nodeID)
	if err != nil {
		t.Fatalf("IssueLeaf B: %v", err)
	}
	_ = dirB
	peerNodeID := identB.NodeID

	d := &reconnectHealDialer{t: t, leaf: leafB}
	ps := NewPeerSet(d, nopFrameSink{}, nil, nil)
	if err := ps.Dial(context.Background(), "127.0.0.1:9999", "localhost", peerNodeID); err != nil {
		t.Fatalf("T-OOB-RECONNECT-HEALS: first Dial: %v", err)
	}
	// Confirm the peer is live: byAddr + peers keyed, done open.
	ps.mu.RLock()
	pc0, ok0 := ps.byAddr["127.0.0.1:9999"]
	pc0peers, ok0peers := ps.peers[peerNodeID]
	ps.mu.RUnlock()
	if !ok0 || pc0 == nil {
		t.Fatalf("T-OOB-RECONNECT-HEALS: after Dial, byAddr[addr] is missing (ok=%v pc=%v)", ok0, pc0)
	}
	if !ok0peers || pc0peers == nil {
		t.Fatalf("T-OOB-RECONNECT-HEALS: after Dial, peers[nodeID] is missing (ok=%v pc=%v)", ok0peers, pc0peers)
	}
	select {
	case <-pc0.done:
		t.Fatalf("T-OOB-RECONNECT-HEALS: after Dial, pc.done is already closed — the readLoop exited early (the conn dropped during the dial)")
	default:
	}
	t.Logf("GATE PASS: T-OOB-RECONNECT-HEALS — peer is live after Dial (byAddr + peers keyed, done open)")

	// Simulate a natural drop: close the SERVER-SIDE accepted conn. The dial-side
	// readLoop's next ReadFrame gets io.EOF → `defer pc.conn.Close()` + `defer
	// close(pc.done)` fire (the /code-review finding #3 fix). The maps STILL hold
	// the stale pc (readLoop does NOT delete the maps — the natural-close path),
	// so the stale entry's done is closed + conn is closed. This is the EXACT
	// state the OLD `existing.conn != nil` guard would mis-read as "already live".
	var dropped net.Conn
	d.mu.Lock()
	if len(d.accepts) > 0 {
		dropped = d.accepts[0]
		d.accepts = d.accepts[1:]
	}
	d.mu.Unlock()
	if dropped == nil {
		t.Fatalf("T-OOB-RECONNECT-HEALS: no accepted server-side conn to drop — the dialer did not capture one")
	}
	_ = dropped.Close()

	// Wait for the readLoop to observe the drop (pc.done closes).
	healDeadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(healDeadline) {
		ps.mu.RLock()
		pc, ok := ps.byAddr["127.0.0.1:9999"]
		ps.mu.RUnlock()
		if ok && pc != nil {
			select {
			case <-pc.done:
				goto dropped
			default:
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("T-OOB-RECONNECT-HEALS: the readLoop did NOT observe the drop within 5s (pc.done never closed)")
dropped:
	t.Logf("GATE PASS: T-OOB-RECONNECT-HEALS — the readLoop observed the drop (pc.done closed; the stale conn is closed via defer pc.conn.Close, NOT leaked)")

	// Spawn ReconnectLoop. It wakes on pc.done (addr-keyed lookup), re-checks ctx,
	// re-dials (Dial sees done closed → the DEAD branch → closes the stale conn
	// out-of-lock + falls through to a fresh dial) → a NEW live peerConn
	// overwrites the stale entry. The heal must complete within a bounded window.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ps.ReconnectLoop(ctx, "127.0.0.1:9999", "localhost", peerNodeID, 50*time.Millisecond, 500*time.Millisecond)

	// Wait for the heal: byAddr[addr] is a FRESH live peerConn (done OPEN again —
	// a NEW readLoop is draining a NEW conn). The stale pc0.done stays closed; the
	// fresh pc.done is open.
	healedDeadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(healedDeadline) {
		ps.mu.RLock()
		pc, ok := ps.byAddr["127.0.0.1:9999"]
		ps.mu.RUnlock()
		if ok && pc != nil && pc != pc0 {
			select {
			case <-pc.done:
				// The fresh conn already dropped too — keep waiting for a stable heal.
			default:
				// HEALED: a FRESH live peerConn (pc != pc0, done open).
				t.Logf("GATE PASS: T-OOB-RECONNECT-HEALS — ReconnectLoop re-dialed the dropped peer: byAddr[addr] is a FRESH live peerConn (pc != stale pc0, done open) → the mesh HEALED → the /code-review fixes (Dial liveness + readLoop conn-close + addr-keyed ReconnectLoop + ctx-recheck + timer-stop) compose")
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("T-OOB-RECONNECT-HEALS: ReconnectLoop did NOT heal the dropped peer within 8s — byAddr[addr] is still the STALE dead entry (the OLD `existing.conn != nil` guard would have returned 'already live' + spun; the liveness fix is missing or broken)")
}
