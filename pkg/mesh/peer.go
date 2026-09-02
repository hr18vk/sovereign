// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

// Package mesh is the production peer-to-peer gossip layer that rides the
// TLS 1.3 transport.
//
// Scope (per the design): a PeerSet dials each configured
// peer over mTLS, keeps a per-peer reader goroutine feeding the
// Receiver.HandleFrame sink (the accept loop, reused on the dial side so a
// node that both dials and accepts converges symmetrically), and publishes
// outbound signed envelopes via pkg/transport.TransmitTLSFrame. The mesh is a
// NEW CALLER of the engine + identity + envelope + forward + transport APIs; it
// modifies none of those packages.
//
// Identity model (the load-bearing seam): each
// node owns a CRDT-delta signing seed (Ed25519, 32 bytes, distinct from the
// TLS leaf key). The nodeID is the first 16 bytes of the seed's derived public
// key; the identity.Directory keys originNodeID -> pubkey, and the engine's
// localNodeID must equal the originNodeID every signed delta carries, so the
// signing identity and the engine identity MUST coincide. A NodeIdentity
// bundles the nodeID + the seed + the derived pubkey so the gossiper signs with
// the seed and every peer Directory registers the pubkey.
package mesh

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"filippo.io/mldsa"
	"fmt"
	ed25519 "github.com/cloudflare/circl/sign/ed25519"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hr18vk/sovereign/pkg/identity"
	"github.com/hr18vk/sovereign/pkg/receive"
	eng "github.com/hr18vk/sovereign/pkg/sync"
	"github.com/hr18vk/sovereign/pkg/transport"
)

// NodeIdentity is the CRDT-delta signing identity of one node. It is the
// per-node counterpart of the engine's localNodeID: the seed is the hook into
// identity.SignCRDTFrame, the pubkey is what every peer Directory registers so
// VerifyCRDTFrame succeeds on the receive side, and the nodeID is the [16]byte
// that MUST equal engine.localNodeID (so the origin's OriginNodeID, which the
// engine stamps onto every InsertLocal entry, matches the Directory key the
// receiver resolves).
//
// nodeID is the first 16 bytes of the Ed25519 public key. This keeps the
// identity space flat (one derivation from one seed) and matches the
// [16]byte OriginNodeID the capnp CRDTDeltaEvent carries; the pubkey is the
// full 32 bytes the Directory stores. A peer verifying a frame resolves
// OriginNodeID[:16] -> the 32-byte pubkey via Directory.Lookup.
//
// (ADR-0037): PQPriv is the OPTIONAL ML-DSA-65 private key for the
// hybrid SIGN (under --hybrid-sign the gossiper's ShipBatchHybrid signs the
// batch wire under BOTH Ed25519 + ML-DSA-65 via identity.SignCRDTFrame_Hybrid).
// It is nil by default (the default posture — a node with NO PQ key produces
// v1 BatchEnvelopes byte-identical to the classical path; --hybrid-sign=false
// is the byte-identical default). When --hybrid-sign is set, buildNodeIdentity
// mints the PQ keypair from the SAME 32-byte seed (identity.GeneratePreviewKey65
// — the deterministic seed form, byte-identical across runs) + registers the PQ
// pubkey in the Directory via RegisterPQ so peers' hybrid verify resolves it.
// The PQ key is derived from the SAME seed as the Ed25519 key (one identity
// space — the deploy discipline named), so a node's Ed25519 pubkey +
// ML-DSA-65 pubkey BOTH key off the one --identity-seed.
type NodeIdentity struct {
	NodeID [16]byte
	Seed   []byte // len 32 (ed25519.SeedSize); owned, never mutated
	Pub    ed25519.PublicKey
	// PQPriv is the (ADR-0037) OPTIONAL ML-DSA-65 private key for the
	// hybrid SIGN. nil by default (the default posture — no hybrid frame is
	// produced). When non-nil, ShipBatchHybrid signs under BOTH Ed25519 +
	// ML-DSA-65; the corresponding PQPub is registered in the Directory via
	// RegisterPQ so peers' hybrid verify resolves it. Owned by the NodeIdentity;
	// never mutated post-construction.
	PQPriv *mldsa.PrivateKey
	// PQPub is the ML-DSA-65 public key paired with PQPriv. Registered in
	// the Directory via RegisterPQ when PQPriv is non-nil; nil otherwise. Owned
	// by the NodeIdentity; never mutated post-construction.
	PQPub *mldsa.PublicKey
}

// NewNodeIdentity derives a NodeIdentity from a 32-byte Ed25519 seed. The
// returned NodeID is the first 16 bytes of the derived public key and MUST be
// passed to eng.NewDeltaCRDTEngine as its nodeID so the engine's
// locally-inserted entries carry an OriginNodeID the receiver-side Directory
// can resolve back to Pub.
//
// The PQ key (PQPriv/PQPub) is NOT derived here — NewNodeIdentity is the
// CLASSICAL-ONLY constructor (the classical default, byte-identical). The
// hybrid-SIGN constructor is NewNodeIdentityHybrid, which derives the
// ML-DSA-65 keypair from the SAME seed. A NodeIdentity from NewNodeIdentity has
// PQPriv == nil -> ShipBatchHybrid is a no-op (the gossiper's hybrid arm is
// disarmed) -> NO hybrid frame is produced (the byte-identical-default).
func NewNodeIdentity(seed []byte) (*NodeIdentity, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("mesh: NewNodeIdentity: seed len %d, want %d", len(seed), ed25519.SeedSize)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	ni := &NodeIdentity{
		Seed: make([]byte, ed25519.SeedSize),
		Pub:  make(ed25519.PublicKey, ed25519.PublicKeySize),
	}
	copy(ni.Seed, seed)
	copy(ni.Pub, pub)
	copy(ni.NodeID[:], pub[:16])
	return ni, nil
}

// NewNodeIdentityHybrid is the (ADR-0037) hybrid-SIGN constructor: it
// derives a NodeIdentity carrying BOTH the Ed25519 keypair (from seed) AND the
// ML-DSA-65 keypair (from the SAME seed, via identity.GeneratePreviewKey65 — the
// deterministic seed form, byte-identical across runs). A NodeIdentity from
// this constructor has PQPriv != nil -> ShipBatchHybrid signs under BOTH sigs
// -> hybrid frames are produced under --hybrid-sign. The Ed25519 half is
// byte-identical to NewNodeIdentity (the SAME derivation); the PQ half is the
// ADD. The returned PQPub is what the caller registers in the Directory via
// RegisterPQ so peers' hybrid verify resolves it.
func NewNodeIdentityHybrid(seed []byte) (*NodeIdentity, error) {
	ni, err := NewNodeIdentity(seed)
	if err != nil {
		return nil, err
	}
	pqPriv, err := identity.GeneratePreviewKey65(seed)
	if err != nil {
		return nil, fmt.Errorf("mesh: NewNodeIdentityHybrid: GeneratePreviewKey65: %w", err)
	}
	ni.PQPriv = pqPriv
	// Use the concrete PublicKey getter (mldsa.go:139 — returns *PublicKey
	// directly), NOT the Public interface method (mldsa.go:122 — returns
	// crypto.PublicKey, which would need an unchecked type assertion). A review
	// flagged the assertion as a needless panic risk: a future
	// KMS/HSM-backed mldsa.PrivateKey (the ADR-0037 future-work note
	// "operator-path hybrid SIGN via a KMS/HSM minter") could return a
	// non-*mldsa.PublicKey
	// from Public, panicking at boot; the concrete getter returns the exact
	// type with no assertion.
	ni.PQPub = pqPriv.PublicKey()
	return ni, nil
}

// dialer is the subset of pkg/transport.TLSConnections the PeerSet uses to open
// peer connections. Exposed as an interface so the in-process test harness wires
// a net.Pipe-based dialer WITHOUT a real TCP listener, while the production binary
// wires the real *transport.TLSConnections (which satisfies Dial — see
// tls_transport.go:150).
type dialer interface {
	Dial(network, addr, serverName string) (*tls.Conn, error)
}

// frameSink is the subset of pkg/receive.Receiver the PeerSet feeds inbound
// frames into. Exposed as an interface so the in-process test harness can wire
// an instrumented sink; the production binary wires the real *receive.Receiver
// (which satisfies HandleFrame — see receiver.go:253 — and HandleBatchFrame —
// see receiver.go, the batch path). The return type is
// receive.AcceptVerdict exactly (not any) so *receive.Receiver satisfies the
// interface without an adapter.
//
// dispatch: readLoop peeks the first 4 bytes of each reassembled frame
// (post-length-prefix) and routes a BatchEnvelope (attribution.IsBatchFrame) to
// HandleBatchFrame; everything else routes to HandleFrame (the
// RelayEnvelope path — back-compat default). The batch path is opt-in via
// --batch-size>1 on the SEND side; the RECEIVE side dispatches on the wire
// magic so a node accepts batches from a peer that opted in regardless of its
// own --batch-size.
//
// (ADR-0037): the FOUR-way dispatch adds the hybrid-PQ batch path — a
// frame tagged WireHybridPQMagic (attribution.IsHybridFrame) routes to
// HandleHybridFrame (the BOTH-sig verify path). The hybrid path is opt-in via
// --hybrid-sign on the SEND side + --hybrid-verify on the RECEIVE side; a node
// accepts hybrid frames from a peer that opted in regardless of its own
// --hybrid-sign (the SAME dispatch-on-magic discipline the batch path uses).
type frameSink interface {
	HandleFrame(frameBytes []byte) receive.AcceptVerdict
	HandleBatchFrame(batchFrameBytes []byte) receive.AcceptVerdict
	HandleHybridFrame(hybridFrameBytes []byte) receive.AcceptVerdict
}

// peerConn is one dialed peer connection. The reader goroutine (readLoop) owns
// the conn's read side; Publish writes to the conn under the read lock. A
// stalled peer goroutine never stalls the others — each peer owns its own loop.
type peerConn struct {
	addr   string
	conn   *tls.Conn
	peerID [16]byte

	cancelReader context.CancelFunc
	done         chan struct{}
	// closeDoneOnce (the silicon-found close-path TOCTOU) closes
	// pc.done EXACTLY ONCE across the racing goroutines that can both legitimately
	// signal a peerConn dead: the readLoop's exit defer (peer.go:605) AND
	// ReleaseInbound (peer.go:573, the accept-loop drop). The earlier code had
	// the readLoop's `defer close(pc.done)` UNGUARDED + ReleaseInbound guarded by
	// a `select{case <-pc.done: default: close(pc.done)}` — a check-then-act TOCTOU:
	// both goroutines see `done` open, both call close → `panic: close of closed
	// channel` (peer.go:619, the readLoop's deferred close, +0x2bc). At 3 nodes the
	// window is too narrow to hit; at 100-node silicon the accept-loop churn +
	// outbound ReconnectLoop firing ReleaseInbound on a conn whose readLoop is
	// also exiting makes the race fire on the early nodes → the process panics on
	// boot → the node never serves /livecheck → 1/100-live. sync.Once makes
	// the close atomic: whichever path wins, the channel closes exactly once;
	// the loser's Once.Do is a no-op (NOT a panic). closeDone is the ONLY path
	// that touches pc.done's closed-state (the readers at peer.go:327/691/725/767
	// only RECEIVE on it, never close).
	closeDoneOnce sync.Once

	// framesReceived is a dial-side receive counter — the
	// readLoop is the sole writer (one writer per peerConn, launched at Dial),
	// read only by diagnostics. It is a symmetry probe: did the peer write
	// ANYTHING back over the connection WE dialed out? (The seed->peer delta and
	// the peer->seed bootstrap both arrive on the ACCEPT loop at main.go's
	// serveConnWithDigest, NOT here — so this
	// counter observes only what the peer Publish'es onto OUR dial.) Accessed
	// atomically; sole-writer/sole-reader so a plain uint64 would be race-free,
	// but -race runs a concurrent metrics read, so atomic it is. Last field: zero
	// existing atomics on this struct (no cache-line neighbor), absorbs into tail
	// padding (fieldalignment -fix is forbidden here — reorder manually).
	framesReceived uint64
}

// PeerSet dials each configured peer over mTLS, keeps a per-peer reader
// goroutine feeding the Receiver.HandleFrame sink, and publishes
// outbound signed envelopes via pkg/transport.TransmitTLSFrame. It is safe for
// concurrent use.
type PeerSet struct {
	dialer dialer
	recv   frameSink
	owner  *NodeIdentity
	engine *eng.DeltaCRDTEngine

	// digester is the digest-exchange sink (ADR-0034). It is the
	// Gossiper bound to this PeerSet (the Gossiper satisfies DigestSink); nil
	// by default (a PeerSet with no gossiper-bound digester drops digest
	// frames — the honest cold-start when stratified is OFF). Set via
	// SetDigestSink AFTER NewGossiper so the readLoop's DispatchFrame can route
	// a WireDigestMagic-tagged frame to the sweep's per-peer blocking-receive
	// channel. The digester is read on the readLoop goroutine; SetDigestSink is
	// called once at construction before the readLoop starts — the
	// single-writer-before-reader discipline makes the non-atomic set race-free.
	digester DigestSink

	mu     sync.RWMutex
	peers  map[[16]byte]*peerConn
	byAddr map[string]*peerConn

	// autoReconcile is the (ADR-0040) OPT-IN runtime TLS-leaf reconcile
	// flag (Seam B). default false = byte-identical (the dial loop stores
	// peers under the caller-supplied peerID — zero for an un-provisioned peer —
	// and the topology selector keys under peerIDForAddr(addr), which never
	// matches the zero peerID → the region lookup misses → the N=2 no-op
	// ADR-0040 describes). ON switches Dial to read the peer's TLS leaf
	// CommonName (hex.DecodeString the 32-char CN → [16]byte — the SAME mirror
	// mintSelftestCerts uses, IssueLeaf(hex.EncodeToString(nodeID[:])) main.go:1543)
	// + re-key the peerConn under the REAL nodeID so the topology selector HITS
	// → Publish(realNodeID) succeeds → the 2-node binary mesh converges.
	// ROUTING-only: the reconcile re-keys the ROUTING key (which ps.peers entry
	// Publish writes to); it NEVER touches the verification pubkey (the
	// Directory's OOB-provisioned key is the verification anchor; a self-
	// announced node with NO OOB pubkey is ROUTED but NOT VERIFIED → its deltas
	// DROPPED LOUD via VerifyFail — the correct zero-trust posture, disclosed
	// ADR-0040 §6). Set via SetAutoReconcile once at construction (the
	// single-writer-before-reader discipline; read on the Dial goroutine — the
	// cmd dial loop is single-threaded at boot, and ReconnectLoop's per-peer
	// goroutine reads it post-boot; the non-atomic read is race-free under the
	// same discipline SetDigestSink uses). Placed LAST so the 1-byte bool absorbs
	// into the struct's tail padding (the fieldalignment discipline — manual
	// reorder, NOT -fix; the bool's trailing padding is NOT counted toward the
	// struct's useful size, the SAME placement topology.go:60 uses for selfRegion).
	autoReconcile bool
}

// NewPeerSet constructs a PeerSet bound to a TLS dialer, the receive
// sink, and the owner's signing identity. engine is the gossiper's own state
// (GenerateDigest/GenerateDelta source); recv is the sink every
// inbound frame flows through.
func NewPeerSet(d dialer, recv frameSink, owner *NodeIdentity, engine *eng.DeltaCRDTEngine) *PeerSet {
	return &PeerSet{
		dialer: d,
		recv:   recv,
		owner:  owner,
		engine: engine,
		peers:  make(map[[16]byte]*peerConn),
		byAddr: make(map[string]*peerConn),
	}
}

// SetDigestSink binds the digest-exchange sink (ADR-0034). The Gossiper
// calls it once after NewGossiper so the readLoop's DispatchFrame can route a
// WireDigestMagic-tagged frame to the sweep's per-peer blocking-receive channel.
// Nil-safe (the SetRoundReporter precedent): a PeerSet with no digester drops
// digest frames — the honest cold-start when stratified is OFF (the opt-IN
// default keeps the oversend path byte-identical). Called once at construction
// before the readLoop starts; the single-writer-before-reader discipline makes
// the non-atomic set race-free.
func (ps *PeerSet) SetDigestSink(d DigestSink) { ps.digester = d }

// SetAutoReconcile arms the (ADR-0040) runtime TLS-leaf reconcile (Seam
// B). Called once at construction (the cmd path wires it from
// --peer-auto-reconcile before the dial loop starts; the single-writer-before-
// reader discipline). default false = byte-identical. Nil-safe-by-being-
// a-primitive (the flag is a bool; the false zero-value is the byte-identical
// default — no nil-guard needed). See the autoReconcile field doc for the
// ROUTING-only contract + the zero-trust posture a self-announced-but-not-
// OOB-provisioned peer has.
func (ps *PeerSet) SetAutoReconcile(on bool) { ps.autoReconcile = on }

// Dial opens an mTLS connection to addr and installs a per-peer reader goroutine
// feeding the sink. peerID is the remote's CRDT-delta signing nodeID.
// It is idempotent for an already-live peer.
func (ps *PeerSet) Dial(ctx context.Context, addr, serverName string, peerID [16]byte) error {
	// (ADR-0040) — the post-drop re-dial liveness fix.
	// The earlier early-return checked `existing.conn != nil` (a pointer
	// non-nil test), but a DROPPED peer's readLoop exits via `defer close(pc.done)`
	// WITHOUT deleting ps.byAddr[addr] / ps.peers[peerID] (the natural-close path
	// — only the explicit ClosePeer primitive evicts). A closed *tls.Conn is
	// STILL a non-nil pointer, so the old guard returned nil "already live" for a
	// DEAD peer → ReconnectLoop's Dial returned nil → the backoff time.After was
	// NEVER entered → ReconnectLoop tight-spun at 100% CPU per dropped peer,
	// never re-dialing (the root cause a review found).
	// The fix: gate the early-return on LIVENESS via pc.done (closed == dead), NOT
	// on conn-pointer-non-nil. A live peer (done open) → return nil (idempotent).
	// A dead peer (done closed) → fall through + re-dial; the stale pc's conn is
	// closed here (the readLoop exited but never closed the conn — the leak the
	// re-dial would otherwise orphan) + the stale entry is overwritten at the
	// ps.peers/ps.byAddr writes below (line 332-333). This also fixes the
	// reconcile-key-mismatch: the lookup is by ADDR (the stable
	// identity), NOT by peerID — so an un-provisioned reconciled peer (Dial keyed
	// under the REAL nodeID, ReconnectLoop spawned with zero) is found here
	// regardless of which nodeID it was keyed under.
	ps.mu.Lock()
	// staleConn is the DEAD peer's conn to close AFTER releasing the lock (a
	// review finding: a tls.Conn.Close sends a close-notify alert via
	// a BLOCKING Write; doing it UNDER ps.mu would stall every concurrent
	// Publish (RLock) + Peers (RLock) for one slow peer's close. Capture the
	// stale conn under the lock; close it outside. No SetWriteDeadline exists in
	// pkg/transport (grep-confirmed), so the close-notify Write has no bound —
	// moving it out of the lock is the load-bearing fix.
	var staleConn *tls.Conn
	if existing, ok := ps.byAddr[addr]; ok && existing.conn != nil {
		select {
		case <-existing.done:
			// DEAD — the readLoop exited (io.EOF / read error / ctx cancel).
			// Capture the stale conn for an out-of-lock close (the readLoop did
			// NOT close it — the orphan-conn leak a review found) + let
			// the re-dial fall through to overwrite the stale entry. The later
			// close is idempotent if a concurrent path already closed it.
			staleConn = existing.conn
		default:
			// LIVE — the readLoop is still draining. Idempotent: a concurrent
			// Dial (or a ReconnectLoop racing the boot dial) returns nil instead
			// of opening a second conn.
			ps.mu.Unlock()
			return nil // already live
		}
	}
	ps.mu.Unlock()
	if staleConn != nil {
		_ = staleConn.Close() // OUT of the lock — see the staleConn comment above.
	}

	conn, err := ps.dialer.Dial("tcp", addr, serverName)
	if err != nil {
		return fmt.Errorf("mesh: dial %s: %w", addr, err)
	}
	readerCtx, cancel := context.WithCancel(ctx)
	pc := &peerConn{
		addr:         addr,
		conn:         conn,
		peerID:       peerID,
		cancelReader: cancel,
		done:         make(chan struct{}),
	}
	// (ADR-0040) Seam B: the runtime TLS-leaf reconcile. When
	// autoReconcile is ON AND the caller supplied the ZERO peerID (an
	// un-provisioned peer — the honest gap), read the peer's TLS leaf
	// CommonName + re-key the peerConn under the REAL nodeID so the topology
	// selector HITS + Publish(realNodeID) succeeds → the 2-node binary mesh
	// converges. The reconcile is a ROUTING fix ONLY: it changes WHICH
	// ps.peers entry Publish writes to; it NEVER touches the verification
	// pubkey (the Directory's OOB-provisioned key is the verification anchor).
	// A PROVISIONED peer (caller passed the real nodeID — Seam A already
	// resolved it) SKIPS the reconcile: the peer is keyed correctly already, +
	// the leaf CN is a redundant signal. The reconcile is the ZERO-CONFIG bonus
	// for a deploy that opts into --peer-auto-reconcile WITHOUT --peer-dir (the
	// ROUTING re-key lands the Publish under the real nodeID — BUT convergence
	// STILL REQUIRES the OOB verification pubkey, provisioned via --peer-dir; a
	// reconcile-only deploy routes but the receiver's Directory.Lookup MISSES
	// (receiver.go:436) → DropVerify → NO convergence. A binary-harness
	// honest-negative run PROVES this: reconcile-only does NOT converge. See
	// reconcilePeerID for the leaf-CN decode + the re-key under ps.mu.
	effectivePeerID := peerID
	if ps.autoReconcile && peerID == ([16]byte{}) {
		if real, ok := ps.reconcilePeerID(pc, conn); ok {
			effectivePeerID = real
		}
		// A reconcile MISS (ok=false) leaves effectivePeerID == zero — the
		// peerConn stays keyed under the zero peerID, the byte-identical
		// behavior. The miss is logged inside reconcilePeerID (a peer whose
		// leaf has NO CN, OR a CN that does not hex-decode to 16 bytes — the
		// honest "leaf did not self-announce a nodeID" case).
	}
	ps.mu.Lock()
	ps.peers[effectivePeerID] = pc
	ps.byAddr[addr] = pc
	pc.peerID = effectivePeerID
	ps.mu.Unlock()
	go ps.readLoop(readerCtx, pc)
	log.Printf("mesh: dialed peer %x at %s", effectivePeerID, addr)
	return nil
}

// reconcilePeerID reads the peer's TLS leaf CommonName + hex-decodes it to the
// REAL [16]byte nodeID (Seam B — the ADR-0040 runtime reconcile). The
// leaf is minted by certgen.IssueLeaf(hex.EncodeToString(nodeID[:])) (certgen.go
// :176 CommonName: nodeID; main.go:1543 the binary's own mint), so the CN is the
// LOWERCASE HEX of the 16-byte nodeID (32 ASCII chars) — NOT the 16 raw bytes.
// A naive copy(id[:], []byte(cn)) would truncate the 32-char ASCII hex to 16
// garbage bytes; the reconcile MUST hex.DecodeString the CN (the SAME mirror
// resolveNodeID main.go:458 + buildNodeIdentity main.go:1642 use for --node-id
// / --identity-seed). Returns (realNodeID, true) on a successful decode +
// (zeroPeerID, false) on a miss:
//
//   - zero peer certs (the peer presented NO leaf — a misconfigured RequireAny
//     client cert, NOT the production RequireAndVerifyClientCert posture): the
//     reconcile cannot read a CN; the peerConn stays keyed under zero (the
//
// byte-identical behavior — the honest "leaf did not self-announce").
//   - a CN that is not 32 hex chars / does not hex-decode to 16 bytes: a leaf
//     minted by a NON-engine CA (the dev-mesh CA mints engine-shaped CNs; a
//     foreign CA's CN is arbitrary). The reconcile logs + returns false (the
//     peerConn stays keyed under zero; the topology selector misses →
//     RegionUnset = intra = byte-identical full-mesh — the honest conservative
//     default for an unrecognized leaf, NOT a crash).
//
// ROUTING-only: the reconcile re-keys the ROUTING map (ps.peers); it does
// NOT call Directory.Register/RegisterPQ (the verification pubkey stays the
// deploy's OOB concern). A self-announced node with NO OOB-provisioned
// Directory pubkey is ROUTED (Publish succeeds via ps.byAddr) but NOT VERIFIED
// (the receiver's Directory.Lookup misses → the delta DROPPED LOUD via
// VerifyFail — the correct zero-trust posture, disclosed ADR-0040 §6).
//
// Called on the Dial goroutine (the cmd dial loop is single-threaded at boot;
// ReconnectLoop's per-peer goroutine calls it post-boot). The re-key takes ps.mu
// (the write lock) so a concurrent Publish observes a consistent pre- or post-
// re-key peerID, never a torn one. The conn is already post-handshake (the
// dialer.Dial returned a *tls.Conn whose Handshake ran inside Dial), so
// ConnectionState.PeerCertificates is populated + non-blocking.
func (ps *PeerSet) reconcilePeerID(pc *peerConn, conn *tls.Conn) ([16]byte, bool) {
	real, ok := nodeIDFromConn(conn)
	if !ok {
		log.Printf("mesh: reconcile %s: peer leaf did not self-announce a nodeID — staying keyed under zero peerID (the byte-identical behavior)", pc.addr)
		return [16]byte{}, false
	}
	log.Printf("mesh: reconcile %s: peer leaf CN -> real nodeID %x (re-keying PeerSet under the real nodeID; ROUTING-only)", pc.addr, real)
	return real, true
}

// nodeIDFromConn extracts the peer's REAL [16]byte nodeID from the TLS leaf
// CommonName (certgen.go:192/244 embeds the hex nodeID as the CN; certgen.NodeID
// mirrors it). Shared by the Dial-side reconcile (reconcilePeerID) and the
// accept-side RegisterInbound (ADR-0045) so the decode is a SINGLE
// source of truth. The conn MUST be post-handshake (ConnectionState populated).
// Returns (realNodeID, true) on a 32-hex-char CN that decodes to 16 bytes;
// (zero, false) otherwise (no leaf, empty CN, non-hex, or wrong length — the
// honest "leaf did not self-announce a nodeID" case, the conservative default).
func nodeIDFromConn(conn *tls.Conn) ([16]byte, bool) {
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return [16]byte{}, false
	}
	cn := state.PeerCertificates[0].Subject.CommonName
	if cn == "" {
		return [16]byte{}, false
	}
	nid, err := hex.DecodeString(cn)
	if err != nil || len(nid) != 16 {
		return [16]byte{}, false
	}
	var real [16]byte
	copy(real[:], nid)
	return real, true
}

// RegisterInbound is the accept-loop half of the accept-symmetry change (ADR-0045):
// it installs a peerConn for a connection the PEER dialed IN, keyed by the
// peer's REAL nodeID (decoded from the inbound TLS leaf CN — the same
// nodeIDFromConn the Dial-side reconcile uses). This makes a connection a
// BIDIRECTIONAL publishable edge: before the accept fix, ps.peers was populated ONLY on
// outbound Dial (peer.go:389), so a B→A edge was publishable for B but NOT for
// A — A's Publish to a peer that dialed A returned "no live peer" (the
// cardinality cliff: at 100 nodes the seed's boot dial races 99 listeners, a
// failed dial leaves the peer permanently absent from ps.peers → the peer never
// receives A's deltas → 99/99 root-zero, the blocker).
//
// The accept loop (serveConnWithDigest / serveTestConn) OWNS the read side of
// the inbound conn — RegisterInbound installs a peerConn with NO readLoop (a
// second readLoop would double-read the conn, each stealing half the frames).
// The peerConn exists so Publish(realNodeID) can WRITE back over the same conn
// the peer dialed in (full-duplex: one TCP conn, two directions, each side
// reads its own read side + writes via Publish to the peer's entry in its own
// ps.peers) + so Peers/topology.Select list the inbound peer.
//
// PeerConnHandle is an OPAQUE registration receipt. It
// exists because `peerConn` is unexported while the accept loop that must bind its
// release to a specific registration lives in package main
// (cmd/sovereign-node/main.go serveConnWithDigest). The handle carries no methods
// and exposes no fields: the caller's only legitimate use is to hand it back to
// ReleaseInboundConn, which compares it by IDENTITY against the currently-
// registered peerConn. A nil handle means "nothing was installed" (a decode miss
// or a decline) and makes the release a no-op.
type PeerConnHandle struct{ pc *peerConn }

// LIVENESS GUARD (the storm's close). The earlier code
// evicted any existing peerConn for realNodeID/addr UNCONDITIONALLY, and its
// comment claimed that was "the SAME discipline Dial uses at peer.go:389". That
// claim was FALSE on the bytes: Dial (peer.go:344-358) is LIVENESS-GUARDED —
// `select <-existing.done` → DEAD: replace; `default` → LIVE: return nil
// "already live". RegisterInbound had no such guard, and that ASYMMETRY WAS the
// colocated stampede:
//
//  1. A and B dial each other (at 34 nodes/host, mutual dials are the NORM).
//  2. B's accept loop calls RegisterInbound for A's inbound conn → it evicts
//     B's own LIVE outbound peerConn to A + cancels its readLoop → B's
//     pc.done CLOSES.
//  3. B's ReconnectLoop wakes on that closed done, sees DEAD, and re-dials
//     A IMMEDIATELY (the success path has no backoff floor).
//  4. A's accept loop registers the new inbound, evicting A's live outbound
//     → goto 1.
//
// Silicon measured ~700 dials/sec/node sustained for 4 minutes (127,163 dials
// on ONE eu-west-1 node for 99 peers), and BOTH remote regions received ZERO
// frames for the whole run.
//
// The guard makes the comment true: if the existing peerConn is LIVE, do NOT
// evict and do NOT register — return a DECLINE (nil pc). The caller (the accept
// loop) KEEPS SERVING the conn unregistered, which is exactly the original
// semantics: the remote still Publishes over it and the frames still reach our
// receive path via DispatchFrame. No close, no done fired, no ReconnectLoop
// wake. First-writer-wins-if-live.
//
// WHY A GUARD AND NOT A TIE-BREAK: the invariant the engine needs is NOT "exactly
// one conn per pair" — it is "no live edge is ever evicted". A lower-nodeID
// tie-break would need a winner election plus loser-close choreography, and the
// done-close seam is the one with TOCTOU history (the
// `close of closed channel` boot panic at 100 nodes). Every avoidable close
// removed from this seam is risk removed. Steady state: mutual dials →
// 2 conns/pair, each side publishing on its OWN outbound (the proven
// topology); staggered boot → 1 conn registered by the accept side (the
// inbound-registration repair, INTACT — TestMutualDialStaggeredBoot is the
// anti-tautology guard proving it cannot be implemented as an unconditional decline).
//
// DISCLOSED WINDOW (an accepted trade-off): crash-restart staleness. A peer that
// crashes and restarts dials in; the guard DECLINES because our old conn to it
// still reads LIVE (its done does not close until that readLoop observes RST/EOF).
// Recovery is bounded by dead-conn detection latency, NOT deadlocked — the same
// order as the tie-break's worst case. Revisit with a keepalive/deadline if a
// ≥1K-node run shows it dominating.
//
// Stale-close discipline for the DEAD case (mirrors Dial at peer.go:316-345):
// under ps.mu, capture the dead peerConn for an out-of-lock close + reader cancel
// (a tls.Conn.Close sends a blocking close-notify Write; doing it under ps.mu
// would stall every concurrent Publish/Peers), then install the inbound peerConn.
// The accept loop's own defer conn.Close owns the inbound conn's close;
// RegisterInbound does NOT close the inbound conn.
//
// RETURNS (the identity-guarded release): the real nodeID AND the INSTALLED
// *peerConn. The pc is nil on a decode miss OR on a decline (nothing was
// installed) — and on a DECLINE the returned nodeID is ZERO, so the caller's
// deferred ReleaseInboundConn no-ops at its zero check instead of slipping
// past the identity guard with a nil mine and closeDoneing the LIVE edge
// the decline just protected. The caller MUST bind its deferred release to
// the RETURNED pc — not to the nodeID — via ReleaseInboundConn, so a goroutine
// whose registration was superseded (or declined) cannot close a conn it never
// owned. See ReleaseInbound/ReleaseInboundConn for the wrong-kill this closes.
// Safe to call concurrently with Dial/Publish/Peers.
func (ps *PeerSet) RegisterInbound(conn *tls.Conn) ([16]byte, *PeerConnHandle) {
	real, ok := nodeIDFromConn(conn)
	if !ok {
		// The peer's leaf did not self-announce a nodeID (no leaf, empty CN,
		// non-hex, or wrong length — a non-engine CA). Stay byte-identical to the
		// original accept path: do NOT register, so Publish to this peer keeps
		// missing (the honest conservative default, the SAME posture reconcile
		// keeps for an unrecognized Dial-side leaf).
		return [16]byte{}, nil
	}
	addr := conn.RemoteAddr().String()
	pc := &peerConn{
		addr:   addr,
		conn:   conn,
		peerID: real,
		done:   make(chan struct{}),
	}

	// Look up the existing edge, then BRANCH ON LIVENESS (the Dial mirror).
	// LIVE → decline (no evict, no register, no close). DEAD → capture it for an
	// out-of-lock close + reader cancel, and install the inbound peerConn.
	var stalePC *peerConn
	ps.mu.Lock()
	existing, ok := ps.peers[real]
	if !ok || existing == nil {
		existing, ok = ps.byAddr[addr]
	}
	if ok && existing != nil {
		select {
		case <-existing.done:
			// DEAD — the readLoop exited (io.EOF / read error / ctx cancel) or a
			// prior release closed it. Replace: capture for the out-of-lock close.
			stalePC = existing
		default:
			// LIVE — we already hold a working edge to this peer (we dialed them
			// outbound, or another accept goroutine registered first). DECLINE.
			// Evicting here is what armed the mutual-eviction storm; keeping the
			// live edge means no pc.done fires, so no ReconnectLoop wakes.
			//
			// The decline
			// MUST return the ZERO nodeID, not `real`. The accept loops defer
			// ReleaseInboundConn(inboundNodeID, myPC) UNCONDITIONALLY, and a
			// (real, nil) pair slips PAST ReleaseInboundConn's identity guard
			// (`mine != nil && ...` is false when mine==nil), so when this
			// declined conn later dropped, the deferred release closeDoned the
			// LIVE edge — the exact wrong-kill the docstring at :663-667
			// describes. The zero nodeID makes the
			// release no-op at its first check, delivering the documented
			// contract ("a nil handle makes the release a no-op"). The declined
			// conn keeps being SERVED unregistered either way (the original
			// semantics); only the release bookkeeping changes.
			ps.mu.Unlock()
			return [16]byte{}, nil
		}
	}
	ps.peers[real] = pc
	ps.byAddr[addr] = pc
	ps.mu.Unlock()

	if stalePC != nil {
		// Cancel the stale peerConn's readLoop (the outbound Dial spawned it)
		// + close its conn OUT of the lock (the blocking close-notify Write).
		// The stale readLoop exits via its defer close(pc.done) → the stale entry
		// (if it was keyed under a DIFFERENT nodeID, e.g. the zero peerID of an
		// un-reconciled outbound dial) is now dead; a later ReconnectLoop re-dials
		// + re-registers. Idempotent if the stale conn is already closed.
		if stalePC.cancelReader != nil {
			stalePC.cancelReader()
		}
		if stalePC.conn != nil && stalePC.conn != conn {
			_ = stalePC.conn.Close()
		}
	}
	log.Printf("mesh: registered inbound peer %x at %s (accept-symmetry — the B→A edge is now publishable for A)", real, addr)
	return real, &PeerConnHandle{pc: pc}
}

// ReleaseInbound marks the inbound peerConn for nodeID as dead (closes pc.done)
// so a later Dial/ReconnectLoop sees it as dropped + re-establishes. Called by
// the accept loop (serveConnWithDigest / serveTestConn) when its goroutine exits
// (io.EOF / read error / ctx cancel). It does NOT close the conn — the accept
// loop's own defer conn.Close owns that. Safe to call with a nodeID that was
// never registered (a decode-miss skip) or already released (idempotent: the
// select-default guards a double close of pc.done, which would panic).
func (ps *PeerSet) ReleaseInbound(nodeID [16]byte) {
	ps.ReleaseInboundConn(nodeID, nil)
}

// ReleaseInboundConn is the IDENTITY-GUARDED release.
// It marks the inbound peerConn for nodeID dead ONLY IF the currently-registered
// peerConn IS the one the caller installed (ps.peers[nodeID] == mine). The accept
// loop passes the *peerConn RegisterInbound returned; a nil mine preserves the
// legacy identity-blind behavior for callers that have no pc to bind to.
//
// THE WRONG-KILL THIS CLOSES (a review finding — latent before the guard, and
// load-bearing after it):
//
//	Without the identity guard (latent): accept goroutine G1 registers pc1 for
//	  peer P. A newer
//	  registrant (or a Dial) supersedes it, so ps.peers[P] == pc2 (LIVE). G1's
//	  conn then drops and its deferred ReleaseInbound(P) fires — the identity-blind
//	  lookup finds pc2 and closes pc2.done. G1 just killed a LIVE conn it never
//	  owned, waking P's ReconnectLoop for no reason.
//	With a naive guard (would be worse): a DECLINED registration returns nil pc,
//	  but an
//	  identity-blind release keyed on the nodeID would still close whatever edge
//	  IS registered — so every declining accept goroutine would, on exit, kill the
//	  very live edge the guard just protected. Without the identity check, the
//	  guard would trade the eviction storm for a wrong-kill race.
//
// The comparison is a POINTER identity check under ps.mu, so it is atomic with
// respect to a concurrent RegisterInbound/Dial swap: either we observe our own pc
// (and close it) or we observe someone else's (and leave it alone). The close
// itself routes through pc.closeDone — the sync.Once — so
// even a double release cannot panic.
func (ps *PeerSet) ReleaseInboundConn(nodeID [16]byte, mine *PeerConnHandle) {
	if nodeID == ([16]byte{}) {
		return // a decode-miss skip — nothing was registered.
	}
	ps.mu.Lock()
	pc, ok := ps.peers[nodeID]
	ps.mu.Unlock()
	if !ok || pc == nil {
		return
	}
	// Release ONLY our own registration. A nil `mine` keeps the legacy
	// identity-blind behavior (no caller in this repo relies on it — the accept
	// loops all bind to the returned pc — but the ReleaseInbound wrapper preserves
	// the exported signature for any external caller).
	if mine != nil && pc != mine.pc {
		return // superseded (or declined): NOT ours to close.
	}
	select {
	case <-pc.done:
		// already closed (a double-release, or the stale-close path closed it).
	default:
		pc.closeDone()
	}
	// An inbound edge has no readLoop to run the removal defer — the
	// accept-loop release IS its death path, so the byAddr bound lives here.
	ps.removeDeadEntry(pc)
}

// closeDone closes pc.done EXACTLY ONCE (the sync.Once at the closeDoneOnce
// field). Both ReleaseInbound (the accept-loop drop) + the readLoop's exit
// defer route through this — whichever fires first wins, the other's Once.Do
// is a no-op. This is the fix for the silicon-found
// `panic: close of closed channel` (the TOCTOU between the readLoop's UNGUARDED
// `defer close(pc.done)` + ReleaseInbound's select-guarded close).
func (pc *peerConn) closeDone() {
	pc.closeDoneOnce.Do(func() { close(pc.done) })
}

// removeDeadEntry (ADR-0045) deletes pc's ps.byAddr and
// ps.peers entries — ONLY if the maps still point at THIS peerConn. It is the
// byAddr cardinality bound: RegisterInbound keys byAddr under the peer's
// EPHEMERAL source port, so every inbound reconnection minted a FRESH key and
// nothing ever deleted on a natural close — the map grew without bound,
// pinning each dead peerConn → *tls.Conn → grown record buffers.
//
// THE TRAP THIS RESPECTS (do not "simplify" it away): the identity check
// (cur == pc) is what makes deletion safe against the re-registration race —
// if Dial or RegisterInbound already replaced the entry with a NEWER live
// peerConn, the delete is skipped. Deletion and the dead-entry tolerance in
// Dial/liveReconnectEdge are COMPLEMENTS: a lookup that races the delete sees
// either the dead entry (and falls through past it) or no entry (and dials) —
// both correct. The tolerance MUST REMAIN (deletion can never be assumed to
// have won the race); it is the correctness floor, this is the bound.
func (ps *PeerSet) removeDeadEntry(pc *peerConn) {
	ps.mu.Lock()
	if cur, ok := ps.byAddr[pc.addr]; ok && cur == pc {
		delete(ps.byAddr, pc.addr)
	}
	if pc.peerID != ([16]byte{}) {
		if cur, ok := ps.peers[pc.peerID]; ok && cur == pc {
			delete(ps.peers, pc.peerID)
		}
	}
	ps.mu.Unlock()
}

// readLoop reads frames from the conn and dispatches them
// -> recv.HandleFrame / recv.HandleBatchFrame (the receive sinks). It exits on
// ctx cancel or a read error (io.EOF on peer close); the reconnect loop
// (ReconnectLoop) re-dials with bounded backoff.
//
// dispatch: after ReadFrame strips the 4-byte length prefix, read the
// first 4 bytes of the frame body. attribution.IsBatchFrame returns true iff
// they match WireV1Magic (big-endian) — route to HandleBatchFrame (the batch
// path); else route to HandleFrame (the RelayEnvelope path — back-compat
// default). The peek is a NO-COPY slice-header read (it never allocates); the
// magic is DISTINCT from the RelayEnvelope's uint16-LE version prefix so the
// dispatch is unambiguous (a batch is never handed to the RelayEnvelope parser,
// which would DropMalformed it — a silent throughput collapse).
func (ps *PeerSet) readLoop(ctx context.Context, pc *peerConn) {
	// A review finding: close the conn when the readLoop exits so
	// a natural peer drop (io.EOF / read error / ctx cancel) does NOT leak the
	// underlying *tls.Conn + its TCP socket + fd. The earlier code had only
	// `defer close(pc.done)` (the goroutine-signal) — the conn was closed only
	// by ClosePeer (the explicit primitive, never called for a natural drop) or
	// the Dial DEAD-branch (post-drop re-dial, which never fires during a
	// meshCtx-canceled shutdown). A drop during shutdown (ReconnectLoop returns
	// without re-dialing on ctx.Err) leaked the conn for the process lifetime.
	// The close is idempotent (tls.Conn.Close after a TCP RST returns an error
	// we discard; a double-close is a no-op on the fd). LIFO defer order:
	// declare pc.conn.Close FIRST + close(pc.done) SECOND so close(pc.done)
	// RUNS FIRST — a concurrent Dial's DEAD-branch capture sees pc.done closed
	// BEFORE the conn is closed, so the liveness check (`<-existing.done`) stays
	// the gating signal, NOT a conn-state sniff (no torn-state window where done
	// is open but the conn is closing).
	defer pc.conn.Close()
	// After the done-signal, drop this edge's map entries (identity-checked
	// — a re-registered newer edge at the same addr survives). LIFO: closeDone
	// runs first, then the removal, then the conn close.
	defer ps.removeDeadEntry(pc)
	defer pc.closeDone()                  // Once-guarded (was unguarded `defer close(pc.done)` → the silicon TOCTOU panic)
	fr := receive.NewFrameReader(pc.conn) // receiver.go:474 (io.Reader)
	for {
		if ctx.Err() != nil {
			return
		}
		frame, err := fr.ReadFrame() // receiver.go:486
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if !errors.Is(err, io.EOF) {
				log.Printf("mesh: peer %x frame read: %v", pc.peerID, err)
			}
			return
		}
		// Dial-side receive-count (a symmetry probe).
		// Bounded: ONE log line every 100th frame so the hot loop is NOT a log
		// storm. Answers: did the peer write anything back over the connection WE
		// dialed? (NOT the seed->peer delta nor the peer->seed bootstrap — both
		// arrive on the accept loop. This is the narrower symmetry check.) The
		// DispatchFrame verdict stays discarded into `_` below — do NOT remove the
		// discard (the accept side at main.go owns verdict logging).
		rcvd := atomic.AddUint64(&pc.framesReceived, 1)
		if rcvd%100 == 0 {
			log.Printf("mesh: peer %x dial-side received %d frame(s)", pc.peerID, rcvd)
		}
		// dispatch: peek the post-length-prefix body's first 4
		// bytes. DispatchFrame centralizes the three-way routing — a
		// BatchEnvelope magic routes to HandleBatchFrame (the batch
		// path); a WireDigestMagic routes to the digestSink (the
		// stratified-anti-entropy digest-exchange, ADR-0034); the default routes
		// to HandleFrame (the relay path). The digestSink is the
		// Gossiper bound to this PeerSet (nil-safe: a Gossiper with stratified
		// OFF never registers a sink, so the digest branch is a no-op drop).
		_ = DispatchFrame(frame, pc.peerID, ps.recv, ps.digester)
	}
}

// Publish writes length-prefixed frame bytes to a live peer identified by
// peerID. The caller (gossip.go) has already length-prefixed the bytes via
// receive.LengthPrefixFrame; Publish just runs the TransmitTLSFrame
// copy-mode writer.
func (ps *PeerSet) Publish(peerID [16]byte, prefixed []byte) error {
	ps.mu.RLock()
	pc, ok := ps.peers[peerID]
	ps.mu.RUnlock()
	if !ok || pc == nil {
		return fmt.Errorf("mesh: Publish: no live peer %x", peerID)
	}
	if _, err := transport.TransmitTLSFrame(pc.conn, prefixed); err != nil { // transport.go:142
		return fmt.Errorf("mesh: Publish to %x: %w", peerID, err)
	}
	return nil
}

// Peers returns a snapshot of the live peer IDs. Used by the gossip sweep to
// iterate peers deterministically (the caller sorts the result).
func (ps *PeerSet) Peers() [][16]byte {
	ps.mu.RLock()
	ids := make([][16]byte, 0, len(ps.peers))
	for id := range ps.peers {
		ids = append(ids, id)
	}
	ps.mu.RUnlock()
	return ids
}

// Close cancels all reader goroutines and closes the peer connections.
func (ps *PeerSet) Close() error {
	ps.mu.Lock()
	conns := make([]*peerConn, 0, len(ps.peers))
	for _, pc := range ps.peers {
		conns = append(conns, pc)
	}
	ps.mu.Unlock()
	var firstErr error
	for _, pc := range conns {
		if pc.cancelReader != nil {
			pc.cancelReader()
		}
		if t := pc.conn; t != nil {
			if err := t.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		// (ADR-0045): an INBOUND peerConn has no
		// readLoop, so nothing closes its done once the accept loop is gone —
		// `<-pc.done` would block forever (the deadlock shape ClosePeer
		// already fixes at :885). closeDone is the sync.Once no-op for
		// outbound conns (their readLoop's deferred close is the primary
		// path) and the deadlock break for inbound ones.
		pc.closeDone()
		<-pc.done
	}
	return firstErr
}

// ClosePeer closes ONE peer's connection and cancels its readLoop, leaving every
// other peer untouched. It is the per-peer partition primitive the
// ConvergenceProbe composes: a partition drops a single peer's conn (NOT
// Close-all), and a later Dial re-establishes it (the heal). The peer is removed
// from BOTH the peers and byAddr maps under the write lock BEFORE the conn is
// closed, so a concurrent Publish finds the peer already gone and returns
// ErrNoPeers (never a write to a closed/nil conn — the nil-safety).
// Returns nil for a peer that is not present (already gone = idempotent).
func (ps *PeerSet) ClosePeer(peerID [16]byte) error {
	ps.mu.Lock()
	pc, ok := ps.peers[peerID]
	if !ok {
		ps.mu.Unlock()
		return nil // not present = already gone (idempotent)
	}
	delete(ps.peers, peerID)
	for addr, cand := range ps.byAddr {
		if cand == pc {
			delete(ps.byAddr, addr)
			break
		}
	}
	ps.mu.Unlock()
	if pc.cancelReader != nil {
		pc.cancelReader()
	}
	if pc.conn != nil {
		_ = pc.conn.Close()
	}
	// An INBOUND
	// peerConn (RegisterInbound, peer.go:578) has NO readLoop and NO
	// cancelReader — its only done-closer is the accept loop's deferred
	// ReleaseInboundConn, which early-returns because this function ALREADY
	// deleted the map entry (ps.peers[nodeID] misses → return). Waiting on
	// `<-pc.done` then blocks FOREVER: a deterministic deadlock the moment
	// ClosePeer meets an inbound-registered edge. closeDone here is the fix;
	// the sync.Once makes it a no-op for OUTBOUND conns,
	// whose readLoop's deferred close is the primary path — the wait below
	// still observes the close.
	pc.closeDone()
	<-pc.done // the readLoop goroutine exits on ctx cancel / io.EOF
	return nil
}

// ErrNoPeers is returned by the sweep when the PeerSet has zero live peers.
var ErrNoPeers = errors.New("mesh: no live peers")

// liveReconnectEdge returns the LIVE peerConn representing "we already have a
// working connection to this peer", or nil if there is none. It is the liveness
// predicate ReconnectLoop drives off, and it consults BOTH keyings:
//
//   - ps.byAddr[addr] — the OUTBOUND edge we dialed (the addr-keyed
//     lookup: stable across Dial's reconcile re-key, which moves the ps.peers
//     key from the caller's zero peerID to the real nodeID).
//   - ps.peers[peerID] — the edge Publish ACTUALLY consults (peer.go:798). This
//     is the inbound edge (ADR-0045), and it is the load-bearing addition:
//
// RegisterInbound keys byAddr under conn.RemoteAddr — the peer's EPHEMERAL
//
//	port (peer.go:634) — NOT the configured listen addr ReconnectLoop holds.
//	So a live SYMMETRIC inbound edge is INVISIBLE to any byAddr[configuredAddr]
//	lookup, including Dial's own liveness guard (peer.go:343). That invisibility
//	is the colocated stampede: at 34 nodes/host A holds a live publishable
//	inbound edge from B, yet A's ReconnectLoop re-dials B anyway; B's
//	RegisterInbound then stale-closes B's own outbound peerConn (peer.go:597-643),
//	B's ReconnectLoop wakes and re-dials A, and the two hosts ping-pong
//	re-registrations — the "registered inbound peer ~10× at different ephemeral
//
// ports" the 100-node silicon logged, starving the anti-entropy sweep
//
//	to 1 round in 91s. Checking ps.peers closes it: an already-publishable peer
//	is not re-dialed.
//
// The ZERO peerID is EXCLUDED from the ps.peers half deliberately. An
// un-provisioned peer whose leaf-CN reconcile MISSES stays keyed under the zero
// nodeID (Dial's effectivePeerID), so ps.peers[zero] is a COLLISION BUCKET shared
// by every un-provisioned peer: honoring it would let one peer's liveness
// suppress a DIFFERENT peer's reconnect (a false dedupe that would silently
// partition the mesh). For the zero peerID the predicate degrades to exactly the
// original byAddr-only behavior. Production (--peer-dir provisioned) always passes
// a real nodeID, so the ps.peers half is live where it matters.
//
// "Live" means the peerConn exists AND its done channel is still open (closed ==
// the readLoop exited == dead — the liveness discipline, NOT a
// conn-pointer-non-nil test).
func (ps *PeerSet) liveReconnectEdge(addr string, peerID [16]byte) *peerConn {
	ps.mu.RLock()
	pc, ok := ps.byAddr[addr]
	if ok && pc != nil {
		select {
		case <-pc.done:
			// DEAD byAddr entry. A natural drop never deletes it (only
			// ClosePeer does), so it SHADOWED any live inbound edge keyed by
			// peerID — a review finding: ReconnectLoop
			// re-dialed into an already-connected peer, the churn the
			// recheck exists to stop. Fall through to the peerID keying.
			ok = false
		default:
		}
	}
	if (!ok || pc == nil) && peerID != ([16]byte{}) {
		pc, ok = ps.peers[peerID]
	}
	ps.mu.RUnlock()
	if !ok || pc == nil {
		return nil
	}
	select {
	case <-pc.done:
		return nil // DEAD — the readLoop exited; the caller re-dials.
	default:
		return pc // LIVE.
	}
}

// ReconnectLoop re-establishes a peer that dropped, with bounded exponential
// backoff (backoff0 initial, backoffMax ceiling). It is optional (the production
// binary wires it); the in-process test harness uses persistent net.Pipe connections.
func (ps *PeerSet) ReconnectLoop(ctx context.Context, addr, serverName string, peerID [16]byte, backoff0, backoffMax time.Duration) {
	// base is the NORMALIZED initial backoff. The earlier code normalized into
	// `b` but reset with `b = backoff0` (the raw argument) after a successful dial
	// — so a caller passing backoff0 <= 0 got b = 0 on the reset, then
	// time.NewTimer(0) fired instantly and `b *= 2` stayed 0: a 100%-CPU tight
	// re-dial spin, which at colocated density IS a stampede. Reset to `base`, not
	// to the raw argument. (Production passes time.Second — the spin was latent,
	// not live — but a zero-backoff loop is exactly the failure mode the backoff-bucket
	// fix exists to remove, so it closes here.)
	base := backoff0
	if base <= 0 {
		base = time.Second
	}
	b := base
	if backoffMax <= 0 {
		backoffMax = 10 * time.Second
	}
	// (ADR-0045) — the per-loop deterministic jitter source.
	// math/rand/v2 has NO top-level Seed (v1's rand.Seed is REMOVED), and the
	// process-global source would serialize 3366 colocated loops on one lock; a
	// per-loop rand.New(rand.NewPCG(...)) is goroutine-local, allocation-free on
	// use, and DETERMINISTIC per (addr, peerID) — the topology.go:298
	// precedent. The seed is an inline FNV-1a over addr THEN the peerID bytes, so
	// every ReconnectLoop in a 100-node mesh (distinct peer per loop) draws a
	// DISTINCT jitter sequence: that de-correlation is the whole point. The second
	// PCG word is the first XOR the golden-ratio constant so the two state words
	// are not identical for a low-entropy seed.
	seed := uint64(14695981039346656037) // FNV-1a offset basis
	for i := 0; i < len(addr); i++ {
		seed ^= uint64(addr[i])
		seed *= 1099511628211 // FNV-1a prime
	}
	for i := 0; i < len(peerID); i++ {
		seed ^= uint64(peerID[i])
		seed *= 1099511628211
	}
	rng := rand.New(rand.NewPCG(seed, seed^0x9E3779B97F4A7C15))
	for {
		if ctx.Err() != nil {
			return
		}
		// (ADR-0040) — the ADDR-KEYED liveness lookup.
		// The earlier lookup was `ps.peers[peerID]` (the caller-supplied
		// peerID), but Dial re-keys an UN-PROVISIONED reconciled peer under the
		// REAL nodeID (reconcilePeerID → effectivePeerID), so the caller's zero
		// peerID never matches → the lookup MISSed → the `pc.done` wait was
		// skipped → ReconnectLoop called Dial immediately → Dial's old
		// `existing.conn != nil` guard returned nil "already live" for the LIVE
		// reconciled peer → no backoff → a tight CPU spin (the
		// reconcile-key-mismatch a review found). The fix: look up by ADDR
		// (the stable identity the dial loop + the reconnect watcher share),
		// NOT by peerID — so the wait finds the peer regardless of whether Dial
		// keyed it under the zero or the reconciled real nodeID. A live peer
		// (done open) → block on pc.done until the drop; a dead/absent peer →
		// fall through to Dial, which now re-dials (the accept fix: the done-liveness
		// check, NOT conn-pointer-non-nil).
		//
		// (ADR-0045): the lookup is liveReconnectEdge —
		// byAddr[addr] OR ps.peers[peerID] (the inbound edge Publish
		// consults, which byAddr CANNOT see because RegisterInbound keys it under
		// the peer's ephemeral port). Waiting on the SAME predicate the post-wait
		// dedupe below re-checks is what makes the loop structurally spin-free:
		// every iteration either BLOCKS on a live edge's done channel or DIALS
		// with backoff. Never neither.
		if pc := ps.liveReconnectEdge(addr, peerID); pc != nil {
			select {
			case <-pc.done:
			case <-ctx.Done():
				return
			}
		}
		// A review finding: re-check ctx.Err AFTER the pc.done
		// wait + BEFORE the dial. The runtime may pick the pc.done case at the
		// SAME instant ctx is canceled (a peer drop racing SIGINT/meshCancel) —
		// without this re-check, control falls straight to ps.Dial with a
		// canceled ctx. ps.dialer.Dial (tls.Dial, NOT tls.DialContext — no ctx
		// param, tls_transport.go:430) ignores the canceled ctx + completes a real
		// TCP+TLS dial against a peer that's up → installs a conn whose readLoop
		// exits immediately (readerCtx is a child of the canceled meshCtx) → the
		// *tls.Conn + its fd leak (peerSet.Close is never called on the production
		// shutdown path). The re-check retires the leak: a woken-on-shutdown
		// ReconnectLoop returns without dialing.
		if ctx.Err() != nil {
			return
		}
		// (ADR-0045) — the POST-WAIT re-check: the storm drain.
		// The liveness lookup above is the guard BEFORE the wait; it was NOT
		// re-checked after. Between our wake-up (this peer's edge died) and this
		// point, ANOTHER path may have already re-established the peer:
		//   - the peer re-dialed US and the accept loop called RegisterInbound
		//     (the symmetric inbound edge — the common case at colocated density,
		//     because a host-wide drop makes both ends reconnect simultaneously);
		//   - a concurrent boot dial or a sibling ReconnectLoop won the race.
		// Re-dialing on top of a live edge is not merely wasted work: it makes the
		// remote's RegisterInbound stale-close the peer's own outbound peerConn
		// (peer.go:597-643), which wakes THAT node's ReconnectLoop, which re-dials
		// us — the self-sustaining ping-pong. Returning to the top of the loop
		// re-enters the wait on the NEW live edge (no dial, no timer, no spin) and
		// resets the backoff, because a healthy peer must not inherit a stale
		// backoff ladder. This is a pure ADDITION: when there is no live edge the
		// behavior is byte-identical to the original path.
		if pc := ps.liveReconnectEdge(addr, peerID); pc != nil {
			b = base
			continue
		}
		if err := ps.Dial(ctx, addr, serverName, peerID); err != nil {
			log.Printf("mesh: reconnect %x@%s: %v (backoff %v)", peerID, addr, err, b)
			// A review finding: time.NewTimer + Stop (NOT
			// time.After, which returns a channel with no Stop handle). A
			// ReconnectLoop in backoff when meshCancel fires selects the ctx.Done
			// branch + returns, but a time.After(b) Timer it created is NOT
			// stopped → the Timer + its channel leak in the runtime heap until b
			// elapses (up to 10s), then fire into a channel no one reads. Per-peer
			// Timer leak on shutdown. time.NewTimer gives a Stop handle: stop
			// the timer on the ctx.Done branch + drain its channel if Stop reports
			// the timer already fired (the time.AfterFunc/Stop drain idiom) so the
			// Timer is reclaimed immediately.
			// (ADR-0045) — ±20% uniform jitter: the anti-stampede.
			// The backoff ladder is per-peer-per-goroutine and was PERFECTLY
			// DETERMINISTIC (1s, 2s, 4s, 8s, 10s, 10s...). At 34 colocated nodes ×
			// 99 peers each, a host-wide event (a listener restart, a GC pause, a
			// NIC hiccup) drops thousands of edges within the same millisecond, and
			// every one of those loops then re-dials in LOCKSTEP — the classic
			// thundering herd, re-synchronizing at every rung of the ladder because
			// doubling preserves phase. Jitter breaks the phase lock: the dial
			// arrivals spread across a window instead of spiking, so the dial/TLS
			// work per instant drops from O(all colocated edges) to O(fanout) and
			// the anti-entropy sweep goroutine actually gets scheduled.
			//
			// The jittered value is used ONLY for THIS sleep; the ladder variable b
			// keeps the clean power-of-two so the ceiling logic stays exact and the
			// jitter cannot compound into a random walk (a jittered-and-fed-back
			// ladder drifts and can collapse toward the floor, re-creating the
			// storm it was meant to prevent).
			//
			// Int64N(2*span+1) - span yields a symmetric integer offset in
			// [-span, +span] with span = b/5 (20%). The nanosecond magnitudes are
			// huge (b >= 1ms in every real caller), so integer truncation of b/5 is
			// immaterial; the span==0 guard keeps Int64N's "panics if n <= 0"
			// contract satisfied for a sub-5ns backoff (a test could pass one).
			d := b
			if span := int64(b) / 5; span > 0 {
				d = b + time.Duration(rng.Int64N(2*span+1)-span)
			}
			timer := time.NewTimer(d)
			select {
			case <-timer.C:
			case <-ctx.Done():
				if !timer.Stop() {
					<-timer.C // drain if the timer fired between the select + Stop.
				}
				return
			}
			b *= 2
			if b > backoffMax {
				b = backoffMax
			}
			continue
		}
		// Reset to the NORMALIZED base (not the raw backoff0 argument) — see the
		// `base` comment at the top of the function: resetting to a caller's
		// zero/negative backoff0 re-armed a 100%-CPU tight re-dial spin.
		b = base
		// — THE SUCCESS-PATH FLOOR. A SUCCESSFUL dial fell
		// straight back to the top of the loop with no sleep at all: the timer sits
		// on the FAILURE branch only. So any mechanism that killed the freshly-dialed
		// edge produced an UNTHROTTLED re-dial — dial, get evicted, dial again, at
		// whatever rate the TLS handshake allows. Silicon measured ~700
		// dials/sec/node sustained for 4 minutes (127,163 dials on one node) with
		// `mesh: reconnect` = 0 on EVERY node, i.e. the failure path (and its
		// backoff ladder) never executed once — the storm rode entirely on this
		// unfloored success path.
		//
		// The liveness guard removes the eviction that drove that loop; this floor
		// is the BACKSTOP
		// that bounds the damage of ANY future instant-death cause (a peer closing
		// on us, a half-open conn, a TLS-level reject that still returns nil). It is
		// deliberately small (successFloor = 250ms): large enough that a pathological
		// churn is ~4 dials/sec instead of ~700, small enough to be invisible to a
		// legitimate reconnect (the caller's backoff0 is 1s in production).
		// Jittered from the SAME per-loop PCG source as the failure ladder so a
		// colocated fleet cannot re-synchronize on the floor either.
		floor := successFloor
		if span := int64(floor) / 5; span > 0 {
			floor += time.Duration(rng.Int64N(2*span+1) - span)
		}
		ft := time.NewTimer(floor)
		select {
		case <-ft.C:
		case <-ctx.Done():
			if !ft.Stop() {
				<-ft.C
			}
			return
		}
	}
}

// successFloor is the minimum interval between a SUCCESSFUL ReconnectLoop dial
// and the next dial attempt for the same peer. See the comment in
// ReconnectLoop: it bounds an instant-death re-dial loop to ~4/sec instead of the
// ~700/sec silicon measured, without delaying a legitimate reconnect (whose
// caller-supplied backoff0 is 1s in production).
const successFloor = 250 * time.Millisecond

// splitHostPort returns the host (SNI) portion of a host:port address.
func splitHostPort(addr string) (host string, err error) {
	host, _, err = net.SplitHostPort(addr)
	return host, err
}
