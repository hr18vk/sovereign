// Package mesh is the production peer-to-peer gossip layer that rides the
// Day-1 TLS 1.3 transport.
//
// Day 2 scope (per the Day-2 executor prompt): a PeerSet dials each configured
// peer over mTLS, keeps a per-peer reader goroutine feeding the FROZEN
// Receiver.HandleFrame sink (Day 1's accept loop, reused on the dial side so a
// node that both dials and accepts converges symmetrically), and publishes
// outbound signed envelopes via pkg/transport.TransmitTLSFrame. The mesh is a
// NEW CALLER of the engine + identity + envelope + forward + transport APIs; it
// touches NO FROZEN file.
//
// Identity model (the load-bearing Day-2 seam, NOT carried by Day 1): each
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
	"net"
	"sync"
	"time"

	"github.com/hr18vk/supremum/pkg/identity"
	"github.com/hr18vk/supremum/pkg/receive"
	eng "github.com/hr18vk/supremum/pkg/sync"
	"github.com/hr18vk/supremum/pkg/transport"
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
// Day 32 (ADR-0037): PQPriv is the OPTIONAL ML-DSA-65 private key for the
// hybrid SIGN (under --hybrid-sign the gossiper's ShipBatchHybrid signs the
// batch wire under BOTH Ed25519 + ML-DSA-65 via identity.SignCRDTFrame_Hybrid).
// It is nil by default (the pre-Day-32 posture — a node with NO PQ key produces
// v1 BatchEnvelopes byte-identical to Day-31; --hybrid-sign=false is the
// byte-identical-Day-31 default). When --hybrid-sign is set, buildNodeIdentity
// mints the PQ keypair from the SAME 32-byte seed (identity.GeneratePreviewKey65
// — the deterministic seed form, byte-identical across runs) + registers the PQ
// pubkey in the Directory via RegisterPQ so peers' hybrid verify resolves it.
// The PQ key is derived from the SAME seed as the Ed25519 key (one identity
// space — the deploy discipline Day-2 named), so a node's Ed25519 pubkey +
// ML-DSA-65 pubkey BOTH key off the one --identity-seed.
type NodeIdentity struct {
	NodeID [16]byte
	Seed   []byte // len 32 (ed25519.SeedSize); owned, never mutated
	Pub    ed25519.PublicKey
	// PQPriv is the Day-32 (ADR-0037) OPTIONAL ML-DSA-65 private key for the
	// hybrid SIGN. nil by default (the pre-Day-32 posture — no hybrid frame is
	// produced). When non-nil, ShipBatchHybrid signs under BOTH Ed25519 +
	// ML-DSA-65; the corresponding PQPub is registered in the Directory via
	// RegisterPQ so peers' hybrid verify resolves it. Owned by the NodeIdentity;
	// never mutated post-construction.
	PQPriv *mldsa.PrivateKey
	// PQPub is the Day-32 ML-DSA-65 public key paired with PQPriv. Registered in
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
// CLASSICAL-ONLY constructor (the pre-Day-32 default, byte-identical). The
// hybrid-SIGN constructor is NewNodeIdentityHybrid (Day 32), which derives the
// ML-DSA-65 keypair from the SAME seed. A NodeIdentity from NewNodeIdentity has
// PQPriv == nil -> ShipBatchHybrid is a no-op (the gossiper's hybrid arm is
// disarmed) -> NO hybrid frame is produced (the byte-identical-Day-31 default).
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

// NewNodeIdentityHybrid is the Day-32 (ADR-0037) hybrid-SIGN constructor: it
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
	// Use the concrete PublicKey() getter (mldsa.go:139 — returns *PublicKey
	// directly), NOT the Public() interface method (mldsa.go:122 — returns
	// crypto.PublicKey, which would need an unchecked type assertion). The
	// /verify audit flagged the assertion as a needless panic risk: a future
	// KMS/HSM-backed mldsa.PrivateKey (the ADR-0037 carry-forward "operator-path
	// hybrid SIGN via a KMS/HSM minter") could return a non-*mldsa.PublicKey
	// from Public(), panicking at boot; the concrete getter returns the exact
	// type with no assertion.
	ni.PQPub = pqPriv.PublicKey()
	return ni, nil
}

// dialer is the subset of pkg/transport.TLSConnections the PeerSet uses to open
// peer connections. Exposed as an interface so the in-process gate wires a
// net.Pipe-based dialer WITHOUT a real TCP listener, while the production binary
// wires the real *transport.TLSConnections (which satisfies Dial — see
// tls_transport.go:150).
type dialer interface {
	Dial(network, addr, serverName string) (*tls.Conn, error)
}

// frameSink is the subset of pkg/receive.Receiver the PeerSet feeds inbound
// frames into. Exposed as an interface so the in-process gate can wire an
// instrumented sink; the production binary wires the real *receive.Receiver
// (which satisfies HandleFrame — see receiver.go:253 — and HandleBatchFrame —
// see receiver.go, the Day-5 batch path). The return type is
// receive.AcceptVerdict exactly (not any) so *receive.Receiver satisfies the
// interface without an adapter.
//
// Day-5 dispatch: readLoop peeks the first 4 bytes of each reassembled frame
// (post-length-prefix) and routes a BatchEnvelope (attribution.IsBatchFrame) to
// HandleBatchFrame; everything else routes to HandleFrame (the FROZEN
// RelayEnvelope path — back-compat default). The batch path is opt-in via
// --batch-size>1 on the SEND side; the RECEIVE side dispatches on the wire
// magic so a node accepts batches from a peer that opted in regardless of its
// own --batch-size.
//
// Day 32 (ADR-0037): the FOUR-way dispatch adds the hybrid-PQ batch path — a
// frame tagged WireHybridPQMagic (attribution.IsHybridFrame) routes to
// HandleHybridFrame (the BOTH-sig verify gate). The hybrid path is opt-in via
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
}

// PeerSet dials each configured peer over mTLS, keeps a per-peer reader
// goroutine feeding the FROZEN Receiver.HandleFrame sink, and publishes
// outbound signed envelopes via pkg/transport.TransmitTLSFrame. It is safe for
// concurrent use.
type PeerSet struct {
	dialer dialer
	recv   frameSink
	owner  *NodeIdentity
	engine *eng.DeltaCRDTEngine

	// digester is the Day-29 digest-exchange sink (ADR-0034). It is the
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

	// autoReconcile is the Day-35 (ADR-0040) OPT-IN runtime TLS-leaf reconcile
	// flag (Seam B). default false = byte-identical Day-34 (the dial loop stores
	// peers under the caller-supplied peerID — zero for an un-provisioned peer —
	// and the topology selector keys under peerIDForAddr(addr), which never
	// matches the zero peerID → the region lookup misses → the N=2 no-op the
	// Day-34 §7.1 residual names). ON switches Dial to read the peer's TLS leaf
	// CommonName (hex.DecodeString the 32-char CN → [16]byte — the SAME mirror
	// mintSelftestCerts uses, IssueLeaf(hex.EncodeToString(nodeID[:])) main.go:1543)
	// + re-key the peerConn under the REAL nodeID so the topology selector HITS
	// → Publish(realNodeID) succeeds → the 2-node binary mesh converges. ROUTING-
	// only per M3: the reconcile re-keys the ROUTING key (which ps.peers entry
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

// NewPeerSet constructs a PeerSet bound to a TLS dialer, the FROZEN receive
// sink, and the owner's signing identity. engine is the gossiper's own state
// (GenerateDigest/GenerateDelta source); recv is the FROZEN sink every
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

// SetDigestSink binds the Day-29 digest-exchange sink (ADR-0034). The Gossiper
// calls it once after NewGossiper so the readLoop's DispatchFrame can route a
// WireDigestMagic-tagged frame to the sweep's per-peer blocking-receive channel.
// Nil-safe (the SetRoundReporter precedent): a PeerSet with no digester drops
// digest frames — the honest cold-start when stratified is OFF (the opt-IN
// default keeps the oversend path byte-identical). Called once at construction
// before the readLoop starts; the single-writer-before-reader discipline makes
// the non-atomic set race-free.
func (ps *PeerSet) SetDigestSink(d DigestSink) { ps.digester = d }

// SetAutoReconcile arms the Day-35 (ADR-0040) runtime TLS-leaf reconcile (Seam
// B). Called once at construction (the cmd path wires it from
// --peer-auto-reconcile before the dial loop starts; the single-writer-before-
// reader discipline). default false = byte-identical Day-34. Nil-safe-by-being-
// a-primitive (the flag is a bool; the false zero-value is the byte-identical
// default — no nil-guard needed). See the autoReconcile field doc for the
// ROUTING-only (M3) contract + the zero-trust posture a self-announced-but-not-
// OOB-provisioned peer has.
func (ps *PeerSet) SetAutoReconcile(on bool) { ps.autoReconcile = on }

// Dial opens an mTLS connection to addr and installs a per-peer reader goroutine
// feeding the FROZEN sink. peerID is the remote's CRDT-delta signing nodeID.
// It is idempotent for an already-live peer.
func (ps *PeerSet) Dial(ctx context.Context, addr, serverName string, peerID [16]byte) error {
	// Day 35 (ADR-0040) carry-forward — the post-drop re-dial liveness fix.
	// The PRE-EXISTING early-return checked `existing.conn != nil` (a pointer
	// non-nil test), but a DROPPED peer's readLoop exits via `defer close(pc.done)`
	// WITHOUT deleting ps.byAddr[addr] / ps.peers[peerID] (the natural-close path
	// — only the explicit ClosePeer primitive evicts). A closed *tls.Conn is
	// STILL a non-nil pointer, so the old guard returned nil "already live" for a
	// DEAD peer → ReconnectLoop's Dial returned nil → the backoff time.After was
	// NEVER entered → ReconnectLoop tight-spun at 100% CPU per dropped peer,
	// never re-dialing (the /code-review root-cause: Angle A #1, D #1, E #1).
	// The fix: gate the early-return on LIVENESS via pc.done (closed == dead), NOT
	// on conn-pointer-non-nil. A live peer (done open) → return nil (idempotent).
	// A dead peer (done closed) → fall through + re-dial; the stale pc's conn is
	// closed here (the readLoop exited but never closed the conn — the leak the
	// re-dial would otherwise orphan) + the stale entry is overwritten at the
	// ps.peers/ps.byAddr writes below (line 332-333). This also fixes the
	// reconcile-key-mismatch (Angle A #1/D #2): the lookup is by ADDR (the stable
	// identity), NOT by peerID — so an un-provisioned reconciled peer (Dial keyed
	// under the REAL nodeID, ReconnectLoop spawned with zero) is found here
	// regardless of which nodeID it was keyed under.
	ps.mu.Lock()
	// staleConn is the DEAD peer's conn to close AFTER releasing the lock (the
	// /code-review finding #4: a tls.Conn.Close() sends a close-notify alert via
	// a BLOCKING Write; doing it UNDER ps.mu would stall every concurrent
	// Publish (RLock) + Peers() (RLock) for one slow peer's close. Capture the
	// stale conn under the lock; close it outside. No SetWriteDeadline exists in
	// pkg/transport (grep-confirmed), so the close-notify Write has no bound —
	// moving it out of the lock is the load-bearing fix.
	var staleConn *tls.Conn
	if existing, ok := ps.byAddr[addr]; ok && existing.conn != nil {
		select {
		case <-existing.done:
			// DEAD — the readLoop exited (io.EOF / read error / ctx cancel).
			// Capture the stale conn for an out-of-lock close (the readLoop did
			// NOT close it — the orphan-conn leak, /code-review finding #3) + let
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
	// Day 35 (ADR-0040) Seam B: the runtime TLS-leaf reconcile. When
	// autoReconcile is ON AND the caller supplied the ZERO peerID (an
	// un-provisioned peer — the Day-2 honest gap), read the peer's TLS leaf
	// CommonName + re-key the peerConn under the REAL nodeID so the topology
	// selector HITS + Publish(realNodeID) succeeds → the 2-node binary mesh
	// converges. The reconcile is a ROUTING fix ONLY (M3): it changes WHICH
	// ps.peers entry Publish writes to; it NEVER touches the verification
	// pubkey (the Directory's OOB-provisioned key is the verification anchor).
	// A PROVISIONED peer (caller passed the real nodeID — Seam A already
	// resolved it) SKIPS the reconcile: the peer is keyed correctly already, +
	// the leaf CN is a redundant signal. The reconcile is the ZERO-CONFIG bonus
	// for a deploy that opts into --peer-auto-reconcile WITHOUT --peer-dir (the
	// ROUTING re-key lands the Publish under the real nodeID — BUT convergence
	// STILL REQUIRES the OOB verification pubkey, provisioned via --peer-dir; a
	// reconcile-only deploy routes but the receiver's Directory.Lookup MISSES
	// (receiver.go:436) → DropVerify → NO convergence. The binary harness RUN 3
	// honest-negative PROVES this: reconcile-only does NOT converge. See
	// reconcilePeerID for the leaf-CN decode + the re-key under ps.mu.
	effectivePeerID := peerID
	if ps.autoReconcile && peerID == ([16]byte{}) {
		if real, ok := ps.reconcilePeerID(pc, conn); ok {
			effectivePeerID = real
		}
		// A reconcile MISS (ok=false) leaves effectivePeerID == zero — the
		// peerConn stays keyed under the zero peerID, the byte-identical Day-34
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
// REAL [16]byte nodeID (Seam B — the Day-35 ADR-0040 runtime reconcile). The
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
//     byte-identical Day-34 behavior — the honest "leaf did not self-announce").
//   - a CN that is not 32 hex chars / does not hex-decode to 16 bytes: a leaf
//     minted by a NON-engine CA (the dev-mesh CA mints engine-shaped CNs; a
//     foreign CA's CN is arbitrary). The reconcile logs + returns false (the
//     peerConn stays keyed under zero; the topology selector misses →
//     RegionUnset = intra = byte-identical full-mesh — the honest conservative
//     default for an unrecognized leaf, NOT a crash).
//
// ROUTING-only (M3): the reconcile re-keys the ROUTING map (ps.peers); it does
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
// ConnectionState().PeerCertificates is populated + non-blocking.
func (ps *PeerSet) reconcilePeerID(pc *peerConn, conn *tls.Conn) ([16]byte, bool) {
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		log.Printf("mesh: reconcile %s: peer presented no leaf cert — staying keyed under zero peerID (the byte-identical Day-34 behavior)", pc.addr)
		return [16]byte{}, false
	}
	cn := state.PeerCertificates[0].Subject.CommonName
	if cn == "" {
		log.Printf("mesh: reconcile %s: peer leaf has empty CommonName — staying keyed under zero peerID", pc.addr)
		return [16]byte{}, false
	}
	nid, err := hex.DecodeString(cn)
	if err != nil {
		log.Printf("mesh: reconcile %s: peer leaf CN %q is not hex — staying keyed under zero peerID (a non-engine CA's CN is arbitrary; the honest conservative default)", pc.addr, cn)
		return [16]byte{}, false
	}
	if len(nid) != 16 {
		log.Printf("mesh: reconcile %s: peer leaf CN %q hex-decodes to %d bytes, want 16 — staying keyed under zero peerID", pc.addr, cn, len(nid))
		return [16]byte{}, false
	}
	var real [16]byte
	copy(real[:], nid)
	log.Printf("mesh: reconcile %s: peer leaf CN %q -> real nodeID %x (re-keying PeerSet under the real nodeID; ROUTING-only per M3)", pc.addr, cn, real)
	return real, true
}

// readLoop drains receive.NewFrameReader(conn).ReadFrame -> the dispatch peek
// -> recv.HandleFrame / recv.HandleBatchFrame (the FROZEN sinks). It exits on
// ctx cancel or a read error (io.EOF on peer close); the reconnect loop
// (ReconnectLoop) re-dials with bounded backoff.
//
// Day-5 dispatch: after ReadFrame strips the 4-byte length prefix, read the
// first 4 bytes of the frame body. attribution.IsBatchFrame returns true iff
// they match WireV1Magic (big-endian) — route to HandleBatchFrame (the batch
// path); else route to HandleFrame (the FROZEN RelayEnvelope path — back-compat
// default). The peek is a NO-COPY slice-header read (it never allocates); the
// magic is DISTINCT from the RelayEnvelope's uint16-LE version prefix so the
// dispatch is unambiguous (a batch is never handed to the RelayEnvelope parser,
// which would DropMalformed it — a silent throughput collapse).
func (ps *PeerSet) readLoop(ctx context.Context, pc *peerConn) {
	// Day 35 /code-review finding #3: close the conn when the readLoop exits so
	// a natural peer drop (io.EOF / read error / ctx cancel) does NOT leak the
	// underlying *tls.Conn + its TCP socket + fd. The PRE-EXISTING code had only
	// `defer close(pc.done)` (the goroutine-signal) — the conn was closed only
	// by ClosePeer (the explicit primitive, never called for a natural drop) or
	// the Dial DEAD-branch (post-drop re-dial, which never fires during a
	// meshCtx-canceled shutdown). A drop during shutdown (ReconnectLoop returns
	// without re-dialing on ctx.Err()) leaked the conn for the process lifetime.
	// The close is idempotent (tls.Conn.Close after a TCP RST returns an error
	// we discard; a double-close is a no-op on the fd). LIFO defer order:
	// declare pc.conn.Close() FIRST + close(pc.done) SECOND so close(pc.done)
	// RUNS FIRST — a concurrent Dial's DEAD-branch capture sees pc.done closed
	// BEFORE the conn is closed, so the liveness check (`<-existing.done`) stays
	// the gating signal, NOT a conn-state sniff (no torn-state window where done
	// is open but the conn is closing).
	defer pc.conn.Close()
	defer close(pc.done)
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
		// Day-5/Day-29 dispatch: peek the post-length-prefix body's first 4
		// bytes. DispatchFrame centralizes the three-way routing — a
		// BatchEnvelope magic routes to HandleBatchFrame (the Day-5 batch gate
		// stack); a WireDigestMagic routes to the digestSink (the Day-29
		// stratified-anti-entropy digest-exchange, ADR-0034); the default routes
		// to HandleFrame (the FROZEN relay gate stack). The digestSink is the
		// Gossiper bound to this PeerSet (nil-safe: a Gossiper with stratified
		// OFF never registers a sink, so the digest branch is a no-op drop).
		_ = DispatchFrame(frame, pc.peerID, ps.recv, ps.digester)
	}
}

// Publish writes length-prefixed frame bytes to a live peer identified by
// peerID. The caller (gossip.go) has already length-prefixed the bytes via
// receive.LengthPrefixFrame; Publish just runs the Day-1 TransmitTLSFrame
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
// ErrNoPeers (never a write to a closed/nil conn — the ATTACK-2 nil-safety).
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
	<-pc.done // the readLoop goroutine exits on ctx cancel / io.EOF
	return nil
}

// ErrNoPeers is returned by the sweep when the PeerSet has zero live peers.
var ErrNoPeers = errors.New("mesh: no live peers")

// ReconnectLoop re-establishes a peer that dropped, with bounded exponential
// backoff (backoff0 initial, backoffMax ceiling). It is optional (the production
// binary wires it); the in-process gate uses persistent net.Pipe connections.
func (ps *PeerSet) ReconnectLoop(ctx context.Context, addr, serverName string, peerID [16]byte, backoff0, backoffMax time.Duration) {
	b := backoff0
	if b <= 0 {
		b = time.Second
	}
	if backoffMax <= 0 {
		backoffMax = 10 * time.Second
	}
	for {
		if ctx.Err() != nil {
			return
		}
		// Day 35 (ADR-0040) carry-forward — the ADDR-KEYED liveness lookup.
		// The PRE-EXISTING lookup was `ps.peers[peerID]` (the caller-supplied
		// peerID), but Dial re-keys an UN-PROVISIONED reconciled peer under the
		// REAL nodeID (reconcilePeerID → effectivePeerID), so the caller's zero
		// peerID never matches → the lookup MISSed → the `pc.done` wait was
		// skipped → ReconnectLoop called Dial immediately → Dial's old
		// `existing.conn != nil` guard returned nil "already live" for the LIVE
		// reconciled peer → no backoff → a tight CPU spin (the /code-review
		// reconcile-key-mismatch: Angle A #1, D #2). The fix: look up by ADDR
		// (the stable identity the dial loop + the reconnect watcher share),
		// NOT by peerID — so the wait finds the peer regardless of whether Dial
		// keyed it under the zero or the reconciled real nodeID. A live peer
		// (done open) → block on pc.done until the drop; a dead/absent peer →
		// fall through to Dial, which now re-dials (Fix 1: the done-liveness
		// check, NOT conn-pointer-non-nil).
		ps.mu.RLock()
		pc, ok := ps.byAddr[addr]
		ps.mu.RUnlock()
		if ok && pc != nil {
			select {
			case <-pc.done:
			case <-ctx.Done():
				return
			}
		}
		// Day 35 /code-review finding #5: re-check ctx.Err() AFTER the pc.done
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
		if err := ps.Dial(ctx, addr, serverName, peerID); err != nil {
			log.Printf("mesh: reconnect %x@%s: %v (backoff %v)", peerID, addr, err, b)
			// Day 35 /code-review finding #7: time.NewTimer + Stop() (NOT
			// time.After, which returns a channel with no Stop handle). A
			// ReconnectLoop in backoff when meshCancel fires selects the ctx.Done
			// branch + returns, but a time.After(b) Timer it created is NOT
			// stopped → the Timer + its channel leak in the runtime heap until b
			// elapses (up to 10s), then fire into a channel no one reads. Per-peer
			// Timer leak on shutdown. time.NewTimer gives a Stop() handle: stop
			// the timer on the ctx.Done branch + drain its channel if Stop reports
			// the timer already fired (the time.AfterFunc/Stop drain idiom) so the
			// Timer is reclaimed immediately.
			timer := time.NewTimer(b)
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
		b = backoff0
	}
}

// splitHostPort returns the host (SNI) portion of a host:port address.
func splitHostPort(addr string) (host string, err error) {
	host, _, err = net.SplitHostPort(addr)
	return host, err
}
