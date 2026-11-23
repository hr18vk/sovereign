// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// Package mesh implements peer-to-peer gossip over the TLS 1.3 transport.
// A PeerSet dials configured peers over mTLS, reads inbound frames into a
// Receiver, and publishes signed envelopes with transport.TransmitTLSFrame.
// Accepted and dialed connections use the same receive path, so convergence
// does not depend on which node initiated a connection.
//
// Each node signs CRDT deltas with a 32-byte Ed25519 seed separate from its TLS
// leaf key. Its node ID is the first 16 bytes of the derived public key. The
// engine's local node ID must equal the origin node ID on every signed delta;
// receivers use that ID to find the public key in an identity.Directory.
// NodeIdentity keeps the node ID, seed, and public key together.
package mesh

import (
	"context"
	crand "crypto/rand"
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

// NodeIdentity is a node's CRDT signing identity. Seed is used by
// identity.SignCRDTFrame, Pub is registered in peer directories for
// VerifyCRDTFrame, and NodeID must equal the engine's local node ID. InsertLocal
// stamps that ID as OriginNodeID, and the receiver uses it for Directory.Lookup.
//
// NodeID is the first 16 bytes of the 32-byte Ed25519 public key, matching the
// origin ID carried by a capnp CRDTDeltaEvent.
//
// The optional ML-DSA-65 keys support hybrid signing (ADR-0037). With
// --hybrid-sign, ShipBatchHybrid signs each batch with both Ed25519 and
// ML-DSA-65. The post-quantum keypair is derived deterministically from the same
// identity seed, and PQPub is registered with RegisterPQ for hybrid verification.
// Without a post-quantum private key, the node emits ordinary v1 batch envelopes.
type NodeIdentity struct {
	NodeID [16]byte
	Seed   []byte // len 32 (ed25519.SeedSize); owned, never mutated
	Pub    ed25519.PublicKey
	// PQPriv is the optional ML-DSA-65 private key. When non-nil,
	// ShipBatchHybrid signs with both Ed25519 and ML-DSA-65. The key is owned by
	// NodeIdentity and is not mutated after construction.
	PQPriv *mldsa.PrivateKey
	// PQPub is paired with PQPriv and registered with RegisterPQ when hybrid
	// signing is enabled. It is nil when PQPriv is nil and is not mutated after
	// construction.
	PQPub *mldsa.PublicKey
}

// NewNodeIdentity derives an Ed25519-only NodeIdentity from a 32-byte seed.
// The returned NodeID is the first 16 bytes of the public key; pass it to
// eng.NewDeltaCRDTEngine so local entries carry an origin ID that receivers
// can resolve to Pub.
//
// PQPriv and PQPub remain nil. ShipBatchHybrid therefore does nothing, and the
// gossiper emits no hybrid frames. NewNodeIdentityHybrid derives both keypairs
// when hybrid signing is required.
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

// NewNodeIdentityHybrid derives Ed25519 and ML-DSA-65 keypairs from the same
// 32-byte seed (ADR-0037). The Ed25519 derivation is identical to
// NewNodeIdentity. With PQPriv set, ShipBatchHybrid can emit hybrid frames when
// --hybrid-sign is enabled. The caller registers PQPub with RegisterPQ so peers
// can resolve it during hybrid verification.
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
	// PublicKey returns the concrete key type. Public would require a type
	// assertion, which could panic if another PrivateKey implementation backed
	// by a KMS or HSM returned a different public-key representation.
	ni.PQPub = pqPriv.PublicKey()
	return ni, nil
}

// dialer is the part of transport.TLSConnections used by PeerSet. Tests can
// supply a net.Pipe dialer without a TCP listener; production supplies the real
// TLS transport.
type dialer interface {
	Dial(network, addr, serverName string) (*tls.Conn, error)
}

// frameSink is the portion of receive.Receiver used by PeerSet. The exact
// AcceptVerdict return types let *receive.Receiver satisfy the interface
// directly, while tests can install an instrumented sink.
//
// DispatchFrame examines each frame's wire magic. Batch envelopes go to
// HandleBatchFrame, hybrid envelopes to HandleHybridFrame, and relay envelopes
// to HandleFrame. Senders opt into batches with --batch-size>1 and hybrid
// signing with --hybrid-sign. Receivers dispatch on the wire format regardless
// of their own sending mode; accepting hybrid frames requires --hybrid-verify.
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
	// suspectKey identifies this edge in the write-stall breaker. An outbound
	// edge uses its configured address; an inbound edge uses the node ID from
	// its certificate because its source address changes on every dial.
	// RegisterInbound installs only successfully decoded identities. Publish
	// uses the same key for checks and failure marks, so breaker state survives
	// reconnection. Outbound edges cannot use the node ID: a failed reconcile
	// leaves it zero, and the zero-ID map entry is shared by unresolved peers.
	suspectKey string

	cancelReader context.CancelFunc
	done         chan struct{}
	// closeDoneOnce closes pc.done when either the read loop exits or
	// ReleaseInbound drops the accepted connection. Those paths can race, and a
	// check followed by close is insufficient: both goroutines could observe an
	// open channel and the second close would panic. sync.Once gives every path
	// the same atomic close operation (ADR-0046). Readers only receive from done.
	closeDoneOnce sync.Once

	// framesReceived counts frames arriving on the dialed connection. readLoop
	// is its only writer; diagnostics and metrics read it concurrently, so all
	// accesses are atomic. It does not include frames arriving on the separate
	// accept loop. Challenge state is cold and occupies the following fields.
	framesReceived uint64
	// remoteVerified records a successful proof that the peer holds the
	// Directory-registered private key for pc.peerID (ADR-0068). Only
	// handleConnChallengeFrame sets it. It changes from false to true once per
	// connection; a replacement peerConn starts unverified, preventing a new
	// connection from inheriting its predecessor's proof. Sweeps, DeliverDigest,
	// and respondToDigest read it concurrently, so it is atomic. The single
	// store per connection keeps this cold state away from the frame counter.
	remoteVerified atomic.Bool
	// challengeNonce is generated with crypto/rand before the connection's
	// reader starts. Goroutine creation orders that write before reads. A valid
	// response echoes the nonce exactly, rejecting a replay before signature
	// verification.
	challengeNonce [32]byte
	// challengeArmed records that this connection sent a challenge. A response
	// without an outstanding challenge is ignored. The field is written before
	// the dial or accept reader starts and is safe to read there.
	challengeArmed bool
	// challengeAnswers counts signatures produced for challenges on this
	// connection, up to the per-connection answer budget. A replacement
	// connection gets a fresh budget. Metrics reads require an atomic counter.
	challengeAnswers atomic.Uint64
}

// Challenge answers require an Ed25519 signature, so budgets bound the work an
// unverified peer can request with 53-byte frames. A connected peer gets 16
// answers per connection, leaving room above the one answer normally needed.
// Stateless answers on declined connections use two limits: 64 reservations
// per suspect key and 65,536 across the PeerSet. A decode miss is keyed by
// remote address, which an attacker can rotate; the global ceiling remains the
// rotation-independent bound.
//
// Reservations expire rather than refilling on a schedule. Exhaustion disables
// stateless answers until recovery or restart, while new connected peers still
// receive fresh per-connection budgets (ADR-0069). The global ceiling is a
// variable so tests can exercise the limit with a small value.
var challengeAnswerGlobalCeiling = uint64(65536)

const (
	challengeAnswerPerConnBudget       = 16
	challengeAnswerPerSuspectKeyBudget = 64
)

// declinedRes records reservations for one suspect key and the most recent
// reservation time. Expiring the whole record avoids permanently excluding a
// peer after repeated mutual-dial declines. With the default limits and TTL,
// the aggregate stateless-answer rate is about 109 signatures per second.
type declinedRes struct {
	count        uint64
	lastUnixNano int64
}

// challengeDeclinedReservationTTL controls how long a reservation counts
// against its key and the global total. Records are reclaimed lazily when read
// or during a sweep at the global ceiling. It is a variable so tests can use
// short expiry windows; production uses ten minutes.
var challengeDeclinedReservationTTL = 10 * time.Minute

// challengeDeclinedSweepInterval rate-limits reclamation sweeps at the global
// ceiling. Without this interval, each 53-byte challenge could trigger an
// O(map) walk. Tests may shorten the interval.
var challengeDeclinedSweepInterval = time.Second

// refundDeclinedReservation releases a reservation after a signing failure.
// A recorded per-key reservation decrements both its record and the global
// total. Another connection may already have reclaimed the record, so both
// operations are guarded: decrementing a missing record would create a
// zero-value entry and wrap it to MaxUint64, while decrementing the global
// again would refund a count that reclamation already removed. An unrecorded
// reservation requires no refund; that state is reachable only through a test
// injection or direct unit call.
func (ps *PeerSet) refundDeclinedReservation(suspectKey string, reservedPerKey bool) {
	ps.challengeDeclinedMu.Lock()
	defer ps.challengeDeclinedMu.Unlock()
	if !reservedPerKey {
		// Every normal reservation writes a record. An unrecorded reservation
		// can arise only under the sweep-retain test injection or a direct unit
		// call. Do not decrement the global: if it is already zero, unsigned
		// subtraction would wrap to MaxUint64.
		return
	}
	if res, ok := ps.challengeDeclinedByKey[suspectKey]; ok && res.count > 0 {
		res.count--
		ps.challengeDeclinedByKey[suspectKey] = res
		ps.challengeDeclinedGlobal--
	}
	// A missing or zero-count record has already been reclaimed together with
	// its contribution to the global. Touching either value would underflow it.
}

// PeerSet maintains mutually authenticated peer connections, feeds inbound
// frames to a Receiver, and publishes outbound envelopes. It is safe for
// concurrent use.
type PeerSet struct {
	dialer dialer
	recv   frameSink
	owner  *NodeIdentity
	engine *eng.DeltaCRDTEngine

	// digester is the Gossiper's digest-exchange sink (ADR-0034). SetDigestSink
	// binds it after NewGossiper so DispatchFrame can route WireDigestMagic
	// frames to the sweep's per-peer receive channel. A nil sink drops digest
	// frames when stratified anti-entropy is disabled. Binding happens once,
	// before readLoop starts, so the plain field needs no atomic access.
	digester DigestSink

	// challengeDir resolves the identity claimed in a challenge response, using
	// the same out-of-band Directory as origin verification. Directory
	// membership alone never authorizes routing or data delivery; only the
	// possession proof sets remoteVerified. A nil Directory leaves every
	// connection unverified and all egress gates closed. NewGossiper binds the
	// Directory once before any connection reader starts.
	challengeDir *identity.Directory

	// digestSeamDrops counts digest frames rejected because their own dial or
	// accept connection was not verified. DeliverDigest separately counts
	// unverified and identity-mismatched deliveries. Checking the receiving
	// connection prevents a frame on a superseded connection from borrowing the
	// verified state of the current ps.peers entry.
	digestSeamDrops atomic.Uint64
	// These counters measure dispatch time in the dial readLoop and accept
	// serve loop, exposing head-of-line delay. setL0IExchDebug enables them at
	// construction. Each sweep reports deltas of the cumulative values and
	// reads and resets the maxima; a frame spanning two reporting windows is
	// attributed to the window in which it finishes.
	l0iExchDebug      atomic.Bool
	l0iReadBusyNs     atomic.Int64
	l0iReadBusyMaxNs  atomic.Int64
	l0iServeBusyNs    atomic.Int64
	l0iServeBusyMaxNs atomic.Int64

	// Keep handshake outcomes separate so tests and diagnostics can distinguish
	// replays, mismatches, missing keys, bad signatures, and successful proofs.
	// challengeVerified is incremented by the only path that sets
	// remoteVerified. These atomics are local diagnostics, not registry counters.
	challengeReplay   atomic.Uint64
	challengeMismatch atomic.Uint64
	challengeNoEntry  atomic.Uint64
	challengeSigFail  atomic.Uint64
	challengeVerified atomic.Uint64

	// disableDigestSeamBugInject disables the per-connection digest check for
	// a negative control. The default false keeps the check active. The control
	// also disables the Gossiper's digest-channel gate; otherwise this seam
	// would still block the frame. digestSeamDrops confirms which check fired.
	disableDigestSeamBugInject atomic.Bool

	mu     sync.RWMutex
	peers  map[[16]byte]*peerConn
	byAddr map[string]*peerConn

	// A write to a half-open peer can block until the kernel's retransmission
	// timeout, measured at about 924.6 seconds with the default tcp_retries2.
	// Because AntiEntropySweep writes serially, one such peer would delay every
	// healthy peer. writeTimeout bounds each frame write when nonzero.
	//
	// A TLS write timeout permanently corrupts Go's TLS write state, so recovery
	// requires closing and re-dialing rather than retrying on the connection.
	// The edge-keyed suspect breaker then avoids paying another full timeout on
	// every redial. Outbound keys use configured addresses and inbound keys use
	// certificate node IDs, allowing state to survive replacement peerConns.
	// Keep the hand-arranged field layout; autoReconcile remains last.
	writeTimeout         time.Duration // zero disables write deadlines
	suspectBackoff       time.Duration // zero disables suspect skips
	suspects             map[string]*suspectEntry
	writeTimeoutReporter func() // nil disables timeout reporting

	// Test-only switches disable individual write-liveness protections. Their
	// zero values keep deadlines, close-on-error, and the suspect breaker
	// active; negative controls set them to make the corresponding tests fail.
	disableWriteDeadline  atomic.Bool
	disableCloseOnError   atomic.Bool
	disableSuspectBreaker atomic.Bool

	// disableSuspectEviction skips time-based suspect eviction in a negative
	// control for the bounded-map behavior.
	disableSuspectEviction atomic.Bool

	// disableChallengeVerifyBugInject accepts any signature after the Directory
	// and identity checks. It lets a negative control demonstrate that the
	// possession proof is necessary; production leaves it false.
	disableChallengeVerifyBugInject atomic.Bool

	// autoReconcile enables TLS-leaf identity reconciliation (ADR-0040). It is
	// off by default. When enabled and Dial receives a zero peer ID, Dial decodes
	// the 32-character hexadecimal CommonName into the real node ID and re-keys
	// peerConn. The topology selector and Publish can then find the peer.
	//
	// The following cold fields are written at connection-setup rate by serve
	// goroutines. Cache-line padding separates them from ps.mu, which Publish
	// read-locks per frame, and from the challenge counters. Keep the manual
	// field layout rather than applying fieldalignment -fix.
	_padFloodHead eng.CacheLinePad
	// challengeAnswerBudgetDrops combines connected and declined answer-budget
	// rejections. Tests drive one path at a time to attribute each increment.
	challengeAnswerBudgetDrops atomic.Uint64
	// Declined-connection state is cold and protected by its own mutex, not
	// ps.mu on the per-frame data path. The map is allocated on first use.
	// Signing failures refund their reservations.
	challengeDeclinedMu sync.Mutex
	// Each record carries its last reservation time. challengeDeclinedGlobal
	// is the sum of unexpired record counts; the sweep at the ceiling recomputes
	// that sum after removing expired records.
	challengeDeclinedByKey map[string]declinedRes
	// challengeDeclinedLiveEdge records a decline made because this node already
	// holds a live edge to the peer. A fresh mark skips the per-key reservation
	// because mutual dialing caused the decline, but the global reservation
	// still counts so CA-leaf holders cannot bypass the aggregate bound. Marks
	// expire through lazy reclamation.
	challengeDeclinedLiveEdge map[string]int64
	// challengeDeclinedLastSweepNano rate-limits sweeps at the global ceiling.
	challengeDeclinedLastSweepNano int64
	challengeDeclinedGlobal        uint64
	// Test-only controls disable both answer-budget checks, disable live-edge
	// and TTL policy, or omit live-edge records. Their zero values preserve the
	// production checks; negative controls use them to restore the guarded
	// failure modes.
	disableChallengeAnswerBudgetBugInject atomic.Bool
	disableDeclinedPolicyBugInject        atomic.Bool
	disableLiveEdgeRecordBugInject        atomic.Bool
	signFailBugInject                     atomic.Bool // forces SignCRDTFrame to fail in tests
	// These controls skip Dial's live peer-ID check or ArmDeclinedInbound's
	// challenge arming to test connection overwrite and declined verification.
	disableDialPeerIDCheckBugInject atomic.Bool
	disableDeclinedVerifyBugInject  atomic.Bool
	// challengeNoiseLogSeq limits noise logs to the first 8 and every 1000th;
	// per-class counters continue to count every event.
	challengeNoiseLogSeq atomic.Uint64
	_padFloodTail        eng.CacheLinePad

	// Reconciliation changes only the routing key used by Publish. It does not
	// register verification keys: without an out-of-band Directory entry, a
	// self-announced peer can be routed but its deltas still fail verification
	// (ADR-0040 §6). SetAutoReconcile writes this field once before the dial and
	// reconnect goroutines start, so reads need no atomic operation. The bool is
	// last to fit within the struct's tail padding, as with topology selfRegion.
	autoReconcile bool
}

// NewPeerSet constructs a PeerSet using d for TLS connections, recv for inbound
// frames, owner for signing, and engine as the gossiper's digest and delta
// source.
func NewPeerSet(d dialer, recv frameSink, owner *NodeIdentity, engine *eng.DeltaCRDTEngine) *PeerSet {
	return &PeerSet{
		dialer: d,
		recv:   recv,
		owner:  owner,
		engine: engine,
		peers:  make(map[[16]byte]*peerConn),
		byAddr: make(map[string]*peerConn),
		// Dial and RegisterInbound create suspect entries keyed by configured
		// address or certificate node ID. Later map mutations remove entries
		// whose skipUntil has expired, including zero-valued cleared entries.
		// Size is bounded by distinct peer identities rather than connection
		// count. An unset skipUntil imposes no work on healthy writes.
		suspects: make(map[string]*suspectEntry),
	}
}

// SetDigestSink binds the Gossiper's digest sink after NewGossiper and before
// any readLoop starts (ADR-0034). DispatchFrame then routes WireDigestMagic
// frames to the sweep's per-peer receive channel. A nil sink drops digest
// frames, which is the default while stratified anti-entropy is disabled. The
// construction-time write is ordered before reader goroutines start.
func (ps *PeerSet) SetDigestSink(d DigestSink) { ps.digester = d }

// SetAutoReconcile configures TLS-leaf identity reconciliation from
// --peer-auto-reconcile before dialing starts (ADR-0040). It is disabled by
// default. Reconciliation changes routing only; delta verification still
// requires an out-of-band Directory key, as documented on autoReconcile.
func (ps *PeerSet) SetAutoReconcile(on bool) { ps.autoReconcile = on }

// SetWriteTimeout sets a fresh deadline for each Publish write. Zero leaves
// writes without a deadline and disables the associated close and suspect-skip
// behavior. A positive duration prevents one half-open peer from blocking the
// serial sweep until the kernel retransmission timeout. TLS write timeouts make
// the connection unusable, so it is closed and the peer enters suspect backoff.
// Production passes --mesh-write-timeout, whose default is 10 seconds. Call
// this before the first Publish.
func (ps *PeerSet) SetWriteTimeout(d time.Duration) { ps.writeTimeout = d }

// SetSuspectBackoff sets how long a failed edge is skipped before another write
// probes it. Zero disables skipping. Production uses DefaultSuspectBackoff,
// derived from the reconnect backoff ceiling. Call this before publishing.
func (ps *PeerSet) SetSuspectBackoff(d time.Duration) { ps.suspectBackoff = d }

// SetWriteTimeoutReporter registers a callback for a write timeout that closes
// a connection and marks its edge suspect. The callback avoids a direct
// internal/telemetry dependency; production binds it to
// telemetry.MeshWriteTimeouts.Inc at startup. Nil disables reporting.
func (ps *PeerSet) SetWriteTimeoutReporter(fn func()) { ps.writeTimeoutReporter = fn }

// Dial opens an mTLS connection to addr and starts a reader into the frame
// sink. peerID is the remote's CRDT signing node ID. Dial is idempotent while
// that peer's existing connection remains live.
func (ps *PeerSet) Dial(ctx context.Context, addr, serverName string, peerID [16]byte) error {
	// A non-nil *tls.Conn does not imply a live peer: its readLoop may already
	// have exited. Use pc.done for the liveness decision (ADR-0040). An open done
	// channel makes Dial idempotent; a closed one permits re-dial and replacement
	// of the stale map entries. Look up by configured address rather than peerID
	// so reconciliation from a zero ID to a certificate node ID cannot hide the
	// existing edge from ReconnectLoop.
	ps.mu.Lock()
	// tls.Conn.Close sends close-notify with a blocking write. Capture a stale
	// connection under ps.mu but close it after unlocking so one slow peer
	// cannot stall concurrent Publish and Peers calls.
	var staleConn *tls.Conn
	if existing, ok := ps.byAddr[addr]; ok && existing.conn != nil {
		select {
		case <-existing.done:
			// The readLoop exited. Close the stale connection after unlocking;
			// re-dial will replace its map entries. Close is idempotent if
			// another path wins the race.
			staleConn = existing.conn
		default:
			// The readLoop is still active, so another Dial racing startup or
			// ReconnectLoop must not open a duplicate connection.
			ps.mu.Unlock()
			return nil // already live
		}
	}
	// An inbound edge may be keyed by its ephemeral source address and therefore
	// invisible in byAddr under the configured listen address. Check peerID too.
	// A live match suppresses a duplicate dial and preserves the existing entry.
	if peerID != ([16]byte{}) && !ps.disableDialPeerIDCheckBugInject.Load() {
		if p, ok := ps.peers[peerID]; ok && p != nil {
			select {
			case <-p.done:
			default:
				ps.mu.Unlock()
				if staleConn != nil {
					_ = staleConn.Close()
				}
				return nil // already live via ps.peers[peerID]
			}
		}
	}
	ps.mu.Unlock()
	if staleConn != nil {
		_ = staleConn.Close() // outside ps.mu; close-notify may block
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
		suspectKey:   addr, // outbound breaker state follows the configured address
		cancelReader: cancel,
		done:         make(chan struct{}),
	}
	// With autoReconcile enabled and no provisioned peer ID, decode the TLS
	// leaf CommonName and route under the certificate's node ID (ADR-0040).
	// A caller-supplied real ID needs no reconciliation. Reconciliation changes
	// routing only: convergence still requires the peer's out-of-band public
	// key in the receiver Directory, normally provisioned by --peer-dir.
	effectivePeerID := peerID
	if ps.autoReconcile && peerID == ([16]byte{}) {
		if real, ok := ps.reconcilePeerID(pc, conn); ok {
			effectivePeerID = real
		}
		// A missing or malformed leaf CN leaves effectivePeerID zero, as when
		// reconciliation is disabled. reconcilePeerID logs the decode failure.
	}
	// Arm before publishing pc in the maps. The nonce and armed fields are
	// still private to this goroutine, and the later map-install lock orders
	// those writes before any test reads the installed entry under RLock.
	armed := false
	if ps.owner != nil {
		armed = ps.armChallenge(pc)
	}
	ps.mu.Lock()
	ps.peers[effectivePeerID] = pc
	ps.byAddr[addr] = pc
	pc.peerID = effectivePeerID
	// Reuse the map-install lock to evict expired suspect entries before adding
	// this edge's entry. The outbound key is the configured address, so the
	// entry and its breaker state survive replacement peerConns.
	ps.evictExpiredSuspectsLocked(time.Now().UnixNano())
	if ps.suspects != nil {
		if _, ok := ps.suspects[pc.suspectKey]; !ok {
			ps.suspects[pc.suspectKey] = &suspectEntry{}
		}
	}
	ps.mu.Unlock()
	// Send the challenge after installation and before starting readLoop. A
	// send failure leaves the connection routed but unverified, with data
	// egress closed. Without an owner identity no challenge is sent, so the
	// connection likewise remains unverified.
	if armed {
		_ = ps.sendChallengeFrame(pc)
	}
	go ps.readLoop(readerCtx, pc)
	log.Printf("mesh: dialed peer %x at %s", effectivePeerID, addr)
	return nil
}

// reconcilePeerID decodes a node ID from the peer's TLS leaf CommonName
// (ADR-0040). certgen.IssueLeaf stores the 16-byte ID as 32 hexadecimal
// characters, so the CN must be hex-decoded rather than copied as raw bytes.
// It returns (realNodeID, true) after a valid decode and (zero, false) when no
// certificate is present, the CN is empty, or it is not a 16-byte hexadecimal
// ID. Failure leaves the peer keyed under zero. An unrecognized leaf therefore
// falls back to RegionUnset and full-mesh routing rather than causing a crash.
//
// Reconciliation changes only ps.peers routing. It does not call Register or
// RegisterPQ: without a separately provisioned Directory key, Publish can route
// to the peer but the receiver rejects its deltas as unverified (ADR-0040 §6).
// The map update takes ps.mu, so Publish sees either the old or new key. Dial
// has already completed the TLS handshake, making PeerCertificates available
// without blocking.
func (ps *PeerSet) reconcilePeerID(pc *peerConn, conn *tls.Conn) ([16]byte, bool) {
	real, ok := nodeIDFromConn(conn)
	if !ok {
		log.Printf("mesh: reconcile %s: peer leaf did not self-announce a nodeID — staying keyed under zero peerID (the byte-identical region-fanout behavior)", pc.addr)
		return [16]byte{}, false
	}
	log.Printf("mesh: reconcile %s: peer leaf CN -> real nodeID %x (re-keying PeerSet for routing only)", pc.addr, real)
	return real, true
}

// nodeIDFromConn extracts a 16-byte node ID from the TLS leaf CommonName,
// which certgen encodes as hexadecimal. Dial reconciliation and
// RegisterInbound share this decoder (ADR-0045). The connection must have
// completed its handshake. It returns (id, true) for a valid 32-character CN
// and (zero, false) for a missing leaf, empty CN, invalid hexadecimal, or an
// incorrect decoded length.
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

// RegisterInbound installs a peerConn for an accepted TLS connection, keyed by
// the node ID decoded from its leaf CN (ADR-0045). Publish can then write back
// over the connection the peer dialed, and Peers and topology.Select include
// the inbound peer. Without this registration, only the dialing side could
// publish over its connection.
//
// serveConnWithDigest or serveTestConn retains ownership of the inbound read
// loop. RegisterInbound deliberately starts no second reader, which would split
// frames unpredictably between two goroutines. The full-duplex TCP connection
// carries reads in the accept loop and writes through Publish.
//
// PeerConnHandle identifies one registration to the accept loop in package main
// without exposing peerConn. ReleaseInboundConn compares the handle's identity
// with the currently registered connection before closing it. A nil handle
// means registration failed or was declined and makes release a no-op.
type PeerConnHandle struct{ pc *peerConn }

// If an edge for this node ID or address is already live, RegisterInbound
// declines the new registration rather than replacing it. The accept loop still
// serves the unregistered connection, so inbound frames continue through
// DispatchFrame, but no done channel closes and ReconnectLoop is not woken.
//
// Replacing live edges creates a mutual-dial feedback loop: A's accepted
// connection replaces its outbound edge to B, the old reader exits,
// ReconnectLoop dials B again, and B repeats the same replacement. At 34 nodes
// per host this reached about 700 dials per second per node for four minutes;
// one node recorded 127,163 dials to 99 peers while the remote regions received
// no frames.
//
// The invariant is to preserve live edges, not to force exactly one connection
// per pair. Mutual dials can leave two connections, with each node publishing
// on its outbound edge. A staggered connection with no existing edge is still
// registered. Avoiding a node-ID tie-break also avoids another close protocol
// around done, whose close race previously caused a double-close panic
// (ADR-0046).
//
// A restarted peer's new inbound connection can be declined while the old
// outbound connection still appears live. Recovery waits for the old readLoop
// to observe RST or EOF; keepalives or read deadlines can shorten that window
// if measurements show it dominates recovery.
//
// For a dead edge, capture the old peerConn under ps.mu, install the new one,
// then cancel the old reader and close its connection after unlocking. Close
// can block on close-notify and must not stall Publish or Peers. The accept
// loop remains responsible for closing the inbound connection itself.
//
// RegisterInbound returns the real node ID and an installed handle. A decode
// failure or live-edge decline returns zero and nil. The zero ID makes a
// deferred ReleaseInboundConn a no-op, preventing a declined goroutine from
// closing the live edge it does not own. Callers must release the returned
// handle rather than just the node ID. The method is safe concurrently with
// Dial, Publish, and Peers.
func (ps *PeerSet) RegisterInbound(conn *tls.Conn) ([16]byte, *PeerConnHandle) {
	real, ok := nodeIDFromConn(conn)
	if !ok {
		// Without a valid engine-shaped leaf CN there is no stable node ID to
		// register. Leave the connection unregistered, as Dial reconciliation
		// does for an unrecognized leaf.
		return [16]byte{}, nil
	}
	addr := conn.RemoteAddr().String()
	pc := &peerConn{
		addr:       addr,
		conn:       conn,
		peerID:     real,
		suspectKey: suspectKeyForNodeID(real), // inbound breaker key from the certificate
		done:       make(chan struct{}),
	}
	// Arm while pc is still private to this accept goroutine. The map-install
	// lock publishes those writes before any RLock reader can inspect them.
	// Decode failures return before any handshake state is created.
	armed := false
	if ps.owner != nil {
		armed = ps.armChallenge(pc)
	}

	// A live edge is preserved and the new registration is declined. A dead
	// edge is captured for close and reader cancellation after unlocking.
	var stalePC *peerConn
	ps.mu.Lock()
	existing, ok := ps.peers[real]
	if !ok || existing == nil {
		existing, ok = ps.byAddr[addr]
	}
	if ok && existing != nil {
		select {
		case <-existing.done:
			// The old reader exited or a prior release marked it dead. Capture
			// the edge so its connection can be closed after unlocking.
			stalePC = existing
		default:
			// A working edge already exists, either outbound or accepted by
			// another goroutine. Decline without evicting it or waking its
			// ReconnectLoop. Return a zero node ID as well as a nil handle:
			// accept loops defer ReleaseInboundConn unconditionally, and the
			// zero check must stop this declined connection from releasing the
			// live edge it never owned. It continues serving inbound frames.
			ps.mu.Unlock()
			// Record that this decline came from our own live edge. The peer's
			// mutual-dial verification should not consume its per-key answer
			// reservation. Take the leaf lock only after releasing ps.mu.
			ps.challengeDeclinedMu.Lock()
			if ps.challengeDeclinedLiveEdge == nil {
				ps.challengeDeclinedLiveEdge = make(map[string]int64) // lazy, cold
			}
			ps.challengeDeclinedLiveEdge[pc.suspectKey] = time.Now().UnixNano()
			ps.challengeDeclinedMu.Unlock()
			return [16]byte{}, nil
		}
	}
	ps.peers[real] = pc
	ps.byAddr[addr] = pc
	// Key the inbound breaker by certificate node ID, not pc.addr: the source
	// port changes on every dial, while sweeps publish by ps.peers node ID.
	// Reusing this stable key preserves backoff across replacement connections.
	// Evict expired entries before inserting; an entry with a future skipUntil
	// survives, so redialing during backoff does not clear the skip.
	ps.evictExpiredSuspectsLocked(time.Now().UnixNano())
	if ps.suspects != nil {
		if _, ok := ps.suspects[pc.suspectKey]; !ok {
			ps.suspects[pc.suspectKey] = &suspectEntry{}
		}
	}
	ps.mu.Unlock()

	if stalePC != nil {
		// Cancel the old outbound reader and close its connection outside ps.mu.
		// Its deferred closeDone marks any stale zero-ID entry dead so a later
		// ReconnectLoop can replace it. Repeated close is harmless.
		if stalePC.cancelReader != nil {
			stalePC.cancelReader()
		}
		if stalePC.conn != nil && stalePC.conn != conn {
			_ = stalePC.conn.Close()
		}
	}
	// Both ends prove key possession. Send this side's challenge after
	// installation, on the accept goroutine that will read the response after
	// RegisterInbound returns to the serve loop.
	if armed {
		_ = ps.sendChallengeFrame(pc)
	}
	log.Printf("mesh: registered inbound peer %x at %s (inbound edge is publishable)", real, addr)
	return real, &PeerConnHandle{pc: pc}
}

// ReleaseInbound marks an inbound peerConn dead so Dial or ReconnectLoop can
// replace it. The accept loop calls it on EOF, a read error, or cancellation.
// Closing the TLS connection remains the accept loop's responsibility. Unknown
// and already released IDs are harmless.
func (ps *PeerSet) ReleaseInbound(nodeID [16]byte) {
	ps.ReleaseInboundConn(nodeID, nil)
}

// ReleaseInboundConn releases nodeID only when mine is the currently registered
// peerConn. Without this identity check, an old accept goroutine could release
// a newer connection after its own registration had been superseded. A declined
// registration could likewise close the live edge that caused the decline.
// A nil mine retains the identity-blind behavior for external callers of
// ReleaseInbound; accept loops in this repository pass their returned handle.
//
// The pointer comparison under ps.mu is atomic with concurrent registration and
// dialing. closeDone uses sync.Once (ADR-0046), so a duplicate release cannot
// panic by closing done twice.
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
	// A non-nil handle must match the current registration. Accept loops always
	// pass their handle; nil retains ReleaseInbound's compatibility behavior for
	// external callers.
	if mine != nil && pc != mine.pc {
		return // the registration was superseded or declined
	}
	select {
	case <-pc.done:
		// A duplicate release or stale-close path already closed it.
	default:
		pc.closeDone()
	}
	// Inbound edges have no readLoop defer to remove their map entries, so the
	// accept-loop release performs that cleanup here.
	ps.removeDeadEntry(pc)
}

// closeDone closes pc.done once across the racing readLoop exit and
// ReleaseInbound paths. The sync.Once prevents the double-close panic that a
// check followed by close cannot avoid (ADR-0046).
func (pc *peerConn) closeDone() {
	pc.closeDoneOnce.Do(func() { close(pc.done) })
}

// removeDeadEntry deletes pc's byAddr and peers entries only when they still
// point to that exact peerConn (ADR-0045). Inbound source ports change on every
// connection, so without removal byAddr would retain dead TLS connections and
// their record buffers indefinitely.
//
// The identity check preserves a newer connection installed by Dial or
// RegisterInbound. Lookup paths must still tolerate dead entries: racing this
// deletion, they can see either the old entry or no entry, and both cases must
// lead to a valid redial decision.
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

// readLoop reads length-prefixed frames from pc and dispatches them to the
// receive or digest sink. It exits on cancellation, EOF, or a read error;
// ReconnectLoop can then re-dial with bounded backoff.
//
// ReadFrame strips the four-byte length prefix. DispatchFrame examines the body
// prefix without copying it: WireV1Magic selects HandleBatchFrame,
// WireHybridPQMagic selects HandleHybridFrame, WireDigestMagic selects the
// digest sink, and a little-endian RelayEnvelope version selects HandleFrame.
// The distinct prefixes prevent a batch or hybrid frame from being rejected as
// a malformed RelayEnvelope.
func (ps *PeerSet) readLoop(ctx context.Context, pc *peerConn) {
	// Close the TLS connection on every exit, including cancellation during
	// shutdown, so its socket and file descriptor are not retained. Close is
	// idempotent after a reset or another close path.
	//
	// Defers run in reverse order: closeDone, removeDeadEntry, then conn.Close.
	// A concurrent Dial therefore observes done closed before the connection
	// closes and continues to use done as the liveness signal. Map removal is
	// identity-checked so a replacement edge at the same address survives.
	defer pc.conn.Close()
	defer ps.removeDeadEntry(pc)
	defer pc.closeDone() // sync.Once shared with ReleaseInbound (ADR-0046)
	fr := receive.NewFrameReader(pc.conn)
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
		// Count frames arriving on this dialed connection, including handshake
		// frames, and log only every hundredth. Frames on the accept loop are
		// accounted separately. DispatchFrame verdicts are discarded here; the
		// accept loop owns verdict logging.
		rcvd := atomic.AddUint64(&pc.framesReceived, 1)
		if rcvd%100 == 0 {
			log.Printf("mesh: peer %x dial-side received %d frame(s)", pc.peerID, rcvd)
		}
		// DispatchFrame has no challenge arm, so route challenge frames before
		// data-plane parsing. The prefix check is allocation-free. Accepted
		// connections handle challenges in their serve loops instead.
		if IsChallengeFrame(frame) {
			ps.handleConnChallengeFrame(pc, frame)
			continue
		}
		// Reject a digest received on an unverified connection before identity
		// processing. DeliverDigest separately checks identity binding. Using
		// the frame's own connection prevents a superseded connection from
		// borrowing the current map entry's verified bit. The check adds one
		// atomic load and branch to digest frames only.
		if frameIsDigest(frame) && !pc.remoteVerified.Load() && !ps.disableDigestSeamBugInject.Load() {
			ps.digestSeamDrops.Add(1)
			continue
		}
		// DispatchFrame routes batch, hybrid, digest, and relay frames by magic.
		// A nil digest sink drops digests while stratified anti-entropy is off
		// (ADR-0034). When exchange diagnostics are disabled, the else branch
		// makes the same dispatch call without timing it.
		if ps.l0iExchDebug.Load() {
			l0iT0 := time.Now()
			_ = DispatchFrame(frame, pc.peerID, ps.recv, ps.digester)
			ps.NoteDispatchBusy(L0ILoopRead, time.Since(l0iT0).Nanoseconds())
		} else {
			_ = DispatchFrame(frame, pc.peerID, ps.recv, ps.digester)
		}
	}
}

// DefaultSuspectBackoff matches the production ReconnectLoop backoff ceiling.
// A write probe cannot succeed before re-dial completes, so a shorter suspect
// window would mostly probe dead connections. Ten seconds limits a chronically
// failing peer to about one write-timeout per reconnect cycle while allowing a
// recovered peer to be probed after the next dial. The window always expires;
// it is not a permanent partition.
const DefaultSuspectBackoff = 10 * time.Second

// errPeerSuspected lets Publish fail immediately while an edge is in suspect
// backoff. The sweep skips that peer for the current round, and errors.Is lets
// diagnostics distinguish a temporary skip from other write failures.
var errPeerSuspected = errors.New("mesh: peer is in write-stall suspect backoff")

// suspectKeyForNodeID namespaces a certificate-derived node ID with a NUL
// prefix. Printable host:port addresses cannot contain NUL, so inbound and
// outbound breaker keys cannot collide. The string is allocated once during
// edge installation.
func suspectKeyForNodeID(id [16]byte) string {
	b := make([]byte, 17)
	b[0] = 0
	copy(b[1:], id[:])
	return string(b)
}

// evictExpiredSuspectsLocked deletes entries whose skipUntil is at or before
// now, including zero-valued cleared entries. markSuspect, Dial, and
// RegisterInbound call it under ps.mu, avoiding another lock or goroutine.
// removeDeadEntry and ClosePeer deliberately do not call it: connection loss
// must not erase the backoff that suppresses immediate retries.
//
// Expiry is lazy. During complete quiescence an expired entry remains until
// the next mutation, so the bound is on distinct identities and at most one
// unswept generation, not on how long an expired entry can remain in memory.
func (ps *PeerSet) evictExpiredSuspectsLocked(now int64) {
	if ps.suspects == nil {
		return
	}
	if ps.disableSuspectEviction.Load() {
		return // test-only eviction control
	}
	for k, se := range ps.suspects {
		if se == nil || se.skipUntil.Load() <= now {
			delete(ps.suspects, k)
		}
	}
}

// suspectEntry holds write-stall backoff for one configured address or
// certificate node ID. Dial and RegisterInbound create entries that survive
// replacement peerConns. markSuspect sets skipUntil after any write error,
// Publish reads it for its fast-fail check, and a successful write clears it.
// Atomic access avoids a new hot-path mutex. Lazy expiry bounds the map by
// distinct peer identities rather than connection count.
type suspectEntry struct {
	skipUntil atomic.Int64
}

// markSuspect records a write failure under the edge's stable configured
// address or certificate node ID. It runs only on Publish's cold error path.
// The upsert also supports a zero-value PeerSet used directly by a test.
//
// Expired entries are swept before the upsert. A positive backoff leaves the
// new skipUntil in the future so the entry survives its own sweep. Zero
// backoff stores the current time, and the next mutation removes the entry.
func (ps *PeerSet) markSuspect(key string) {
	now := time.Now()
	ps.mu.Lock()
	ps.evictExpiredSuspectsLocked(now.UnixNano())
	se, ok := ps.suspects[key]
	if !ok || se == nil {
		if ps.suspects == nil {
			ps.suspects = make(map[string]*suspectEntry)
		}
		se = &suspectEntry{}
		ps.suspects[key] = se
	}
	// Store skipUntil while still holding ps.mu. If a new zero-valued entry
	// were published first, a concurrent eviction could delete it before this
	// store, losing the mark and leaving the store on an orphaned entry.
	se.skipUntil.Store(now.Add(ps.suspectBackoff).UnixNano())
	ps.mu.Unlock()
}

// Publish writes a frame already prefixed by receive.LengthPrefixFrame to the
// live peer identified by peerID. It delegates to transport.TransmitTLSFrame
// through writeToPC.
func (ps *PeerSet) Publish(peerID [16]byte, prefixed []byte) error {
	// writeToPC is the sole production caller of TransmitTLSFrame. Data frames,
	// digest responses, challenges, and challenge responses therefore share the
	// same write deadline, close-on-error handling, and suspect bookkeeping.
	ps.mu.RLock()
	pc, ok := ps.peers[peerID]
	if !ok || pc == nil {
		ps.mu.RUnlock()
		return fmt.Errorf("mesh: Publish: no live peer %x", peerID)
	}
	// Read the suspect entry under the same RLock as the peer lookup. Its
	// configured-address or certificate-ID key survives redials. A live backoff
	// makes writeToPC fail before touching the connection, avoiding another
	// write-timeout delay in every sweep round.
	var se *suspectEntry
	if !ps.disableSuspectBreaker.Load() {
		se = ps.suspects[pc.suspectKey]
	}
	ps.mu.RUnlock()
	// Challenge senders also call writeToPC directly, keeping connection writes
	// on one deadline, abort, and suspect-accounting path.
	return ps.writeToPC(peerID, pc, prefixed, se)
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

// isLive reports whether peerID is registered in the PeerSet. It is used by
// peer-root and deferred-state eviction and is private to the mesh package.
// isLive takes ps.mu.RLock itself: ps.mu, not the caller's peerRootsMu,
// serializes this membership read against PeerSet mutations.
func (ps *PeerSet) isLive(peerID [16]byte) bool {
	ps.mu.RLock()
	_, ok := ps.peers[peerID]
	ps.mu.RUnlock()
	return ok
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
		// Inbound peerConns have no readLoop defer to close done after the
		// accept loop exits, so closeDone prevents the wait below from blocking.
		// For outbound connections it is harmless if the reader already closed
		// done (ADR-0045).
		pc.closeDone()
		<-pc.done
	}
	return firstErr
}

// ClosePeer closes one peer's connection and cancels its readLoop without
// affecting other peers. ConvergenceProbe uses it to create a per-peer
// partition; a later Dial restores the connection. The peers and byAddr entries
// are removed under the write lock before the connection closes, so concurrent
// Publish calls cannot write to a closed connection. Missing peers return nil.
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
	// An inbound peerConn has no readLoop or cancelReader. Its accept loop's
	// deferred release cannot close done because the map entry is already gone,
	// so closeDone prevents a permanent wait here. sync.Once handles outbound
	// readers that close done concurrently (ADR-0046).
	pc.closeDone()
	<-pc.done // the readLoop goroutine exits on ctx cancel / io.EOF
	return nil
}

// ErrNoPeers is returned by the sweep when the PeerSet has zero live peers.
var ErrNoPeers = errors.New("mesh: no live peers")

// liveReconnectEdge returns a live connection to peerID, or nil when
// ReconnectLoop should dial. It checks byAddr for the configured outbound
// address, which remains stable when reconciliation changes the peers key from
// zero to the certificate node ID. It also checks peers[peerID], the map Publish
// uses. An accepted connection is keyed by its ephemeral source address in
// byAddr and is therefore invisible under the configured listen address
// (ADR-0045). Recognizing that publishable inbound edge prevents redundant
// dials and mutual reconnection churn.
//
// A zero peerID is never looked up in peers. Every unresolved peer can share
// the zero entry, so treating it as proof of connectivity could suppress a
// different peer's reconnect. Provisioned deployments pass real node IDs.
//
// A connection is live only when its peerConn exists and done remains open;
// a non-nil TLS pointer alone is insufficient.
func (ps *PeerSet) liveReconnectEdge(addr string, peerID [16]byte) *peerConn {
	ps.mu.RLock()
	pc, ok := ps.byAddr[addr]
	if ok && pc != nil {
		select {
		case <-pc.done:
			// A dead byAddr entry can hide a live accepted connection under
			// peerID. Fall through to that lookup before deciding to re-dial.
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
		return nil // dead: the readLoop exited; the caller re-dials
	default:
		return pc // live
	}
}

// ReconnectLoop re-establishes a peer that dropped, with bounded exponential
// backoff (backoff0 initial, backoffMax ceiling). It is optional (the production
// binary wires it); the in-process gate uses persistent net.Pipe connections.
func (ps *PeerSet) ReconnectLoop(ctx context.Context, addr, serverName string, peerID [16]byte, backoff0, backoffMax time.Duration) {
	// Normalize a nonpositive initial backoff once and always reset to base.
	// Resetting to the raw argument would leave b at zero: timers would fire
	// immediately and doubling would never increase the delay, producing a tight
	// redial loop. Production supplies one second.
	base := backoff0
	if base <= 0 {
		base = time.Second
	}
	b := base
	if backoffMax <= 0 {
		backoffMax = 10 * time.Second
	}
	// Each loop gets a goroutine-local PCG source (ADR-0045). A shared source
	// would serialize thousands of colocated reconnect loops. FNV-1a over the
	// address and peer ID gives each peer a deterministic but distinct jitter
	// sequence, and XORing the golden-ratio constant differentiates the two PCG
	// state words for low-entropy seeds.
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
		// liveReconnectEdge checks the stable configured address and the real
		// peer-ID entry (ADR-0040, ADR-0045). Looking up only the caller's ID
		// would miss after reconciliation replaces a zero ID with the leaf's
		// node ID; looking up only byAddr would miss an accepted edge keyed by
		// its ephemeral source port. A live result blocks on done, while a dead
		// or absent result proceeds to Dial. The post-wait recheck below uses
		// the same predicate, so every iteration either waits or dials.
		if pc := ps.liveReconnectEdge(addr, peerID); pc != nil {
			select {
			case <-pc.done:
			case <-ctx.Done():
				return
			}
		}
		// Recheck cancellation after the done wait and before dialing. A peer drop
		// and shutdown can become ready together. The transport dialer does not
		// accept a context, so it could otherwise establish a new TLS connection
		// whose reader exits immediately, retaining the connection and descriptor
		// when the production shutdown path does not call PeerSet.Close.
		if ctx.Err() != nil {
			return
		}
		// Recheck liveness after waking. The peer may already have dialed us and
		// been registered by the accept loop, or a concurrent boot dial may have
		// won. Dialing again could make the remote replace a live edge and wake
		// another reconnect loop. Returning to the top waits on the new edge and
		// resets backoff; if no edge appeared, this recheck changes nothing
		// (ADR-0045).
		if pc := ps.liveReconnectEdge(addr, peerID); pc != nil {
			b = base
			continue
		}
		if err := ps.Dial(ctx, addr, serverName, peerID); err != nil {
			log.Printf("mesh: reconnect %x@%s: %v (backoff %v)", peerID, addr, err, b)
			// NewTimer provides a Stop handle so cancellation can release the
			// timer immediately. If Stop reports that it already fired, drain the
			// channel before returning. time.After would retain each timer and
			// channel until its delay expired.
			//
			// Apply uniform ±20% jitter to this sleep (ADR-0045). Without it, a
			// host-wide connection drop makes many loops redial in lockstep, and
			// doubling preserves that alignment at every backoff level. Jitter
			// spreads TLS and dial work across the window.
			//
			// Only the sleep is jittered; b retains its exact power-of-two ladder
			// and ceiling, preventing accumulated random drift. Int64N(2*span+1)
			// minus span gives an offset in [-span,+span], with span=b/5. The
			// span>0 guard avoids Int64N panicking for test backoffs below 5 ns.
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
		// Reset to the normalized base, not a raw nonpositive backoff0.
		b = base
		// Successful dials also need a delay. If a new connection dies
		// immediately, otherwise only the failure branch sleeps and the loop can
		// redial at handshake speed. A measured mutual-eviction case reached
		// about 700 dials per second per node without entering the failure path.
		// The live-edge guard addresses that cause; this 250 ms floor bounds any
		// similar immediate-death loop to about four dials per second while
		// remaining small relative to the one-second production backoff. Reuse
		// the loop's PCG source to jitter the floor and avoid synchronization.
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

// successFloor is the minimum interval between a successful ReconnectLoop dial
// and the next attempt for that peer. It limits an immediate-death loop to
// about four dials per second, compared with roughly 700 in the measured
// mutual-eviction case, and is shorter than the production one-second backoff.
const successFloor = 250 * time.Millisecond

// splitHostPort returns the host (SNI) portion of a host:port address.
func splitHostPort(addr string) (host string, err error) {
	host, _, err = net.SplitHostPort(addr)
	return host, err
}

// Verified-key challenges (ADR-0068) are armed and sent during Dial and
// RegisterInbound installation, before the connection's reader starts. This
// orders the nonce and armed writes before response handling. The dial readLoop
// and accept serve loop recognize IsChallengeFrame before data dispatch and
// call handleConnChallengeFrame.
//
// A node answers a challenge with its own node ID and a signature over the
// challenger's nonce, proving possession of its own key without revealing
// other state. An impostor using a victim's certificate CN either answers with
// a different ID or presents a signature for its own Directory key, so the
// connection remains unverified. The sweep, DeliverDigest, and respondToDigest
// then deny data egress while leaving the routing entry installed.

// SetChallengeDirectory binds the Directory used to verify a challenge
// response's claimed identity. NewGossiper calls it once before any connection
// reader starts. A nil Directory leaves all connections unverified, so data
// egress remains closed rather than defaulting to acceptance.
func (ps *PeerSet) SetChallengeDirectory(d *identity.Directory) { ps.challengeDir = d }

// egressVerified reports whether the current peerConn installed under peerID
// has proved possession of its registered key. The sweep, DeliverDigest, and
// respondToDigest consult this bit before data egress. Directory membership
// alone is insufficient, an absent connection is unverified, and a replacement
// connection starts false until it completes its own challenge.
func (ps *PeerSet) egressVerified(peerID [16]byte) bool {
	ps.mu.RLock()
	pc := ps.peers[peerID]
	verified := pc != nil && pc.remoteVerified.Load()
	ps.mu.RUnlock()
	return verified
}

// armChallenge generates a fresh per-connection nonce and marks the challenge
// armed before the reader goroutine starts. A crypto/rand failure returns false
// and leaves the connection unverified with data egress closed; it does not
// fail the dial itself.
func (ps *PeerSet) armChallenge(pc *peerConn) bool {
	if _, err := crand.Read(pc.challengeNonce[:]); err != nil {
		log.Printf("mesh: challenge arm %x: crypto/rand: %v — conn stays unverified", pc.peerID, err)
		return false
	}
	pc.challengeArmed = true
	return true
}

// writeToPC applies the common per-frame deadline, close-on-error handling,
// and suspect skip, mark, and clear logic. Publish calls it after resolving
// peerID and pc under RLock. Challenge and response senders call it directly,
// so 53-byte challenges and 133-byte responses follow the same write path as
// data frames.
//
// se is the suspect entry captured by Publish, or nil for challenge senders.
// A fresh connection has no active skip, but a failed challenge write still
// closes the connection and marks its suspect key. The caller resolves the
// peerID/pc pair; returned errors retain Publish's existing text.
func (ps *PeerSet) writeToPC(peerID [16]byte, pc *peerConn, prefixed []byte, se *suspectEntry) error {
	var skipUntil int64
	if se != nil {
		skipUntil = se.skipUntil.Load()
	}
	if skipUntil != 0 && time.Now().UnixNano() < skipUntil {
		return fmt.Errorf("mesh: Publish to %x at %s skipped: write-stall suspect backoff until %v: %w",
			peerID, pc.addr, time.Unix(0, skipUntil), errPeerSuspected)
	}
	// Set a fresh absolute deadline for each frame, so a slow but progressing
	// WAN peer is not charged for earlier writes. Frames are bounded by
	// MaxBatchSize deltas, roughly 20-41 KB for a digest, or roughly 65 bytes
	// for a root announcement. Read and write deadlines are independent, so the
	// readLoop is unaffected. If setting the deadline fails because the
	// connection is closing, the following write reports the same failure.
	if d := ps.writeTimeout; d > 0 && !ps.disableWriteDeadline.Load() {
		_ = pc.conn.SetWriteDeadline(time.Now().Add(d))
	}
	if _, err := transport.TransmitTLSFrame(pc.conn, prefixed); err != nil { // transport.go:142
		// Go's crypto/tls records a write timeout as a permanentError: the TLS
		// state is corrupt and every later Write returns the same error. Retrying
		// on this connection cannot recover it. Closing unblocks readLoop, whose
		// defers call closeDone, removeDeadEntry, and conn.Close. ReconnectLoop
		// then dials a fresh connection whose first write probes recovery.
		if !ps.disableCloseOnError.Load() {
			// Abort the underlying TCP connection rather than calling
			// tls.Conn.Close. The latter attempts close-notify with its own
			// five-second write deadline over the same full kernel buffers;
			// a wedged 256 KiB write measured an extra 5.2 seconds. The TLS
			// state is already unusable, so NetConn().Close avoids that wait
			// and immediately unblocks readLoop for the ordinary recovery path.
			// The receiver sees the same abrupt EOF as a peer crash, which the
			// AEAD record layer and 16 MiB-bounded FrameReader already handle.
			// The deferred TLS close then operates on an already closed fd.
			_ = pc.conn.NetConn().Close()
		}
		// Any write error arms the edge-keyed breaker, limiting a failing peer
		// to roughly one timeout per backoff window instead of one per redial.
		if !ps.disableSuspectBreaker.Load() {
			ps.markSuspect(pc.suspectKey)
		}
		// Report actual timeouts through the injected callback without adding
		// an internal/telemetry dependency. Ordinary connection drops do not
		// increment this metric.
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() && ps.writeTimeoutReporter != nil {
			ps.writeTimeoutReporter()
		}
		return fmt.Errorf("mesh: Publish to %x: %w", peerID, err)
	}
	// A successful write CLEARS the suspect state: the peer answered a probe
	// on a (fresh) conn — it is healthy again and must not be skipped.
	if se != nil && se.skipUntil.Load() != 0 {
		se.skipUntil.Store(0)
	}
	return nil
}

// sendChallengeFrame writes a length-prefixed 53-byte challenge through
// writeToPC, inheriting its deadline, TCP abort, and suspect marking. Dial and
// RegisterInbound call it after armChallenge and before their readers start.
// A send failure leaves the connection installed but unverified, with data
// egress closed; it is logged rather than failing the connection installation.
func (ps *PeerSet) sendChallengeFrame(pc *peerConn) error {
	frame := buildChallengeFrame(ps.owner.NodeID, pc.challengeNonce)
	return ps.writeToPC(pc.peerID, pc, receive.LengthPrefixFrame(frame), nil)
}

// handleConnChallengeFrame processes handshake frames on the dial readLoop or
// accept serve loop.
//
// For a CHALLENGE, this node signs (domain || peer nonce || own ID || peer ID)
// with its own key. The answer proves possession of that key over a fresh nonce
// and reveals no other state; data egress still requires separate verification.
//
// For a RESPONSE, verification rejects cheap failures before signature work:
//   - no challenge is outstanding on this connection;
//   - challengerID is not this node's ID;
//   - responderID differs from the connection's claimed pc.peerID;
//   - the nonce differs from this connection's fresh nonce, including a replay
//     captured on an earlier connection;
//   - challengeDir is nil or has no key for responderID.
//
// Only identity.VerifyCRDTFrame then sets pc.remoteVerified. The Directory
// supplies the expected public key but does not itself verify the connection.
// Failures are logged and dropped while the routing entry remains installed
// with data egress denied.
// challengeNoiseLog limits malformed-frame, replay, mismatch, missing-entry,
// and unknown-role messages to the first 8 and every 1000th per PeerSet.
// Per-class counters remain exact. This prevents a stream of small invalid
// frames from filling the log while answer budgets bound signing work.
func (ps *PeerSet) challengeNoiseLog() bool {
	n := ps.challengeNoiseLogSeq.Add(1)
	return n <= 8 || n%1000 == 0
}

func (ps *PeerSet) handleConnChallengeFrame(pc *peerConn, frame []byte) {
	switch challengeFrameRole(frame) {
	case challengeRoleChallenge:
		challengerID, nonce, ok := parseChallengeFrame(frame)
		if !ok || ps.owner == nil {
			if ps.challengeNoiseLog() {
				log.Printf("mesh: challenge from %x: malformed frame or no owner identity — not answered (conn stays unverified)", pc.peerID)
			}
			return
		}
		// Bound the signatures an unverified challenger can request on this
		// connection. Each 53-byte challenge otherwise buys about 60 us of
		// Ed25519 signing. A normal handshake needs one answer; a redial gets a
		// fresh budget, while suspect-key backoff bounds reconnection churn.
		// Remember whether this frame reserved a slot. A later test-injection
		// change must not cause a refund without a reservation and underflow
		// the counter.
		reserved := false
		if !ps.disableChallengeAnswerBudgetBugInject.Load() {
			if n := pc.challengeAnswers.Add(1); n > challengeAnswerPerConnBudget {
				// Count every rejected answer but log only the first and every
				// 1000th rejection to avoid a log flood.
				if d := ps.challengeAnswerBudgetDrops.Add(1); d == 1 || d%1000 == 0 {
					log.Printf("mesh: challenge from %x dropped: per-conn answer budget exhausted (%d answered, cap %d; drop #%d) — the pre-verify answer flood is bounded", pc.peerID, n-1, challengeAnswerPerConnBudget, d)
				}
				return
			}
			reserved = true
		}
		msg := buildChallengeMsg(nonce, ps.owner.NodeID, challengerID)
		sig, err := identity.SignCRDTFrame(ps.owner.Seed, msg)
		if ps.signFailBugInject.Load() {
			err = errors.New("test-only sign failure injection")
		}
		if err != nil {
			// Only a successful signature consumes a budget slot. Refund this
			// frame's reservation on the same sequential reader, so a seed
			// configuration error can be corrected without exhausting the
			// connection and a flood of failed signatures cannot burn its budget.
			// The local reservation flag, not a fresh injection check, controls
			// the refund.
			if reserved {
				// ^uint64(0) == -1 mod 2^64: the unsigned wrap-around
				// decrement. Safe by construction — the refund pairs with
				// THIS frame's own Add(1) above, so the counter returns to
				// its pre-frame value, never below.
				pc.challengeAnswers.Add(^uint64(0))
			}
			log.Printf("mesh: challenge from %x: sign: %v — not answered (conn stays unverified; the budget slot is refunded)", pc.peerID, err)
			return
		}
		resp := buildChallengeResponseFrame(ps.owner.NodeID, challengerID, nonce, sig)
		if err := ps.writeToPC(pc.peerID, pc, receive.LengthPrefixFrame(resp), nil); err != nil {
			log.Printf("mesh: challenge response to %x: %v", pc.peerID, err)
		}
	case challengeRoleResponse:
		responderID, challengerID, nonce, sig, ok := parseChallengeResponseFrame(frame)
		if !ok {
			return // short frame — wire noise; never a verify event
		}
		// Count each rejection class separately. Check the nonce first so a
		// replayed response on a fresh armed connection is always classified as
		// a replay rather than another identity or arming mismatch.
		if nonce != pc.challengeNonce {
			ps.challengeReplay.Add(1)
			if ps.challengeNoiseLog() {
				log.Printf("mesh: challenge response from %x dropped: nonce echo mismatch; captured responses cannot verify a new connection", responderID)
			}
			return
		}
		if !pc.challengeArmed || ps.owner == nil || challengerID != ps.owner.NodeID || responderID != pc.peerID {
			ps.challengeMismatch.Add(1)
			if ps.challengeNoiseLog() {
				log.Printf("mesh: challenge response from %x dropped: not this conn's outstanding challenge (armed=%v, identity-match=%v)",
					responderID, pc.challengeArmed, responderID == pc.peerID)
			}
			return
		}
		if ps.challengeDir == nil {
			ps.challengeNoEntry.Add(1)
			if ps.challengeNoiseLog() {
				log.Printf("mesh: challenge response from %x dropped: no challenge Directory wired; verify-closed", responderID)
			}
			return
		}
		key, ok := ps.challengeDir.Lookup(responderID)
		if !ok {
			ps.challengeNoEntry.Add(1)
			if ps.challengeNoiseLog() {
				log.Printf("mesh: challenge response from %x dropped: no Directory entry — membership is not verification, and absence is not proof", responderID)
			}
			return
		}
		// A test-only control skips only signature verification while retaining
		// the Directory and identity checks. It demonstrates that rejecting a
		// wrong key depends on the possession proof.
		if ps.disableChallengeVerifyBugInject.Load() {
			pc.remoteVerified.Store(true)
			log.Printf("mesh: peer %x verified (test-only fault injection: possession proof skipped)", responderID)
			return
		}
		msg := buildChallengeMsg(nonce, responderID, challengerID)
		if identity.VerifyCRDTFrame(key, msg, sig) {
			ps.challengeVerified.Add(1)
			pc.remoteVerified.Store(true)
			log.Printf("mesh: peer %x verified (connect-time possession proof)", responderID)
		} else {
			ps.challengeSigFail.Add(1)
			log.Printf("mesh: challenge response from %x: signature verification failed; dropped", responderID)
		}
	default:
		if ps.challengeNoiseLog() {
			log.Printf("mesh: challenge frame from %x: unknown role %d — dropped", pc.peerID, challengeFrameRole(frame))
		}
	}
}

// HandleConnChallengeFrame routes an accepted connection's challenge-family
// frame through the same handler used by the dial readLoop. myPC is the handle
// from RegisterInbound, or nil after a decode failure or live-edge decline; tc
// is the accepted TLS connection.
//
// A declined connection has no registered peerConn, data egress, or digest
// identity, but it still answers CHALLENGE frames. In a mutual-dial mesh, each
// connection can be declined at one end, and the other end's registered edge
// needs that answer to verify. The response reveals only possession of this
// node's key over the challenger's nonce.
//
// The decliner never initiates a challenge on this connection, so a RESPONSE
// has no armed state and is dropped. Answers use a transient peerConn solely
// for writeToPC's common write handling. It is never installed or retained.
// Its suspect key uses the certificate node ID when available, or the remote
// address after a decode failure, so a failed answer marks the right edge.
func (ps *PeerSet) HandleConnChallengeFrame(myPC *PeerConnHandle, tc *tls.Conn, frame []byte) {
	if myPC != nil && myPC.pc != nil {
		ps.handleConnChallengeFrame(myPC.pc, frame)
		return
	}
	if tc == nil || challengeFrameRole(frame) != challengeRoleChallenge {
		return // a declined conn serves the responder arm only; a RESPONSE has no armed state to verify against
	}
	challengerID, nonce, ok := parseChallengeFrame(frame)
	if !ok || ps.owner == nil {
		return // malformed, or no identity to answer with — the dialer times out and stays unverified
	}
	// A declined connection has no persistent per-connection state, so its
	// answer budget uses a per-suspect-key limit and a PeerSet-wide ceiling.
	// After a decode failure the key is the remote address, which an attacker
	// can rotate; the global ceiling remains the rotation-independent bound.
	// Derive the key before signing, and refund a reservation if signing fails.
	// Expiry and reclamation allow recovery without a periodic refill. Exhaustion
	// disables stateless answers until recovery or restart, while new connected
	// peers retain fresh per-connection budgets (ADR-0069).
	addr := ""
	if ra := tc.RemoteAddr(); ra != nil {
		addr = ra.String()
	}
	suspectKey := addr // decode-miss: the outbound addr convention (never the zero bucket)
	if real, ok := nodeIDFromConn(tc); ok {
		suspectKey = suspectKeyForNodeID(real) // inbound certificate node ID convention
	}
	// Capture whether and how this frame reserved budget. Refunds must use
	// these snapshots rather than rechecking a mutable test-injection flag.
	// Normal reservations have per-key records; an unrecorded reservation is
	// reachable only through the sweep-retain injection or a direct unit call.
	reserved := false
	reservedPerKey := false
	if !ps.disableChallengeAnswerBudgetBugInject.Load() {
		ps.challengeDeclinedMu.Lock()
		if ps.challengeDeclinedByKey == nil {
			ps.challengeDeclinedByKey = make(map[string]declinedRes) // lazy, cold
		}
		if ps.challengeDeclinedLiveEdge == nil {
			ps.challengeDeclinedLiveEdge = make(map[string]int64) // lazy, cold
		}
		now := time.Now().UnixNano()
		ttlNS := int64(challengeDeclinedReservationTTL)
		n2 := !ps.disableDeclinedPolicyBugInject.Load()
		// Expired records are absent and return their counts to the global,
		// allowing a fresh reservation window without restart. Live-edge marks
		// expire the same way. Disabling the policy preserves lifetime records
		// for the negative control.
		if n2 {
			if res, ok := ps.challengeDeclinedByKey[suspectKey]; ok && now-res.lastUnixNano >= ttlNS {
				ps.challengeDeclinedGlobal -= res.count
				delete(ps.challengeDeclinedByKey, suspectKey)
			}
			if mark, ok := ps.challengeDeclinedLiveEdge[suspectKey]; ok && now-mark >= ttlNS {
				delete(ps.challengeDeclinedLiveEdge, suspectKey)
			}
		}
		// A fresh live-edge mark skips the per-key reservation because our own
		// working connection caused the decline. The global still counts, so a
		// CA-leaf holder cannot use live edges to bypass the aggregate bound.
		liveEdgeFresh := false
		if n2 {
			if mark, ok := ps.challengeDeclinedLiveEdge[suspectKey]; ok && now-mark < ttlNS {
				liveEdgeFresh = true
			}
		}
		perKey := uint64(0)
		if !liveEdgeFresh {
			if res, ok := ps.challengeDeclinedByKey[suspectKey]; ok {
				perKey = res.count
			}
			perKey++
		}
		globalNow := ps.challengeDeclinedGlobal
		// At the ceiling, remove expired records and recompute the global as
		// the surviving map sum; reserve and refund keep those values equal.
		// Rate-limit this work so a saturated flood cannot turn every 53-byte
		// challenge into an O(map) sweep.
		if n2 && globalNow >= challengeAnswerGlobalCeiling && now-ps.challengeDeclinedLastSweepNano >= int64(challengeDeclinedSweepInterval) {
			ps.challengeDeclinedLastSweepNano = now
			total := uint64(0)
			for k, res := range ps.challengeDeclinedByKey {
				if now-res.lastUnixNano >= ttlNS {
					delete(ps.challengeDeclinedByKey, k)
					continue
				}
				total += res.count
			}
			ps.challengeDeclinedGlobal = total
			globalNow = total
		}
		over := perKey > challengeAnswerPerSuspectKeyBudget || globalNow >= challengeAnswerGlobalCeiling
		if !over {
			record := !liveEdgeFresh || !ps.disableLiveEdgeRecordBugInject.Load()
			if record {
				res := ps.challengeDeclinedByKey[suspectKey]
				if liveEdgeFresh {
					// Record live-edge reservations too so the ceiling sweep
					// includes them in the global sum and the guarded refund can
					// find the record. Omitting the record would let repeated
					// sweeps restart an adversarial live-edge window. The per-key
					// cap still does not bind because perKey remained zero above.
					res.count++
				} else {
					res.count = perKey
				}
				res.lastUnixNano = now
				ps.challengeDeclinedByKey[suspectKey] = res
			}
			reservedPerKey = record
			ps.challengeDeclinedGlobal++
		}
		ps.challengeDeclinedMu.Unlock()
		if over {
			// Log the snapshot captured under the mutex, not
			// challengeDeclinedGlobal after unlocking: another declined serve
			// goroutine could increment it concurrently. globalNow is the value
			// used for this reservation decision.
			if d := ps.challengeAnswerBudgetDrops.Add(1); d == 1 || d%1000 == 0 {
				// suspectKey can contain a NUL-prefixed raw node ID. Format it
				// with %x rather than %s so logs remain valid UTF-8 and
				// searchable.
				log.Printf("mesh: declined-conn challenge from %x dropped: the stateless answer budget is exhausted (per-key %d > cap %d, or global %d >= ceiling %d; drop #%d) — the pre-verify answer flood is bounded (no refill; restart resets; ADR-0069)", suspectKey, perKey, challengeAnswerPerSuspectKeyBudget, globalNow, challengeAnswerGlobalCeiling, d)
			}
			return
		}
		reserved = true
	}
	msg := buildChallengeMsg(nonce, ps.owner.NodeID, challengerID)
	sig, err := identity.SignCRDTFrame(ps.owner.Seed, msg)
	if ps.signFailBugInject.Load() {
		err = errors.New("test-only sign failure injection")
	}
	if err != nil {
		if reserved {
			// Signing failed, so return this reservation through the guarded
			// helper rather than consuming budget for an answer never sent.
			ps.refundDeclinedReservation(suspectKey, reservedPerKey)
		}
		return
	}
	resp := buildChallengeResponseFrame(ps.owner.NodeID, challengerID, nonce, sig)
	tpc := &peerConn{addr: addr, conn: tc, done: make(chan struct{})}
	tpc.suspectKey = suspectKey
	if real, ok := nodeIDFromConn(tc); ok {
		tpc.peerID = real
	}
	_ = ps.writeToPC(tpc.peerID, tpc, receive.LengthPrefixFrame(resp), nil)
}

// ArmDeclinedInbound arms per-connection challenge verification for an inbound
// TLS connection that RegisterInbound declined because ps.peers[real] already
// holds a live edge, as can happen during simultaneous mutual dialing. It
// returns real and an unregistered handle that serveConnWithDigest or
// serveTestConn uses only to verify challengeRoleResponse frames and answer
// DigestConnVerified. RegisterInbound and ReleaseInboundConn retain their
// existing return and no-op behavior for declined registrations.
func (ps *PeerSet) ArmDeclinedInbound(tc *tls.Conn) ([16]byte, *PeerConnHandle) {
	if ps == nil || tc == nil || ps.owner == nil || ps.disableDeclinedVerifyBugInject.Load() {
		return [16]byte{}, nil
	}
	real, ok := nodeIDFromConn(tc)
	if !ok || real == ([16]byte{}) {
		return [16]byte{}, nil
	}
	ps.mu.RLock()
	existing, ok := ps.peers[real]
	live := false
	if ok && existing != nil {
		select {
		case <-existing.done:
		default:
			live = true
		}
	}
	ps.mu.RUnlock()
	if !live {
		return [16]byte{}, nil
	}
	addr := ""
	if ra := tc.RemoteAddr(); ra != nil {
		addr = ra.String()
	}
	pc := &peerConn{
		addr:       addr,
		conn:       tc,
		peerID:     real,
		suspectKey: suspectKeyForNodeID(real),
		done:       make(chan struct{}),
	}
	if ps.armChallenge(pc) {
		_ = ps.sendChallengeFrame(pc)
	}
	return real, &PeerConnHandle{pc: pc}
}

// HandleDeclinedChallengeFrame routes challenge-family frames on a declined
// connection. A challengeRoleResponse with a non-nil declPC goes to
// handleConnChallengeFrame, which verifies the dialer's response to
// ArmDeclinedInbound against ps.challengeDir and sets declPC.pc.remoteVerified.
// Other roles go to HandleConnChallengeFrame with a nil handle, preserving the
// stateless responder and its per-key and global answer budgets.
func (ps *PeerSet) HandleDeclinedChallengeFrame(declPC *PeerConnHandle, tc *tls.Conn, frame []byte) {
	if ps == nil {
		return
	}
	if challengeFrameRole(frame) == challengeRoleResponse && declPC != nil && declPC.pc != nil {
		ps.handleConnChallengeFrame(declPC.pc, frame)
		return
	}
	ps.HandleConnChallengeFrame(nil, tc, frame)
}

// DigestConnVerified reports whether the accepted connection represented by h
// has completed its own key-possession challenge. A nil declined or decode-miss
// handle and an unverified connection return false and increment
// digestSeamDrops. The dial readLoop performs the corresponding check; both use
// the receiving connection's bit rather than the current map entry. It is
// exported for cmd's serve loop and serveTestConn.
func (ps *PeerSet) DigestConnVerified(h *PeerConnHandle) bool {
	verified := (h != nil && h.pc != nil && h.pc.remoteVerified.Load()) || ps.disableDigestSeamBugInject.Load()
	if !verified {
		ps.digestSeamDrops.Add(1)
	}
	return verified
}
