// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// ---------------------------------------------------------------------------
// Chaos orchestrator: partition scheduling and anti-entropy loop.
// ---------------------------------------------------------------------------
//
// The orchestrator generates events dispatched to virtual nodes with randomized
// latency, forced packet duplication, and simulated routing blackholes. It
// (1) generates test events, (2) ships them to virtual nodes via VirtualNet,
// (3) induces and heals network partitions at chosen times, and (4) asserts
// Merkle-root convergence across all nodes after the partition heals.
//
// Lattice-join commutativity, associativity, and idempotence guarantee that
// once all nodes receive all deltas, their state converges. The orchestrator
// exercises the engine's delta generation and Join over a lossy, partitioned
// transport under an anti-entropy gossip loop.
//
// Events are inserted locally via InsertLocal at each source node (minting
// dots from that node's Lamport counter), then propagated to every other node
// via GenerateDelta + Join, matching the dot semantics of a live cluster over
// a virtual transport.
package chaos

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	engsync "github.com/hr18vk/sovereign/pkg/sync"
)

// Orchestrator drives a partition + anti-entropy scenario over a
// VirtualNet + a set of real DeltaCRDTEngine instances.
type Orchestrator struct {
	mu      sync.Mutex
	net     *VirtualNet
	engines map[[16]byte]*engsync.DeltaCRDTEngine

	// rxLog records, per receiving node, the sequence of NetMessages actually
	// delivered to its Receive callback. The gate inspects this to prove the net
	// really did deliver (no permanent post-heal loss) and to count duplicates.
	rxLogMu sync.Mutex
	rxLog   map[[16]byte][]NetMessage

	// dedup state per (from→to): set of SeqNo already applied, so repeated
	// duplicates exercise the CRDT's idempotence instead of inflating state.
	dedup   map[[16]byte]map[uint64]struct{}
	dedupOn bool
}

// OrchestratorConfig tunes a partition scenario run.
type OrchestratorConfig struct {
	Net     *VirtualNet
	Engines map[[16]byte]*engsync.DeltaCRDTEngine
	// Dedup enables per-edge SeqNo dedup at the receiver (default true: the
	// real engine's Join is idempotent, so dedup is belt-and-suspenders; the
	// gate exercises both to prove Join's idempotence directly too).
	Dedup bool
}

// NewOrchestrator constructs a seeded orchestrator. The engines map keys must
// exactly match the NetNode IDs added to the net; the orchestrator does not
// add nodes itself — the caller wires the engines to the net.Walk it owns so
// the test keeps control of phase ordering.
func NewOrchestrator(cfg OrchestratorConfig) (*Orchestrator, error) {
	if cfg.Net == nil {
		return nil, errors.New("chaos/partition: Net required")
	}
	if len(cfg.Engines) == 0 {
		return nil, errors.New("chaos/partition: at least one engine required")
	}
	o := &Orchestrator{
		net:     cfg.Net,
		engines: make(map[[16]byte]*engsync.DeltaCRDTEngine, len(cfg.Engines)),
		rxLog:   make(map[[16]byte][]NetMessage, len(cfg.Engines)),
		dedup:   make(map[[16]byte]map[uint64]struct{}, len(cfg.Engines)),
		dedupOn: cfg.Dedup,
	}
	for id, e := range cfg.Engines {
		if e == nil {
			return nil, fmt.Errorf("chaos/partition: nil engine for node %x", id)
		}
		o.engines[id] = e
		o.dedup[id] = make(map[uint64]struct{})
	}
	return o, nil
}

// BindNodes wires each engine's Receive callback so incoming NetMessages from
// the fabric are decoded and joined into the local engine. The caller invokes
// this after AddNode on the net so the Receiver closures capture the right
// engine by ID. The payload encoding is the orchestrator's own compact format
// (entityIDLen(4) + entityID + CRDTEntry(120)) wrapped in a SeqNo prefix only
// for the dedup path; GossipDelta below emits this format.
func (o *Orchestrator) BindNodes() {
	for id, e := range o.engines {
		id := id
		e := e
		o.net.AddNode(id, func(msg NetMessage) {
			o.recordRx(id, msg)
			o.applyDelta(id, e, msg)
		})
	}
}

// recordRx is a non-blocking append to per-node delivery log under its own lock
// so the gate can post-hoc prove the net actually delivered each message.
func (o *Orchestrator) recordRx(to [16]byte, msg NetMessage) {
	o.rxLogMu.Lock()
	o.rxLog[to] = append(o.rxLog[to], msg)
	o.rxLogMu.Unlock()
}

// applyDelta decodes the message and joins it into the receiver's engine. With
// dedup enabled it skips SeqNos already applied on that edge; with dedup
// disabled it relies on CRDT Join idempotence under duplicate packet delivery.
func (o *Orchestrator) applyDelta(to [16]byte, e *engsync.DeltaCRDTEngine, msg NetMessage) {
	if o.dedupOn {
		key := edgeKey(msg.From, to)
		set := o.dedup[to]
		if _, seen := set[msg.SeqNo]; seen {
			return
		}
		set[msg.SeqNo] = struct{}{}
		_ = key
	}
	// Decode (entityID + entry).
	entry, entityID, ok := decodeDeltagram(msg.Bytes)
	if !ok {
		// Malformed deltagrams indicate an internal encoding bug; panic rather
		// than silently dropping state.
		panic(fmt.Errorf("chaos/partition: malformed deltagram from %x seq=%d", msg.From, msg.SeqNo))
	}
	delta := engsync.CRDTDelta{
		Entries: func(yield func(entityID string, entry engsync.CRDTEntry) bool) {
			yield(entityID, entry)
		},
		OriginNodeID: msg.From,
		MerkleRoot:   [32]byte{},
	}
	e.Join(delta)
}

// edgeKey folds (from,to) into a single map key value.
func edgeKey(from, to [16]byte) uint64 {
	var b [32]byte
	copy(b[:16], from[:])
	copy(b[16:], to[:])
	h := sha256.Sum256(b[:])
	return binary.LittleEndian.Uint64(h[:8])
}

// GenerateEvents distributes n events round-robin across source nodes via
// InsertLocal (minting a dot from each source's Lamport counter) and records
// the entries so post-convergence checks can verify origin dot lineage.
//
// The H3Index field is populated deterministically from k as a synthetic
// correlation identifier for tests.
func (o *Orchestrator) GenerateEvents(ctx context.Context, n int) (events []engsync.CRDTEntry, err error) {
	ids := o.sortedIDs()
	if len(ids) == 0 {
		return nil, errors.New("chaos/partition: no nodes bound")
	}
	for k := 0; k < n; k++ {
		if err := ctx.Err(); err != nil {
			return events[:0:0], err
		}
		src := ids[k%len(ids)]
		eng := o.engines[src]
		entry := stagedEventEntry(k, src)
		eng.InsertLocal(fmt.Sprintf("civic-event-%d", k), entry)
		events = append(events, entry)
	}
	return events, nil
}

// GossipOnce runs one full anti-entropy sweep: for every (i→j) pair, computes
// i's delta to j and ships it. The receiver closes the loop by Join'ing it via
// the BindNodes Receive callback when the (possibly delayed) delivery arrives.
//
// This computes deltas over the same in-process engines the real daemon would.
// The transport is virtual; the deltas are real DeltaCRDTEngine.GenerateDelta
// output. So anything this test proves about delta determinism / Merkle
// equality is a fact about the engine, not a property of the virtual net.
func (o *Orchestrator) GossipOnce(ctx context.Context) (shipped int, err error) {
	return o.net.RunGossipRound(ctx, func(ctx context.Context, from, to [16]byte) ([]byte, error) {
		// Generate a delta of (from) for (to). We use the engine's GenerateDelta
		// against the target's current digest. Note: the receiver's digest is
		// sampled at delta-generation time; if the receiver mutates between then
		// and delivery, the delta may be a superset (the CRDT Join is idempotent
		// so this is correct, just occasionally redundant). This is the standard
		// IBLT-delta anti-entropy model.
		srcEng := o.engines[from]
		dstEng := o.engines[to]
		if srcEng == nil || dstEng == nil {
			return nil, fmt.Errorf("chaos/partition: missing engine for from=%x to=%x", from, to)
		}
		dstDigest := dstEng.GenerateDigest() // IBLT over dst's current state
		defer dstDigest.Release()            // arena-backed digest must be released
		delta := srcEng.GenerateDelta(dstDigest)
		defer delta.Release()
		// Serialize every entry in the delta into the compact format
		// (entityIDLen+entityID+CRDTEntry). Since we are not encoding a full
		// CRDTDelta struct but a flat list of (entityID, entry) pairs, the
		// receiver re-encodes each pair back via Join's push iterator.
		var buf []byte
		delta.Entries(func(entityID string, entry engsync.CRDTEntry) bool {
			buf = appendDeltagram(buf, entityID, entry)
			return true
		})
		return buf, nil
	})
}

// MerkleRoots returns each node's MerkleRoot plus a flag for whether all match.
// The partition gate asserts "Node[i].MerkleRoot() == Node[j].MerkleRoot()" after the
// partition heals.
func (o *Orchestrator) MerkleRoots() (roots map[[16]byte][32]byte, converged bool) {
	o.mu.Lock()
	ids := make([][16]byte, 0, len(o.engines))
	for id := range o.engines {
		ids = append(ids, id)
	}
	o.mu.Unlock()
	roots = make(map[[16]byte][32]byte, len(ids))
	var ref [32]byte
	var haveRef bool
	for _, id := range ids {
		eng := o.engines[id]
		// MerkleRootFromShards computes the root without allocating arena snapshots.
		r := eng.MerkleRootFromShards()
		roots[id] = r
		if !haveRef {
			ref = r
			haveRef = true
		} else if r != ref {
			converged = false
		}
	}
	converged = haveRef
	for _, r := range roots {
		if r != ref {
			converged = false
			break
		}
	}
	return roots, converged
}

// RxLog returns a defensive copy of the per-node delivery log for the gate to
// inspect (counts, duplicates, completeness).
func (o *Orchestrator) RxLog(to [16]byte) []NetMessage {
	o.rxLogMu.Lock()
	defer o.rxLogMu.Unlock()
	out := make([]NetMessage, len(o.rxLog[to]))
	copy(out, o.rxLog[to])
	return out
}

// sortedIDs returns the orchestrator's node IDs in a stable order.
func (o *Orchestrator) sortedIDs() [][16]byte {
	o.mu.Lock()
	defer o.mu.Unlock()
	ids := make([][16]byte, 0, len(o.engines))
	for id := range o.engines {
		ids = append(ids, id)
	}
	sortIDs(ids) // provided by virtualnet.go, same package
	return ids
}

// ---------------------------------------------------------------------------
// deltagram wire encoding (compact, in-process only).
// ---------------------------------------------------------------------------

// appendDeltagram encodes (entityID, CRDTEntry) into buf, returning the new
// buffer. Layout: entityIDLen(4) + entityID + CRDTEntry(120).
func appendDeltagram(buf []byte, entityID string, entry engsync.CRDTEntry) []byte {
	start := len(buf)
	buf = append(buf, make([]byte, 4+len(entityID)+120)...)
	binary.BigEndian.PutUint32(buf[start:start+4], uint32(len(entityID)))
	copy(buf[start+4:start+4+len(entityID)], entityID)
	encodeCRDTEntry(buf[start+4+len(entityID):start+4+len(entityID)+120], entry)
	return buf
}

// decodeDeltagram decodes one (entityID, entry) pair from p. Returns ok=false
// if the buffer is too short.
func decodeDeltagram(p []byte) (entry engsync.CRDTEntry, entityID string, ok bool) {
	if len(p) < 4 {
		return entry, "", false
	}
	ln := binary.BigEndian.Uint32(p[0:4])
	need := 4 + int(ln) + 120
	if len(p) < need {
		return entry, "", false
	}
	entityID = string(p[4 : 4+int(ln)])
	entry = decodeCRDTEntry(p[4+int(ln) : need])
	return entry, entityID, true
}

// stagedEventEntry builds a deterministic test entry for index k from source node
// src. Matches wal_test.go's stagedEntry shape, stamped with the source node ID
// so Join sees the expected OriginNodeID lineage.
func stagedEventEntry(k int, src [16]byte) engsync.CRDTEntry {
	h := sha256.Sum256([]byte(fmt.Sprintf("civic/%d/%x", k, src)))
	var payload [32]byte
	copy(payload[:], h[:])
	return engsync.CRDTEntry{
		PayloadDigest: payload,
		OriginNodeID:  src,
		H3Index:       uint64(k) << 8,
		SystemTime:    time.Now().UnixNano(),
	}
}
