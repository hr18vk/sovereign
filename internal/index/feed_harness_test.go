// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package index

// The feed harness drives each mutation path and records its writes in the
// secondary index:
//
//   - durable local writes through Bridge.PutLocals and an on-disk WAL;
//   - in-memory local writes through the gossiper's engine.InsertLocal call;
//   - remote writes through Receiver.HandleFrame, HandleBatchFrame, and
//     HandleHybridFrame with signed v3 relay, batch, and hybrid frames;
//   - boot replay through ReplayWAL and RecoverEngine.
//
// Remote field extraction uses lightDecodeEvent and lightDecodeBatch. The
// harness constructs production objects but is not part of a production
// binary.

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"path/filepath"
	"testing"
	"time"

	capnp "capnproto.org/go/capnp/v3"
	"github.com/cloudflare/circl/sign/ed25519"
	capnp_schema "github.com/hr18vk/sovereign/api/capnp/api/capnp"

	db "github.com/hr18vk/sovereign/internal/database"
	adm "github.com/hr18vk/sovereign/pkg/admission"
	attr "github.com/hr18vk/sovereign/pkg/attribution"
	clk "github.com/hr18vk/sovereign/pkg/clock"
	dur "github.com/hr18vk/sovereign/pkg/durability"
	ident "github.com/hr18vk/sovereign/pkg/identity"
	mesh "github.com/hr18vk/sovereign/pkg/mesh"
	recv "github.com/hr18vk/sovereign/pkg/receive"
	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// harnessOrigin is the nonzero test origin and the engine's local node ID.
// Self-origin frames join normally, and the index includes their state.
var harnessOrigin = [16]byte{0x6f, 0x72, 0x69, 0x67, 0x69, 0x6e, 0x24, 0x66, 0x6b, 0x32, 0x34, 0x0a, 0x0c, 0x0d, 0x0e, 0x0f}

const (
	harnessWallBaseUSec = int64(1_700_000_000_000_000) // SyntheticClock pin and hop wall base
	harnessBudgetNS     = int64(1_000_000_000)         // 1 s -> MaxHopsForBudget=15; admits one hop
)

// harnessEngine builds an engine with an isolated data directory.
func harnessEngine(t testing.TB) *eng.DeltaCRDTEngine {
	t.Helper()
	e, err := eng.NewDeltaCRDTEngine(harnessOrigin, 0, 64*1024*1024)
	if err != nil {
		t.Fatalf("NewDeltaCRDTEngine: %v", err)
	}
	e.SetDataDir(t.TempDir())
	t.Cleanup(func() {
		if cerr := e.Close(); cerr != nil {
			t.Logf("engine.Close: %v", cerr)
		}
	})
	return e
}

// harnessPubArray and harnessSigArray copy the variable-length key and
// signature slices into the fixed-size arrays used by the wire helpers.
func harnessPubArray(pub ed25519.PublicKey) [32]byte {
	var a [32]byte
	copy(a[:], pub)
	return a
}

func harnessSigArray(sig []byte) [64]byte {
	var a [64]byte
	copy(a[:], sig)
	return a
}

// harnessEventWire builds a single CRDTDeltaEvent that ApplyCRDTDeltaEvent
// accepts. DotNodeID matches OriginNodeID, PayloadDigest is SHA-256(payload),
// and the wire version matches the compiled schema. The arguments set the
// entity ID, H3 cell, system time, and dot counter under test.
func harnessEventWire(t testing.TB, entityID string, h3 uint64, sys int64, dotCounter uint64) []byte {
	t.Helper()
	dgst := sha256.Sum256([]byte(entityID)) // payload == entityID: digest-consistent by construction
	msg, seg, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		t.Fatalf("capnp.NewMessage: %v", err)
	}
	ev, err := capnp_schema.NewRootCRDTDeltaEvent(seg)
	if err != nil {
		t.Fatalf("NewRootCRDTDeltaEvent: %v", err)
	}
	ev.SetVersion(eng.CRDTDeltaEventWireVersion)
	if err := ev.SetPayloadDigest(dgst[:]); err != nil {
		t.Fatalf("SetPayloadDigest: %v", err)
	}
	if err := ev.SetOriginNodeID(harnessOrigin[:]); err != nil {
		t.Fatalf("SetOriginNodeID: %v", err)
	}
	if err := ev.SetDotNodeID(harnessOrigin[:]); err != nil {
		t.Fatalf("SetDotNodeID: %v", err)
	}
	ev.SetDotCounter(dotCounter)
	ev.SetH3Index(h3)
	ev.SetSystemTime(sys)
	ev.SetValidTimeStart(1)
	ev.SetValidTimeEnd(2)
	ev.SetAssertionTime(sys)
	ev.SetDecisionTime(sys)
	if err := ev.SetEntityId(entityID); err != nil {
		t.Fatalf("SetEntityId: %v", err)
	}
	if err := ev.SetPayload(entityID); err != nil {
		t.Fatalf("SetPayload: %v", err)
	}
	data, err := msg.Marshal()
	if err != nil {
		t.Fatalf("msg.Marshal: %v", err)
	}
	return data
}

// harnessDecodeGateFields reads dotCounter and originNodeID from the inner
// wire so the v3 envelope header can carry the same values and pass the
// receiver's header/inner cross-check.
func harnessDecodeGateFields(t testing.TB, innerWire []byte) (uint64, [16]byte) {
	t.Helper()
	msg, err := capnp.Unmarshal(innerWire)
	if err != nil {
		t.Fatalf("harnessDecodeGateFields: capnp unmarshal: %v", err)
	}
	defer msg.Release()
	ev, err := capnp_schema.ReadRootCRDTDeltaEvent(msg)
	if err != nil {
		t.Fatalf("harnessDecodeGateFields: read root: %v", err)
	}
	originBytes, err := ev.OriginNodeID()
	if err != nil {
		t.Fatalf("harnessDecodeGateFields: originNodeID: %v", err)
	}
	var origin [16]byte
	copy(origin[:], originBytes)
	return ev.DotCounter(), origin
}

// harnessRelayFrame signs innerWire with the origin key, adds one signed relay
// hop, and returns the v3 envelope bytes consumed by HandleFrame.
func harnessRelayFrame(t testing.TB, innerWire []byte, originPriv ed25519.PrivateKey) []byte {
	t.Helper()
	originSig := ed25519.Sign(originPriv, innerWire)
	relayPub, relayPriv := harnessGenKey(t)
	hop := attr.SignHop(relayPriv, harnessPubArray(relayPub), innerWire, nil, 0, harnessWallBaseUSec)
	dotCounter, originNodeID := harnessDecodeGateFields(t, innerWire)
	env := attr.NewSignedRelayEnvelopeV3(innerWire, harnessSigArray(originSig), dotCounter, originNodeID, []attr.Hop{hop})
	return env.Marshal()
}

// harnessSetupReceiver constructs a Receiver with an admission bucket, a
// SyntheticClock pinned at the hop wall base, an HLC scalar cap, and an
// identity Directory containing the origin.
func harnessSetupReceiver(t testing.TB, engine *eng.DeltaCRDTEngine, originPub ed25519.PublicKey) (*recv.Receiver, *ident.Directory) {
	t.Helper()
	bucket := adm.NewPeerBucket()
	sc := clk.NewSyntheticClock(harnessWallBaseUSec)
	capGate := clk.NewIngressHLCScalarCap(sc, engine)
	dir := ident.NewDirectory()
	if err := dir.Register(harnessOrigin, originPub); err != nil {
		t.Fatalf("Directory.Register: %v", err)
	}
	return recv.NewReceiver(bucket, capGate, sc, dir, engine, harnessBudgetNS), dir
}

// harnessBridge opens an on-disk WAL at walPath and connects it to engine
// through a Bridge. The caller retains walPath so the boot path can replay it
// after the bridge closes.
func harnessBridge(t testing.TB, engine *eng.DeltaCRDTEngine, walPath string) *dur.Bridge {
	t.Helper()
	wal, err := dur.OpenWAL(walPath)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	b := dur.NewBridge(engine, wal, 0)
	t.Cleanup(func() {
		if cerr := b.Close(); cerr != nil {
			t.Logf("bridge.Close: %v", cerr)
		}
	})
	return b
}

// harnessBatchWire builds a CRDTDeltaBatch containing n distinct entities
// with explicit H3 cells and system times. The result is the inner payload for
// HandleBatchFrame and HandleHybridFrame.
func harnessBatchWire(t testing.TB, base string, n int, h3 uint64, sys int64, firstCounter uint64) []byte {
	t.Helper()
	events := make([]mesh.BuiltEvent, n)
	for i := range events {
		payload := fmt.Sprintf("%s-payload-%d", base, i)
		dgst := sha256.Sum256([]byte(payload))
		e := eng.CRDTEntry{
			PayloadDigest:  dgst,
			OriginNodeID:   harnessOrigin,
			DotNodeID:      harnessOrigin,
			DotCounter:     firstCounter + uint64(i),
			H3Index:        h3 + uint64(i),
			SystemTime:     sys + int64(i),
			ValidTimeStart: 1,
			ValidTimeEnd:   2,
		}
		events[i] = mesh.BuiltEvent{EntityID: fmt.Sprintf("%s-%d", base, i), Payload: payload, Entry: e}
	}
	wire, err := mesh.BuildCRDTDeltaBatch(events)
	if err != nil {
		t.Fatalf("BuildCRDTDeltaBatch: %v", err)
	}
	return wire
}

// harnessBatchEnvelope signs batchWire once with Ed25519 and wraps it in the
// flat BatchEnvelope consumed by HandleBatchFrame. originSeq is the origin's
// monotonic batch sequence; the rate gate uses the difference between
// successive values.
func harnessBatchEnvelope(batchWire []byte, originPriv ed25519.PrivateKey, originSeq uint64, n int) []byte {
	sig := ed25519.Sign(originPriv, batchWire)
	return attr.MarshalBatchEnvelope(harnessOrigin, harnessSigArray(sig), originSeq, uint16(n), batchWire)
}

// harnessHybridFrame signs batchWire with Ed25519 and ML-DSA-65 over the same
// SHAKE256 pad, then returns the HybridEnvelope consumed by HandleHybridFrame
// when hybrid verification is enabled.
func harnessHybridFrame(t testing.TB, batchWire []byte, originSeed []byte, originSeq uint64, n int) []byte {
	t.Helper()
	pqPriv, err := ident.GeneratePreviewKey65(originSeed)
	if err != nil {
		t.Fatalf("GeneratePreviewKey65: %v", err)
	}
	edSig, pqSig, err := ident.SignCRDTFrame_Hybrid(originSeed, pqPriv, batchWire, "")
	if err != nil {
		t.Fatalf("SignCRDTFrame_Hybrid: %v", err)
	}
	return attr.MarshalHybridFrame(harnessOrigin, edSig, pqSig, originSeq, uint16(n), batchWire)
}

// harnessFaultDrop names a path whose feed emission the harness silently
// drops for negative-control testing. By default all paths emit; each drop-*
// subtest sets one key and verifies that the write disappears from the
// candidate set.
var harnessFaultDrop = map[string]bool{}

// harnessEmit applies records from one write path to the index. The site tag
// selects which path the current negative-control subtest suppresses.
func harnessEmit(ix *Index, site string, recs ...Record) {
	for _, r := range recs {
		if harnessFaultDrop[site] {
			continue
		}
		ix.Apply(r)
	}
}

// harnessDriveAllClusters runs one full six-path drive (local durable, local
// in-memory, remote frame/batch/hybrid, and boot replay) against fresh state
// and feeds records through harnessEmit under the active fault map. It returns
// the index and the per-cell expected candidate counts.
func harnessDriveAllClusters(t *testing.T) (*Index, map[uint64]int) {
	t.Helper()
	ix := NewWith(16, 3600*1e9)

	// Durable local write through Bridge.PutLocals and the on-disk WAL.
	engine := harnessEngine(t)
	walPath := filepath.Join(t.TempDir(), "wal")
	bridge := harnessBridge(t, engine, walPath)
	dg := sha256.Sum256([]byte("local-payload"))
	items := []dur.LocalItem{{
		EntityID: "ent-local-bridge",
		Payload:  "local-payload",
		Entry:    eng.CRDTEntry{PayloadDigest: dg, H3Index: 0xAA01, SystemTime: 1000, ValidTimeStart: 1, ValidTimeEnd: 2},
	}}
	if _, _, err := bridge.PutLocals(items); err != nil {
		t.Fatalf("PutLocals: %v", err)
	}
	harnessEmit(ix, "local-durable", Record{EntityID: "ent-local-bridge", H3Index: 0xAA01, SystemTime: 1000})

	// In-memory local write through the gossiper's bridge==nil branch:
	// digest and InsertLocal, with no WAL.
	e2 := eng.CRDTEntry{PayloadDigest: dg, H3Index: 0xAA02, SystemTime: 1001, ValidTimeStart: 1, ValidTimeEnd: 2}
	engine.InsertLocal("ent-local-mem", e2)
	harnessEmit(ix, "local-memory", Record{EntityID: "ent-local-mem", H3Index: 0xAA02, SystemTime: 1001})

	// Remote single frame through Receiver.HandleFrame and a signed one-hop
	// v3 relay chain. The feed emits the light-decoded fields used by the
	// receiver hook.
	originPub, originPriv := harnessGenKey(t)
	rcv, dir := harnessSetupReceiver(t, engine, originPub)
	inner := harnessEventWire(t, "ent-remote-frame", 0xAA03, 1002, 7)
	if v := rcv.HandleFrame(harnessRelayFrame(t, inner, originPriv)); v.Verdict != recv.Accept {
		t.Fatalf("HandleFrame verdict=%s reason=%v", v.Verdict, v.Reason)
	}
	frec, err := lightDecodeEvent(inner)
	if err != nil {
		t.Fatalf("lightDecodeEvent: %v", err)
	}
	harnessEmit(ix, "remote-frame", frec)

	// Remote batch through Receiver.HandleBatchFrame and a flat BatchEnvelope
	// with one Ed25519 signature over the batch wire.
	batchWire := harnessBatchWire(t, "ent-remote-batch", 3, 0xAA10, 1003, 8)
	if v := rcv.HandleBatchFrame(harnessBatchEnvelope(batchWire, originPriv, 1, 3)); v.Verdict != recv.Accept {
		t.Fatalf("HandleBatchFrame verdict=%s reason=%v", v.Verdict, v.Reason)
	}
	brecs, err := lightDecodeBatch(batchWire)
	if err != nil {
		t.Fatalf("lightDecodeBatch: %v", err)
	}
	harnessEmit(ix, "remote-batch", brecs...)

	// Remote hybrid batch through Receiver.HandleHybridFrame with both
	// Ed25519 and ML-DSA-65 verification enabled.
	originSeed := originPriv.Seed()
	pqPriv, err := ident.GeneratePreviewKey65(originSeed)
	if err != nil {
		t.Fatalf("GeneratePreviewKey65: %v", err)
	}
	if err := dir.RegisterPQ(harnessOrigin, pqPriv.PublicKey()); err != nil {
		t.Fatalf("Directory.RegisterPQ: %v", err)
	}
	rcv.SetHybridVerify(true)
	hybridWire := harnessBatchWire(t, "ent-remote-hybrid", 3, 0xAA20, 1010, 16)
	hframe := harnessHybridFrame(t, hybridWire, originSeed, 2, 3)
	if v := rcv.HandleHybridFrame(hframe); v.Verdict != recv.Accept {
		t.Fatalf("HandleHybridFrame verdict=%s reason=%v", v.Verdict, v.Reason)
	}
	hrecs, err := lightDecodeBatch(hybridWire)
	if err != nil {
		t.Fatalf("lightDecodeBatch(hybrid): %v", err)
	}
	harnessEmit(ix, "remote-hybrid", hrecs...)

	// Boot replay uses a separate engine, bridge, and WAL. After closing them,
	// ReplayWAL supplies the same record stream consumed by recovery.
	bootEngine, err := eng.NewDeltaCRDTEngine(harnessOrigin, 0, 64*1024*1024)
	if err != nil {
		t.Fatalf("boot engine: %v", err)
	}
	bootEngine.SetDataDir(t.TempDir())
	bootWalPath := filepath.Join(t.TempDir(), "wal")
	bootBridge := harnessBridge(t, bootEngine, bootWalPath)
	bootItems := make([]dur.LocalItem, 3)
	for i := range bootItems {
		payload := fmt.Sprintf("boot-payload-%d", i)
		bootItems[i] = dur.LocalItem{
			EntityID: fmt.Sprintf("ent-boot-%d", i),
			Payload:  payload,
			Entry:    eng.CRDTEntry{PayloadDigest: sha256.Sum256([]byte(payload)), H3Index: 0xBB00 + uint64(i), SystemTime: 1100 + int64(i), ValidTimeStart: 1, ValidTimeEnd: 2},
		}
	}
	if _, _, err := bootBridge.PutLocals(bootItems); err != nil {
		t.Fatalf("boot PutLocals: %v", err)
	}
	if err := bootBridge.Close(); err != nil {
		t.Fatalf("boot bridge.Close: %v", err)
	}
	if err := bootEngine.Close(); err != nil {
		t.Fatalf("boot engine.Close: %v", err)
	}
	rep, err := dur.ReplayWAL(bootWalPath)
	if err != nil {
		t.Fatalf("ReplayWAL: %v", err)
	}
	for _, r := range rep.Ordered {
		if r.Type == dur.WALRecMutationV2 && !r.Mutation.Legacy {
			harnessEmit(ix, "boot", Record{EntityID: r.Mutation.EntityID, H3Index: r.Mutation.Full.H3Index, SystemTime: r.Mutation.Full.SystemTime})
		}
	}
	return ix, map[uint64]int{
		0xAA01: 1, 0xAA02: 1, 0xAA03: 1,
		0xAA10: 1, 0xAA11: 1, 0xAA12: 1,
		0xAA20: 1, 0xAA21: 1, 0xAA22: 1,
		0xBB00: 1, 0xBB01: 1, 0xBB02: 1,
	}
}

// TestFeed_CompletenessProof checks that every write path is queryable through
// the index. The main path requires each cell to contain its expected
// candidate. Each control subtest suppresses one path's emission and requires
// the corresponding write to disappear, demonstrating that the main assertion
// can detect a missing feed.
//
// Removing any harnessEmit call fails the main assertion. A suppression that
// does not remove the write fails its control subtest.
func TestFeed_CompletenessProof(t *testing.T) {
	ix, want := harnessDriveAllClusters(t)
	for cell, n := range want {
		if got := ix.CandidatesByH3(cell); len(got) != n {
			t.Fatalf("feed.completeness: cell %x: candidates=%v, want count %d — a cluster's write did not reach the feed", cell, got, n)
		}
	}
	if st := ix.Stats(); st.Entities != 12 {
		t.Fatalf("feed.completeness: indexed %d entities, want 12 (1 local-bridge + 1 local-mem + 1 frame + 3 batch + 3 hybrid + 3 boot)", st.Entities)
	}
	controls := []struct {
		site  string
		cells []uint64
	}{
		{"local-durable", []uint64{0xAA01}},
		{"local-memory", []uint64{0xAA02}},
		{"remote-frame", []uint64{0xAA03}},
		{"remote-batch", []uint64{0xAA10, 0xAA11, 0xAA12}},
		{"remote-hybrid", []uint64{0xAA20, 0xAA21, 0xAA22}},
		{"boot", []uint64{0xBB00, 0xBB01, 0xBB02}},
	}
	for _, c := range controls {
		t.Run("drop-"+c.site, func(t *testing.T) {
			harnessFaultDrop[c.site] = true
			defer delete(harnessFaultDrop, c.site)
			ix2, _ := harnessDriveAllClusters(t)
			for _, cell := range c.cells {
				if got := ix2.CandidatesByH3(cell); len(got) != 0 {
					t.Fatalf("drop-%s: cell %x still has candidates %v — the fault drop did not lose the write (a negative control)", c.site, cell, got)
				}
			}
		})
	}
}

// TestFeed_BootEquivalence closes a durable write set, feeds ReplayWAL's
// rep.Ordered records to the index, and rebuilds the engine from the same WAL
// with RecoverEngine. For every entity, the recovered entry with the greatest
// SystemTime must name the cell where the index lists that entity.
//
// Negative control: truncating the boot feed to the first replay record fails
// the equivalence assertion for the remaining entities.
func TestFeed_BootEquivalence(t *testing.T) {
	const n = 6
	engine, err := eng.NewDeltaCRDTEngine(harnessOrigin, 0, 64*1024*1024)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	engine.SetDataDir(t.TempDir())
	walPath := filepath.Join(t.TempDir(), "wal")
	bridge := harnessBridge(t, engine, walPath)
	items := make([]dur.LocalItem, n)
	for i := range items {
		payload := fmt.Sprintf("boot-eq-payload-%d", i)
		items[i] = dur.LocalItem{
			EntityID: fmt.Sprintf("ent-boot-eq-%d", i),
			Payload:  payload,
			Entry:    eng.CRDTEntry{PayloadDigest: sha256.Sum256([]byte(payload)), H3Index: 0xCC00 + uint64(i), SystemTime: 2000 + int64(i), ValidTimeStart: 1, ValidTimeEnd: 2},
		}
	}
	if _, _, err := bridge.PutLocals(items); err != nil {
		t.Fatalf("PutLocals: %v", err)
	}
	if err := bridge.Close(); err != nil {
		t.Fatalf("bridge.Close: %v", err)
	}
	if err := engine.Close(); err != nil {
		t.Fatalf("engine.Close: %v", err)
	}

	rep, err := dur.ReplayWAL(walPath)
	if err != nil {
		t.Fatalf("ReplayWAL: %v", err)
	}
	ix := NewWith(4, 3600*1e9)
	for _, r := range rep.Ordered {
		if r.Type == dur.WALRecMutationV2 && !r.Mutation.Legacy {
			ix.Apply(Record{EntityID: r.Mutation.EntityID, H3Index: r.Mutation.Full.H3Index, SystemTime: r.Mutation.Full.SystemTime})
		}
	}

	recovered, rWal, rep2, err := dur.RecoverEngine(harnessOrigin, walPath, 64*1024*1024)
	if err != nil {
		t.Fatalf("RecoverEngine: %v", err)
	}
	rb := dur.NewBridge(recovered, rWal, 0)
	rb.SetScratchDir(rep2.ScratchDir)
	defer func() {
		if cerr := rb.Close(); cerr != nil {
			t.Logf("recovered bridge.Close: %v", cerr)
		}
	}()
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("ent-boot-eq-%d", i)
		wantCell := uint64(0xCC00 + i)
		entries := recovered.PointGet(id)
		if len(entries) == 0 {
			t.Fatalf("recovered engine lost entity %s", id)
		}
		best := entries[0]
		for _, e := range entries[1:] {
			if e.SystemTime > best.SystemTime {
				best = e
			}
		}
		if best.H3Index != wantCell {
			t.Fatalf("engine/WAL disagree on %s: h3=%x want %x", id, best.H3Index, wantCell)
		}
		if got := ix.CandidatesByH3(wantCell); len(got) != 1 || got[0] != id {
			t.Fatalf("boot equivalence: index/engine disagree on %s: candidates=%v want [%s] — the boot feed is incomplete or dominance diverged", id, got, id)
		}
	}
	if st := ix.Stats(); st.Entities != n {
		t.Fatalf("boot equivalence: %d entities boot-fed, want %d", st.Entities, n)
	}
}

// harnessNoopLister provides an empty durable tier: ListObjects returns no
// objects and Download returns an error. Resolver composition therefore uses
// only the live source, with checkpoints disabled.
type harnessNoopLister struct{}

func (harnessNoopLister) ListObjects(ctx context.Context, bucket, prefix string, maxKeys int) ([]string, error) {
	return nil, nil
}

func (harnessNoopLister) Download(ctx context.Context, bucket, key string) (io.ReadCloser, error) {
	return io.NopCloser(nil), fmt.Errorf("harness: the empty durable tier never downloads")
}

// harnessLiveSource adapts the engine to the resolver's live-read interface.
// It applies the SystemTime <= txTimeNs visibility filter and maps matching
// entries to LiveEvent values. Payload remains nil because PayloadDigest
// identifies the content.
type harnessLiveSource struct {
	engine *eng.DeltaCRDTEngine
}

func (h harnessLiveSource) LiveRead(ctx context.Context, entityID string, txTimeNs int64) ([]db.LiveEvent, error) {
	entries := h.engine.PointGet(entityID)
	out := make([]db.LiveEvent, 0, len(entries))
	for _, e := range entries {
		if e.SystemTime > txTimeNs {
			continue // Filter2: the visibility bound
		}
		out = append(out, db.LiveEvent{
			SystemTime:     e.SystemTime,
			ValidTimeStart: e.ValidTimeStart,
			ValidTimeEnd:   e.ValidTimeEnd,
			AssertionTime:  e.AssertionTime,
			H3Index:        e.H3Index,
			PayloadDigest:  e.PayloadDigest,
		})
	}
	return out, nil
}

// TestFeed_ResolverComposition resolves index candidates with Resolver.AsOf
// over a live engine and an empty durable tier. A future-dated write must be
// invisible at the query's transaction time. Equal-time writes to two cells
// exercise the filter that discards a candidate whose resolved row names a
// different cell.
//
// Negative control: removing the resolved-H3Index filter retains the tie
// entity as a false member and fails the exact-membership assertion.
func TestFeed_ResolverComposition(t *testing.T) {
	engine := harnessEngine(t)
	ix := NewWith(8, 3600*1e9)
	write := func(id string, h3 uint64, sys int64) {
		e := eng.CRDTEntry{PayloadDigest: sha256.Sum256([]byte(id)), H3Index: h3, SystemTime: sys, ValidTimeStart: 1, ValidTimeEnd: 2000}
		engine.InsertLocal(id, e)
		ix.Apply(Record{EntityID: id, H3Index: h3, SystemTime: sys})
	}
	write("ent-r-a", 0xEE01, 500)
	write("ent-r-b", 0xEE01, 501)
	write("ent-r-c", 0xEE01, 502)
	write("ent-r-d", 0xEE02, 503)
	write("ent-r-future", 0xEE01, 10_000) // invisible at txTime=900
	write("ent-r-tie", 0xEE04, 501)       // the tie's first cell...
	write("ent-r-tie", 0xEE01, 501)       // ...and its equal-sys second cell

	cfg := db.DefaultResolverConfig()
	cfg.LiveSource = harnessLiveSource{engine: engine}
	r := db.NewResolver(harnessNoopLister{}, harnessNoopLister{}, db.NewJemallocAllocator(), "harness", cfg)
	ctx := context.Background()
	valid := time.Unix(0, 1000)
	tx := time.Unix(0, 900)

	members := map[string]bool{}
	for _, cand := range ix.CandidatesByH3(0xEE01) {
		ev, err := r.AsOf(ctx, cand, valid, tx)
		if err != nil {
			continue // the skip-not-error rule: no visible row at txTime
		}
		if ev.H3Index == 0xEE01 { // discard candidates resolved to another cell
			members[cand] = true
		}
	}
	want := map[string]bool{"ent-r-a": true, "ent-r-b": true, "ent-r-c": true}
	if len(members) != len(want) {
		t.Fatalf("resolver.composition: QueryByH3(0xEE01) at txTime=900: got %d members %v, want exactly %v — the composition is not exact (a false candidate survived or a true member was lost)", len(members), members, want)
	}
	for w := range want {
		if !members[w] {
			t.Fatalf("resolver.composition: true member %s lost", w)
		}
	}
	if members["ent-r-future"] {
		t.Fatalf("resolver.composition: the future-dated row (sys=10000) must be skipped at txTime=900, not returned")
	}
	if members["ent-r-tie"] {
		t.Fatalf("resolver.composition: the tie entity resolved to cell 0xEE04 (the resolver's first-encountered tie rule) — it must be trimmed from 0xEE01's members by the h3 filter")
	}
	// No entity other than the tie may resolve into EE04.
	for _, cand := range ix.CandidatesByH3(0xEE04) {
		ev, err := r.AsOf(ctx, cand, valid, tx)
		if err == nil && ev.H3Index == 0xEE04 && cand != "ent-r-tie" {
			t.Fatalf("resolver.composition: cell 0xEE04 resolved unexpected member %s", cand)
		}
	}
	// The index still lists the future-dated entity as a current-state
	// candidate; Resolver.AsOf applies transaction-time visibility.
	cands := ix.CandidatesByH3(0xEE01)
	found := false
	for _, c := range cands {
		if c == "ent-r-future" {
			found = true
		}
	}
	if !found {
		t.Fatalf("resolver.composition: the future-dated entity must still be a candidate — the index tracks current state; visibility is the resolve's job")
	}
}

// harnessGenKey adapts circl's three-value GenerateKey result to the public
// key, private key pair used by the harness call sites.
func harnessGenKey(t testing.TB) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return pub, priv
}
