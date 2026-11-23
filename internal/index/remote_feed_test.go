// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package index

// These tests exercise the remote ingest feed through HandleFrame,
// HandleBatchFrame, and HandleHybridFrame, including stale writes and an
// unset feeder. They live in internal/index because a pkg/receive test that
// imports pkg/mesh would create an import cycle. A _test.go file can exercise
// both packages without adding a non-test dependency. Local helpers keep the
// file self-contained.

import (
	"crypto/sha256"
	"fmt"
	"testing"

	capnp "capnproto.org/go/capnp/v3"
	"github.com/cloudflare/circl/sign/ed25519"
	capnp_schema "github.com/hr18vk/sovereign/api/capnp/api/capnp"
	adm "github.com/hr18vk/sovereign/pkg/admission"
	attr "github.com/hr18vk/sovereign/pkg/attribution"
	clk "github.com/hr18vk/sovereign/pkg/clock"
	ident "github.com/hr18vk/sovereign/pkg/identity"
	mesh "github.com/hr18vk/sovereign/pkg/mesh"
	recv "github.com/hr18vk/sovereign/pkg/receive"
	eng "github.com/hr18vk/sovereign/pkg/sync"
)

const (
	remoteWallUSec = int64(1_700_000_000_000_000)
	remoteBudgetNS = int64(1_000_000_000) // 1 s budget admits the tests' one-hop relay frames
)

var remoteOrigin = [16]byte{0x25, 0x0f, 0x25, 0x0a, 0x25, 0x0b, 0x25, 0x0c, 0x25, 0x0d, 0x25, 0x0e, 0x25, 0x0f, 0x25, 0x10}

func remotePubArray(pub ed25519.PublicKey) [32]byte {
	var a [32]byte
	copy(a[:], pub)
	return a
}

func remoteSigArray(sig []byte) [64]byte {
	var a [64]byte
	copy(a[:], sig)
	return a
}

func remoteGenKey(t testing.TB) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return pub, priv
}

// remoteEngine builds a fresh engine with an isolated data dir.
func remoteEngine(t testing.TB) *eng.DeltaCRDTEngine {
	t.Helper()
	e, err := eng.NewDeltaCRDTEngine(remoteOrigin, 0, 64*1024*1024)
	if err != nil {
		t.Fatalf("NewDeltaCRDTEngine: %v", err)
	}
	e.SetDataDir(t.TempDir())
	t.Cleanup(func() { _ = e.Close() })
	return e
}

// remoteEventWire builds a canonical single CRDTDeltaEvent inner wire the
// engine accepts (DotNodeID == OriginNodeID, digest == SHA-256(payload)).
func remoteEventWire(t testing.TB, entityID string, h3 uint64, sys int64, dotCounter uint64) []byte {
	t.Helper()
	dgst := sha256.Sum256([]byte(entityID))
	msg, seg, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		t.Fatalf("capnp.NewMessage: %v", err)
	}
	ev, err := capnp_schema.NewRootCRDTDeltaEvent(seg)
	if err != nil {
		t.Fatalf("NewRootCRDTDeltaEvent: %v", err)
	}
	ev.SetVersion(eng.CRDTDeltaEventWireVersion)
	_ = ev.SetPayloadDigest(dgst[:])
	_ = ev.SetOriginNodeID(remoteOrigin[:])
	_ = ev.SetDotNodeID(remoteOrigin[:])
	ev.SetDotCounter(dotCounter)
	ev.SetH3Index(h3)
	ev.SetSystemTime(sys)
	ev.SetValidTimeStart(1)
	ev.SetValidTimeEnd(2)
	ev.SetAssertionTime(sys)
	ev.SetDecisionTime(sys)
	_ = ev.SetEntityId(entityID)
	_ = ev.SetPayload(entityID)
	data, err := msg.Marshal()
	if err != nil {
		t.Fatalf("msg.Marshal: %v", err)
	}
	return data
}

func remoteGateFields(t testing.TB, innerWire []byte) (uint64, [16]byte) {
	t.Helper()
	msg, err := capnp.Unmarshal(innerWire)
	if err != nil {
		t.Fatalf("remoteGateFields: unmarshal: %v", err)
	}
	defer msg.Release()
	ev, err := capnp_schema.ReadRootCRDTDeltaEvent(msg)
	if err != nil {
		t.Fatalf("remoteGateFields: read root: %v", err)
	}
	originBytes, err := ev.OriginNodeID()
	if err != nil {
		t.Fatalf("remoteGateFields: originNodeID: %v", err)
	}
	var origin [16]byte
	copy(origin[:], originBytes)
	return ev.DotCounter(), origin
}

// remoteRelayFrame wraps an inner wire in a one-hop signed v3 relay chain.
func remoteRelayFrame(t testing.TB, innerWire []byte, originPriv ed25519.PrivateKey) []byte {
	t.Helper()
	originSig := ed25519.Sign(originPriv, innerWire)
	relayPub, relayPriv := remoteGenKey(t)
	hop := attr.SignHop(relayPriv, remotePubArray(relayPub), innerWire, nil, 0, remoteWallUSec)
	dotCounter, originNodeID := remoteGateFields(t, innerWire)
	env := attr.NewSignedRelayEnvelopeV3(innerWire, remoteSigArray(originSig), dotCounter, originNodeID, []attr.Hop{hop})
	return env.Marshal()
}

// remoteReceiver constructs a Receiver and an empty identity Directory.
// Callers register the origin and install the index feeder when needed.
func remoteReceiver(t testing.TB, engine *eng.DeltaCRDTEngine, ix *Index) (*recv.Receiver, *ident.Directory) {
	t.Helper()
	bucket := adm.NewPeerBucket()
	sc := clk.NewSyntheticClock(remoteWallUSec)
	capGate := clk.NewIngressHLCScalarCap(sc, engine)
	dir := ident.NewDirectory()
	_ = ix // callers install SetIndexFeeder themselves so the nil case stays covered
	rcv := recv.NewReceiver(bucket, capGate, sc, dir, engine, remoteBudgetNS)
	return rcv, dir
}

// remoteBatchWire builds a CRDTDeltaBatch wire over n distinct entities.
func remoteBatchWire(t testing.TB, base string, n int, h3 uint64, sys int64, firstCounter uint64) []byte {
	t.Helper()
	events := make([]mesh.BuiltEvent, n)
	for i := range events {
		payload := fmt.Sprintf("%s-payload-%d", base, i)
		dgst := sha256.Sum256([]byte(payload))
		e := eng.CRDTEntry{
			PayloadDigest:  dgst,
			OriginNodeID:   remoteOrigin,
			DotNodeID:      remoteOrigin,
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

func remoteBatchEnvelope(batchWire []byte, originPriv ed25519.PrivateKey, originSeq uint64, n int) []byte {
	sig := ed25519.Sign(originPriv, batchWire)
	return attr.MarshalBatchEnvelope(remoteOrigin, remoteSigArray(sig), originSeq, uint16(n), batchWire)
}

// TestRemoteFeed_ThreeHandlers checks that all three remote handlers feed the
// index through Receiver.SetIndexFeeder rather than a manual test emission.
//
// Negative control: removing any one of the three feed calls in receiver.go
// leaves that handler's deltas out of the candidate set and fails this test.
func TestRemoteFeed_ThreeHandlers(t *testing.T) {
	engine := remoteEngine(t)
	ix := NewWith(8, 3600*1e9)
	rcv, dir := remoteReceiver(t, engine, ix)
	rcv.SetIndexFeeder(func(entityID string, h3 uint64, sys int64) {
		ix.Apply(Record{EntityID: entityID, H3Index: h3, SystemTime: sys})
	})
	originPub, originPriv := remoteGenKey(t)
	if err := dir.Register(remoteOrigin, originPub); err != nil {
		t.Fatalf("Directory.Register: %v", err)
	}
	// 1. HandleFrame accepts one frame in a distinct cell.
	inner := remoteEventWire(t, "remote-frame", 0xAA03, 1002, 7)
	if v := rcv.HandleFrame(remoteRelayFrame(t, inner, originPriv)); v.Verdict != recv.Accept {
		t.Fatalf("HandleFrame: %s %v", v.Verdict, v.Reason)
	}
	// 2. HandleBatchFrame accepts three deltas with one Ed25519 signature over
	// the batch wire.
	batchWire := remoteBatchWire(t, "remote-batch", 3, 0xAA10, 1003, 8)
	if v := rcv.HandleBatchFrame(remoteBatchEnvelope(batchWire, originPriv, 1, 3)); v.Verdict != recv.Accept {
		t.Fatalf("HandleBatchFrame: %s %v", v.Verdict, v.Reason)
	}
	// 3. HandleHybridFrame: three deltas with both Ed25519 and ML-DSA-65
	// signatures enabled.
	originSeed := originPriv.Seed()
	pqPriv, err := ident.GeneratePreviewKey65(originSeed)
	if err != nil {
		t.Fatalf("GeneratePreviewKey65: %v", err)
	}
	if err := dir.RegisterPQ(remoteOrigin, pqPriv.PublicKey()); err != nil {
		t.Fatalf("Directory.RegisterPQ: %v", err)
	}
	rcv.SetHybridVerify(true)
	hybridWire := remoteBatchWire(t, "remote-hybrid", 3, 0xAA20, 1010, 16)
	edSig, pqSig, serr := ident.SignCRDTFrame_Hybrid(originSeed, pqPriv, hybridWire, "")
	if serr != nil {
		t.Fatalf("SignCRDTFrame_Hybrid: %v", serr)
	}
	hframe := attr.MarshalHybridFrame(remoteOrigin, edSig, pqSig, 2, 3, hybridWire)
	if v := rcv.HandleHybridFrame(hframe); v.Verdict != recv.Accept {
		t.Fatalf("HandleHybridFrame: %s %v", v.Verdict, v.Reason)
	}
	// Every written cell must contain exactly the expected candidate.
	want := map[uint64]int{
		0xAA03: 1,
		0xAA10: 1, 0xAA11: 1, 0xAA12: 1,
		0xAA20: 1, 0xAA21: 1, 0xAA22: 1,
	}
	for cell, n := range want {
		if got := ix.CandidatesByH3(cell); len(got) != n {
			t.Fatalf("remote feed: cell %#x: candidates=%v, want count %d — a handler's delta did not reach the index feed", cell, got, n)
		}
	}
	if st := ix.Stats(); st.Entities != 7 {
		t.Fatalf("remote feed: indexed %d entities, want 7 (1 frame + 3 batch + 3 hybrid)", st.Entities)
	}
}

// TestRemoteFeed_StaleNoRegress sends an older remote delta after a newer
// write through Receiver.SetIndexFeeder and light decoding. The older delta
// must not move the entity back to its old cell.
//
// Negative control: changing Apply's dominance guard from `>` to `!=` moves
// the stale delta and fails this test.
func TestRemoteFeed_StaleNoRegress(t *testing.T) {
	engine := remoteEngine(t)
	ix := NewWith(4, 1)
	rcv, dir := remoteReceiver(t, engine, ix)
	rcv.SetIndexFeeder(func(entityID string, h3 uint64, sys int64) {
		ix.Apply(Record{EntityID: entityID, H3Index: h3, SystemTime: sys})
	})
	originPub, originPriv := remoteGenKey(t)
	if err := dir.Register(remoteOrigin, originPub); err != nil {
		t.Fatalf("Directory.Register: %v", err)
	}
	// The newer delta first: sys=200, cell 0xC2, dot 20.
	inner := remoteEventWire(t, "remote-stale", 0xC2, 200, 20)
	if v := rcv.HandleFrame(remoteRelayFrame(t, inner, originPriv)); v.Verdict != recv.Accept {
		t.Fatalf("HandleFrame: %s %v", v.Verdict, v.Reason)
	}
	// The stale delta arrives second: sys=100, cell 0xC1, dot 21.
	inner2 := remoteEventWire(t, "remote-stale", 0xC1, 100, 21)
	if v := rcv.HandleFrame(remoteRelayFrame(t, inner2, originPriv)); v.Verdict != recv.Accept {
		t.Fatalf("HandleFrame(stale): %s %v", v.Verdict, v.Reason)
	}
	if got := ix.CandidatesByH3(0xC1); len(got) != 0 {
		t.Fatalf("stale no regress: the stale remote delta regressed the entity into C1 (candidates=%v) — the dominance guard does not match the query logic", got)
	}
	if got := ix.CandidatesByH3(0xC2); len(got) != 1 || got[0] != "remote-stale" {
		t.Fatalf("stale no regress: the entity lost its C2 membership on a stale write (candidates=%v)", got)
	}
}

// TestRemoteFeed_NilFeederIdentical checks that receivers with and without an
// index feeder accept the same frame. Only the wired receiver adds the delta
// to an index.
func TestRemoteFeed_NilFeederIdentical(t *testing.T) {
	engine := remoteEngine(t)
	// The first receiver has no feeder, as when the index flag is disabled.
	rcv, dir := remoteReceiver(t, engine, NewWith(4, 1))
	// Both directories register the origin so feeder wiring is the only
	// difference between the two receivers.
	engine2 := remoteEngine(t)
	ix := NewWith(4, 1)
	rcv2, dir2 := remoteReceiver(t, engine2, ix)
	rcv2.SetIndexFeeder(func(entityID string, h3 uint64, sys int64) {
		ix.Apply(Record{EntityID: entityID, H3Index: h3, SystemTime: sys})
	})
	originPub, originPriv := remoteGenKey(t)
	for _, d := range []*ident.Directory{dir, dir2} {
		if err := d.Register(remoteOrigin, originPub); err != nil {
			t.Fatalf("Directory.Register: %v", err)
		}
	}
	inner := remoteEventWire(t, "remote-nil", 0xAA01, 1000, 30)
	v1 := rcv.HandleFrame(remoteRelayFrame(t, inner, originPriv))
	inner2 := remoteEventWire(t, "remote-nil", 0xAA01, 1000, 30)
	v2 := rcv2.HandleFrame(remoteRelayFrame(t, inner2, originPriv))
	if v1.Verdict != recv.Accept || v2.Verdict != recv.Accept {
		t.Fatalf("nil feeder: both receivers must Accept (verdicts %s / %s)", v1.Verdict, v2.Verdict)
	}
	// The wired receiver feeds its index; the unwired receiver has no index to
	// update. Both return the same verdict.
	if got := ix.CandidatesByH3(0xAA01); len(got) != 1 {
		t.Fatalf("nil feeder: the wired receiver must feed the index (candidates=%v)", got)
	}
}
