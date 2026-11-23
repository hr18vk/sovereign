// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// CRDT wire-format roundtrip tests.
//
// A delta generated on one engine is encoded as CRDTDeltaEvent, sent through a
// channel, decoded on a second engine, and joined. The assertions compare every
// CRDTEntry field and the full entity ID and payload. Separate tests pin the
// ingestion and CRDT schema accessor surfaces and single-segment framing.
package sync

import (
	"crypto/sha256"
	"encoding/binary"
	"testing"

	capnp "capnproto.org/go/capnp/v3"
	capnp_schema "github.com/hr18vk/sovereign/api/capnp/api/capnp"
)

// Deterministic, field-distinct sentinel constants. No time.Now(), no RNG.
// Every temporal dim is a distinct nonzero sentinel; the entityID is long;
// the payload string is recoverable bytes that are deliberately not byte-equal
// to its SHA-256 digest.
const (
	// 40-char entityID so a 16-byte-truncated entityIDHash[:16] regression
	// changes both the length and the content of the emitted string.
	rtEntityID = "tenant=acme;ledger=txn;id=0a1b2c3d4e5f60718293a4b5c6d7e8f9"

	// rtPayload is recoverable payload text, distinct from the 32 raw bytes
	// of rtPayloadDigest.
	rtPayload = "this-is-recoverable-payload-bytes-not-its-digest"

	// Distinct nonzero sentinels for every CRDTEntry temporal/dot field.
	rtSystemTime     int64  = 0x1111111111111111
	rtValidTimeStart int64  = 0x2222222222222222
	rtValidTimeEnd   int64  = 0x3333333333333333
	rtAssertionTime  int64  = 0x4444444444444444
	rtDecisionTime   int64  = 0x5555555555555555
	rtH3Index        uint64 = 0x8928308280fffff

	// Latitude and longitude belong only to the ingestion schema; CRDTEntry
	// has no corresponding fields. Distinct sentinels keep those dimensions
	// separate in the accessor-surface test.
	rtLatSentinel = 1.5
	rtLngSentinel = -2.5
)

// rtHostA / rtHostB are fixed, distinct 16-byte identities. Distinctness
// matters: if a serializer ever swapped DotNodeID with OriginNodeID, the
// far-side assertion comparing them against rtHostA (and not rtHostB) would
// catch it.
var (
	rtHostA = [16]byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	}
	rtHostB = [16]byte{
		0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
		0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
	}
	// rtPayloadDigest is SHA-256(rtPayload). Kept as a var so init-only
	// computation stays cheap and the digest is identical to what a
	// production PayloadDigest would be.
	rtPayloadDigest [32]byte
)

func init() {
	d := sha256.Sum256([]byte(rtPayload))
	copy(rtPayloadDigest[:], d[:])
}

// replayTriple holds the entity ID and payload alongside the CRDTEntry copied
// from one decoded event. Keeping the payload permits a direct byte comparison
// independently of the digest field.
type replayTriple struct {
	entityID string
	payload  string
	entry    CRDTEntry
}

// makeReplaySeq yields reconstructed entries to Join in wire order.
func makeReplaySeq(rec []replayTriple) Seq {
	return func(yield func(entityID string, entry CRDTEntry) bool) {
		for i := range rec {
			if !yield(rec[i].entityID, rec[i].entry) {
				return
			}
		}
	}
}

// setupRTEngine builds an engine with an isolated on-disk Lamport dir and a
// deterministic node ID, with cleanup wired. Isolating DataDir per test
// prevents cross-test interference on /data/crdt.
func setupRTEngine(tb testing.TB, nodeID [16]byte, initialCounter uint64) *DeltaCRDTEngine {
	tb.Helper()
	oldDataDir := DataDir
	DataDir = tb.TempDir()
	tb.Cleanup(func() { DataDir = oldDataDir })
	eng, err := NewDeltaCRDTEngine(nodeID, initialCounter, 64*1024*1024)
	if err != nil {
		tb.Fatalf("NewDeltaCRDTEngine(%x): %v", nodeID, err)
	}
	tb.Cleanup(func() {
		if cerr := eng.Close(); cerr != nil {
			tb.Logf("engine.Close: %v", cerr)
		}
	})
	return eng
}

// The tests use CRDTDeltaEventWireVersion from crdt_apply.go directly so the
// wire version has one definition.

// encodeEntryToCRDTDeltaEvent serializes an entity ID, payload, and entry with
// the engine-to-engine CRDTDeltaEvent schema, distinct from the client
// ingestion TriTemporalEvent schema. Every CRDTEntry field has a wire field.
//
// Field mapping onto CRDTDeltaEvent (12 contract fields + 1 version tag):
//
//	version        <- CRDTDeltaEventWireVersion (forward-compat tag)
//	payloadDigest  <- entry.PayloadDigest  ([32]byte -> Data)
//	originNodeID   <- entry.OriginNodeID   ([16]byte -> Data)
//	dotNodeID      <- entry.DotNodeID      ([16]byte -> Data)
//	dotCounter     <- entry.DotCounter     (uint64 -> UInt64)
//	h3Index        <- entry.H3Index        (uint64 -> UInt64)
//	systemTime     <- entry.SystemTime
//	validTimeStart <- entry.ValidTimeStart
//	validTimeEnd   <- entry.ValidTimeEnd
//	assertionTime  <- entry.AssertionTime
//	decisionTime   <- entry.DecisionTime
//	entityId       <- entityID string       (not entityIDHash[:16])
//	payload        <- payload string        (bytes, not the digest)
//
// CRDTDeltaEvent carries no latitude/longitude: ingestion-only dimensions.
func encodeEntryToCRDTDeltaEvent(t *testing.T, entityID, payload string, entry CRDTEntry) []byte {
	t.Helper()
	msg, seg, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		t.Fatalf("capnp.NewMessage: %v", err)
	}
	ev, err := capnp_schema.NewRootCRDTDeltaEvent(seg)
	if err != nil {
		t.Fatalf("NewRootCRDTDeltaEvent: %v", err)
	}
	ev.SetVersion(CRDTDeltaEventWireVersion)
	if err := ev.SetPayloadDigest(entry.PayloadDigest[:]); err != nil {
		t.Fatalf("SetPayloadDigest: %v", err)
	}
	if err := ev.SetOriginNodeID(entry.OriginNodeID[:]); err != nil {
		t.Fatalf("SetOriginNodeID: %v", err)
	}
	if err := ev.SetDotNodeID(entry.DotNodeID[:]); err != nil {
		t.Fatalf("SetDotNodeID: %v", err)
	}
	ev.SetDotCounter(entry.DotCounter)
	ev.SetH3Index(entry.H3Index)
	ev.SetSystemTime(entry.SystemTime)
	ev.SetValidTimeStart(entry.ValidTimeStart)
	ev.SetValidTimeEnd(entry.ValidTimeEnd)
	ev.SetAssertionTime(entry.AssertionTime)
	ev.SetDecisionTime(entry.DecisionTime)
	if err := ev.SetEntityId(entityID); err != nil {
		t.Fatalf("SetEntityId: %v", err)
	}
	if err := ev.SetPayload(payload); err != nil {
		t.Fatalf("SetPayload: %v", err)
	}
	data, err := msg.Marshal()
	if err != nil {
		t.Fatalf("msg.Marshal: %v", err)
	}
	return data
}

// decodeCRDTDeltaEvent unmarshals a CRDTDeltaEvent and rejects an unsupported
// wire version instead of interpreting it with zero-valued fields.
func decodeCRDTDeltaEvent(t *testing.T, data []byte) capnp_schema.CRDTDeltaEvent {
	t.Helper()
	m, err := capnp.Unmarshal(data)
	if err != nil {
		t.Fatalf("capnp.Unmarshal: %v", err)
	}
	ev, err := capnp_schema.ReadRootCRDTDeltaEvent(m)
	if err != nil {
		t.Fatalf("ReadRootCRDTDeltaEvent: %v", err)
	}
	if ev.Version() != CRDTDeltaEventWireVersion {
		t.Fatalf("CRDTDeltaEvent wire version mismatch: got %d, want %d; refusing to decode zero-valued fields",
			ev.Version(), CRDTDeltaEventWireVersion)
	}
	return ev
}

// TestCapnpWireFormatRoundtrip runs InsertLocal and GenerateDelta on the
// source, transports encoded CRDTDeltaEvent frames over a channel, and joins
// the reconstructed entries on the receiver. It compares all fields after the
// roundtrip.
func TestCapnpWireFormatRoundtrip(t *testing.T) {
	// Source engine.
	engineA := setupRTEngine(t, rtHostA, 0)

	srcEntry := CRDTEntry{
		PayloadDigest:  rtPayloadDigest,
		OriginNodeID:   rtHostA,
		SystemTime:     rtSystemTime,
		ValidTimeStart: rtValidTimeStart,
		ValidTimeEnd:   rtValidTimeEnd,
		AssertionTime:  rtAssertionTime,
		DecisionTime:   rtDecisionTime,
		H3Index:        rtH3Index,
		// DotNodeID/DotCounter are stamped by InsertLocal via NextDot().
	}
	dot := engineA.InsertLocal(rtEntityID, srcEntry)
	srcEntry.DotNodeID = dot.NodeID
	srcEntry.DotCounter = dot.Counter

	if dot.NodeID != rtHostA {
		t.Fatalf("InsertLocal dot.NodeID %x, want %x", dot.NodeID, rtHostA)
	}
	if dot.Counter != 1 {
		t.Fatalf("InsertLocal dot.Counter %d, want 1 (initial counter 0)", dot.Counter)
	}

	// An empty remote IBLT requests the source's full state.
	// An empty IBLT means "peer B knows nothing," so the delta contains every
	// entry host A has. This is the simplest deterministic generate path and
	// avoids the stratified estimator's dynamic sizing.
	emptyRemoteDigest := NewIBLT(1024, 4)
	delta := engineA.GenerateDelta(emptyRemoteDigest)
	defer delta.Release()

	type emittedEntry struct {
		entityID string
		entry    CRDTEntry
	}
	var emitted []emittedEntry
	delta.Entries(func(entityID string, entry CRDTEntry) bool {
		emitted = append(emitted, emittedEntry{entityID, entry})
		return true
	})
	if len(emitted) != 1 {
		t.Fatalf("delta emitted %d entries, want 1", len(emitted))
	}

	// Early producer-side check: the delta iterator must yield the real
	// entityID string, not a 16-byte hash. If the in-process generator were
	// ever regressed to entityIDHash[:16], the emitted string would be 16 raw
	// bytes and would not equal the 40-char rtEntityID.
	if emitted[0].entityID != rtEntityID {
		t.Fatalf("producer-side entityID: got %q (len %d), want %q (len %d) — entityIDHash[:16] regression on the producer",
			emitted[0].entityID, len(emitted[0].entityID), rtEntityID, len(rtEntityID))
	}

	// ---- Transport: capnp encode -> chan []byte ---------------------------------
	transport := make(chan []byte, 4)
	go func() {
		defer close(transport)
		for i := range emitted {
			// Serialize the payload itself; receiver assertions detect digest
			// substitution or truncation.
			data := encodeEntryToCRDTDeltaEvent(t, emitted[i].entityID, rtPayload, emitted[i].entry)
			transport <- data
		}
	}()

	// ---- Host B: receive, decode, reconstruct, Join -----------------------------
	engineB := setupRTEngine(t, rtHostB, 100)

	var reconstructed []replayTriple
	for wire := range transport {
		ev := decodeCRDTDeltaEvent(t, wire)

		gotEID, err := ev.EntityId()
		if err != nil {
			t.Fatalf("EntityId(): %v", err)
		}
		gotPayload, err := ev.Payload()
		if err != nil {
			t.Fatalf("Payload(): %v", err)
		}

		// CRDTDeltaEvent carries every CRDTEntry field. Copy the dot, digest,
		// origin, temporal values, and H3 index directly; the later assertions
		// independently compare payload and digest.
		dotID, err := ev.DotNodeID()
		if err != nil {
			t.Fatalf("DotNodeID(): %v", err)
		}
		origID, err := ev.OriginNodeID()
		if err != nil {
			t.Fatalf("OriginNodeID(): %v", err)
		}
		digest, err := ev.PayloadDigest()
		if err != nil {
			t.Fatalf("PayloadDigest(): %v", err)
		}
		var recEntry CRDTEntry
		copy(recEntry.PayloadDigest[:], digest)
		copy(recEntry.OriginNodeID[:], origID)
		copy(recEntry.DotNodeID[:], dotID)
		recEntry.DotCounter = ev.DotCounter()
		recEntry.H3Index = ev.H3Index()
		recEntry.SystemTime = ev.SystemTime()
		recEntry.ValidTimeStart = ev.ValidTimeStart()
		recEntry.ValidTimeEnd = ev.ValidTimeEnd()
		recEntry.AssertionTime = ev.AssertionTime()
		recEntry.DecisionTime = ev.DecisionTime()
		reconstructed = append(reconstructed, replayTriple{gotEID, gotPayload, recEntry})
	}
	if len(reconstructed) != 1 {
		t.Fatalf("received %d wire frames, want 1", len(reconstructed))
	}

	// Build a CRDTDelta whose Entries Seq replays the reconstructed events
	// into host B via Join. makeReplaySeq (not an inline closure) keeps the
	// function literal out of a composite literal.
	incomingDelta := CRDTDelta{
		OriginNodeID: rtHostA,
		Entries:      makeReplaySeq(reconstructed),
	}
	engineB.Join(incomingDelta)

	// ---- Field-by-field assertions on host B's state -----------------
	got := engineB.State().Get(rtEntityID)
	if len(got) == 0 {
		t.Fatalf("host B State().Get(%q) returned no entries — Join did not apply the delta", rtEntityID)
	}
	if len(got) != 1 {
		t.Fatalf("host B got %d entries for %q, want 1", len(got), rtEntityID)
	}
	gotEntry := got[0]
	gotPayloadOnWire := reconstructed[0].payload

	// Looking up the full entity string on the receiver detects accidental use
	// of a truncated entityIDHash as the map key.
	t.Logf("entityID preserved: State().Get(%q) returned 1 entry", rtEntityID)

	// Payload byte-equality (the actual []byte payload, not its digest). This
	// is the payload-lost assertion: if the serializer ever wrote
	// the digest in the payload slot or dropped the payload field,
	// gotPayloadOnWire would be wrong/empty and this assertion fails.
	if gotPayloadOnWire != rtPayload {
		t.Errorf("payload byte-equality: got %q, want %q — payload-lost/digest-substitution regression",
			gotPayloadOnWire, rtPayload)
	}
	if gotPayloadOnWire == string(rtPayloadDigest[:]) {
		t.Errorf("payload equals the digest bytes — digest-substitution regression")
	}
	if gotPayloadOnWire == string(rtPayloadDigest[:16]) {
		t.Errorf("payload equals digest[:16] — entityIDHash[:16]-style truncation regression")
	}

	// AssertionTime is also present in the client-ingestion schema; the fields
	// below distinguish the dedicated CRDT schema.
	if gotEntry.AssertionTime != rtAssertionTime {
		t.Errorf("AssertionTime: got %#x, want %#x (schema carries this — named-field break if this fails)",
			gotEntry.AssertionTime, rtAssertionTime)
	}

	// The dedicated CRDTDeltaEvent schema carries these fields even though the
	// client-ingestion TriTemporalEvent schema does not.
	if gotEntry.SystemTime != rtSystemTime {
		t.Errorf("SystemTime after roundtrip: got %#x, want %#x", gotEntry.SystemTime, rtSystemTime)
	}
	if gotEntry.ValidTimeStart != rtValidTimeStart {
		t.Errorf("ValidTimeStart after roundtrip: got %#x, want %#x", gotEntry.ValidTimeStart, rtValidTimeStart)
	}
	if gotEntry.ValidTimeEnd != rtValidTimeEnd {
		t.Errorf("ValidTimeEnd after roundtrip: got %#x, want %#x", gotEntry.ValidTimeEnd, rtValidTimeEnd)
	}
	if gotEntry.DecisionTime != rtDecisionTime {
		t.Errorf("DecisionTime after roundtrip: got %#x, want %#x", gotEntry.DecisionTime, rtDecisionTime)
	}
	if gotEntry.H3Index != rtH3Index {
		t.Errorf("H3Index after roundtrip: got %#x, want %#x", gotEntry.H3Index, rtH3Index)
	}
	if gotEntry.DotNodeID != dot.NodeID {
		t.Errorf("DotNodeID after roundtrip: got %x, want %x", gotEntry.DotNodeID, dot.NodeID)
	}
	if gotEntry.DotCounter != dot.Counter {
		t.Errorf("DotCounter after roundtrip: got %d, want %d", gotEntry.DotCounter, dot.Counter)
	}
	if gotEntry.OriginNodeID != rtHostA {
		t.Errorf("OriginNodeID after roundtrip: got %x, want %x", gotEntry.OriginNodeID, rtHostA)
	}
	if gotEntry.PayloadDigest != rtPayloadDigest {
		t.Errorf("PayloadDigest after roundtrip: got %x, want %x", gotEntry.PayloadDigest, rtPayloadDigest)
	}
}

// TestTriTemporalEventSchemaSurfaceIsFiveFields pins the ingestion schema's
// five accessors and checks their values and single-segment framing.
func TestTriTemporalEventSchemaSurfaceIsFiveFields(t *testing.T) {
	msg, seg, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		t.Fatalf("capnp.NewMessage: %v", err)
	}
	ev, err := capnp_schema.NewRootTriTemporalEvent(seg)
	if err != nil {
		t.Fatalf("NewRootTriTemporalEvent: %v", err)
	}

	ev.SetLatitude(rtLatSentinel)
	ev.SetLongitude(rtLngSentinel)
	ev.SetAssertionTime(uint64(rtAssertionTime))
	if err := ev.SetEntityId(rtEntityID); err != nil {
		t.Fatalf("SetEntityId: %v", err)
	}
	if err := ev.SetPayload(rtPayload); err != nil {
		t.Fatalf("SetPayload: %v", err)
	}

	if got := ev.Latitude(); got != rtLatSentinel {
		t.Errorf("Latitude accessor: got %v, want %v", got, rtLatSentinel)
	}
	if got := ev.Longitude(); got != rtLngSentinel {
		t.Errorf("Longitude accessor: got %v, want %v", got, rtLngSentinel)
	}
	if got := ev.AssertionTime(); got != uint64(rtAssertionTime) {
		t.Errorf("AssertionTime accessor: got %#x, want %#x", got, uint64(rtAssertionTime))
	}
	if got, err := ev.EntityId(); err != nil || got != rtEntityID {
		t.Errorf("EntityId accessor: got %q err %v, want %q nil", got, err, rtEntityID)
	}
	if got, err := ev.Payload(); err != nil || got != rtPayload {
		t.Errorf("Payload accessor: got %q err %v, want %q nil", got, err, rtPayload)
	}

	data, err := msg.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if len(data) < 8 {
		t.Fatalf("marshalled message too short: %d", len(data))
	}
	// Single-segment framing invariant — catches framing-header drift.
	if segCountMinusOne := binary.LittleEndian.Uint32(data[0:4]); segCountMinusOne != 0 {
		t.Fatalf("expected single-segment message (segCount-1=0), got %d", segCountMinusOne)
	}
}

// TestCRDTDeltaEventSchemaSurface pins every CRDTDeltaEvent accessor,
// including the version tag. Removing or renaming a field fails compilation;
// accessor values and single-segment framing are checked at run time.
func TestCRDTDeltaEventSchemaSurface(t *testing.T) {
	msg, seg, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		t.Fatalf("capnp.NewMessage: %v", err)
	}
	ev, err := capnp_schema.NewRootCRDTDeltaEvent(seg)
	if err != nil {
		t.Fatalf("NewRootCRDTDeltaEvent: %v", err)
	}

	// Pin the forward-compatibility version accessor.
	ev.SetVersion(CRDTDeltaEventWireVersion)
	if got := ev.Version(); got != CRDTDeltaEventWireVersion {
		t.Fatalf("Version accessor: got %d, want %d", got, CRDTDeltaEventWireVersion)
	}

	// Fixed-size Data ([32]byte / [16]byte x2) + UInt64 x2 + Int64 x5 + Text x2
	// — every accessor below is a compile-time pin on the contract field set.
	if err := ev.SetPayloadDigest(rtPayloadDigest[:]); err != nil {
		t.Fatalf("SetPayloadDigest: %v", err)
	}
	if err := ev.SetOriginNodeID(rtHostA[:]); err != nil {
		t.Fatalf("SetOriginNodeID: %v", err)
	}
	if err := ev.SetDotNodeID(rtHostA[:]); err != nil {
		t.Fatalf("SetDotNodeID: %v", err)
	}
	ev.SetDotCounter(1)
	ev.SetH3Index(rtH3Index)
	ev.SetSystemTime(rtSystemTime)
	ev.SetValidTimeStart(rtValidTimeStart)
	ev.SetValidTimeEnd(rtValidTimeEnd)
	ev.SetAssertionTime(rtAssertionTime)
	ev.SetDecisionTime(rtDecisionTime)
	if err := ev.SetEntityId(rtEntityID); err != nil {
		t.Fatalf("SetEntityId: %v", err)
	}
	if err := ev.SetPayload(rtPayload); err != nil {
		t.Fatalf("SetPayload: %v", err)
	}

	// Read-back of every accessor — a renamed/dropped field fails here at
	// compile time (the accessor no longer exists) or at run time (value
	// mismatch surfaces a wire/encoding drift).
	gotDigest, err := ev.PayloadDigest()
	if err != nil || [32]byte(gotDigest) != rtPayloadDigest {
		t.Errorf("PayloadDigest accessor: got %x err %v, want %x", gotDigest, err, rtPayloadDigest)
	}
	gotOrigin, err := ev.OriginNodeID()
	if err != nil || len(gotOrigin) != len(rtHostA) {
		t.Errorf("OriginNodeID accessor: got %x err %v (len %d), want len %d", gotOrigin, err, len(gotOrigin), len(rtHostA))
	}
	gotDot, err := ev.DotNodeID()
	if err != nil || len(gotDot) != len(rtHostA) {
		t.Errorf("DotNodeID accessor: got %x err %v (len %d), want len %d", gotDot, err, len(gotDot), len(rtHostA))
	}
	if got := ev.DotCounter(); got != 1 {
		t.Errorf("DotCounter accessor: got %d, want 1", got)
	}
	if got := ev.H3Index(); got != rtH3Index {
		t.Errorf("H3Index accessor: got %#x, want %#x", got, rtH3Index)
	}
	if got := ev.SystemTime(); got != rtSystemTime {
		t.Errorf("SystemTime accessor: got %#x, want %#x", got, rtSystemTime)
	}
	if got := ev.ValidTimeStart(); got != rtValidTimeStart {
		t.Errorf("ValidTimeStart accessor: got %#x, want %#x", got, rtValidTimeStart)
	}
	if got := ev.ValidTimeEnd(); got != rtValidTimeEnd {
		t.Errorf("ValidTimeEnd accessor: got %#x, want %#x", got, rtValidTimeEnd)
	}
	if got := ev.AssertionTime(); got != rtAssertionTime {
		t.Errorf("AssertionTime accessor: got %#x, want %#x", got, rtAssertionTime)
	}
	if got := ev.DecisionTime(); got != rtDecisionTime {
		t.Errorf("DecisionTime accessor: got %#x, want %#x", got, rtDecisionTime)
	}
	if got, err := ev.EntityId(); err != nil || got != rtEntityID {
		t.Errorf("EntityId accessor: got %q err %v, want %q nil", got, err, rtEntityID)
	}
	if got, err := ev.Payload(); err != nil || got != rtPayload {
		t.Errorf("Payload accessor: got %q err %v, want %q nil", got, err, rtPayload)
	}

	// Single-segment framing invariant — catches framing-header drift on the
	// CRDTDeltaEvent wire, mirroring the ingestion guard's check.
	data, err := msg.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if len(data) < 8 {
		t.Fatalf("marshalled message too short: %d", len(data))
	}
	if segCountMinusOne := binary.LittleEndian.Uint32(data[0:4]); segCountMinusOne != 0 {
		t.Fatalf("expected single-segment message (segCount-1=0), got %d", segCountMinusOne)
	}

	// Latitude and longitude are ingestion-only fields and are deliberately
	// absent from CRDTDeltaEvent.
}
