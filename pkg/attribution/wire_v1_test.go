// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package attribution

import (
	"bytes"
	"crypto/rand"
	"testing"

	ed25519 "github.com/cloudflare/circl/sign/ed25519"
	"github.com/hr18vk/sovereign/pkg/identity"
)

// batchTestSeed derives a 32-byte Ed25519 seed for the batch envelope tests.
// identity.SignCRDTFrame takes a seed (the RFC-8032 32-byte seed), so the
// test mints a fresh keypair and reads the seed off the private key. The
// derived public key's first 16 bytes are the originNodeID the receiver
// resolves via Directory.Lookup (mirroring mesh.NewNodeIdentity's derivation).
func batchTestSeed(t *testing.T) (seed []byte, pub ed25519.PublicKey, nodeID [OriginNodeIDSize]byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	seed = priv.Seed()
	copy(nodeID[:], pub[:16])
	return seed, pub, nodeID
}

// fakeBatchWire returns a deterministic stand-in for the marshaled
// CRDTDeltaBatch capnp wire. The BatchEnvelope carries the batch wire verbatim
// and the origin signature covers it directly; the envelope never re-serializes
// the batch, so a fixed buffer is a faithful stand-in that exercises the
// envelope without importing pkg/sync (the cross-package determinism regression
// test lives in pkg/mesh/batch_test.go, where the real capnp wire is built).
func fakeBatchWire(n int) []byte {
	w := make([]byte, n)
	for i := range w {
		w[i] = byte(i)
	}
	return w
}

// signBatch signs the batch wire with the origin seed via
// identity.SignCRDTFrame (randomized-nonce Ed25519 verified by
// VerifyCRDTFrame). It returns the 64-byte signature stored in the envelope header.
func signBatch(t *testing.T, seed, batchWire []byte) [OriginSigSize]byte {
	t.Helper()
	sig, err := identity.SignCRDTFrame(seed, batchWire)
	if err != nil {
		t.Fatalf("SignCRDTFrame: %v", err)
	}
	var arr [OriginSigSize]byte
	copy(arr[:], sig)
	return arr
}

// TestBatchEnvelopeRoundTrip checks every header field and verifies that the
// parsed batchWire is byte-identical to the signed input. Those are the bytes
// the receiver later passes to ApplyCRDTDeltaBatch.
func TestBatchEnvelopeRoundTrip(t *testing.T) {
	seed, _, nodeID := batchTestSeed(t)
	batchWire := fakeBatchWire(256)
	originSig := signBatch(t, seed, batchWire)

	wire := MarshalBatchEnvelope(nodeID, originSig, 42, 7, batchWire)
	env, err := UnmarshalBatchEnvelope(wire)
	if err != nil {
		t.Fatalf("UnmarshalBatchEnvelope: %v", err)
	}
	if env.OriginNodeID() != nodeID {
		t.Errorf("OriginNodeID: got %x, want %x", env.OriginNodeID(), nodeID)
	}
	if env.OriginSig() != originSig {
		t.Errorf("OriginSig: got %x, want %x", env.OriginSig(), originSig)
	}
	if env.OriginSeq() != 42 {
		t.Errorf("OriginSeq: got %d, want 42 (the monotonic per-batch sequence the rate gate drains on)", env.OriginSeq())
	}
	if env.BatchCount() != 7 {
		t.Errorf("BatchCount: got %d, want 7", env.BatchCount())
	}
	if !bytes.Equal(env.BatchWire(), batchWire) {
		t.Fatalf("BatchWire not byte-identical after round-trip — the wire the origin signs must be the wire the receiver applies (the no-hash-then-reconstruct-gap property)")
	}
}

// TestOneSigCoversBatch checks that changing one batchWire byte makes
// VerifyCRDTFrame return false. The origin signature covers the complete
// batch, so verification rejects the modification before the receiver reaches
// ApplyCRDTDeltaBatch.
func TestOneSigCoversBatch(t *testing.T) {
	seed, pub, nodeID := batchTestSeed(t)
	batchWire := fakeBatchWire(256)
	originSig := signBatch(t, seed, batchWire)

	wire := MarshalBatchEnvelope(nodeID, originSig, 1, 4, batchWire)
	env, err := UnmarshalBatchEnvelope(wire)
	if err != nil {
		t.Fatalf("UnmarshalBatchEnvelope: %v", err)
	}

	// The batch verifies under the origin's public key.
	parsedSig := env.OriginSig()
	if !identity.VerifyCRDTFrame(pub, env.BatchWire(), parsedSig[:]) {
		t.Fatalf("VerifyCRDTFrame rejected a valid batch — the wire the origin signed must verify")
	}

	// Tamper one byte in the batch wire the receiver would apply. The signature
	// covers the wire directly, so a single flipped byte breaks the verify.
	tampered := make([]byte, len(env.BatchWire()))
	copy(tampered, env.BatchWire())
	tampered[100] ^= 0x01
	if identity.VerifyCRDTFrame(pub, tampered, parsedSig[:]) {
		t.Fatalf("VerifyCRDTFrame accepted a tampered batch — the one-sig-covers-the-batch binding is broken (a single flipped byte must fail verify)")
	}
}

// TestVersionGateRejects_v0 checks that an unsupported version returns
// ErrBatchMalformed instead of being interpreted using the v1 header layout.
// The test changes the version byte to WireV1Version + 1.
func TestVersionGateRejects_v0(t *testing.T) {
	seed, _, nodeID := batchTestSeed(t)
	batchWire := fakeBatchWire(64)
	originSig := signBatch(t, seed, batchWire)

	wire := MarshalBatchEnvelope(nodeID, originSig, 1, 1, batchWire)
	// Flip the version byte to a value != WireV1Version.
	wire[4] = WireV1Version + 1
	if _, err := UnmarshalBatchEnvelope(wire); err != ErrBatchMalformed {
		t.Fatalf("UnmarshalBatchEnvelope with wrong version: got %v, want ErrBatchMalformed (the version is honored — no silent downgrade)", err)
	}
}

// TestZeroOriginSigRejected proves a zero originSig is rejected pre-verify —
// no unsigned batch is accepted (the unsigned-batch regression test, mirroring
// envelope.go's zero-originSig rule). A batch that failed to sign produces a
// wire the receiver drops, never a silent accept.
func TestZeroOriginSigRejected(t *testing.T) {
	_, _, nodeID := batchTestSeed(t)
	batchWire := fakeBatchWire(64)
	var zeroSig [OriginSigSize]byte

	wire := MarshalBatchEnvelope(nodeID, zeroSig, 1, 1, batchWire)
	if _, err := UnmarshalBatchEnvelope(wire); err != ErrBatchUnsigned {
		t.Fatalf("UnmarshalBatchEnvelope with zero originSig: got %v, want ErrBatchUnsigned (no unsigned batch is accepted)", err)
	}
}

// TestBatchEnvelopeHeaderOnlyOpaquesBatchWire checks that the parser accepts
// an empty batchWire when the header is valid. The envelope parser does not
// decode that payload; ApplyCRDTDeltaBatch handles payload errors after
// signature verification.
func TestBatchEnvelopeHeaderOnlyOpaquesBatchWire(t *testing.T) {
	seed, _, nodeID := batchTestSeed(t)
	// A zero-length batch wire is a malformed CRDTDeltaBatch (the capnp decode
	// inside ApplyCRDTDeltaBatch would reject it), but the header parse must
	// succeed — the parser does not touch the batch wire.
	batchWire := []byte{}
	originSig := signBatch(t, seed, batchWire)

	wire := MarshalBatchEnvelope(nodeID, originSig, 1, 0, batchWire)
	env, err := UnmarshalBatchEnvelope(wire)
	if err != nil {
		t.Fatalf("UnmarshalBatchEnvelope with empty batchWire: got %v, want nil (the header parse must not decode the batch wire — it is opaque until verify)", err)
	}
	if len(env.BatchWire()) != 0 {
		t.Errorf("BatchWire len: got %d, want 0 (the empty batch wire is carried verbatim)", len(env.BatchWire()))
	}
}

// TestIsBatchFrameDispatch checks recognition of a batch frame, rejection of
// a relay version prefix, and rejection of a frame too short to contain the
// four-byte magic. These cases keep batch and relay frames on their respective
// parser paths.
func TestIsBatchFrameDispatch(t *testing.T) {
	seed, _, nodeID := batchTestSeed(t)
	batchWire := fakeBatchWire(32)
	originSig := signBatch(t, seed, batchWire)
	batchFrame := MarshalBatchEnvelope(nodeID, originSig, 1, 1, batchWire)

	if !IsBatchFrame(batchFrame) {
		t.Fatalf("IsBatchFrame rejected a real batch frame — the dispatch would misroute it to HandleFrame (a silent throughput collapse)")
	}

	// A RelayEnvelope's first 2 bytes are its uint16 LE version (2 or 3). Build
	// a stand-in relay frame whose first bytes are 0x03 0x00 (version 3 LE) and
	// assert the dispatch routes it to the relay path (not a batch).
	relayFrame := make([]byte, 16)
	relayFrame[0] = 0x03 // version 3 low byte (little-endian)
	relayFrame[1] = 0x00 // version 3 high byte
	if IsBatchFrame(relayFrame) {
		t.Fatalf("IsBatchFrame accepted a relay frame (version 3 LE prefix) — the dispatch would misroute a relay frame to HandleBatchFrame")
	}

	// A too-short frame (fewer than 4 bytes) is not a batch (the peek cannot
	// read the magic); it routes to the relay path, which will DropMalformed it.
	if IsBatchFrame([]byte{0x53, 0x42}) {
		t.Fatalf("IsBatchFrame accepted a too-short frame — the peek must require 4 bytes")
	}
}
