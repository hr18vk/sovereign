// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

// Group-commit tests for the batched WAL append and control-plane insert paths
// (ADR-0044). Package mesh gives the tests access to the unexported response
// types and Gossiper batch methods.
//
// The tests cover three contracts: AppendMutations syncs once per batch rather
// than once per mutation, a failed batch sync marks every valid item unavailable,
// and replaying batch-written records reconstructs the live Merkle root. The
// per-mutation append loop and mixed response assertions distinguish these
// contracts from the behavior they replace.

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/hr18vk/sovereign/internal/chaos"
	"github.com/hr18vk/sovereign/pkg/durability"
	"github.com/hr18vk/sovereign/pkg/identity"
	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// ---------------------------------------------------------------------------
// Batch sync count.
// ---------------------------------------------------------------------------

// TestMeshGroupCommitCount counts sync calls through the WAL's test hook. One
// AppendMutations call for 1,000 entries must sync once; 1,000 separate
// AppendMutation calls must sync 1,000 times. The second assertion also detects
// a hook that never runs. Production leaves the hook nil and calls the file's
// Sync method directly.
func TestMeshGroupCommitCount(t *testing.T) {
	// OpenWAL writes real records, while the test hook replaces only the file
	// sync. Counting calls through the hook avoids disk latency and keeps the
	// measurement deterministic.
	walPath := filepath.Join(t.TempDir(), "group-count.wal")
	wal, err := chaos.OpenWAL(walPath)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	t.Cleanup(func() { _ = wal.Close() })

	var fsyncCount int64
	wal.SetSyncHookForTest(func() error {
		atomic.AddInt64(&fsyncCount, 1)
		return nil // do not call the real fsync — the count is the measurement
	})

	// Build 1000 distinct mutations.
	const N = 1000
	mutations := make([]chaos.WALMutation, N)
	for i := 0; i < N; i++ {
		var digest [32]byte
		digest[0] = byte(i)
		// Trailing 0x01 keeps the synthetic nodeID nonzero at i=0 (validateV2
		// rightly rejects a zero OriginNodeID).
		nodeID := [16]byte{byte(i), byte(i >> 8), byte(i >> 16), byte(i >> 24), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
		// NewWALMutation (ADR-0045 §6): full 120-byte entry, dot + origin
		// stamped from the dot — the one construction discipline.
		mutations[i] = chaos.NewWALMutation(
			fmt.Sprintf("group-count-entity-%d", i),
			eng.CausalDot{NodeID: nodeID, Counter: uint64(i + 1)},
			eng.CRDTEntry{PayloadDigest: digest, SystemTime: int64(i) * 1_000})
	}

	// Append the batch and verify that it syncs once.
	atomic.StoreInt64(&fsyncCount, 0) // reset before the batch
	if _, err := wal.AppendMutations(mutations); err != nil {
		t.Fatalf("group commit count: AppendMutations: %v", err)
	}
	batchCount := atomic.LoadInt64(&fsyncCount)
	if batchCount != 1 {
		t.Fatalf("group commit count fail: AppendMutations issued %d fsyncs for a %d-entry batch, want exactly 1 (the 1000× fsync-count cut — a per-mutation fsync inside AppendMutations is a regression)", batchCount, N)
	}

	// The per-mutation path is the control: 1000 calls must sync 1000 times.
	// Records from both paths share this WAL because only sync counts matter here.
	atomic.StoreInt64(&fsyncCount, 0)
	for i := 0; i < N; i++ {
		if err := wal.AppendMutation(mutations[i]); err != nil {
			t.Fatalf("group commit count: AppendMutation %d: %v", i, err)
		}
	}
	perMutCount := atomic.LoadInt64(&fsyncCount)
	if perMutCount != int64(N) {
		t.Fatalf("group commit count fail: %d AppendMutation calls issued %d fsyncs, want %d (the per-mutation path is the control — a broken syncHook that never fires would make both legs 0, caught here)", N, perMutCount, N)
	}

	// The ratio must be 1000: one batch sync versus one sync per mutation.
	ratio := perMutCount / batchCount
	if ratio != int64(N) {
		t.Fatalf("group commit count fail: fsync-count-cut ratio = %d, want %d (the 1000× cut)", ratio, N)
	}
	t.Logf("group commit count: AppendMutations(1000 entries) = %d sync; 1000 AppendMutation calls = %d syncs; ratio = %d", batchCount, perMutCount, ratio)
}

// ---------------------------------------------------------------------------
// Batch failure acknowledgement (ADR-0044 §4).
// ---------------------------------------------------------------------------

// TestMeshGroupCommitAck makes the batch's only WAL sync fail. Every valid item
// must receive status 503 with an empty dot, Inserted must remain zero, and the
// HTTP request itself must still return 200 with failures described in its body.
// Checking every item distinguishes batch atomicity from per-item failure
// reporting; the sync counter also verifies that only one sync was attempted.
func TestMeshGroupCommitAck(t *testing.T) {
	walPath := filepath.Join(t.TempDir(), "group-ack.wal")
	wal, err := durability.OpenWAL(walPath)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	t.Cleanup(func() { _ = wal.Close() })

	// Fail the batch's only sync. The hook is set on the *chaos.WAL underlying
	// the durability alias; both names refer to the same instance.
	var fsyncCalls int64
	chaosWAL := durability.WALAsChaos(wal) // the underlying *chaos.WAL (alias)
	chaosWAL.SetSyncHookForTest(func() error {
		atomic.AddInt64(&fsyncCalls, 1)
		return fmt.Errorf("group commit ack: injected Sync failure")
	})

	// Build the harness (mirrors newBatchControlServer in the batch-insert test).
	eng.DataDir = t.TempDir()
	engine, err := eng.NewDeltaCRDTEngine(test503NodeID, 1, 64*1024*1024)
	if err != nil {
		t.Fatalf("NewDeltaCRDTEngine: %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	bridge := durability.NewBridge(engine, wal, 0)
	g := NewGossiper(nil, nil, engine, identity.NewDirectory())
	g.SetBridge(bridge)
	cs := NewControlServer(g, test503NodeID, nil, nil)
	srv := httptest.NewServer(cs.Handler())
	t.Cleanup(srv.Close)

	// A batch of 5 valid entries (no empty keys — the 400 path is not exercised
	// here; this test isolates the 503-all atomicity). The Sync is rigged to
	// fail on the batch's single fsync → all 5 must be 503.
	const n = 5
	items := make([]batchItemReq, n)
	for i := 0; i < n; i++ {
		items[i] = batchItemReq{Key: batchKey(i), Val: batchVal(i)}
	}
	r := postBatch(t, srv, items)

	// The HTTP layer is 200 (per-batch failures are in the body, not the HTTP
	// status — the same discipline postBatch and the batch-insert test pin).
	if r.Inserted != 0 {
		t.Fatalf("group commit ack fail: Inserted=%d, want 0 (the Sync is rigged to fail → no entry is durable)", r.Inserted)
	}
	if r.Failed != n {
		t.Fatalf("group commit ack fail: Failed=%d, want %d (the per-batch atomicity — all valid entries 503 on a Sync failure)", r.Failed, n)
	}
	if len(r.Items) != n {
		t.Fatalf("group commit ack fail: len(Items)=%d, want %d", len(r.Items), n)
	}
	// Every valid entry must be 503. A per-entry 503 regression would leave the
	// pre-failure entries as 200 — this loop fails on the first 200. This is the
	// load-bearing assertion that distinguishes per-batch from per-entry.
	for _, st := range r.Items {
		if st.Code != http.StatusServiceUnavailable {
			t.Fatalf("group commit ack fail: entry index %d Code=%d, want 503 for all %d entries (the per-batch atomicity — a per-entry 503 regression would leave this as %d); DotHex=%q", st.Index, st.Code, n, http.StatusOK, st.DotHex)
		}
		if st.DotHex != "" {
			t.Fatalf("group commit ack fail: entry index %d DotHex=%q, want empty (no receipt for a non-durable batch)", st.Index, st.DotHex)
		}
	}
	// The Sync was called exactly once (the batch's single fsync — the count cut
	// holds even on the failure path: one fsync attempt, one failure, all 503).
	if got := atomic.LoadInt64(&fsyncCalls); got != 1 {
		t.Fatalf("group commit ack fail: the rigged Sync was called %d times, want 1 (the batch's single fsync — a per-mutation fsync would call it %d times)", got, n)
	}
	t.Logf("group commit ack pass: a rigged Sync failure → all %d valid entries Code 503 (per-batch atomicity, not per-entry); the Sync was called exactly once (the count cut holds on the failure path)", n)
}

// ---------------------------------------------------------------------------
// Batch WAL replay determinism.
// ---------------------------------------------------------------------------

// TestMeshGroupCommitDeterminism appends a batch of live-minted mutations and
// replays its length-prefixed records into a fresh engine. Each replayed dot must
// match the corresponding InsertLocal result, and the recovered Merkle root must
// equal the live root. Restoring the recorded dots avoids deriving an initial
// Lamport counter from the mutation count, which is invalid when concurrent
// minting and WAL appends reorder (ADR-0045 §4).
func TestMeshGroupCommitDeterminism(t *testing.T) {
	walPath := filepath.Join(t.TempDir(), "group-det.wal")
	wal, err := chaos.OpenWAL(walPath)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	t.Cleanup(func() { _ = wal.Close() })

	// A non-zero localNodeID + a non-zero initial counter (the same shape the
	// single-entry determinism test uses — a fresh boot at 0 is the trivial
	// case; the rejoin-at-7 start proves the exact-dot restore needs no seed
	// derivation at all).
	var nodeID [16]byte
	for i := range nodeID {
		nodeID[i] = byte(i + 1)
	}
	const initialCounter uint64 = 7
	const N = 64

	// Build the live engine and insert N mutations, appending the whole batch via
	// AppendMutations (the batch path — one fsync for all N).
	eng.DataDir = t.TempDir()
	live, err := eng.NewDeltaCRDTEngine(nodeID, initialCounter, 64*1024*1024)
	if err != nil {
		t.Fatalf("NewDeltaCRDTEngine live: %v", err)
	}
	t.Cleanup(func() { _ = live.Close() })

	mutations := make([]chaos.WALMutation, N)
	liveDots := make([]eng.CausalDot, 0, N)
	for i := 0; i < N; i++ {
		entityID := "entity-" + string([]byte{byte(i), byte(i >> 8), byte(i >> 16), byte(i >> 24)})
		entry := eng.CRDTEntry{
			PayloadDigest: sha256FirstByte(i),
			OriginNodeID:  originFromIndex(i),
			SystemTime:    int64(i) * 1_000,
		}
		dot := live.InsertLocal(entityID, entry)
		liveDots = append(liveDots, dot)
		// NewWALMutation records the engine-stamped dot and the full entry; the
		// caller's pre-insert entry has no dot or origin (ADR-0045 §6).
		mutations[i] = chaos.NewWALMutation(entityID, dot, entry)
	}
	if _, err := wal.AppendMutations(mutations); err != nil {
		t.Fatalf("group commit determinism: AppendMutations: %v", err)
	}
	liveRoot := live.State().MerkleRoot()
	if err := wal.AppendCheckpoint(chaos.WALCheckpoint{
		MerkleRoot:  liveRoot,
		LamportHigh: live.LamportCounter(),
	}); err != nil {
		t.Fatalf("group commit determinism: AppendCheckpoint: %v", err)
	}

	// Replay restores each recorded dot through a synthetic-delta Join; it does
	// not derive a counter from LamportHigh-len(Mutations), which is invalid when
	// concurrent minting and appends reorder (ADR-0045 §4).
	rep, err := chaos.ReplayWAL(walPath)
	if err != nil {
		t.Fatalf("group commit determinism: ReplayWAL: %v", err)
	}
	if len(rep.Mutations) != N {
		t.Fatalf("group commit determinism: replay got %d mutations, want %d (the batch path wrote %d individual WALRecMutation records — ReplayWAL scans record-by-record via length-prefix)", len(rep.Mutations), N, N)
	}
	// Recover into a fresh DataDir (the same discipline the single-entry
	// determinism test uses): the live engine captured its own t.TempDir() at
	// construction, and its async persist worker may have flushed a
	// lamport_<nodeID>.dat there. The recovered engine reads a fresh dir (no
	// persisted high-water) — a test-harness concern; production recovery
	// replays into the engine's own dataDir, empty on a cold boot.
	recoverDir := t.TempDir()
	eng.DataDir = recoverDir
	recovered, err := eng.NewDeltaCRDTEngine(nodeID, 1, 64*1024*1024)
	if err != nil {
		t.Fatalf("group commit determinism: NewDeltaCRDTEngine recovered: %v", err)
	}
	t.Cleanup(func() { _ = recovered.Close() })

	// Every batch-written record must carry the live-minted dot verbatim.
	for i, m := range rep.Mutations {
		if m.NodeID != liveDots[i].NodeID || m.Counter != liveDots[i].Counter {
			t.Fatalf("group commit determinism: record %d carries dot (%x,%d), want the live-minted (%x,%d) — the batch path recorded the wrong dot",
				i, m.NodeID, m.Counter, liveDots[i].NodeID, liveDots[i].Counter)
		}
	}
	// Exact-dot restore: Join honors each recorded dot verbatim (C1 idempotent).
	muts := rep.Mutations
	recovered.Join(eng.CRDTDelta{Entries: func(yield func(string, eng.CRDTEntry) bool) {
		for i := range muts {
			if !yield(muts[i].EntityID, muts[i].Full) {
				return
			}
		}
	}})
	// Nail the clock to the WAL high-water (the production path's final
	// AdvanceLamportTo — monotone max).
	recovered.AdvanceLamportTo(rep.LamportHigh)

	recoveredRoot := recovered.State().MerkleRoot()
	if recoveredRoot != liveRoot {
		t.Fatalf("group commit determinism: batch-written WAL replay produced a different state:\n  live root = %x\n  recovered root = %x", liveRoot, recoveredRoot)
	}
	if recovered.LamportCounter() != rep.LamportHigh {
		t.Fatalf("group commit determinism fail: recovered lamport %d != checkpoint lamportHigh %d", recovered.LamportCounter(), rep.LamportHigh)
	}
	t.Logf("group commit determinism pass: a %d-entry batch written via AppendMutations replays into a fresh engine and the rebuilt MerkleRoot == the live root (the determinism contract preserved under group-commit — ReplayWAL sees N individual WALRecMutation records, byte-identical to N AppendMutation calls)", N)
}

// ---------------------------------------------------------------------------
// Local digest and origin helpers; the batch request helpers are shared with
// the batch-insert tests in this package.
// ---------------------------------------------------------------------------

// sha256FirstByte returns a 32-byte digest whose first byte is i (a stable,
// content-distinct payload digest per mutation index — mirrors stagedEntry's
// sha256-of-i pattern without importing internal/chaos test helpers).
func sha256FirstByte(i int) [32]byte {
	var d [32]byte
	d[0] = byte(i)
	d[1] = byte(i >> 8)
	d[2] = byte(i >> 16)
	return d
}

// originFromIndex returns a 16-byte origin nodeID derived from i (mirrors
// stagedEntry's binary.BigEndian.PutUint64(origin[:8], uint64(i+100))).
func originFromIndex(i int) [16]byte {
	var o [16]byte
	o[0] = byte(uint64(i+100) >> 56)
	o[1] = byte(uint64(i+100) >> 48)
	o[2] = byte(uint64(i+100) >> 40)
	o[3] = byte(uint64(i+100) >> 32)
	o[4] = byte(uint64(i+100) >> 24)
	o[5] = byte(uint64(i+100) >> 16)
	o[6] = byte(uint64(i+100) >> 8)
	o[7] = byte(uint64(i + 100))
	return o
}

// hexDump is a small helper for diagnostic output (not load-bearing).
func hexDump(b [32]byte) string { return hex.EncodeToString(b[:]) }

// bytesUnused keeps the bytes import used by the shared batch-insert helpers.
var bytesUnused = bytes.NewBuffer(nil)
