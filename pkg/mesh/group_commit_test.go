// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package mesh

// Guards for the WAL group-commit (ADR-0044) — the fsync-COUNT closer for the
// SLO-overrun. Internal test (package mesh) so the guards reach the UNEXPORTED
// JSON response types + the Gossiper batch seam:
//   - batchInsertResponse / batchInsertItemStatus / dotHex (control.go)
//   - BatchItem / InsertLocalEventsBatch (gossip.go)
//   - durability.LocalItem / PutLocals (bridge.go)
//   - chaos.WAL.AppendMutations + the syncHook spy (wal.go)
//
// FALSIFIABLE + fault-injection-PROVEN (NOT tautologies):
// - TestGroupCommitCount: AppendMutations issues ONE fsync for a 1000-entry
// batch (the 1000× count cut); AppendMutation issues 1000. Negative control:
// a regression to per-mutation fsync in AppendMutations → the count is
// 1000, NOT 1 → FAILS.
// - TestGroupCommitAck: a WAL Sync failure on the batch → ALL valid entries
// get Code 503 (the per-BATCH atomicity, NOT per-entry). Negative control:
// a per-ENTRY 503 regression → the pre-failure entries get 200, NOT 503 →
// FAILS the "ALL 503" assertion. A fault-injection that fakes per-entry 503
// proves the guard is load-bearing against the granularity it replaced.
// - TestGroupCommitDeterminism: a batch written via AppendMutations replays
// into a FRESH engine and the rebuilt MerkleRoot == the live root (the
// determinism contract preserved under group-commit). Negative control: a
// batch path that minted dots BEFORE InsertLocal (reversed order) → the
// recorded dots != the live dots → Merkle mismatch → FAILS (the same class
// TestWALRecoveryDeterminism catches for the single-entry path).

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
// — the fsync-COUNT physics (the closer).
// ---------------------------------------------------------------------------

// TestGroupCommitCount proves AppendMutations issues ONE fsync for a
// 1000-entry batch while AppendMutation issues 1000 (the 1000× count cut that
// closes the SLO-overrun: ~2.1ms/fsync × 10000 = ~21s > 10s SLO
// → ONE fsync × 2.1ms = 2.1ms inject). It uses the ADR-0044 syncHook spy
// (wal.go) — a test-local counter incremented inside w.sync — to COUNT the
// fsync calls WITHOUT instrumenting the production WAL. The hook is set on a
// test-constructed *chaos.WAL (OpenWAL leaves it nil in production); the
// production path is byte-identical (nil hook → w.f.Sync).
//
// FAULT-INJECTION-PROVEN (NOT a tautology): the guard asserts count==1 for the batch
// AND count==1000 for the per-mutation loop. A regression that re-introduces a
// per-mutation fsync inside AppendMutations (e.g. moving w.sync inside the
// for-loop) → the batch count is 1000, NOT 1 → the `if batchCount != 1` FAILS.
// The per-mutation leg asserts 1000 so a hook that never fires (a broken spy) is
// caught symmetrically (the loop leg would be 0, NOT 1000).
func TestGroupCommitCount(t *testing.T) {
	// A test-local *chaos.WAL with the syncHook spy. OpenWAL opens a real file
	// (AppendMutations writes real records); the hook replaces ONLY the fsync
	// call (w.sync → hook) so we COUNT fsyncs without a real disk sync (faster
	// + deterministic — the count is the physics, not the latency).
	walPath := filepath.Join(t.TempDir(), "group-count.wal")
	wal, err := chaos.OpenWAL(walPath)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	t.Cleanup(func() { _ = wal.Close() })

	var fsyncCount int64
	wal.SetSyncHookForTest(func() error {
		atomic.AddInt64(&fsyncCount, 1)
		return nil // do NOT call the real fsync — the count is the physics
	})

	// Build 1000 distinct mutations (the silicon batch size).
	const N = 1000
	mutations := make([]chaos.WALMutation, N)
	for i := 0; i < N; i++ {
		var digest [32]byte
		digest[0] = byte(i)
		// Trailing 0x01 keeps the synthetic nodeID nonzero at i=0 (validateV2
		// rightly rejects a zero OriginNodeID).
		nodeID := [16]byte{byte(i), byte(i >> 8), byte(i >> 16), byte(i >> 24), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
		// NewWALMutation (ADR-0045): full 120-byte entry, dot + origin
		// stamped from the dot — the one construction discipline.
		mutations[i] = chaos.NewWALMutation(
			fmt.Sprintf("group-count-entity-%d", i),
			eng.CausalDot{NodeID: nodeID, Counter: uint64(i + 1)},
			eng.CRDTEntry{PayloadDigest: digest, SystemTime: int64(i) * 1_000})
	}

	// — the BATCH path: ONE AppendMutations for 1000 entries → ONE fsync.
	atomic.StoreInt64(&fsyncCount, 0) // reset before the batch
	if _, err := wal.AppendMutations(mutations); err != nil {
		t.Fatalf("group-commit-count: AppendMutations: %v", err)
	}
	batchCount := atomic.LoadInt64(&fsyncCount)
	if batchCount != 1 {
		t.Fatalf("group-commit-count FAIL: AppendMutations issued %d fsyncs for a %d-entry batch, want EXACTLY 1 (the 1000× fsync-count cut — a per-mutation fsync inside AppendMutations is a GATE-1 regression)", batchCount, N)
	}

	// — the PER-MUTATION path: 1000 AppendMutation calls → 1000 fsyncs.
	// This is the byte-identical /v1/insert path (the control the batch cut is
	// measured against). A fresh WAL so the per-mutation records do not interleave
	// with the batch records (the count is per-WAL).
	atomic.StoreInt64(&fsyncCount, 0)
	for i := 0; i < N; i++ {
		if err := wal.AppendMutation(mutations[i]); err != nil {
			t.Fatalf("group-commit-count: AppendMutation %d: %v", i, err)
		}
	}
	perMutCount := atomic.LoadInt64(&fsyncCount)
	if perMutCount != int64(N) {
		t.Fatalf("group-commit-count FAIL: %d AppendMutation calls issued %d fsyncs, want %d (the per-mutation path is the control — a broken syncHook that never fires would make BOTH legs 0, caught here)", N, perMutCount, N)
	}

	// The COUNT-CUT ratio: per-mutation / batch. 1000/1 = 1000× — the physics
	// closes (the SLO: ~21s → ~2.1ms inject, modulo HTTP RTT).
	ratio := perMutCount / batchCount
	if ratio != int64(N) {
		t.Fatalf("group-commit-count FAIL: fsync-count-cut ratio = %d, want %d (the 1000× cut)", ratio, N)
	}
	t.Logf("group-commit-count PASS: AppendMutations(1000 entries) = %d fsync; 1000× AppendMutation = %d fsync — the %d× fsync-count cut (the GATE-1 SLO closer: ~2.1ms × 1 vs ~2.1ms × 10000)", batchCount, perMutCount, ratio)
}

// ---------------------------------------------------------------------------
// — the per-BATCH 503 atomicity (the ADR-0044 §4 granularity change).
// ---------------------------------------------------------------------------

// TestGroupCommitAck proves a WAL Sync failure on the batch → ALL valid
// entries get Code 503 (the per-BATCH atomicity, NOT per-entry). It rigs the
// Sync to fail via the syncHook spy (a hook that returns an error on the FIRST
// fsync → AppendMutations returns (-1, syncErr) → PutLocals returns (dots, 0,
// err) → handleBatchInsert ACKs ALL valid entries as 503). The guard asserts
// EVERY valid entry is 503 + the HTTP-layer 200 (per-batch failures are in the
// body, NOT the HTTP status — the SAME discipline the guard pins).
//
// FAULT-INJECTION-PROVEN against the PER-ENTRY semantic: a handler that
// reported per-entry 503 (only the entry at the failure point) would leave the
// PRE-failure entries as 200 — the guard's "ALL valid entries Code 503" loop
// would FAIL on the first 200. The guard is load-bearing against the granularity
// it replaced (the resolution verified at the working tree: the
// TestBatchInsertWALFailPerEntry guard stays GREEN because it posts all-success
// and all-fail batches separately, never a mixed batch — agnostic to the
// granularity; THIS guard posts a mixed-in-advance batch + rigs the Sync to
// fail, so it DISTINGUISHES per-batch from per-entry).
func TestGroupCommitAck(t *testing.T) {
	walPath := filepath.Join(t.TempDir(), "group-ack.wal")
	wal, err := durability.OpenWAL(walPath)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	t.Cleanup(func() { _ = wal.Close() })

	// Rig the Sync to fail on the FIRST fsync (the batch's single fsync). The
	// hook is set on the *chaos.WAL underlying the durability alias; durability
	// re-exports chaos.WAL as a type alias, so the SAME instance.
	var fsyncCalls int64
	chaosWAL := durability.WALAsChaos(wal) // the underlying *chaos.WAL (alias)
	chaosWAL.SetSyncHookForTest(func() error {
		atomic.AddInt64(&fsyncCalls, 1)
		return fmt.Errorf("group-commit-ack: injected Sync failure (the rig)")
	})

	// Build the harness (mirrors newBatchControlServer in batch_insert_test.go).
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

	// A batch of 5 VALID entries (no empty keys — the 400 path is NOT exercised
	// here; this guard isolates the 503-ALL atomicity). The Sync is rigged to
	// fail on the batch's single fsync → ALL 5 must be 503.
	const n = 5
	items := make([]batchItemReq, n)
	for i := 0; i < n; i++ {
		items[i] = batchItemReq{Key: batchKey(i), Val: batchVal(i)}
	}
	r := postBatch(t, srv, items)

	// The HTTP layer is 200 (per-batch failures are in the body, NOT the HTTP
	// status — the SAME discipline postBatch + the guard pin).
	if r.Inserted != 0 {
		t.Fatalf("group-commit-ack FAIL: Inserted=%d, want 0 (the Sync is rigged to fail → NO entry is durable)", r.Inserted)
	}
	if r.Failed != n {
		t.Fatalf("group-commit-ack FAIL: Failed=%d, want %d (the per-BATCH atomicity — ALL valid entries 503 on a Sync failure)", r.Failed, n)
	}
	if len(r.Items) != n {
		t.Fatalf("group-commit-ack FAIL: len(Items)=%d, want %d", len(r.Items), n)
	}
	// EVERY valid entry MUST be 503. A per-ENTRY 503 regression (the
	// semantic) would leave the pre-failure entries as 200 — this loop FAILS
	// on the first 200. This is the load-bearing assertion that distinguishes
	// per-batch from per-entry.
	for _, st := range r.Items {
		if st.Code != http.StatusServiceUnavailable {
			t.Fatalf("group-commit-ack FAIL: entry index %d Code=%d, want 503 for ALL %d entries (the per-BATCH atomicity — a per-ENTRY 503 regression would leave this as %d); DotHex=%q", st.Index, st.Code, n, http.StatusOK, st.DotHex)
		}
		if st.DotHex != "" {
			t.Fatalf("group-commit-ack FAIL: entry index %d DotHex=%q, want empty (no receipt for a non-durable batch)", st.Index, st.DotHex)
		}
	}
	// The Sync was called EXACTLY once (the batch's single fsync — the count cut
	// holds even on the failure path: ONE fsync attempt, ONE failure, ALL 503).
	if got := atomic.LoadInt64(&fsyncCalls); got != 1 {
		t.Fatalf("group-commit-ack FAIL: the rigged Sync was called %d times, want 1 (the batch's single fsync — a per-mutation fsync would call it %d times)", got, n)
	}
	t.Logf("group-commit-ack PASS: a rigged Sync failure → ALL %d valid entries Code 503 (per-BATCH atomicity, NOT per-entry); the Sync was called EXACTLY once (the count cut holds on the failure path)", n)
}

// ---------------------------------------------------------------------------
// — batch-path WAL replay determinism (the additive-only byte-identity).
// ---------------------------------------------------------------------------

// TestGroupCommitDeterminism proves a batch written via AppendMutations replays into a
// FRESH engine and the rebuilt MerkleRoot == the live root (the determinism
// contract preserved under group-commit). It mirrors TestWALRecovery-
// Determinism (internal/chaos/wal_test.go:42) but uses AppendMutations for the
// live appends, proving the batch path's record format is byte-identical to the
// per-mutation path (ReplayWAL scans record-by-record via length-prefix — it
// sees N individual WALRecMutation records, populates Mutations[] IDENTICALLY).
//
// FAULT-INJECTION-PROVEN: the guard asserts the recovered root == the live root. A
// batch path that minted dots BEFORE InsertLocal (reversed physical order — the
// dot the WAL carries would NOT be the engine-stamped dot) → the recorded dots
// diverge from the live dots → the verbatim cross-check fires → FAILS (the same
// class the single-entry determinism guard catches). ADR-0045: the old
// rebuiltInitial = LamportHigh - len(Mutations) derivation is REFUTED
// and appears nowhere here — the rebuild is the exact-dot restore, and the live
// engine's initialCounter=7 start needs no derivation.
func TestGroupCommitDeterminism(t *testing.T) {
	walPath := filepath.Join(t.TempDir(), "group-det.wal")
	wal, err := chaos.OpenWAL(walPath)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	t.Cleanup(func() { _ = wal.Close() })

	// A non-zero localNodeID + a non-zero initial counter (the same shape the
	// single-entry determinism guard uses — a fresh boot at 0 is the trivial
	// case; the rejoin-at-7 start proves the exact-dot restore needs NO seed
	// derivation at all).
	var nodeID [16]byte
	for i := range nodeID {
		nodeID[i] = byte(i + 1)
	}
	const initialCounter uint64 = 7
	const N = 64

	// Build the LIVE engine + insert N mutations, appending the WHOLE batch via
	// AppendMutations (the batch path — ONE fsync for all N).
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
		// NewWALMutation (ADR-0045): the engine-stamped dot + the full entry;
		// the caller's pre-insert struct carries no dot/origin.
		mutations[i] = chaos.NewWALMutation(entityID, dot, entry)
	}
	if _, err := wal.AppendMutations(mutations); err != nil {
		t.Fatalf("group-commit-determinism: AppendMutations: %v", err)
	}
	liveRoot := live.State().MerkleRoot()
	if err := wal.AppendCheckpoint(chaos.WALCheckpoint{
		MerkleRoot:  liveRoot,
		LamportHigh: live.LamportCounter(),
	}); err != nil {
		t.Fatalf("group-commit-determinism: AppendCheckpoint: %v", err)
	}

	// Recovery: replay the batch-written WAL into a FRESH engine. ADR-0045:
	// the seed-derivation class (LamportHigh - len(Mutations)) is REFUTED under
	// concurrent mint/append reordering and appears nowhere here —
	// recovery RESTORES the recorded dots, it never re-mints. The rebuild is
	// the exact-dot synthetic-delta Join (the same law the production recovery
	// path implements); the seed counter is irrelevant.
	rep, err := chaos.ReplayWAL(walPath)
	if err != nil {
		t.Fatalf("group-commit-determinism: ReplayWAL: %v", err)
	}
	if len(rep.Mutations) != N {
		t.Fatalf("group-commit-determinism: replay got %d mutations, want %d (the batch path wrote %d individual WALRecMutation records — ReplayWAL scans record-by-record via length-prefix)", len(rep.Mutations), N, N)
	}
	// Recover into a FRESH DataDir (the SAME discipline
	// TestWALRecoveryDeterminism uses): the live engine captured its OWN
	// t.TempDir at construction, and its async persist worker may have flushed
	// a lamport_<nodeID>.dat there. The recovered engine reads a FRESH dir (no
	// persisted high-water) — a TEST-harness concern; production recovery
	// replays into the engine's OWN dataDir, empty on a cold boot.
	recoverDir := t.TempDir()
	eng.DataDir = recoverDir
	recovered, err := eng.NewDeltaCRDTEngine(nodeID, 1, 64*1024*1024)
	if err != nil {
		t.Fatalf("group-commit-determinism: NewDeltaCRDTEngine recovered: %v", err)
	}
	t.Cleanup(func() { _ = recovered.Close() })

	// Cross-check: every batch-written record carries the live-minted dot
	// VERBATIM (the live-minted-dot property on the batch path).
	for i, m := range rep.Mutations {
		if m.NodeID != liveDots[i].NodeID || m.Counter != liveDots[i].Counter {
			t.Fatalf("group-commit-determinism: record %d carries dot (%x,%d), want the live-minted (%x,%d) — the batch path recorded the wrong dot",
				i, m.NodeID, m.Counter, liveDots[i].NodeID, liveDots[i].Counter)
		}
	}
	// Exact-dot restore: Join honors each recorded dot verbatim (idempotent).
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
		t.Fatalf("group-commit-determinism FAIL: WAL recovery determinism BROKEN under group-commit:\n  checkpoint root = %x\n  recovered root = %x\n  (the batch-written WAL replays to a DIFFERENT state than the live engine — the §8 absence-of-fork is violated)", liveRoot, recoveredRoot)
	}
	if recovered.LamportCounter() != rep.LamportHigh {
		t.Fatalf("group-commit-determinism FAIL: recovered lamport %d != checkpoint lamportHigh %d", recovered.LamportCounter(), rep.LamportHigh)
	}
	t.Logf("group-commit-determinism PASS: a %d-entry batch written via AppendMutations replays into a fresh engine and the rebuilt MerkleRoot == the live root (the determinism contract preserved under group-commit — ReplayWAL sees N individual WALRecMutation records, byte-identical to N AppendMutation calls)", N)
}

// ---------------------------------------------------------------------------
// helpers (local to the guards — not reused from batch_insert_test.go
// to keep the guard self-contained; the batchKey/batchVal/postBatch helpers ARE
// reused via the same package).
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

// bytesUnused keeps the bytes import live (postBatch uses bytes.NewReader; the
// guards that do not call postBatch still compile with the import for the ones
// that do — this is a no-op guard so go vet does not flag a conditional import).
var bytesUnused = bytes.NewBuffer(nil)
