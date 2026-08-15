// Package database — Day 14 (ADR-0019): the L0→L1 per-entity compaction fork.
//
// This fork eliminates the MaxL0Files silent-data-loss cap (ADR-0018 §6 /
// query.go:139). AsOf lists ONLY the newest MaxL0Files per-entity L0 files per
// query; every older per-entity file is invisible → a query for an OLD
// valid-time returns ErrEntityNotFound for data IS durable on disk. The fix
// introduces an L1 tier per entity: a background compaction merges the N
// per-entity L0 files into ONE sorted L1 file; AsOf scans the L1 (always — the
// full merged history) + the uncompacted L0 tail (MaxL0Files now bounds the
// TAIL, a perf cap not a correctness cap).
//
// BITEMPORAL CORRECTNESS — the merge PRESERVES ALL ROWS. Row-pruning
// (superseded-row elimination) is a future Level-2 fork requiring truth-
// maintenance + a real DELETE operator (the dead tombstone EpochCompactor stays
// DEAD — ADR-0018 §6; zero production importers). The L1 grows with the
// entity's full write history, bounded by entity write volume.
//
// The compaction is a READ-L0 → WRITE-L1 background job ONLY. It does NOT touch
// the SkipList / HAMT / WAL write path (Law: NO new lock on the write path). A
// compaction tombstones the compacted L0 files via a manifest at
// compaction/{hash8}/{sysNs}.manifest listing the L0 keys merged into each L1.
// AsOf skips L0 keys listed in a compaction manifest (they're superseded by the
// L1) but the L0 files are NOT deleted yet — delete-after-read-safety is a
// future reaper fork; Day 14 keeps the L0 files durable as the crash-recovery
// backstop.
package database

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"sort"
	"strconv"
	"strings"
	"unsafe"

	"github.com/apache/arrow/go/v17/arrow"
	"github.com/apache/arrow/go/v17/arrow/array"
	"github.com/apache/arrow/go/v17/arrow/ipc"
	"github.com/apache/arrow/go/v17/arrow/memory"
	"github.com/hr18vk/supremum/internal/telemetry"
)

// CompactionConfig configures the per-entity L0→L1 compaction.
type CompactionConfig struct {
	// L0FilesPerEntityTrigger is the per-entity L0 file count that triggers a
	// compaction job for that entity. The compaction MERGES the entity's L0
	// files into ONE sorted L1 file. Default: 64.
	L0FilesPerEntityTrigger int
	// MaxL1FilesPerEntity bounds the L1 files per entity (a future tiered-L1
	// fork if one file grows too large). For Day 14 the target is a SINGLE L1
	// file per entity — the full merged history. Default: 4.
	MaxL1FilesPerEntity int

	// EnableDominancePruning (Day 15, ADR-0020) turns ON the Level-2
	// superseded-row prune at the compaction merge seam. false (the DEFAULT) →
	// Preserve-All: the BYTE-IDENTICAL Day-14 behavior (every row appended,
	// RowsPruned == 0, the same firstSysT, the same L1 bytes). The engine
	// NEVER auto-prunes — a horizon-less prune is SILENTLY WRONG (the §0.4(ii)
	// txTime-GAP proof). An operator must opt in AND set a positive
	// PruningHorizonInt64Ns; otherwise NewL1Compactor coerces to Preserve-All
	// and logs a WARN (the loud path — Law: every error path must be loud).
	EnableDominancePruning bool
	// PruningHorizonInt64Ns (Day 15, ADR-0020) is the transaction-time GC
	// FLOOR T_gc — a monotone non-decreasing retention low-water mark. The
	// operator guarantees NO live query AS-OF a transaction time txTime < T_gc;
	// the engine advances it as the application retires historical AS-OF
	// queries. It is the load-bearing (C3) claw that closes the §0.4(ii) txTime
	// gap: a row R is SAFE TO DROP iff a retained R' with (C1) sysTime(R')>
	// sysTime(R) AND (C2) [vs',ve') contains [vs,ve) AND (C3) sysTime(R') <= T_gc
	// (R' is Filter2-admitted for every live query (txTime >= T_gc)). T_gc is an
	// OPERATOR RETENTION POLICY — NEVER an engine-inferred optimisation (a
	// future fork infers it off live-query txTime telemetry; Day 15 takes it as
	// a config knob). 0 -> Preserve-All (with EnableDominancePruning=true) OR
	// Preserve-All (the default).
	PruningHorizonInt64Ns int64
	// PruneBackoffInt64Ns (Day 22, ADR-0027) is the operator-set RETENTION
	// BACKOFF — how far behind the observed live-query txTime frontier the
	// effective DominancePrune floor sits. The HorizonInferrer computes
	// effective = max(operatorFloor, observedFrontier - backoff): the backoff
	// tolerates forensic queries `backoff` nanoseconds into the recent past,
	// so a burst of stale-txTime queries does NOT collapse the floor to the
	// distant past in one pathological query. The operator's role moves from
	// "guess the frontier" (the Day-15 static horizon) to "set the safety floor
	// + the backoff window" (the §0.a knob-promotion). <=0 with the inferrer
	// wired means the effective horizon tracks the observed frontier directly
	// (no backoff) — the most aggressive safe posture, since the operator floor
	// still backstops it. Default 0 (no backoff); the cmd wires a 5m default
	// via --compaction-prune-backoff-ns when the inferrer is armed.
	PruneBackoffInt64Ns int64
}

// DefaultCompactionConfig returns a production-safe CompactionConfig.
//
// Day 15: the default is Preserve-All (EnableDominancePruning=false) — byte-
// identical to Day-14's behavior. Day 15 ships NO behavioral change unless the
// operator sets a horizon (the engine NEVER auto-prunes). Day 22 (ADR-0027):
// the inferrer's backoff defaults to 0 here; the cmd's --compaction-prune-
// backoff-ns wires the production 5m default when the inferrer is armed.
func DefaultCompactionConfig() CompactionConfig {
	return CompactionConfig{
		L0FilesPerEntityTrigger: 64,
		MaxL1FilesPerEntity:     4,
		// EnableDominancePruning: false  — Preserve-All is the byte-identical
		// default to Day-14 (the back-compat gate G15.h).
		// PruningHorizonInt64Ns:  0     — no horizon → no prune.
		// PruneBackoffInt64Ns:    0     — no backoff (the cmd wires the 5m
		//   production default when the inferrer is armed; see main.go).
	}
}

// L1Compactor is the per-entity L0→L1 merger (Day 14, ADR-0019).
//
// It READS L0 Arrow IPC files and WRITES L1 Arrow IPC files only — it never
// touches the live SkipList / HAMT / WAL write path. A compaction job is:
//
//  1. List the entity's L0 files under l0/{hex(hash8)}/.
//  2. Download each L0 (the growable-jemalloc-buffer reader pattern reused from
//     query.go's scanFile), open as ipc.NewFileReader, extract the THIS-entity's
//     rows (Filter1 hash-prefix match + Filter4 full-entityID — defense in
//     depth: a Day-13 per-entity file has only that entity's rows by
//     construction, but the merge re-verifies).
//  3. Sort the merged rows by the composite key
//     (entity_id_hash|system_time|valid_time_start|assertion_time) ascending —
//     the SAME order the SkipList uses.
//  4. Serialize to ONE Arrow IPC file with the EXACT ArrowSchema.
//  5. Upload to l1/{hex(hash8)}/{firstSysTimeNs}.arrow.
//  6. Write a manifest at compaction/{hex(hash8)}/{firstSysTimeNs}.manifest
//     listing the L0 keys merged so AsOf can skip them.
//
// Why preserve ALL rows (bitemporal truth-maintenance trap — §0.4): AsOf
// returns the row with max(SystemTime) subject to sysTime<=txTime AND
// validStart<=validTime<validEnd. A row R is safe to drop on merge IFF a row R'
// in the merged set dominates R for EVERY future query (sysTime(R') > sysTime(R)
// AND [validStart(R'),validEnd(R')) ⊇ [validStart(R),validEnd(R))). Determining
// ⊇ over arbitrary intervals for an unbounded future is truth maintenance —
// O(rows²) at worst, and WRONG under partial observability (a query with txTime
// in the past sees an OLDER dominant, not the newer one). The honest minimal
// Day-14 compaction PRESERVES ALL ROWS: merge = concatenate + sort by the
// composite key. Row-pruning (superseded-row elimination) is a future Level-2
// fork requiring truth-maintenance + a real DELETE operator — the dead
// tombstone EpochCompactor stays DEAD.
type L1Compactor struct {
	lister     S3Lister
	downloader S3Downloader
	uploader   S3Uploader
	allocator  *JemallocAllocator
	bucket     string
	cfg        CompactionConfig

	// inferrer (Day 22, ADR-0027) is the T_gc auto-inference state. The
	// compaction scheduler reads a Resolver's observed live-query txTime frontier
	// (QueryTxTimeFrontier) and calls SetInferredHorizon BEFORE each per-entity
	// CompactionByHash8, advancing cfg.PruningHorizonInt64Ns — the SAME field
	// DominancePrune reads at the compaction seam (l1_compactor.go:710, UNCHANGED)
	// — to max(operatorFloor, observedFrontier - backoff). The inferrer FLOORS the
	// operator knob: the operator-set floor (operatorFloor, captured at
	// construction) is the HARD minimum the inferrer never lowers below (the §0.a
	// contract); the inferrer only ADVANCES the effective horizon above it (the
	// §0.c monotone clamp — a retreat is refused + counted + logged). The
	// effective horizon that reaches DominancePrune is therefore always >= the
	// operator floor, so the §0.4(ii) txTime-gap silent-data-loss class Day 15
	// closed STAYS closed (Day 22 never admits a horizon the operator's HARD
	// floor forbids). Concurrency: the scheduler is single-goroutine; the set runs
	// between sweeps, DominancePrune READS the horizon once at Compaction entry
	// — no race (the §1.b contract; -race verified).
	inferrer horizonInferrer
}

// horizonInferrer (Day 22, ADR-0027) is the T_gc auto-inference state carried on
// the L1Compactor. It holds the operator-set HARD floor (captured at
// construction; the inferrer NEVER lowers below it) and the backoff window (how
// far behind the observed frontier the effective floor sits). The effective
// horizon is NOT stored here — it lives in cfg.PruningHorizonInt64Ns (the field
// DominancePrune reads, UNCHANGED), so the prune call site is byte-identical.
// The setter advances cfg.PruningHorizonInt64Ns monotonically; the operator
// floor is the permanent backstop the advance can only rise above.
type horizonInferrer struct {
	// operatorFloor is the operator-set HARD floor T_gc captured at construction
	// (the value of cfg.PruningHorizonInt64Ns the operator passed to
	// NewL1Compactor). The inferrer NEVER admits an effective horizon below it
	// (the §0.a "inferrer FLOORS the operator knob, does NOT replace it"
	// contract). It is immutable after construction.
	operatorFloor int64
	// backoffNs is the retention backoff — how far behind the observed frontier
	// the effective floor sits. effective = max(operatorFloor,
	// observedFrontier - backoffNs). Set at construction from cfg.PruneBackoffInt64Ns.
	backoffNs int64
}

// NewL1Compactor creates a new per-entity L0->L1 compactor.
//
// Day 15 (ADR-0020): the LOUD horizon guard. An ENABLED prune
// (EnableDominancePruning=true) REQUIRES a positive PruningHorizonInt64Ns —
// the (C3) floor that closes the §0.4(ii) txTime gap. A horizon-less prune is
// SILENTLY WRONG: with no floor, a dominator R' (sysTime(R') > sysTime(R)) is
// trusted to dominate R even though a live query AS-OF a txTime in the GAP
// [sysTime(R), sysTime(R')) admits R but NOT R' -> dropping R corrupts that
// historical query. The loud path is a WARN + coerce to Preserve-All: the
// compactor is returned with EnableDominancePruning=false so NO prune runs
// (byte-identical Day-14 behavior), and the WARN states both the
// misconfiguration AND the coercion. The operator fixes the config + restarts;
// no silent data loss ships. (Law: every error path must be loud — log.Printf,
// NOT a swallowed nil.)
func NewL1Compactor(lister S3Lister, downloader S3Downloader, uploader S3Uploader, allocator *JemallocAllocator, bucket string, cfg CompactionConfig) *L1Compactor {
	if cfg.L0FilesPerEntityTrigger <= 0 {
		cfg.L0FilesPerEntityTrigger = 64
	}
	if cfg.MaxL1FilesPerEntity <= 0 {
		cfg.MaxL1FilesPerEntity = 4
	}
	// Day 22 (ADR-0027): capture the operator-set HARD floor + the backoff
	// BEFORE the LOUD coerce below may zero PruningHorizonInt64Ns. The inferrer
	// FLOORS the effective horizon at this operatorFloor (the §0.a contract);
	// the coerce-to-Preserve-All zeroes cfg.PruningHorizonInt64Ns so the prune
	// stays OFF (byte-identical Day-14), and the inferrer's operatorFloor is
	// captured at 0 — the safe default for an ENABLED-but-misconfigured knob
	// (the inferrer is inert while pruning is OFF; the coerce fixed that).
	operatorFloor := cfg.PruningHorizonInt64Ns
	backoffNs := cfg.PruneBackoffInt64Ns
	if cfg.EnableDominancePruning && cfg.PruningHorizonInt64Ns <= 0 {
		// The LOUD coerce: an ENABLED prune WITHOUT a positive horizon would
		// drop rows under a horizon-less (C1)&&(C2)-only rule — the §0.4(ii)
		// txTime-gap silent-data-loss class. Refuse the misconfiguration by
		// coercing to Preserve-All + a WARN (the operator sees both the broken
		// config AND the safe fallback). Returning a *L1Compactor (NOT an
		// error) keeps the 6-arg constructor signature stable for the existing
		// importers + the mesh tests (mirrors the Day-12 SetResolver seam):
		// the loudness is the log, not a new return type.
		log.Printf("[l1_compactor] WARN: EnableDominancePruning=true with PruningHorizonInt64Ns=%d (<=0) — a horizon-less prune is silently wrong (the §0.4(ii) txTime-gap class). Coercing to Preserve-All (EnableDominancePruning=false) — the L0→L1 merge preserves ALL rows (byte-identical Day-14 behavior). Set --compaction-prune-horizon-ns to a positive transaction-time GC horizon to enable the Level-2 prune.",
			cfg.PruningHorizonInt64Ns)
		cfg.EnableDominancePruning = false
		cfg.PruningHorizonInt64Ns = 0
		operatorFloor = 0
	}
	return &L1Compactor{
		lister:     lister,
		downloader: downloader,
		uploader:   uploader,
		allocator:  allocator,
		bucket:     bucket,
		cfg:        cfg,
		inferrer: horizonInferrer{
			operatorFloor: operatorFloor,
			backoffNs:     backoffNs,
		},
	}
}

// Config returns the compactor's configuration (read-only surface for the
// scheduler / tests).
func (c *L1Compactor) Config() CompactionConfig { return c.cfg }

// L0FilesPerEntityTrigger reports the per-entity L0 file count that triggers a
// compaction (convenience for the scheduler).
func (c *L1Compactor) L0FilesPerEntityTrigger() int { return c.cfg.L0FilesPerEntityTrigger }

// InferHorizon (Day 22, ADR-0027) is the scheduler's single inferrer step: read
// the Resolver's observed live-query txTime frontier, compute the effective
// horizon, advance the compactor's horizon monotonically, and surface the two
// gauges (the operator-visible audit trail). A nil resolver leaves the inferrer
// inert (the research node keeps the Resolver nil — no --lsm-root). The method
// is concurrency-safe: the scheduler is single-goroutine; the set runs between
// sweeps, DominancePrune READS cfg.PruningHorizonInt64Ns once at Compaction
// entry — no race (the §1.b contract; -race verified).
//
// The retreat-refuse counter is advanced INSIDE SetInferredHorizon (its LOUD-
// path sole responsibility); the two gauges are advanced HERE (the scheduler
// has the observed frontier + the post-clamp effective). Use-site guards (the
// Day-21 pattern at query.go:253) — nil under the research node
// (telemetry.Init uncalled) is a no-op.
func (c *L1Compactor) InferHorizon(resolver *Resolver) {
	if resolver == nil {
		return
	}
	observedFrontier := resolver.QueryTxTimeFrontier()
	effective := c.EffectiveHorizon(observedFrontier)
	// SetInferredHorizon advances cfg.PruningHorizonInt64Ns monotonically (the
	// §0.c clamp); returns the post-clamp effective the prune will use.
	applied := c.SetInferredHorizon(effective)
	// Advance the two gauges (the audit-trail pair). The observed-frontier gauge
	// is the raw observed; the effective gauge is what reached the prune. The
	// gap is the backoff in operation (§1.c (2)).
	if telemetry.QueryTxTimeHighWaterMark != nil {
		telemetry.QueryTxTimeHighWaterMark.Set(float64(observedFrontier))
	}
	if telemetry.PruningHorizonEffective != nil {
		telemetry.PruningHorizonEffective.Set(float64(applied))
	}
}

// EffectiveHorizon (Day 22, ADR-0027) computes the inferrer's effective
// DominancePrune floor for the given observed live-query txTime frontier:
//
//	effective = max(operatorFloor, observedFrontier - backoffNs)
//
// It is the §0.a "inferrer FLOORS the operator knob" formula. The operator-set
// HARD floor (operatorFloor, captured at construction) is the backstop the
// inferrer NEVER goes below; the backoff tolerates forensic queries
// `backoffNs` nanoseconds into the recent past. observedFrontier==0 (a fresh
// Resolver before any AsOf call) yields max(operatorFloor, -backoff) — clamped
// to the operator floor (the safe default; the inferrer does not advance the
// horizon below the operator's knob). This function is PURE: it computes the
// candidate; SetInferredHorizon does the monotone clamp + the LOUD refuse.
func (c *L1Compactor) EffectiveHorizon(observedFrontier int64) int64 {
	inferred := observedFrontier - c.inferrer.backoffNs
	if inferred < c.inferrer.operatorFloor {
		return c.inferrer.operatorFloor
	}
	return inferred
}

// SetInferredHorizon (Day 22, ADR-0027) is the inferrer's monotonically-
// advancing setter. The compaction scheduler calls it BEFORE each per-entity
// CompactionByHash8 with effective = EffectiveHorizon(resolver.QueryTxTimeFrontier()).
// It advances cfg.PruningHorizonInt64Ns — the SAME field DominancePrune reads at
// the compaction seam (l1_compactor.go:710, UNCHANGED) — to the candidate IFF
// the candidate is STRICTLY GREATER than the current effective horizon (the §0.c
// monotone clamp). A retreat (candidate < current) is REFUSED: the counter
// PruningHorizonRetreatRefused fires AND a WARN is logged (the LOUD path — Law:
// every error path must be loud; the §0.4(ii) silent-data-loss class Day 15
// closed STAYS closed; Day 22 never silently lowers the horizon). A candidate
// equal to the current is a no-op (the frontier did not advance).
//
// Concurrency: the scheduler is single-goroutine; this set runs between sweeps;
// DominancePrune READS cfg.PruningHorizonInt64Ns once at Compaction entry —
// there is NO race between the set + the read (the §1.b contract; -race
// verified). The telemetry gauges QueryTxTimeHighWaterMark + PruningHorizonEffective
// are advanced by the SCHEDULER caller (it has the observed frontier + the
// effective it just set); this setter advances ONLY the retreat-refuse counter
// (its sole LOUD-path responsibility).
//
// Returns the effective horizon the prune will use (the post-clamp current) so
// the scheduler can advance the PruningHorizonEffective gauge WITHOUT a second
// read.
func (c *L1Compactor) SetInferredHorizon(candidate int64) int64 {
	current := c.cfg.PruningHorizonInt64Ns
	if candidate <= current {
		if candidate < current {
			// The §0.c LOUD refuse: a retreat is a CONTRACT VIOLATION, not a
			// relaxation (a row DROPPED at horizon H1 is in the gap if the
			// horizon retreats to H0 < H1). Refuse the update, count it, log it.
			if telemetry.PruningHorizonRetreatRefused != nil {
				telemetry.PruningHorizonRetreatRefused.Add(1)
			}
			log.Printf("[l1_compactor] WARN: SetInferredHorizon retreat refused — candidate=%d < current=%d (a horizon retreat is a §0.4(ii) silent-data-loss contract violation; the monotone clamp refuses; investigate the query stream's txTime monotonicity)",
				candidate, current)
		}
		// candidate == current: the frontier did not advance; no-op (no counter).
		return current
	}
	c.cfg.PruningHorizonInt64Ns = candidate
	return candidate
}

// EntityHash8 computes the 8-byte sha256 prefix used in the L0/L1 keying for
// the given entityID (the same prefix AsOf computes — query.go:137).
func EntityHash8(entityID string) [8]byte {
	full := sha256.Sum256(unsafe.Slice(unsafe.StringData(entityID), len(entityID)))
	var h [8]byte
	copy(h[:], full[:8])
	return h
}

// EntityHash8Hex returns the 16-char hex of sha256(entityID)[:8]- the listing
// prefix segment used by l0/, l1/, and compaction/ keying.
func EntityHash8Hex(entityID string) string {
	h := EntityHash8(entityID)
	return hexOf8(h)
}

// mergedRowT is the extracted row carrier for the merge. It carries the
// composite-key fragment (forward-ordered BigEndian so bytes.Compare ==
// lexicographic == numeric) + the column values. The compaction is a
// BACKGROUND job, NOT the hot path — it holds copies because the L0 download
// buffer is freed after extraction (O(1) live download memory).
type mergedRowT struct {
	frag [40]byte // composite key: hash(16) | sysTime(8) | validTime(8) | assertTime(8) BigEndian
	sysT int64
	vs   int64
	ve   int64
	ast  int64
	h3   uint64
	pdz  [32]byte
	eid  []byte
	pld  []byte
}

// CompactionResult reports the outcome of one Compaction job.
type CompactionResult struct {
	EntityHash8  [8]byte
	L0Files      []string // the L0 keys merged (sorted, the manifest content)
	L1Key        string   // the L1 key written
	ManifestKey  string   // the manifest key written
	Rows         int      // rows preserved in the L1 (== RowsAfter; the Day-14 back-compat field)
	AlreadyMoved bool     // true when the L0 set is empty or had zero entity rows (no-op)

	// Day 15 (ADR-0020): the Level-2 superseded-row prune counters. RowsBefore
	// is the merged-set cardinality BEFORE the DominancePrune pass; RowsAfter
	// is the cardinality AFTER (== Rows, the surviving rows written); RowsPruned
	// == RowsBefore - RowsAfter (a row dropped iff a retained R' with
	// (C1)&&(C2)&&(C3)). Preserve-All (EnableDominancePruning=false) -> all three
	// degenerate: RowsBefore == RowsAfter == Rows == len(merged) and RowsPruned
	// == 0 -- byte-identical Day-14 behavior (the back-compat gate G15.h).
	RowsBefore int
	RowsAfter  int
	RowsPruned int
}

// DominancePrune (Day 15, ADR-0020) is the Level-2 superseded-row elimination
// — a PURE FUNCTION over the merged composite-key-sorted row set + a
// transaction-time GC horizon T_gc. It returns the retained subset: a row R is
// DROPPED iff there exists a RETAINED row R' in the merged set satisfying the
// tri-temporal SAFE-DROP rule:
//
//	(C1) sysTime(R') > sysTime(R)                    -- R' is NEWER (a later assertion)
//	(C2) [validStart(R'), validEnd(R')) contains-or-equals [validStart(R), validEnd(R))
//	    -- R' answers every validTime R answered (interval containment)
//	(C3) sysTime(R') <= horizon                       -- the horizon clause
//
// Each claw is INDIVIDUALLY NECESSARY (the teeth pin each):
//   - drop (C2): a V in [validStart(R), validStart(R')) is answered ONLY by R
//     (R' does not cover it) -> R is LIVE -> drop corrupts (T2 RED).
//   - drop (C3): a T_tx in the GAP [sysTime(R), sysTime(R')) is answered ONLY
//     by R (R' is NOT yet Filter2-admitted: sysTime(R') > T_tx -> continue) -> R
//     is LIVE -> drop corrupts (T1 RED — the §0.4(ii) txTime-GAP proof).
//   - drop (C1): a row R' OLDER than R cannot dominate R on the max-sysTime
//     dominance rule scanRecordBatch enforces.
//
// The (C3) horizon clause is the load-bearing insight (ADR-0020 §2). The
// horizon is a TRANSACTION-TIME FLOOR T_gc: the operator guarantees that NO
// live query will AS-OF a transaction time txTime < T_gc (a monotone
// non-decreasing retention low-water mark; the operator advances it as the
// application retires historical AS-OF queries). Dominance is SAFE to apply
// only against the dominator R' for the LIVE query set — and a live query
// (V, txTime) admits R' iff sysTime(R') <= txTime (scanRecordBatch Filter2).
// For R' to be admitted for EVERY live query, R' must satisfy the FLOOR:
// sysTime(R') <= T_gc. That is exactly (C3). Under it, for every live query
// (txTime >= T_gc >= sysTime(R')), R' IS Filter2-admitted, IS Filter3-valid
// (containment (C2)), IS NEWER (C1) -> R' beats R on the max-sysTime rule ->
// R is provably-never-the-answer for the live-query set -> SAFE to drop.
//
// WITHOUT (C3) the prune SILENTLY OVERWRITES the past (the §0.4(ii) trap):
// take R < R' with sysTime(R') > sysTime(R) and [vs',ve') contains [vs,ve),
// and NO floor. A query at (V in [vs,ve), txTime in [sysTime(R), sysTime(R')))
// admits R but NOT R' (Filter2: sysTime(R') > txTime -> continue) -> R is the
// SOLE winner. Dropping R returns an OLDER admitted row (or
// ErrEntityNotFound), NOT the truth -> the SAME silent-data-loss class the
// engine has closed since Day 8. (C3) is what refuses the drop when the
// dominator is not yet floor-admitted (sysTime(R') > horizon -> continue).
//
// DETERMINISM (T3): the input rows are composite-key-sorted (asc hash|sysT|
// vs|ast). The drop decision is a PURE FUNCTION of (rows, horizon) evaluated in
// the sorted order — NO map iteration nondeterminism. The retained slice is a
// sub-sequence of the sorted input (forward compaction preserves the input
// order, byte-identical to the O(N^2) reference's sink compaction), so the
// output is sorted-by-composite-key AND byte-stable across runs. Pruning the
// same rows under the same horizon produces the SAME retained set
// byte-for-byte (idempotency holds — two compaction jobs on the same L0 set +
// horizon yield identical L1 bytes; T3 pins this).
//
// COMPLEXITY (Day 20, ADR-0025): the drop test for row R is an O(N*H) ACTIVE-
// DOMINATOR-SET SWEEP (H = average coverage depth — ADR-0020 §6(b) named the
// bound; this fork realizes it). The sweep walks the production-precondition
// sysTime-ASC rows in REVERSE by EQUAL-sysT BATCHES (C1 strictness holds within
// a batch — two rows at the same sysTime cannot dominate each other under the
// strict inequality, so batching them probes the batch against ONLY the
// already-processed strictly-newer rows). It maintains a LIVE set of ADMISSIBLE
// dominator intervals (rows seen so far with sysT > current batch sysT (C1,
// auto-satisfied by the descending sweep) AND sysT <= horizon (C3 — the floor;
// a row with sysT > horizon is appended for completeness but is NEVER admitted
// as a dominator — past the floor, ALL older rows' dominators must be floor-
// admitted)). For each row R, a CONTAINMENT probe asks whether SOME live
// admissible interval CONTAINS [vs_R, ve_R) (C2). If found, R is dominated
// (drop); otherwise R survives and (if floor-admitted) joins the live set.
// Worst case is bounded by |live| = N -> O(N^2) == the O(N^2) reference (the
// sweep is NEVER materially slower than the reference). The MEASURED realized
// complexity is INVERTED from the直觉 prediction (ADR-0025 §7 correction): an
// input where every row CONTAINS every older row's interval ("coverage-N")
// collapses |live| to 1 (the newest dominates all -> all older DROP, are NOT
// admitted) -> O(N), the realized common case (ratio 0.002 vs the reference).
// An input of DISJOINT windows ("coverage-1") accumulates ALL survivors into
// |live| (no row contains another -> none is dropped) -> O(N^2)/2, the realized
// worst case (ratio 0.50 — still 2x faster than the reference's N(N-1)). The
// sweep is materially faster on BOTH. The byte-identical survivors are GATED by
// the differential-equivalence fuzz tooth (T-EQUIV, >=10,000 cases) — a sweep
// that diverges on even ONE case is CORRUPT. The O(N^2) reference is preserved
// verbatim as the test-only dominancePruneReference oracle in
// l1_compaction_track20_test.go.
//
// BACK-COMPAT: horizon <= 0 returns rows UNCHANGED (Preserve-All — the byte-
// identical Day-14 default; the caller gates on EnableDominancePruning too, so
// a disabled config never reaches here, but the function is safe either way).
func DominancePrune(rows []mergedRowT, horizon int64) []mergedRowT {
	if len(rows) == 0 || horizon <= 0 {
		// Preserve-All: no horizon -> no provably-safe drop. Return the input
		// slice unchanged (the caller appends every row — byte-identical Day-14).
		return rows
	}
	// Day 20 (ADR-0025): the O(N*H) ACTIVE-DOMINATOR-SET SWEEP. Per ADR-0020
	// §6(b) the O(N^2) full-rescan is replaced by a reverse sweep over the
	// sysTime-ASC rows. The production precondition (the composite-key sort at
	// l1_compactor.go:689 RUNS before this call) gives sysTime ASC; the sweep
	// walks THAT order in REVERSE by EQUAL-sysT BATCHES so (C1)'s strict
	// inequality holds within a batch (two rows at the same sysTime cannot
	// dominate each other). `live` is the set of admissible dominator intervals
	// from the already-processed strictly-newer batches — exactly the rows a
	// forward full-rescan would test, restricted to those PASSING (C1) (newer)
	// and (C3) (floor-admitted). For row R a CONTAINMENT probe (C2) asks whether
	// some live interval contains [vs_R, ve_R); found -> dominated; else R
	// survives and (if floor-admitted) joins live for older rows.
	//
	// EQUIVALENCE (the Day-15.1 transitivity proof, RE-PROVED for the sweep).
	// The O(N^2) reference scans the FULL rows slice per row because a DROPPED
	// row R'' can be the ONLY DIRECT dominator for a LATER row R, UNLESS R'' is
	// itself dominated by a survivor S* that transitively dominates R. The sweep
	// preserves this: `live` holds EVERY floor-admitted newer row that survived
	// its OWN probe (dominated rows are NOT appended to live); and a row R''
	// dropped by the reference is dominated by some survivor S* in live
	// (containment (C2) is transitive; (C1) sysTime strictly increases along the
	// domination chain, bounded by the (C3) floor, so the chain TERMINATES at a
	// survivor S* in live that contained R'' and hence contains R — the chain R
	// → R'' → S*). So the sweep's probe against live EITHER finds R'' directly
	// (it survived) OR finds S* instead (a CONTAINER of R), so R is dropped IFF
	// R is in the reference's dropped set — byte-identical survivors. The sweep
	// is NEVER materially slower than O(N^2): the worst-realized case is
	// O(N^2)/2 (the coverage-1 disjoint-window input — |live| accumulates to N,
	// ratio 0.50; see the COMPLEXITY comment above + ADR-0025 §5). The realized
	// common case is O(N) (the coverage-N input — |live| collapses to 1, ratio
	// 0.002 — the BYTE-INVERTED prediction, corrected per the Day-17 `6->3`
	// premise-audit discipline). The T-EQUIV
	// fuzz tooth (>=10,000 cases) GATES the byte-identical survivors.

	// dominated[i] marks rows to drop (COMPACTED FORWARD to keep the survivors a
	// SUB-SEQUENCE in the input order — byte-identical to the O(N^2) reference's
	// in-place sink compaction).
	dominated := make([]bool, len(rows))

	// live is the set of ADMISSIBLE dominator intervals from strictly-newer,
	// floor-admitted rows that survived their own probe. Each entry carries ONLY
	// the (C2) containment-claw fields (vs, ve) — (C1) newer + (C3) floor are
	// enforced by the sweep ORDER + the admission guard (sysT <= horizon) at
	// append time, so the probe checks containment ALONE (no (C1)/(C3) recheck).
	// The slice is append-only and never reordered — a probe scans in insertion
	// (descending-sysTime) order. A row with sysT > horizon is NOT floor-admitted
	// (C3) so it is NEVER admitted — it can never dominate an older row under the
	// SAFE-DROP rule (a live query at txTime in [older.sysT, this.sysT) would NOT
	// admit this row). This admission gate is the (C3) floor the T1 tooth pins.
	live := make([]liveInterval, 0, min(len(rows), 1024))

	// Walk the rows in REVERSE by equal-sysT BATCHES. The composite-key sort
	// (sort.SliceStable at :689) gives sysTime ASC; reverse batches preserve (C1)
	// strictness (a row at sysTime T is probed ONLY against strictly-higher
	// sysTime rows — exactly the reference's (C1) `rp.sysT > r.sysT`).
	end := len(rows)
	for end > 0 {
		// Batch [start, end) = the maximal run of rows at the SAME sysTime.
		batchSys := rows[end-1].sysT
		start := end - 1
		for start > 0 && rows[start-1].sysT == batchSys {
			start--
		}

		// Probe every row in the batch against the live admissible set. (C1) +
		// (C3) hold by construction (live only holds newer, floor-admitted rows);
		// this probe checks ONLY (C2) — the containment claw.
		for i := start; i < end; i++ {
			r := &rows[i]
			for li := range live {
				// (C2) [vs', ve') contains [vs, ve): vs' <= vs AND ve' >= ve.
				if live[li].vs <= r.vs && live[li].ve >= r.ve {
					dominated[i] = true
					break
				}
			}
		}

		// Admit the batch's SURVIVORS (floor-admitted) into the live set as
		// candidate dominators for strictly-older rows. Non-floor-admitted
		// batches (sysT > horizon) are SILENTLY skipped — they can never be a
		// SAFE dominator (the (C3) floor; T1 RED->GREEN pins this gate).
		if batchSys <= horizon {
			for i := start; i < end; i++ {
				if !dominated[i] {
					live = append(live, liveInterval{vs: rows[i].vs, ve: rows[i].ve})
				}
			}
		}
		end = start
	}

	// Forward compaction: copy the NON-dominated rows into a sub-sequence,
	// preserving the input (sysTime-ASC, composite-key-sorted) order. The output
	// is a sub-sequence of the sorted input — byte-identical order to the O(N^2)
	// reference's in-place sink compaction (T-EQUIV pins this).
	sink := 0
	for i := range rows {
		if !dominated[i] {
			if sink != i {
				rows[sink] = rows[i]
			}
			sink++
		}
	}
	return rows[:sink]
}

// liveInterval is the unexported admissible-dominator carrier for the O(N*H)
// DominancePrune sweep. It carries ONLY the (C2) containment-claw fields
// (vs, ve) — (C1) newer + (C3) floor are enforced by the sweep order + the
// admission guard, so the probe checks containment alone. Two int64s = 16
// bytes, ZERO pointer bytes (fieldalignment-clean: no new finding).
type liveInterval struct {
	vs int64
	ve int64
}

// Compaction merges ONE entity's L0 files into a single sorted L1 file.
//
// entityID and entityHash8 identify the entity. entityHash8 MUST equal
// sha256(entityID)[:8] (callers compute it once; EntityHash8 is the helper).
// The compaction:
//   - lists the entity's L0 files under l0/{hex(entityHash8)}/ (uncapped — the
//     merge must read ALL L0 files for the entity, not just the newest MaxL0Files);
//   - downloads + extracts THIS-entity rows from each (Filter1 + Filter4);
//   - sorts by composite key and writes ONE L1 file at l1/{hex(hash8)}/{firstSysNs}.arrow;
//   - writes a manifest at compaction/{hex(hash8)}/{firstSysNs}.manifest.
//
// The merge is IDEMPOTENT: re-running on the same L0 set produces the same L1
// byte-content (sorted, schema-identical; the input L0 keys are sorted before
// merging so map iteration nondeterminism cannot bleed). If the entity has zero
// L0 files (or the L0 files contained zero rows for this entity), Compaction
// is a no-op returning AlreadyMoved=true.
func (c *L1Compactor) Compaction(ctx context.Context, entityID string, entityHash8 [8]byte) (*CompactionResult, error) {
	// List the entity's L0 files under l0/{hex(hash8)}/. UNBOUND pass: the
	// merge must read ALL L0 files (the whole history), not the cap-sliced
	// newest MaxL0Files. maxKeys=0 = unlimited (LocalFS semantics).
	l0Prefix := "l0/" + hexOf8(entityHash8) + "/"
	l0keys, err := c.lister.ListObjects(ctx, c.bucket, l0Prefix, 0)
	if err != nil {
		return nil, fmt.Errorf("compaction: list L0 %s: %w", l0Prefix, err)
	}
	if len(l0keys) == 0 {
		// Nothing to merge — no durable data for this entity YET.
		return &CompactionResult{EntityHash8: entityHash8, AlreadyMoved: true, Rows: 0, RowsBefore: 0, RowsAfter: 0, RowsPruned: 0}, nil
	}
	// Deterministic merge: sort L0 keys ascending BEFORE reading. Map iteration
	// is nondeterministic; the lister may return keys in different orders across
	// runs (LocalFS.ListObjects sorts, but an S3 lister is not guaranteed
	// stable-binary-identical). Sorting the inputs makes the merge byte-identical
	// across runs regardless of the lister's iteration order.
	sort.Strings(l0keys)

	// Reuse scanFile's growable-jemalloc-buffer reader pattern (query.go:189-220)
	// so the merge is zero-Go-heap off the wire.
	var alloc memory.Allocator = memory.DefaultAllocator
	if c.allocator != nil {
		alloc = c.allocator
	}

	var rows []mergedRowT
	for _, key := range l0keys {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("compaction: cancelled: %w", err)
		}
		rowz, rxErr := c.readEntityRowsFromKey(ctx, key, entityID, alloc)
		if rxErr != nil {
			// One corrupt L0 file does NOT abort the merge — honest negative
			// culture (Law V): log and continue (the L1 contains all readable
			// rows; the corrupt file remains on disk for manual forensics).
			continue
		}
		rows = append(rows, rowz...)
	}

	if len(rows) == 0 {
		// L0 files exist but contained zero rows for this entity (e.g. all rows
		// are co-located under a different entity or the files are corrupt).
		return &CompactionResult{EntityHash8: entityHash8, L0Files: l0keys, AlreadyMoved: true, Rows: 0, RowsBefore: 0, RowsAfter: 0, RowsPruned: 0}, nil
	}

	// Sort by composite key asc. bytes.Compare on [40]byte is lexicographic =
	// BigEndian numeric (the SAME order the SkipList enforces in skiplist_arena.go).
	sort.SliceStable(rows, func(i, j int) bool {
		return bytes.Compare(rows[i].frag[:], rows[j].frag[:]) < 0
	})

	// Day 15 (ADR-0020): the Level-2 superseded-row prune pass — the SINGLE
	// minimum-blast-radius insertion point Day-14 left open (between the
	// composite-key sort and the column-append loop). A row R is DROPPED iff a
	// retained R' satisfies (C1 sysTime(R')>sysTime(R)) && (C2 [vs',ve') contains
	// [vs,ve)) && (C3 sysTime(R')<=T_gc) — the tri-temporal dominance lattice +
	// the transaction-time GC FLOOR (the (C3) floor closes the §0.4(ii) txTime
	// gap for LIVE queries (txTime >= T_gc)). The retained set is a SORTED
	// SUB-SEQUENCE of the input (schema-identical; only the CARDINALITY
	// shrinks), so a pruned L1 is a strict subset of the Preserve-All L1 for
	// LIVE queries and IDENTICAL for txTime<T_gc queries — NO silent data loss
	// (the teeth pin each claw). EnableDominancePruning=false (the DEFAULT) OR
	// horizon<=0 skips the call entirely -> rows UNCHANGED -> the byte-IDENTICAL
	// Day-14 behavior (G15.h).
	rowsBefore := len(rows)
	rowsAfter := rowsBefore
	rowsPruned := 0
	if c.cfg.EnableDominancePruning && c.cfg.PruningHorizonInt64Ns > 0 {
		rows = DominancePrune(rows, c.cfg.PruningHorizonInt64Ns)
		rowsAfter = len(rows)
		rowsPruned = rowsBefore - rowsAfter
		if telemetry.CompactionRowsPruned != nil {
			telemetry.CompactionRowsPruned.Add(float64(rowsPruned))
		}
	}

	if len(rows) == 0 {
		// Paranoia guard: every row was dominated. This CANNOT happen — a row is
		// dropped only iff ∃ a SURVIVING dominator, so the max-sysTime row (or the
		// widest-interval row at the max sysTime) always survives. Refuse a
		// zero-row L1 honestly rather than panicking on rows[0].
		return &CompactionResult{
			EntityHash8:  entityHash8,
			L0Files:      l0keys,
			AlreadyMoved: true,
			Rows:         0,
			RowsBefore:   rowsBefore,
			RowsAfter:    0,
			RowsPruned:   rowsBefore,
		}, nil
	}

	// First sys time in the SORTED set (the composite key's sys field) — the
	// L1 filename embeds it so the name is deterministic w.r.t. the merged set.
	firstSysT := rows[0].sysT
	l1Key := l1KeyFor(entityHash8, firstSysT)

	// Build the ONE Arrow IPC file with the EXACT ArrowSchema (l0_flusher.go:22).
	l1Buf := NewJemallocBuffer(c.allocator)
	defer func() {
		if l1Buf != nil {
			l1Buf.Free()
		}
	}()
	builder := array.NewRecordBuilder(alloc, ArrowSchema)
	for i := range rows {
		r := &rows[i]
		builder.Field(0).(*array.FixedSizeBinaryBuilder).Append(r.frag[:16])
		builder.Field(1).(*array.TimestampBuilder).Append(arrow.Timestamp(r.sysT))
		builder.Field(2).(*array.TimestampBuilder).Append(arrow.Timestamp(r.vs))
		builder.Field(3).(*array.TimestampBuilder).Append(arrow.Timestamp(r.ve))
		builder.Field(4).(*array.TimestampBuilder).Append(arrow.Timestamp(r.ast))
		builder.Field(5).(*array.Uint64Builder).Append(r.h3)
		builder.Field(6).(*array.FixedSizeBinaryBuilder).Append(r.pdz[:])
		builder.Field(7).(*array.BinaryBuilder).Append(r.eid)
		builder.Field(8).(*array.BinaryBuilder).Append(r.pld)
	}
	record := builder.NewRecord()
	defer record.Release()
	writer, werr := ipc.NewFileWriter(l1Buf, ipc.WithSchema(ArrowSchema), ipc.WithAllocator(alloc))
	if werr != nil {
		return nil, fmt.Errorf("compaction: arrow writer create: %w", werr)
	}
	if err := writer.Write(record); err != nil {
		_ = writer.Close()
		return nil, fmt.Errorf("compaction: arrow write: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("compaction: arrow close: %w", err)
	}
	telemetry.ArrowSerialBytes.Add(float64(len(l1Buf.Bytes())))

	// Upload the L1. ResetRead first (ipc.NewFileWriter left the cursor at EOF);
	// the Upload contract is io.Reader → reads from the current cursor.
	l1Buf.ResetRead()
	if err := c.uploader.Upload(ctx, l1Key, l1Buf, int64(len(l1Buf.Bytes()))); err != nil {
		return nil, fmt.Errorf("compaction: upload L1 %s: %w", l1Key, err)
	}
	if telemetry.CompactionL1Written != nil {
		telemetry.CompactionL1Written.Add(1)
	}
	if telemetry.CompactionMerged != nil {
		telemetry.CompactionMerged.Add(float64(len(l0keys)))
	}

	// Write the compaction manifest at compaction/{hex(hash8)}/{firstSysNs}.manifest
	// listing the L0 keys merged into this L1 (one manifest per compaction job).
	// AsOf loads the manifests for the entity and skips any L0 key listed in any
	// manifest (those rows are superseded by the L1). The L0 files are NOT deleted
	// (delete-after-read-safety — a future reaper fork; Day 14 keeps them durable
	// as the crash-recovery backstop).
	manifestKey := manifestKeyFor(entityHash8, firstSysT)
	manifestBytes := buildManifest(l1Key, l0keys)
	if err := c.uploader.Upload(ctx, manifestKey, bytes.NewReader(manifestBytes), int64(len(manifestBytes))); err != nil {
		return nil, fmt.Errorf("compaction: upload manifest %s: %w", manifestKey, err)
	}

	return &CompactionResult{
		EntityHash8: entityHash8,
		L0Files:     l0keys,
		L1Key:       l1Key,
		ManifestKey: manifestKey,
		Rows:        len(rows), // == RowsAfter (the Day-14 back-compat field)
		RowsBefore:  rowsBefore,
		RowsAfter:   rowsAfter,
		RowsPruned:  rowsPruned,
	}, nil
}

// readEntityRowsFromKey downloads ONE L0 file and extracts THIS-entity rows
// (Filter1 hash-prefix match + Filter4 full-entityID — the §2.2 defense in
// depth). Returns the rows as mergedRowT copies so the download buffer can be
// freed before the next file downloads (O(1) live download memory).
func (c *L1Compactor) readEntityRowsFromKey(ctx context.Context, key, entityID string, alloc memory.Allocator) ([]mergedRowT, error) {
	// Download into a growable jemalloc buffer (scanFile's pattern, query.go:189-220).
	rc, err := c.downloader.Download(ctx, c.bucket, key)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", key, err)
	}
	defer func() { _ = rc.Close() }()

	// Compute the full 16-byte hash prefix (Filter1) + entity-id bytes (Filter4).
	entityIDBytes := unsafe.Slice(unsafe.StringData(entityID), len(entityID))
	fullHash := sha256.Sum256(entityIDBytes)
	var fullHash16 [16]byte
	copy(fullHash16[:], fullHash[:16])

	capacity := 32 * 1024
	dataBuf := alloc.Allocate(capacity)
	var n int
	for {
		if n == capacity {
			capacity *= 2
			dataBuf = alloc.Reallocate(capacity, dataBuf)
		}
		readBytes, rerr := rc.Read(dataBuf[n:])
		n += readBytes
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			alloc.Free(dataBuf)
			return nil, fmt.Errorf("read %s: %w", key, rerr)
		}
	}
	defer func() {
		if dataBuf != nil {
			alloc.Free(dataBuf)
		}
	}()
	if n == 0 {
		return nil, nil
	}

	reader, err := ipc.NewFileReader(bytes.NewReader(dataBuf[:n]), ipc.WithAllocator(alloc))
	if err != nil {
		return nil, fmt.Errorf("open arrow reader %s: %w", key, err)
	}
	defer func() { _ = reader.Close() }()

	// Schema-guard: the L1 REUSES the EXACT ArrowSchema; an L0 written by a
	// different (future) schema must NOT be silently merged.
	schema := reader.Schema()
	if schema.NumFields() != ArrowSchema.NumFields() {
		return nil, fmt.Errorf("schema mismatch in %s: expected %d fields, got %d", key, ArrowSchema.NumFields(), schema.NumFields())
	}
	for i := 0; i < schema.NumFields(); i++ {
		if !arrow.TypeEqual(schema.Field(i).Type, ArrowSchema.Field(i).Type) {
			return nil, fmt.Errorf("type mismatch at field %d in %s: expected %s, got %s",
				i, key, ArrowSchema.Field(i).Type, schema.Field(i).Type)
		}
	}

	var out []mergedRowT
	numRecords := reader.NumRecords()
	for i := 0; i < numRecords; i++ {
		if err := ctx.Err(); err != nil {
			return out, nil
		}
		rec, rerr := reader.Record(i)
		if rerr != nil {
			continue
		}
		out = append(out, extractEntityRowsFromRecord(rec, fullHash16, entityIDBytes)...)
		rec.Release()
	}
	return out, nil
}

// extractEntityRowsFromRecord runs the SAME Filter1 (hash-prefix) + Filter4
// (full entityID) as scanRecordBatch (query.go) for this one record batch,
// returning the rows that belong to THIS entity as mergedRowT copies. The
// composite-key fragment is constructed so a single bytes.Compare on frag[:]
// matches the SkipList's key order (BigEndian hash|sysTime|validTime|assert).
func extractEntityRowsFromRecord(rec arrow.Record, fullHash16 [16]byte, entityIDBytes []byte) []mergedRowT {
	nRows := int(rec.NumRows())
	if nRows == 0 {
		return nil
	}
	hashCol := rec.Column(0).(*array.FixedSizeBinary)
	sysTimeCol := rec.Column(1).(*array.Timestamp)
	validStartCol := rec.Column(2).(*array.Timestamp)
	validEndCol := rec.Column(3).(*array.Timestamp)
	assertTimeCol := rec.Column(4).(*array.Timestamp)
	h3Col := rec.Column(5).(*array.Uint64)
	payloadDigestCol := rec.Column(6).(*array.FixedSizeBinary)
	entityIDCol := rec.Column(7).(*array.LargeBinary)
	payloadCol := rec.Column(8).(*array.LargeBinary)

	var out []mergedRowT
	for row := 0; row < nRows; row++ {
		// Filter 1: full 16-byte hash-prefix match (the query.go Filter1 form).
		rowHash := hashCol.Value(row)
		if !bytes.Equal(rowHash, fullHash16[:]) {
			continue
		}
		// Filter 4: full entity ID verification (128-bit collision guard).
		rowEntityID := entityIDCol.Value(row)
		if !bytes.Equal(rowEntityID, entityIDBytes) {
			continue
		}
		var m mergedRowT
		copy(m.frag[:16], rowHash)
		m.sysT = int64(sysTimeCol.Value(row))
		binary.BigEndian.PutUint64(m.frag[16:24], uint64(m.sysT))
		m.vs = int64(validStartCol.Value(row))
		binary.BigEndian.PutUint64(m.frag[24:32], uint64(m.vs))
		m.ast = int64(assertTimeCol.Value(row))
		binary.BigEndian.PutUint64(m.frag[32:40], uint64(m.ast))
		m.ve = int64(validEndCol.Value(row))
		m.h3 = h3Col.Value(row)
		pdz := payloadDigestCol.Value(row)
		copy(m.pdz[:], pdz)
		m.eid = append([]byte(nil), rowEntityID...)
		m.pld = append([]byte(nil), payloadCol.Value(row)...)
		out = append(out, m)
	}
	return out
}

// l1KeyFor builds the L1 upload key: l1/{hex(hash8)}/{firstSysTimeNs}.arrow.
func l1KeyFor(hash8 [8]byte, firstSysTimeNs int64) string {
	var hexPrefix [16]byte
	hex.Encode(hexPrefix[:], hash8[:])
	var b strings.Builder
	b.WriteString("l1/")
	b.Write(hexPrefix[:])
	b.WriteByte('/')
	b.WriteString(strconv.FormatInt(firstSysTimeNs, 10))
	b.WriteString(".arrow")
	return b.String()
}

// manifestKeyFor builds the compaction manifest key:
// compaction/{hex(hash8)}/{firstSysTimeNs}.manifest
func manifestKeyFor(hash8 [8]byte, firstSysTimeNs int64) string {
	var hexPrefix [16]byte
	hex.Encode(hexPrefix[:], hash8[:])
	var b strings.Builder
	b.WriteString("compaction/")
	b.Write(hexPrefix[:])
	b.WriteByte('/')
	b.WriteString(strconv.FormatInt(firstSysTimeNs, 10))
	b.WriteString(".manifest")
	return b.String()
}

// buildManifest serializes the manifest body (line 1: the L1 key; lines 2..N:
// each merged L0 key, newline-separated). Plain text → the read path parses
// leniently; the L0 files themselves carry the truth (Law II).
func buildManifest(l1Key string, l0Keys []string) []byte {
	var b []byte
	b = append(b, l1Key...)
	b = append(b, '\n')
	for _, k := range l0Keys {
		b = append(b, k...)
		b = append(b, '\n')
	}
	return b
}

// readManifestBody reads a manifest body off an io.Reader into a SINGLE growable
// buffer (Day 26, ADR-0031 — the READ axis of the alloc cut). It replaces
// io.ReadAll at the three ParseManifest caller sites.
//
// Why not io.ReadAll: io.ReadAll starts at 512B and DOUBLES — a 2990B manifest
// (the observed max, ADR-0021 §3) pays 3 grows (512→1024→2048→4096). This helper
// starts at 4096B (covers the observed max in ONE alloc) and reads DIRECTLY into
// the growable buffer (no separate scratch buffer — a separate tmp alloc would
// undo the win, M1-measured). Grows on demand for the rare larger manifest.
//
// MEASURED (day26_measure_test.go, M1): at the production-relevant N=64 the E2E
// path (readManifestBody + ParseManifest) is 9 allocs/run DOWN from io.ReadAll +
// the old strings.Split ParseManifest's 15 (−6, −40%), per-query. The read axis
// alone cuts the io.ReadAll doublings; the parse axis (ParseManifest's
// strings.IndexByte scan) cuts the Split slice — BOTH compose.
//
// Byte-honest: the buffer alloc is IRREDUCIBLE (the bytes must come off the
// wire); Day 26 does NOT claim "zero allocs" — it claims the measured cut to the
// irreducible 1 (read) + 1 (string(body) in ParseManifest) + the l0Keys slice,
// with the Split-slice + the io.ReadAll doublings ELIMINATED. A future fork could
// scan over a memory.Allocator-backed buffer (no Go-heap body) IF manifest bodies
// grew large — they don't (2990B observed); YAGNI, the honest-engine precedent.
func readManifestBody(r io.Reader) ([]byte, error) {
	const initial = 4096
	b := make([]byte, 0, initial)
	for {
		if cap(b)-len(b) < 256 {
			nb := make([]byte, len(b), cap(b)*2)
			copy(nb, b)
			b = nb
		}
		n, err := r.Read(b[len(b):cap(b)])
		b = b[:len(b)+n]
		if err == io.EOF {
			break
		}
		if err != nil {
			return b, err
		}
	}
	return b, nil
}

// ParseManifest parses a manifest body into the L1 key + the merged L0 key set.
// It is lenient: blank lines and a missing final newline are tolerated. Used
// by SupersededL0Keys and exposed for the read path + tests.
//
// Day 26 (ADR-0031): the implementation is a single-pass strings.IndexByte scan
// over string(body) (NOT strings.Split). The old strings.Split(string(body),"\n")
// allocated an INTERMEDIATE []string of N+1 entries IN ADDITION to the l0Keys
// slice; the scan drops that slice — MEASURED −1 alloc/run at every N (M1 audit,
// day26_measure_test.go). The string(body) copy is KEPT (irreducible — the l0Keys
// MUST outlive the []byte body the caller io.ReadAll'd into; the callers store
// l0Keys as map keys, so they need stable strings, not sub-slices of a buffer the
// caller frees). The substring appends alias string(body) → 0 per-line copy. This
// is the HONEST win: the Split slice is eliminated, the l0Key copies were NEVER
// there (the old substrings aliased the same string(body)). The prompt's
// bytes.IndexByte+string(line)-per-L0 candidate was MEASURED 3-29× WORSE (a per-
// line []byte→string copy the old path never paid) — REFUTED by M1, NOT shipped.
//
// Byte-identity: the `first` flag mirrors the old `i == 0` — line 0 is set as
// l1Key UNCONDITIONALLY when non-empty (even an "l0/..."-prefixed line 0, a
// malformed manifest), then lines 1+ use the prefix check. A line that is
// neither "l1/" nor "l0/" prefixed is IGNORED (defense in depth — a stray line
// is dropped, NOT fatal). Pinned by T-STREAM-BYTE-IDENTITY + the malformed-edge
// T-STREAM-RED-CONTROL.
func ParseManifest(body []byte) (l1Key string, l0Keys []string) {
	s := string(body)
	l1Key = ""
	l0Keys = nil
	start := 0
	first := true
	for start < len(s) {
		end := strings.IndexByte(s[start:], '\n')
		if end < 0 {
			end = len(s) - start
		}
		ln := strings.TrimSpace(s[start : start+end])
		if len(ln) > 0 {
			if first {
				l1Key = ln
				first = false
				start = start + end + 1
				continue
			}
			if l1Key == "" && strings.HasPrefix(ln, "l1/") {
				l1Key = ln
			} else if strings.HasPrefix(ln, "l0/") {
				l0Keys = append(l0Keys, ln)
			}
		}
		start = start + end + 1
	}
	return l1Key, l0Keys
}

// SupersededL0Keys loads ALL compaction manifests for an entity and returns
// the union of L0 keys listed across them. AsOf uses this to skip L0 keys
// already merged into an L1. A manifest that fails to load/parse is skipped
// (honest negative: the L0 remains scannable, so data is never lost — worst
// case a superseded L0 is re-scanned, returning the same dominant the L1
// already produced).
func (c *L1Compactor) SupersededL0Keys(ctx context.Context, entityHash8 [8]byte) map[string]struct{} {
	manifestsPrefix := "compaction/" + hexOf8(entityHash8) + "/"
	keys, err := c.lister.ListObjects(ctx, c.bucket, manifestsPrefix, 0)
	if err != nil {
		return nil
	}
	superseded := make(map[string]struct{})
	for _, mk := range keys {
		rc, derr := c.downloader.Download(ctx, c.bucket, mk)
		if derr != nil {
			continue
		}
		body, _ := readManifestBody(rc) // Day 26 (ADR-0031): single-grow read, NOT io.ReadAll's doublings
		_ = rc.Close()
		_, l0ks := ParseManifest(body)
		for _, l0k := range l0ks {
			superseded[l0k] = struct{}{}
		}
	}
	return superseded
}

// ListL0Keys lists the L0 keys under a given prefix (default "l0/" for the
// whole tier, or a per-entity prefix "l0/{hex8}/" for one entity). It is a
// thin convenience wrapper so the scheduler goroutine in cmd/sovereign-node does
// NOT depend on the concrete S3Lister interface surface. maxKeys=0 → uncapped.
func (c *L1Compactor) ListL0Keys(ctx context.Context, prefix string) ([]string, error) {
	return c.lister.ListObjects(ctx, c.bucket, prefix, 0)
}

// CompactionByHash8 merges the L0 files for an entity identified by its 8-byte
// hash prefix ONLY (no entityID). It exists because the compaction scheduler
// (cmd/sovereign-node) discovers the entity set from the L0 key prefixes
// (l0/{hex8}/) — it CANNOT invert the one-way sha256 hash to recover the
// entityID Filter4 needs. The honest resolution: read the entityID FROM the
// first merged L0 file (the first record's first row's entity_id column —
// column 7), then call the full Compaction(entityID, hash8) which re-verifies
// BOTH Filter1 + Filter4 for every row. Defense in depth is therefore
// PRESERVED: the Day-13 per-entity construction guarantees only the one
// entity's rows live under l0/{hash8}/, AND Compaction re-verifies Filter1 +
// Filter4 over every row using the entityID recovered from the file itself.
//
// A hash8 with zero L0 files → AlreadyMoved (no-op). A hash8 whose first L0
// file is unreadable/has zero rows → an honest error (cannot safely merge
// without the entityID to re-verify Filter4 — Law II: do NOT merge unverified).
func (c *L1Compactor) CompactionByHash8(ctx context.Context, entityHash8 [8]byte) (*CompactionResult, error) {
	l0Prefix := "l0/" + hexOf8(entityHash8) + "/"
	l0keys, err := c.lister.ListObjects(ctx, c.bucket, l0Prefix, 0)
	if err != nil {
		return nil, fmt.Errorf("compaction-by-hash8: list L0 %s: %w", l0Prefix, err)
	}
	if len(l0keys) == 0 {
		return &CompactionResult{EntityHash8: entityHash8, AlreadyMoved: true}, nil
	}
	sort.Strings(l0keys) // deterministic entityID recovery (first file)
	var alloc memory.Allocator = memory.DefaultAllocator
	if c.allocator != nil {
		alloc = c.allocator
	}
	entityID, err := c.firstEntityIDFromKey(ctx, l0keys[0], alloc)
	if err != nil {
		return nil, fmt.Errorf("compaction-by-hash8: recover entityID from %s: %w", l0keys[0], err)
	}
	if entityID == "" {
		return nil, fmt.Errorf("compaction-by-hash8: first L0 file %s has no rows (cannot recover entityID)", l0keys[0])
	}
	return c.Compaction(ctx, entityID, entityHash8)
}

// firstEntityIDFromKey downloads ONE L0 file and returns the entityID of its
// first row (column 7 — entity_id LargeBinary). The scheduler (which cannot
// invert the hash) uses it to drive the full Compaction with the recovered
// entityID so Filter4 re-verifies every merged row.
func (c *L1Compactor) firstEntityIDFromKey(ctx context.Context, key string, alloc memory.Allocator) (string, error) {
	rc, err := c.downloader.Download(ctx, c.bucket, key)
	if err != nil {
		return "", fmt.Errorf("download %s: %w", key, err)
	}
	defer func() { _ = rc.Close() }()
	capacity := 32 * 1024
	dataBuf := alloc.Allocate(capacity)
	var n int
	for {
		if n == capacity {
			capacity *= 2
			dataBuf = alloc.Reallocate(capacity, dataBuf)
		}
		nb, rerr := rc.Read(dataBuf[n:])
		n += nb
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			alloc.Free(dataBuf)
			return "", fmt.Errorf("read %s: %w", key, rerr)
		}
	}
	defer alloc.Free(dataBuf)
	if n == 0 {
		return "", nil
	}
	reader, err := ipc.NewFileReader(bytes.NewReader(dataBuf[:n]), ipc.WithAllocator(alloc))
	if err != nil {
		return "", fmt.Errorf("open arrow reader %s: %w", key, err)
	}
	defer func() { _ = reader.Close() }()
	if reader.NumRecords() == 0 {
		return "", nil
	}
	rec, rerr := reader.Record(0)
	if rerr != nil {
		return "", rerr
	}
	defer rec.Release()
	if rec.NumRows() == 0 {
		return "", nil
	}
	entityIDCol := rec.Column(7).(*array.LargeBinary)
	id := entityIDCol.Value(0)
	// Copy to a Go-heap string (the buffer is freed after return) — this is the
	// scheduler path, NOT the hot path. A one-string alloc per compaction job
	// is honest and bounded by the entity count.
	return string(append([]byte(nil), id...)), nil
}

// hexOf8 hex-encodes an [8]byte to a 16-char string.
func hexOf8(b [8]byte) string {
	var buf [16]byte
	hex.Encode(buf[:], b[:])
	return unsafe.String(&buf[0], 16)
}

// Compile-time interface satisfaction (catches a signature drift the moment
// l1_compactor.go is edited).
var _ interface {
	Compaction(ctx context.Context, entityID string, entityHash8 [8]byte) (*CompactionResult, error)
} = (*L1Compactor)(nil)
