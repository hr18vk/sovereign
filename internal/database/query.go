package database

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/apache/arrow/go/v17/arrow"
	"github.com/apache/arrow/go/v17/arrow/array"
	"github.com/apache/arrow/go/v17/arrow/ipc"
	"github.com/apache/arrow/go/v17/arrow/memory"
	"github.com/hr18vk/supremum/internal/telemetry"
)

// ResolverConfig holds configuration for the Bitemporal Query Resolver.
type ResolverConfig struct {
	// LiveSource (Day 27, ADR-0032) is declared FIRST for fieldalignment (an
	// interface field — 16 pointer-bytes — at offset 0 is contiguous with NO
	// preceding padding; a trailing position after the bool carries 24 bytes of
	// pointer-padding waste the gate flags). The full field doc is at the
	// trailing position below (preserved verbatim — the narrative order of the
	// config's documented fields is NOT disturbed; only the physical layout
	// moves). See the trailing comment block for the read-your-writes semantics.
	LiveSource LiveSource

	// MaxL0Files limits the number of L0 Arrow IPC files scanned per query.
	// This bounds memory and network usage before Sprint 5 compaction is online.
	// Default: 1000. Set to 0 for unlimited (NOT recommended without ceiling index).
	MaxL0Files int

	// MaxRangeRows (Day 19, ADR-0024) bounds the number of rows a single
	// Resolver.Range query may return — the unbounded-amplification guard. AsOf
	// returns ONE event; Range returns every durable row whose valid-time
	// interval intersects the query window, which for a wide window over a long
	// history can be O(history) rows in one response (a memory + JSON-marshal
	// amplifier, the SAME class as the missing MaxL0Files cap closed in
	// ADR-0018). The cap is CHECKED in the collector BEFORE the JSON marshal —
	// the marshal never sees more than MaxRangeRows rows.
	//
	// Default: 4096 — a production-safe ceiling for a single bitemporal-history
	// window query. When the cap is hit, Range returns the rows it collected +
	// a `truncated:true` signal (the operator widens the window or paginates;
	// pagination is a FUTURE fork, disclosed in ADR-0024 §6). Set to 0 for
	// UNLIMITED — DISCLOSED as unbounded (NOT the default; the marshal will
	// scale with the full intersecting history).
	MaxRangeRows int

	// EnableFirstSysSkip (Day 24, ADR-0029): when true, the durable read path
	// parses each L0/L1 file's filename-encoded FirstSysTimeNs (the file's MIN
	// sysTime, written by the flush since Day-13 at l0_flusher.go:314 + the
	// compactor at l1_compactor.go:950) and SKIPS the download when firstSys >
	// the query's txTime — a transitively-safe elimination (the file carries ZERO
	// rows visible at txTime; every row fails Filter2 sysTime<=txTime; Law II
	// preserved, §0.e). Default true (production-safe — the bound is on disk
	// for free; the parse is zero-alloc + failsafe). Set false to force-download
	// every survivor (the pre-Day-24 behavior, the comparison path for the
	// T-SKIP-EQUIV differential-equivalence tooth).
	//
	// This is the LOWER bound only (file.min > txTime ⟹ skip). The upper bound
	// (file MAX sysTime, to skip files whose ENTIRE body is BEFORE the query)
	// needs a per-file maxSys the filename does NOT carry today — a SEPARATE
	// manifest-sidecar fork (ADR-0029 §6.a), NOT this flag. The skip is
	// order-INDEPENDENT (a per-file filter), so the reverse-lexical scan sort at
	// query.go:348/512 (the disclosed 19-digit-fixed-width-prod-safe order,
	// range_track19_test.go:74) does NOT affect its correctness.
	EnableFirstSysSkip bool

	// LiveSource (Day 27, ADR-0032) is the read-your-writes seam: an interface
	// the Resolver consults AFTER its durable Arrow scan to merge the live
	// δ-CRDT HAMT's dominant under the SAME bitemporal dominance AsOf already
	// computes. This closes the gap a POST /v1/insert creates: the entry lands
	// in the live HAMT immediately (engine.InsertLocal CAS-spins the per-shard
	// root, crdt.go:983) but is INVISIBLE to /v1/query until the bridge's
	// periodic AppendCheckpoint flushes SnapshotToLSM → L0 → a base the Resolver
	// can list (bridge.go:213, gated by checkpointInterval, default 1000). With
	// the default, every IMMEDIATE /v1/query → 404 — empirically confirmed Day-26
	// (--wal-checkpoint-interval=1 was REQUIRED for the durable read path to
	// work). A nil LiveSource (the DefaultResolverConfig value — a research node
	// / --lsm-root absent) keeps the read-only-durable behavior byte-identical to
	// Day-26 (the 503-disabled honesty contract is at the control layer,
	// control.go:404; a configured-but-nil live source keeps the durable-only
	// answer honest, NOT a silent live miss).
	//
	// STRUCTURAL TWIN of EnableFirstSysSkip (the Day-24 precedent): a behavioral
	// toggle on ResolverConfig, NOT a NewResolver ctor arg. NewResolver keeps
	// its 5-arg signature → ZERO call-site churn outside cmd/sovereign-node (the
	// ONLY site that constructs a resolver, main.go:394). This is MORE faithful
	// to the real Day-12 precedent — SetResolver is a SETTER, not a ctor arg
	// (control.go:66) — than a trailing param would be; the live source is
	// injected at the construction site the SAME way the resolver itself is.
	//
	// (The field is declared at the TOP of the struct for fieldalignment; the
	// comment block stays HERE to preserve the narrative order. See the leading
	// declaration.)
}

// LiveEvent mirrors TriTemporalEvent minus EntityID (the Resolver ALREADY has
// it — it computed hashPrefix from it at AsOf/Range entry). It is the row the
// LiveSource returns per (entityID, txTime) consult. It is a PLAIN struct, NOT
// a pkg/sync.CRDTEntry copy — internal/database does NOT import pkg/sync (M2,
// ADR-0032 §0.b), so the seam is an interface owned by the Resolver with a
// concrete adapter constructed at the cmd/sovereign-node boundary (the
// SetResolver / SetSnapshotter precedent). The adapter maps CRDTEntry →
// LiveEvent at the seam; the Resolver never sees the concrete engine.
//
// Field set = TriTemporalEvent minus EntityID: the four tri-temporal ns fields
// + H3Index + PayloadDigest + Payload. Payload is carried (the live HAMT DOES
// hold it — the durable Arrow index does NOT; the adapter reads it from the
// CRDTEntry's PayloadDigest only, matching the durable index's no-recompute
// discipline — control.go:441, Law V). A future fork that surfaces live
// Payload through the query response is a SEPARATE seam; Day 27 carries the
// digest (the no-recompute identity) + a nil Payload (the durable index's
// payload=sentry discipline, snapshot.go:435, carried to the live path).
type LiveEvent struct {
	// Field order is fieldalignment-optimal (pointer-span minimized): the scalar
	// int64/uint64 fields first, then the [32]byte digest array, then the
	// variable Payload slice LAST (a trailing slice keeps the pointer-span to
	// its own 16 bytes — the tool reports 80→8 pointer-bytes for the naive
	// order where the slice precedes the 32-byte array; this order is the
	// Day-27 fix). The DTO is allocated in a per-query slice (NOT a contended
	// atomic), so the Cache law's 128-byte-stride concern does NOT apply; the
	// reorder is the gate's no-output contract, NOT a cache-line fix.
	Payload        []byte
	PayloadDigest  [32]byte
	SystemTime     int64
	ValidTimeStart int64
	ValidTimeEnd   int64
	AssertionTime  int64
	H3Index        uint64
}

// LiveSource is the read-your-writes seam (Day 27, ADR-0032). The impl wraps the
// live δ-CRDT HAMT — engine.State().Get(entityID) returns the FULL dot set
// (hamt.go:170) — and MUST pin the live store for the call duration (the EBR
// Acquire/Enter/Release the SnapshotToLSM precedent proves, snapshot.go:391-394)
// so a concurrent InsertLocal's CAS cannot retire+free a shard root the
// LiveRead iterates. The adapter applies Filter2 (SystemTime <= txTimeNs) — the
// visibility bound well-defined for BOTH AsOf and Range; the Resolver applies
// Filter3 (point OR window) + dominance, reusing scanRecordBatch's EXACT rule so
// the live dominant and the durable dominant merge under one definition.
//
// hashPrefix is NOT a parameter: Get is an EXACT entityID lookup (the HAMT is
// keyed by entityID), so the 128-bit hash prefix the durable scan uses to scope
// the S3 list is dead on the live path. The (validTimeNs, txTimeNs) pair is the
// AsOf form; Range passes the window bounds — the Resolver, not the adapter,
// owns the Filter3 shape (point vs window), so the LiveRead signature is the
// MINIMAL (entityID, txTimeNs) consult + the adapter returns the full Filter2-
// passing set. The Resolver's AsOf/Range callers then apply their own Filter3.
type LiveSource interface {
	// LiveRead returns the live entries for entityID with SystemTime <= txTimeNs
	// (Filter2, applied by the adapter). The impl MUST pin the live store (EBR
	// on the HAMT) for the call duration. A nil/empty result is NOT an error —
	// it means no live entry is visible at txTime (the durable answer stands
	// alone; the merge is a no-op). An error is logged via the
	// QueryLiveSourceReads counter on the error path and NEVER fails the query
	// (the SAME failure-honesty loadSupersededL0Keys uses — a live miss is a
	// redundancy, NOT a correctness loss, query.go:1283).
	LiveRead(ctx context.Context, entityID string, txTimeNs int64) ([]LiveEvent, error)
}

// DefaultResolverConfig returns a ResolverConfig with production-safe defaults.
func DefaultResolverConfig() ResolverConfig {
	return ResolverConfig{
		MaxL0Files:         1000,
		MaxRangeRows:       4096,
		EnableFirstSysSkip: true,
	}
}

// S3Lister abstracts S3 object listing for testability.
// Implementations return object keys under a given prefix, sorted lexicographically.
type S3Lister interface {
	// ListObjects returns up to maxKeys object keys under the given prefix,
	// sorted lexicographically (ascending). If maxKeys <= 0, returns all keys.
	ListObjects(ctx context.Context, bucket, prefix string, maxKeys int) ([]string, error)
}

// S3Downloader abstracts S3 object downloading for testability.
// Implementations return a ReadCloser for the object content.
type S3Downloader interface {
	// Download retrieves the object at the given key and returns its content.
	// The caller MUST close the returned ReadCloser.
	Download(ctx context.Context, bucket, key string) (io.ReadCloser, error)
}

// S3Deleter abstracts object deletion from object storage (Day 16, ADR-0021). It
// is the FOURTH narrow S3 seam (alongside S3Uploader / S3Lister / S3Downloader)
// and exists for the L0 reaper: the reaper deletes manifest-listed L0 files +
// the manifest itself AFTER verifying the L1 still exists (the Stage C safety
// guard). The seam is SEPARATE from S3Uploader (the reaper only deletes; it
// never uploads). The bucket is carried out-of-band the same way it is for the
// lister/downloader — the concrete *LocalFS the production path injects ignores
// it (one root IS the bucket). Delete is IDEMPOTENT: a missing object (the
// backstop already reclaimed by a prior sweep) is NOT an error — it returns
// nil so the reaper's retry-on-partial-failure loop makes forward progress.
type S3Deleter interface {
	// Delete removes the object at the given key. A missing object is NOT an
	// error (idempotent) — the reaper relies on this for partial-reap retries.
	Delete(ctx context.Context, bucket, key string) error
}

// Resolver implements the Bitemporal Query Resolver (S3.3).
//
// The resolver scans L0 Arrow IPC files on S3-compatible object storage,
// applying the tri-temporal dominance relation to return the single correct
// TriTemporalEvent for a given (entityID, validTime, transactionTime) coordinate.
//
// IMPORTANT: This is the initial "sequential scan" implementation per DR3 S3.3.
// Indexed access via the Ceiling data structure is deferred to Sprint 5 (S5.4).
//
// Zero-GC Compliance:
//   - Arrow record batches are read via ipc.FileReader which operates on the
//     Arrow IPC format's zero-copy memory layout.
//   - No json.Unmarshal or map[string]interface{} is used.
//   - Entity ID verification uses raw byte comparison (no string conversion).
//   - The returned TriTemporalEvent is stack-allocated by the caller.
type Resolver struct {
	lister     S3Lister
	downloader S3Downloader
	allocator  *JemallocAllocator
	// liveSource (Day 27, ADR-0032) is the read-your-writes seam. nil = the
	// DefaultResolverConfig value (a research node / --lsm-root absent) → AsOf
	// + Range keep the durable-only behavior byte-identical to Day-26. The
	// field is declared HERE with the other pointer-width fields
	// (lister/downloader/allocator) for fieldalignment — a trailing interface
	// after pruningFrontierObserved int64 carries 16 bytes of pointer-span
	// waste the gate flags (120→104). The earlier comment claim "fieldalignment
	// does NOT flag an interface field" was FALSE — the §5 gate caught it;
	// corrected here (the §0.b honesty discipline). liveSource is NOT a
	// contended atomic (the Cache law's 128-byte-stride concern is
	// pruningFrontierObserved, which stays on its own slot below), so the move
	// is the gate's no-output contract, NOT a cache-line fix.
	liveSource LiveSource
	bucket     string
	config     ResolverConfig

	// pruningFrontierObserved (Day 22, ADR-0027) is the observed live-query
	// txTime frontier — the MAX transactionTime.UnixNano() seen across every
	// AsOf call this Resolver has served. It is the data source the compaction
	// scheduler's HorizonInferrer reads (via QueryTxTimeFrontier) to compute the
	// effective DominancePrune floor T_gc = max(operatorFloor,
	// observedFrontier - backoff). It is package-private: the inferrer reads it
	// through QueryTxTimeFrontier, never the field directly.
	//
	// It is an atomic int64 (NOT time.Time) so the observation on the AsOf read
	// path is ZERO-ALLOC (the int64 lives on the Resolver struct, not the heap —
	// the §0.e read-path-zero-alloc discipline; measured by T-INFER-ALLOC). The
	// advance is a CompareAndSwap max loop — a Store + Load-compare pair is NOT
	// atomic (a concurrent forensic query AT a LOWER txTime must NOT collapse the
	// frontier: the observation is a MAX, not a last-writer — the §0.b monotone-
	// observed tooth T-INFER-ASOF-OBSERVES). fieldalignment: it sits on its own
	// 8-byte slot after the pointer fields (no contended atomic shares a cache
	// line with another — the Cache law).
	pruningFrontierObserved int64
}

// observeQueryTxTime advances the observed live-query txTime frontier to the
// MAX of (current, txTimeNs). It is the §1.a observation seam: called at
// AsOf-entry after `txTimeNs := transactionTime.UnixNano()` (query.go:237). The
// advance is a CompareAndSwap loop — the atomic-max pattern — so a concurrent
// forensic query AT a LOWER txTime does NOT lower the frontier (the frontier is
// a MAX, not a last-writer; the §0.b monotone-observed contract). A single
// failing CAS retries with the just-loaded current (another AsOf raced the
// advance); it only Stops advancing once the loaded current >= txTimeNs (the
// frontier is already at/above this query's txTime). ZERO allocation: the
// CompareAndSwap + Load are word-sized atomics on the struct int64 — no escape,
// no heap (the §0.e read-path-zero-alloc discipline; T-INFER-ALLOC measures 0
// delta vs the Day-21 AsOf).
func (r *Resolver) observeQueryTxTime(txTimeNs int64) {
	for {
		cur := atomic.LoadInt64(&r.pruningFrontierObserved)
		if cur >= txTimeNs {
			// The frontier is already at/above this query's txTime — a forensic
			// query into the past does NOT collapse it (the §0.b monotone MAX).
			return
		}
		if atomic.CompareAndSwapInt64(&r.pruningFrontierObserved, cur, txTimeNs) {
			return
		}
		// CAS failed: another AsOf advanced the frontier between our Load and
		// our CAS — reload + retest (the loop terminates: the frontier only ever
		// climbs; a higher current makes the next cur >= txTimeNs check pass).
	}
}

// QueryTxTimeFrontier returns the observed live-query txTime frontier (the MAX
// transactionTime.UnixNano() seen across this Resolver's AsOf calls). It is the
// accessor the compaction scheduler's HorizonInferrer reads (the inferrer NEVER
// touches the field directly). Returns 0 before any AsOf call (the fresh-
// Resolver case; the inferrer's max(operatorFloor, 0 - backoff) clamps to the
// operator floor — the safe default, see §1.b).
func (r *Resolver) QueryTxTimeFrontier() int64 {
	return atomic.LoadInt64(&r.pruningFrontierObserved)
}

// NewResolver creates a new Bitemporal Query Resolver.
//
// MaxRangeRows is NOT coerced up here: 0 is the documented UNLIMITED sentinel
// (ADR-0024 §1.2), so a caller that asks for unbounded range results gets them
// (the disclosure lives in the ADR + the truncated flag, not a silent bump).
func NewResolver(lister S3Lister, downloader S3Downloader, allocator *JemallocAllocator, bucket string, config ResolverConfig) *Resolver {
	if config.MaxL0Files <= 0 {
		config.MaxL0Files = 1000
	}
	// MaxRangeRows: deliberately NOT coerced. 0 = UNLIMITED (disclosed). A
	// negative value is non-sensical; coerce to unlimited (same as 0) so a
	// misconfigured caller does not crash on a negative cap comparison.
	if config.MaxRangeRows < 0 {
		config.MaxRangeRows = 0
	}
	return &Resolver{
		lister:     lister,
		downloader: downloader,
		allocator:  allocator,
		bucket:     bucket,
		config:     config,
		liveSource: config.LiveSource, // Day 27 (ADR-0032): the live δ-CRDT HAMT seam; nil = durable-only (DefaultResolverConfig)
	}
}

// SetLiveSource (Day 27, ADR-0032) injects the live δ-CRDT HAMT seam AFTER
// construction. It is the Day-12 SetResolver precedent carried to the live
// source: the adapter is constructed at the cmd/sovereign-node boundary (where
// the concrete engine lives — internal/database does NOT import pkg/sync) and
// injected here, so NewResolver keeps its 5-arg signature (zero call-site churn)
// and the live source is wired at the SAME seam the resolver itself is. A nil
// src keeps the durable-only behavior (the DefaultResolverConfig value).
func (r *Resolver) SetLiveSource(src LiveSource) { r.liveSource = src }

// AsOf resolves the dominant TriTemporalEvent for the given entity at the
// specified (validTime, transactionTime) coordinates.
//
// Tri-Temporal Dominance Relation (from Deep Research - Bitemporal delta-CRDT):
//   - A record R2 dominates R1 for the same entityID if:
//     1. R2.SystemTime > R1.SystemTime (later system assertion supersedes)
//     2. R2.ValidTimeStart <= validTime < R2.ValidTimeEnd (valid time contains query point)
//     3. R2.SystemTime <= transactionTime (system time is within query horizon)
//   - The resolver returns the record with the LATEST SystemTime that satisfies
//     all three conditions.
//
// Sequential Scan Strategy (pre-Sprint 5):
//   - Lists L0 files under "l0/" prefix on S3.
//   - Sorts files in reverse lexicographic order (newest transaction time first).
//   - For each file: opens Arrow IPC reader, scans record batches, applies
//     entity hash filter + full entity ID verification + temporal predicate.
//   - Returns the dominant event across all scanned files.
//
// Error Conditions:
//   - ErrEntityNotFound: no matching event exists for the given coordinates.
//   - context.Canceled/DeadlineExceeded: query was cancelled or timed out.
//   - S3/IO errors: propagated with wrapping context.
func (r *Resolver) AsOf(ctx context.Context, entityID string, validTime time.Time, transactionTime time.Time) (*TriTemporalEvent, error) {
	if entityID == "" {
		return nil, fmt.Errorf("query: entityID must not be empty")
	}

	// Compute the 128-bit entity ID hash prefix for Arrow column filtering.
	// This matches the hash computation in MemTable.Write() (Override 8.4).
	entityIDBytes := unsafe.Slice(unsafe.StringData(entityID), len(entityID))
	fullHash := sha256.Sum256(entityIDBytes)
	var hashPrefix [16]byte
	copy(hashPrefix[:], fullHash[:16])

	// SECURITY AUDIT FIX - PASS 2: Compute hex-encoded prefix for S3 listing scoping.
	var hexBuf [16]byte
	hex.Encode(hexBuf[:], hashPrefix[:8])
	hexPrefixStr := unsafe.String(&hexBuf[0], 16)
	l0Prefix := "l0/" + hexPrefixStr + "/"
	l1Prefix := "l1/" + hexPrefixStr + "/"

	// Convert query time coordinates to nanoseconds (matching Arrow schema).
	validTimeNs := validTime.UnixNano()
	txTimeNs := transactionTime.UnixNano()

	// Day 22 (ADR-0027): observe this query's txTime into the live-query txTime
	// frontier the compaction scheduler's HorizonInferrer reads (§1.a). The
	// advance is a ZERO-ALLOC atomic-max (observeQueryTxTime): a forensic query
	// AT a LOWER txTime does NOT collapse the frontier (the §0.b monotone MAX —
	// T-INFER-ASOF-OBSERVES). This is the READ path, NOT the write-path zero-
	// alloc gate; T-INFER-ALLOC measures a 0-alloc delta vs the Day-21 AsOf.
	r.observeQueryTxTime(txTimeNs)

	// Phase 1: List L0 + L1 files from S3.
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("query: cancelled before listing: %w", err)
	}

	// Day 14 (ADR-0019): the read path now scans BOTH tiers.
	//   - L1 (l1/{hex(hash8)}/): the compacted merged history — ALWAYS scanned,
	//     uncapped. It holds the full per-entity history bounded by write volume,
	//     NOT by MaxL0Files. Under Day-14's single-L1-per-entity shape there is
	//     ≤1 file per entity (the merged set); a future tiered-L1 fork (MaxL1FilesPerEntity)
	//     may produce a few more, but the L1 list is small and never silently dropped.
	//   - L0 (l0/{hex(hash8)}/): the uncompacted TAIL — capped at MaxL0Files.
	//     Day-13’s MaxL0Files cap now bounds the TAIL (the recent uncompacted
	//     checkpoints), which is small in steady state (write-rate × compaction
	//     interval). The cap was the SILENT-DATA-LOSS ceiling (ADR-0018 §6);
	//     compaction turns it into a PERF cap (the rare-stall signal). The
	//     disclosure counter still fires when the TAIL exceeds the cap.
	l1Keys, err := r.lister.ListObjects(ctx, r.bucket, l1Prefix, 0)
	if err != nil {
		return nil, fmt.Errorf("query: list L1 objects: %w", err)
	}
	// Day 14 §0.5: list L0 UNBOUND. The cap (MaxL0Files) now bounds the
	// uncompacted TAIL AFTER supersession, applied newest-N (the recent
	// uncompacted checkpoints that compaction has NOT yet merged). Listing
	// capped at the lister level would (a) drop the NEWEST L0 keys under some
	// listers (LocalFS keeps the oldest, asc-truncated) — the OPPOSITE of the
	// Tail §0.5 mandates — and (b) mis-cap when most L0s are superseded by an
	// L1 (the manifest's superseded L0s would consume the cap, hiding the few
	// real tail files). List uncapped; apply supersession; cap the SURVIVING
	// tail to the newest MaxL0Files. The cost is bounded by the compaction
	// interval (write-rate × interval), NOT by all-time L0 volume.
	l0Keys, err := r.lister.ListObjects(ctx, r.bucket, l0Prefix, 0)
	if err != nil {
		return nil, fmt.Errorf("query: list L0 objects: %w", err)
	}

	// The entity has NO durable data (neither L1 nor L0) on disk → honest miss.
	// Day 27 (ADR-0032): this early-exit is GUARDED on the live source. With a
	// live δ-CRDT HAMT configured (r.liveSource != nil), zero durable keys does
	// NOT mean not-found — the entry a POST /v1/insert just placed is in the LIVE
	// HAMT (engine.InsertLocal CAS-spun the per-shard root) but has NOT yet been
	// flushed by the bridge's periodic AppendCheckpoint to L0. Returning 404
	// here would DEFEAT read-your-writes — the load-bearing empirical proof
	// (insert → IMMEDIATE query → 200, checkpoint disabled, STEP 5 #4) depends
	// on the live consult running BEFORE this honest miss. So: with a live source,
	// skip the durable-only early-exit + fall through to the scan (which finds no
	// durable dominant) + the live merge below (which seeds the dominant from the
	// live HAMT). WITHOUT a live source, the durable-only early-exit stands —
	// byte-identical to Day-26 (T-LIVE-OFF-IS-BYTE-IDENTICAL).
	if len(l1Keys) == 0 && len(l0Keys) == 0 && r.liveSource == nil {
		return nil, ErrEntityNotFound
	}

	// Load the compaction manifest(s) for this entity so AsOf can SKIP the L0
	// keys already merged into the L1 (they are superseded — their rows are in
	// the L1, scanning them again is redundant; the L0 files are NOT deleted,
	// per delete-after-read-safety). A manifest that fails to load is skipped
	// (honest fallback: the L0 remains scannable, so worst case a superseded L0
	// is re-scanned, returning the SAME dominant the L1 already produced — no
	// correctness loss, only redundant work).
	// Day 25 (ADR-0030): pass txTimeNs into loadSupersededL0Keys so the
	// manifest-channel download skip can bound the compaction manifests the
	// SAME way the Day-24 file-skip bounds the L0/L1 scan keys (the SAME
	// tautology, the SAME parser, the SAME EnableFirstSysSkip flag — the
	// manifest's filename-encoded firstSys == the L1's MIN sysTime, so a
	// manifest whose firstSys > txTime points at an L1 the file-skip drops
	// anyway AND lists L0s the file-skip drops anyway → skipping the manifest
	// DOWNLOAD preserves the superseded set w.r.t. the query's VISIBLE rows
	// byte-identically, Law II). txTimeNs is in scope at :259 (AsOf-entry).
	superseded := r.loadSupersededL0Keys(ctx, l0Prefix, txTimeNs)

	// Apply supersession: the tail is the L0 keys NOT in any manifest. The L1
	// holds their rows (verbatim — §0.4 preserve-all); scanning a superseded
	// L0 is redundant, not wrong, but skipping them is the honest Tail bound.
	var tailKeys []string
	for _, k := range l0Keys {
		if _, skip := superseded[k]; skip {
			continue
		}
		tailKeys = append(tailKeys, k)
	}

	// Day-13 MaxL0Files cap disclosure (ADR-0018 §6 → clarified Day 14 §0.5):
	// the cap now bounds the SURVIVING tail (the recent uncompacted checkpoints),
	// NOT all-time L0. If the tail exceeds the cap, the oldest tail files are
	// dropped from the scan — HONEST in a stronger sense than Day-13: the L1 is
	// ALWAYS scanned (the merged history), so the dropped tail files are
	// uncompacted L0s NOT yet merged. The disclosure counter fires as the
	// rare-stall signal (compaction is behind; the tail is growing faster than
	// compaction drains). The honest negative: if compaction is DISABLED (no L1)
	// and the tail exceeds the cap, the OLDEST tail files are lost (the same
	// silent-loss form Day-13 disclosed; compaction is opt-in, the disclosure
	// stays loud, the returned dominant is the newest-N tail's).
	if r.config.MaxL0Files > 0 && len(tailKeys) > r.config.MaxL0Files {
		if telemetry.QueryL0ListCapped != nil {
			telemetry.QueryL0ListCapped.Add(1)
		}
		// Cap to the NEWEST MaxL0Files tail files (sort ascending → truncate the
		// oldest; the survivors are the recent uncompacted checkpoints). A
		// reverse-scan order is applied below; the cap here is asc-truncate so
		// the dropped files are the OLDEST tail (the ones nearest compaction).
		sort.Strings(tailKeys)
		tailKeys = tailKeys[len(tailKeys)-r.config.MaxL0Files:]
	}

	// Combine L1 (always scanned, uncapped) + the capped tail. The dominance
	// relation (max SystemTime wins) is order-independent; the reverse sort
	// below is purely a scan-order optimization (newest files first for
	// early-termination on the dominant SystemTime).
	scanKeys := make([]string, 0, len(l1Keys)+len(tailKeys))
	scanKeys = append(scanKeys, l1Keys...)
	if len(scanKeys) == 0 && len(tailKeys) == 0 {
		// All L0 keys were superseded (compacted) but the L1 list was empty —
		// a manifest pointed at an L1 that no longer exists. Fall back to
		// scanning the (uncapped) L0 keys (the manifests may be stale/corrupt);
		// honest negative: the L0 files carry Truth (Law II).
		scanKeys = l0Keys
	}
	scanKeys = append(scanKeys, tailKeys...)
	if telemetry.QueryL1FilesScanned != nil {
		telemetry.QueryL1FilesScanned.Add(float64(countPrefix(scanKeys, l1Prefix)))
	}
	sort.Sort(sort.Reverse(sort.StringSlice(scanKeys)))

	// Phase 2: Scan files and apply tri-temporal dominance relation.
	var dominant *TriTemporalEvent
	var dominantSystemTime int64

	for _, key := range scanKeys {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("query: cancelled during scan: %w", err)
		}

		// Day 24 (ADR-0029): transitively-safe download skip. The file's MIN
		// sysTime (FirstSysTimeNs) is in the filename (l0_flusher.go:314 /
		// l1_compactor.go:950). If it exceeds this query's txTime, EVERY row in
		// the file fails Filter2 (sysTime<=txTime at scanRecordBatch) → ZERO
		// qualifying rows → skip the download + decode (Law II preserved, §0.e:
		// the file carries ZERO rows visible at txTime; the answer set is byte-
		// IDENTICAL with the file skipped). The skip is order-INDEPENDENT (a
		// per-file filter, NOT a contiguous-prefix break), counted
		// (QueryDownloadSkippedFirstSys), and FAILSAFE: a parse anomaly returns
		// ok=false → NO skip → the pre-Day-24 download+scan path runs (a corrupt/
		// renamed/foreign file is NEVER silently dropped). The bound is STRICT
		// (firstSys > txTime): a row AT sysTime==txTime passes Filter2 (<=), so
		// firstSys==txTime means the file's first row MIGHT qualify → DO NOT skip.
		if r.config.EnableFirstSysSkip {
			if firstSys, ok := parseFirstSysFromKey(key); ok && firstSys > txTimeNs {
				if telemetry.QueryDownloadSkippedFirstSys != nil {
					telemetry.QueryDownloadSkippedFirstSys.Inc()
				}
				continue
			}
		}

		match, sysTime, scanErr := r.scanFile(ctx, key, hashPrefix, entityIDBytes, validTimeNs, txTimeNs)
		if scanErr != nil {
			// Log but continue scanning — one corrupt file should not break queries.
			// In production, this should emit a Prometheus counter for corrupted L0 files.
			continue
		}

		if match != nil && sysTime > dominantSystemTime {
			dominant = match
			dominantSystemTime = sysTime
		}
	}

	// Day 27 (ADR-0032): the read-your-writes live merge. After the durable scan,
	// consult the live δ-CRDT HAMT (engine.State().Get, pinned by the adapter's
	// EBR Acquire/Enter/Release — the SnapshotToLSM precedent, snapshot.go:391-
	// 394) + merge the live dominant under the SAME bitemporal dominance the
	// durable scan just computed. The adapter already applied Filter2
	// (SystemTime <= txTimeNs) — the visibility bound well-defined for AsOf. The
	// Resolver applies Filter3 (point: validStart <= validTimeNs < validEnd —
	// byte-identical to scanRecordBatch's Filter3 at the row-predicate level) +
	// the SAME dominance (sysTime > dominantSystemTime — the `>` at :529). So:
	//   - durable found a dominant → live entries compete under the same `>`; a
	//     live entry with a LATER sysTime wins (the read-your-writes case: the
	//     just-inserted live dot has a sysTime newer than the durable dominant).
	//   - durable found NOTHING (dominant == nil, because the :404 early-exit was
	//     guarded on r.liveSource==nil + zero durable keys) → the live entries
	//     SEED the dominant from scratch. This is the load-bearing rescue: a
	//     POST /v1/insert followed by an IMMEDIATE GET /v1/query (checkpoint
	//     disabled) finds zero durable dominant, then the live merge seeds it.
	//
	// The merge is a 2-input dominance selection — the durable dominant and the
	// live dominant are independent inputs; the merged result is byte-identical
	// to the durable-only result once the live entry is checkpointed into L0
	// (Law II tautology — the live entry IS the durable entry's seed: SnapshotToLSM
	// writes the CRDTEntry verbatim, snapshot.go:447; T-LIVE-MERGE-EQUIV). A
	// live-source error NEVER fails the query — the durable answer stands alone
	// (the SAME failure-honesty loadSupersededL0Keys uses — a live miss is a
	// redundancy, NOT a correctness loss). The QueryLiveSourceReads counter fires
	// ONCE per query that consulted the live path (NOT per live entry — the count
	// is the path disclosure, the SAME Law V class the download-skip counter
	// carries).
	if r.liveSource != nil {
		if telemetry.QueryLiveSourceReads != nil {
			telemetry.QueryLiveSourceReads.Inc()
		}
		lcs, lerr := r.liveSource.LiveRead(ctx, entityID, txTimeNs)
		if lerr == nil {
			for _, le := range lcs {
				// DEFENSIVE Filter2 (Law II guard): the adapter's contract is to
				// return ONLY entries with SystemTime <= txTimeNs (the visibility
				// bound). A buggy/foreign adapter that returns an entry with
				// SystemTime > txTimeNs would — under a trust-only design — pass
				// Filter3 + dominance and become the dominant → a SILENT Law II
				// break (returning a row NOT visible at txTime). The one-comparison
				// re-check is behavior-identical to trust-only when the adapter is
				// correct (the check never fires; zero cost) and a hard guarantee
				// when it is not (the entry is dropped). Defense-in-depth for a
				// correctness-critical seam — the same discipline the EnforceValid
				// guard at scanRecordBatch's Filter2 (:969) carries for the
				// durable path. The bound is STRICT <= (a row AT sysTime==txTime
				// passes — byte-identical to the durable Filter2).
				if le.SystemTime > txTimeNs {
					continue
				}
				// Filter3 (point): validStart <= validTimeNs < validEnd — the
				// SAME half-open bound scanRecordBatch applies (query.go:977).
				if validTimeNs < le.ValidTimeStart || validTimeNs >= le.ValidTimeEnd {
					continue
				}
				// Dominance: max SystemTime wins — the SAME `>` the durable
				// scan uses at :529 (NOT >=; a live entry AT the durable
				// sysTime does NOT displace it — the durable answer is the
				// honest default; T-LIVE-MERGE-EQUIV's BUG-INJECT flips > to
				// >= and proves the boundary is load-bearing, the Day-24 class).
				if le.SystemTime > dominantSystemTime {
					dominant = &TriTemporalEvent{
						EntityID:       entityID,
						SystemTime:     le.SystemTime,
						ValidTimeStart: le.ValidTimeStart,
						ValidTimeEnd:   le.ValidTimeEnd,
						AssertionTime:  le.AssertionTime,
						H3Index:        le.H3Index,
						Payload:        le.Payload,
						PayloadDigest:  le.PayloadDigest,
					}
					dominantSystemTime = le.SystemTime
				}
			}
		}
		// lerr is intentionally NOT returned: a live-source error is a
		// redundancy, not a correctness loss (the durable answer stands alone).
	}

	if dominant == nil {
		return nil, ErrEntityNotFound
	}

	return dominant, nil
}

// Range (Day 19, ADR-0024) resolves EVERY durable row for entity E whose
// valid-time interval intersects [validTimeLo, validTimeHi) AND whose SystemTime
// is <= txTime — the bitemporal-HISTORY range read the single-point Resolver.AsOf
// cannot answer. AsOf collapses the durable index to ONE dominant point; Range
// returns the sorted window of rows that intersect the query's valid-time window
// at the given transaction-time horizon.
//
// THE RANGE SEMANTIC (§1.1) — interval-INTERSECTION, NOT point-in-window. A row
// R qualifies iff:
//
//	(W1) R.validTimeStart < validTimeHi
//	(W2) R.validTimeEnd   > validTimeLo      (the bitemporal interval [vs,ve)
//	                                        INTERSECTS the query window [vLo,vHi))
//	(W3) R.SystemTime     <= txTime           (Filter 2 from scanRecordBatch
//	                                        holds — visibility at txTime)
//	(W4) entity-hash-prefix match + full entityID verify (Filter 1 + Filter 4
//	                                        carry ONE-FOR-ONE — the collision guard)
//
// The (W1)/(W2) bound discipline mirrors Filter 3's strict-vs-non-strict exactly:
// the high end is strict (R.validTimeStart < validTimeHi, NOT <= — a row that
// starts exactly AT validTimeHi is OUTSIDE the half-open window [vLo,vHi)) and the
// low end is strict-negated (R.validTimeEnd > validTimeLo — a row ending exactly AT
// validTimeLo does NOT intersect the half-open window). The composite skip rule
// (rowValidStart >= validTimeHi || rowValidEnd <= validTimeLo) is the inverse of
// (W1)&&(W2) and carries the SAME half-open bounds Filter 3 uses for its point
// membership (validTimeNs >= validStart, validTimeNs < validEnd).
//
// WHY interval-intersection (not point-in-window): a record valid [100,200)
// answers "what was true at v=150" AND "what was true across the window
// [120,180)" — both are queries into the SAME record's validity interval.
// Dropping a record whose interval merely OVERLAPS the window but does not
// contain a queried point would SILENTLY LOSE history (the SAME silent-data-loss
// class this engine has closed since Day-8). The carrier of bitemporal truth is
// the interval, so the window query is over the interval, not a point sweep.
//
// FILE LOOP MIRRORS AsOf (§1.3): the SAME L1-always + L0-tail-after-supersession
// discipline — loadSupersededL0Keys, the MaxL0Files tail cap, the reverse sort,
// the ctx-check. A Range result MUST be a superset of the AsOf point at every v
// in the window (T2), so the durable SURFACE Range scans is byte-identical to
// AsOf's. The ONLY structural difference from AsOf is the terminal action: each
// file contributes EVERY row passing (W1)-(W4) into the caller's slice instead of
// one dominant. See scanWindowFile / scanWindowRecordBatch (the N-row siblings).
//
// THE UNBOUNDED-AMPLIFICATION GUARD (§1.2): AsOf returns ONE event; Range can
// return O(history). The collector caps at MaxRangeRows (default 4096) BEFORE the
// caller's JSON marshal ever sees the slice — the marshal never rows > the cap.
// On a hit, Range returns the capped rows + truncated=true (the operator widens
// the window or paginates; the pagination token is a FUTURE fork — §6). A tooth
// gates MaxRangeRows=4 over a 10-row history asserts truncated=true + exactly 4.
//
// SORT: rows are returned sorted by validTimeStart ascending — the honest raw
// window. CoalesceLatest (per-point dominance across the window) is a DIFFERENT
// query (an AsOf sweep); it is offered ONLY via the optional coalesce bool, which
// is a POST-sort pass reusing the SAME Filter-2 + dominance rule AsOf uses, NOT a
// scanRecordBatch change. Default OFF (raw window).
//
// Error Conditions:
//   - ErrEntityNotFound: no row in the durable index intersects the window at txTime.
//   - context.Canceled/DeadlineExceeded: query was cancelled or timed out.
//   - S3/IO errors: per-file scan errors are swallowed (one corrupt file does not
//     break the window) — the SAME continue-on-error AsOf carries (scanFile).
func (r *Resolver) Range(ctx context.Context, entityID string, validTimeLo, validTimeHi time.Time, transactionTime time.Time) ([]*TriTemporalEvent, bool, error) {
	if entityID == "" {
		return nil, false, fmt.Errorf("query: entityID must not be empty")
	}
	// A half-open window whose hi <= lo is EMPTY by construction — there is no
	// row whose [vs,ve) can intersect a ZERO-or-negative-width window. This is the
	// honest 400-class guard the /v1/range handler surfaces BEFORE listing; the
	// resolver double-guards (a caller that reaches Range directly with an empty
	// window gets the honest empty result, not a silent full scan).
	if !validTimeHi.After(validTimeLo) {
		return nil, false, ErrEntityNotFound
	}

	// Compute hashes — byte-identical to AsOf's path (query.go hash computation).
	entityIDBytes := unsafe.Slice(unsafe.StringData(entityID), len(entityID))
	fullHash := sha256.Sum256(entityIDBytes)
	var hashPrefix [16]byte
	copy(hashPrefix[:], fullHash[:16])

	var hexBuf [16]byte
	hex.Encode(hexBuf[:], hashPrefix[:8])
	hexPrefixStr := unsafe.String(&hexBuf[0], 16)
	l0Prefix := "l0/" + hexPrefixStr + "/"
	l1Prefix := "l1/" + hexPrefixStr + "/"

	// Window + tx horizon in ns (the Arrow schema's ns coordinates).
	validLoNs := validTimeLo.UnixNano()
	validHiNs := validTimeHi.UnixNano()
	txTimeNs := transactionTime.UnixNano()

	// Phase 1: list L1 + L0 — byte-identical to AsOf's listing discipline.
	if err := ctx.Err(); err != nil {
		return nil, false, fmt.Errorf("query: cancelled before listing: %w", err)
	}
	l1Keys, err := r.lister.ListObjects(ctx, r.bucket, l1Prefix, 0)
	if err != nil {
		return nil, false, fmt.Errorf("query: list L1 objects: %w", err)
	}
	l0Keys, err := r.lister.ListObjects(ctx, r.bucket, l0Prefix, 0)
	if err != nil {
		return nil, false, fmt.Errorf("query: list L0 objects: %w", err)
	}
	// The entity has NO durable data (neither L1 nor L0) on disk → honest miss.
	// Day 27 (ADR-0032): this early-exit is GUARDED on the live source — the
	// SAME M-ASOF-EARLY-EXIT refinement AsOf carries (query.go:442). With a live
	// δ-CRDT HAMT configured (r.liveSource != nil), zero durable keys does NOT
	// mean not-found — the entry a POST /v1/insert just placed is in the LIVE
	// HAMT but has NOT yet been flushed by the bridge's periodic AppendCheckpoint
	// to L0. Returning 404 here would DEFEAT read-your-writes on the RANGE path
	// (the load-bearing empirical proof: insert → IMMEDIATE range → 200, the SAME
	// contract the point query carries). So: with a live source, skip the
	// durable-only early-exit + fall through to the scan (which finds no durable
	// window rows) + the live merge below (which appends the live window rows).
	// WITHOUT a live source, the durable-only early-exit stands — byte-identical
	// to Day-26 (T-LIVE-OFF-IS-BYTE-IDENTICAL covers BOTH read paths).
	//
	// BUG HISTORY (the runtime verify that caught this): the first runtime pass
	// returned 200 on the IMMEDIATE point query (AsOf guarded) but 404 on the
	// IMMEDIATE range — the Range early-exit was NOT guarded, so the live-merge
	// block at :867 was never reached (the QueryLiveSourceReads counter was 2,
	// not 3). The T-LIVE-RANGE tooth used a NON-empty durable tier (or a
	// synthetic live source that bypassed the list), so it did NOT surface this;
	// the runtime verify over a REAL empty-durable engine did. The fix is the
	// load-bearing symmetry: BOTH read paths guard the zero-durable early-exit
	// on r.liveSource == nil.
	if len(l1Keys) == 0 && len(l0Keys) == 0 && r.liveSource == nil {
		return nil, false, ErrEntityNotFound
	}

	// Supersession: byte-identical to AsOf (the SAME loadSupersededL0Keys tail
	// discipline — a Range whose tail differs from AsOf's would NOT be a superset).
	// Day 25 (ADR-0030): pass txTimeNs (in scope at :512) so the manifest-channel
	// skip bounds compaction manifests the SAME way AsOf does (the manifest
	// skip bounds sysTime, NOT validTime — the SAME orthogonality the Day-24
	// Range file-skip carries; a wide window does NOT rescue a skipped manifest).
	superseded := r.loadSupersededL0Keys(ctx, l0Prefix, txTimeNs)
	var tailKeys []string
	for _, k := range l0Keys {
		if _, skip := superseded[k]; skip {
			continue
		}
		tailKeys = append(tailKeys, k)
	}
	if r.config.MaxL0Files > 0 && len(tailKeys) > r.config.MaxL0Files {
		if telemetry.QueryL0ListCapped != nil {
			telemetry.QueryL0ListCapped.Add(1)
		}
		sort.Strings(tailKeys)
		tailKeys = tailKeys[len(tailKeys)-r.config.MaxL0Files:]
	}
	scanKeys := make([]string, 0, len(l1Keys)+len(tailKeys))
	scanKeys = append(scanKeys, l1Keys...)
	if len(scanKeys) == 0 && len(tailKeys) == 0 {
		scanKeys = l0Keys
	}
	scanKeys = append(scanKeys, tailKeys...)
	if telemetry.QueryL1FilesScanned != nil {
		telemetry.QueryL1FilesScanned.Add(float64(countPrefix(scanKeys, l1Prefix)))
	}
	sort.Sort(sort.Reverse(sort.StringSlice(scanKeys)))

	// Phase 2: scan files, collecting every window-intersecting row. The cap is
	// MaxRangeRows-resident; 0 = UNLIMITED (the disclosed unbounded sentinel).
	cap := r.config.MaxRangeRows
	var collected []*TriTemporalEvent
	if cap > 0 {
		collected = make([]*TriTemporalEvent, 0, min(cap, 64))
	} else {
		collected = make([]*TriTemporalEvent, 0, 64)
	}
	truncated := false
	for _, key := range scanKeys {
		if err := ctx.Err(); err != nil {
			return nil, false, fmt.Errorf("query: cancelled during scan: %w", err)
		}
		// Day 24 (ADR-0029): transitively-safe download skip — byte-identical to
		// AsOf's block (the SAME FirstSysTimeNs bound, the SAME txTimeNs). The
		// window [vLo,vHi) is IRRELEVANT to the skip: the skip bounds sysTime
		// (Filter2), the window bounds validTime (Filter3). The window-passing
		// rows are a SUBSET of the Filter2-passing rows, so a file with min>
		// txTime has ZERO Filter2-passers ⟹ ZERO window-passers ⟹ the skip is
		// STILL transitively-safe for Range (§0.e step 7: the window slice is
		// UNCHANGED byte-for-byte). FAILSAFE + counted identically to AsOf.
		if r.config.EnableFirstSysSkip {
			if firstSys, ok := parseFirstSysFromKey(key); ok && firstSys > txTimeNs {
				if telemetry.QueryDownloadSkippedFirstSys != nil {
					telemetry.QueryDownloadSkippedFirstSys.Inc()
				}
				continue
			}
		}
		// The cap is checked INSIDE the per-file collector (scanWindowFile) BEFORE
		// the row is appended — so a single file exceeding the cap does not
		// over-allocate past it. The collector signals `stop` on a cap hit; we
		// break the file loop here (the remaining files are newer-dominant-or-
		// older but the cap is the safety contract, not a best-effort hint).
		rows, stop, scanErr := r.scanWindowFile(ctx, key, hashPrefix, entityIDBytes, validLoNs, validHiNs, txTimeNs, collected, cap)
		if scanErr != nil {
			// Same continue-on-error discipline as AsOf (scanFile): one corrupt
			// file does not break the window — the durable surface still serves
			// the rows the surviving files carry (Law II).
			continue
		}
		collected = rows
		if stop {
			truncated = true
			break
		}
	}

	// Day 27 (ADR-0032): the read-your-writes live merge for Range. After the
	// durable scan, consult the live δ-CRDT HAMT + append every live entry that
	// passes the window predicate (W1)&&(W2) — the SAME interval-INTERSECTION
	// scanWindowRecordBatch applies (query.go:1138: validStart < validHiNs AND
	// validEnd > validLoNs). The adapter already applied Filter2 (sysTime<=txTime),
	// so the live set is visibility-bounded; the Resolver applies the window here.
	//
	// THE DEDUP (load-bearing — the live ⊇ durable consequence the prompt's M6
	// tautology assumed away for Range): the live HAMT is APPEND-ONLY and NEVER
	// pruned (grep Prune|Reset|Retire on crdt.go/hamt.go is empty; AppendCheckpoint
	// → SnapshotToLSM only READS engine.State().ForEach, never mutates), and the
	// durable Arrow index is built FROM the live HAMT (snapshot.go:436). So live
	// ⊇ durable, ALWAYS — in steady state AND post-recovery (the dot-bearing image
	// is the full dot set at checkpoint). After a checkpoint, the live HAMT STILL
	// holds the checkpointed dot AND the durable tier now holds the same row → a
	// naive "append every live row" would DUPLICATE every checkpointed row → a
	// Law II break the prompt's M6 reasoned away (M6 reasons about AsOf's SINGLE
	// dominant — max wins, dedup-free — NOT Range's MULTI-ROW slice). The dedup
	// key is (SystemTime, PayloadDigest): the Arrow schema carries NO dot columns,
	// so dot-dedup is impossible at the row level; (sysTime, 32-byte digest) is
	// the honest row identity — the digest is a content hash (the no-recompute
	// law, control.go:441), so two rows with the same (sysTime, digest) ARE the
	// same row. A live row whose (sysTime, digest) is ALREADY in the durable
	// collected slice is a checkpointed twin → skip (NOT append). A live row NOT
	// in durable is a genuine read-your-writes row (not yet checkpointed) → append.
	// The result: live ∪ durable with the durable twins deduped → byte-identical
	// to the fully-flushed durable-only Range once the live rows checkpoint (Law
	// II; T-LIVE-RANGE). A live-source error NEVER fails the query (the durable
	// window stands alone); the QueryLiveSourceReads counter fires once per
	// Range that consulted the live path (the SAME disclosure AsOf carries).
	if r.liveSource != nil {
		if telemetry.QueryLiveSourceReads != nil {
			telemetry.QueryLiveSourceReads.Inc()
		}
		lcs, lerr := r.liveSource.LiveRead(ctx, entityID, txTimeNs)
		if lerr == nil && len(lcs) > 0 {
			// Build the dedup set over the durable rows ALREADY collected (the
			// live ⊇ durable twin check). A map from the dedup key → struct{}
			// is the honest O(1) lookup; the key is (sysTime int64, digest [32]byte)
			// — the SAME identity the no-recompute law makes canonical. Sized to
			// the durable slice so the live append-with-check is amortized O(1).
			seen := make(map[liveRowKey]struct{}, len(collected))
			for _, d := range collected {
				seen[liveRowKey{sys: d.SystemTime, digest: d.PayloadDigest}] = struct{}{}
			}
			for _, le := range lcs {
				// DEFENSIVE Filter2 (Law II guard): byte-identical rationale to the
				// AsOf merge (query.go:570) — a buggy/foreign adapter returning an
				// entry with SystemTime > txTimeNs would otherwise pass the window
				// predicate + append → a SILENT Law II break (a row NOT visible at
				// txTime in the window). The one-comparison re-check is zero cost on
				// a correct adapter (never fires) + a hard guarantee otherwise. The
				// bound is STRICT <= (a row AT sysTime==txTime passes — byte-identical
				// to scanWindowRecordBatch's Filter2 at :969).
				if le.SystemTime > txTimeNs {
					continue
				}
				// Filter3 WINDOW VARIANT: (W1) validStart < validHiNs AND (W2)
				// validEnd > validLoNs — byte-identical to scanWindowRecordBatch's
				// interval-INTERSECTION at query.go:1138 (NOT point-in-window —
				// interval-intersection is the load-bearing Range semantic, §1.1).
				if le.ValidTimeStart >= validHiNs || le.ValidTimeEnd <= validLoNs {
					continue
				}
				key := liveRowKey{sys: le.SystemTime, digest: le.PayloadDigest}
				if _, dup := seen[key]; dup {
					// The live row is a checkpointed twin of a durable row already
					// in the slice — skip (the dedup that live ⊇ durable forces).
					continue
				}
				seen[key] = struct{}{}
				// CAP: the SAME MaxRangeRows guard scanWindowRecordBatch enforces
				// BEFORE each append (query.go:1156). A live append past the cap
				// would let the marshal see > cap rows — the unbounded-amplification
				// leak ADR-0024 closed. Honor the cap identically; on a hit, set
				// truncated + stop appending (the live tail is dropped, same as a
				// durable tail past the cap — the cap is the safety contract).
				if cap > 0 && len(collected) >= cap {
					truncated = true
					break
				}
				collected = append(collected, &TriTemporalEvent{
					EntityID:       entityID,
					SystemTime:     le.SystemTime,
					ValidTimeStart: le.ValidTimeStart,
					ValidTimeEnd:   le.ValidTimeEnd,
					AssertionTime:  le.AssertionTime,
					H3Index:        le.H3Index,
					Payload:        le.Payload,
					PayloadDigest:  le.PayloadDigest,
				})
			}
		}
		// lerr is intentionally NOT returned (the durable window stands alone).
	}

	if len(collected) == 0 {
		return nil, false, ErrEntityNotFound
	}

	// Sort by validTimeStart ascending — the honest raw window (CoalesceLatest
	// is a DIFFERENT query; the default is raw, NOT per-point dominance). The
	// live rows appended above interleave with the durable rows under this SAME
	// sort — no separate live-merge step (the dedup already removed the twins).
	sort.SliceStable(collected, func(i, j int) bool {
		return collected[i].ValidTimeStart < collected[j].ValidTimeStart
	})

	// The truncation flag is the honest operator signal (the cap was hit). The
	// rows returned are the FIRST cap rows the scan encountered (reverse-scan
	// order means newest-SystemTime files first, but within the cap the
	// validTimeStart sort above is the operator-facing order). A future pagination
	// token (= the last returned row's validTimeEnd) is disclosed in §6, NOT
	// implemented here.
	return collected, truncated, nil
}

// CoalesceRange (Day 19, ADR-0024 §1.1) is the OPTIONAL post-sort dominance
// pass over a Range window. It collapses the raw intersecting rows to the
// per-validTime-point dominant (the SAME Filter-2 + max-SystemTime rule AsOf
// uses), returning the dominant event for each maximal valid-time sub-interval.
// It is NOT the default Range output (Range returns the raw sorted window); a
// caller opts in via Range(... ) then CoalesceRange(result) — or via the
// ?coalesce=true /v1/range param (handleRange).
//
// The coalesce is a PURE FUNCTION over the collected rows — it does NOT re-scan
// the durable index. It reuses the SAME dominance rule AsOf applies at a point:
// among rows whose [validStart, validEnd) covers a given validTime, the LATEST
// SystemTime <= txTime wins. The output is sorted by validTimeStart ascending.
//
// This is a carry-as-optional, NOT a substitute for Range's raw output: the raw
// window is the bitemporal history "as-durable"; the coalesced window is the
// "effective-state-over-time" projection. Both are honest; the operator picks.
func CoalesceRange(rows []*TriTemporalEvent) []*TriTemporalEvent {
	if len(rows) <= 1 {
		return rows
	}
	// Sort by validTimeStart asc (stabilize by SystemTime desc so an earlier-start
	// later-system row dominates a same-start earlier-system one — the AsOf rule).
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].ValidTimeStart != rows[j].ValidTimeStart {
			return rows[i].ValidTimeStart < rows[j].ValidTimeStart
		}
		return rows[i].SystemTime > rows[j].SystemTime
	})
	// Deduplicate on validTimeStart: keep the first (highest SystemTime at that
	// start = the AsOf dominant for that sub-interval). This is a coarse per-
	// validTimeStart coalesce; a finer per-point sweep is the AsOf-at-each-v
	// projection (a future fork, disclosed in §6 — the default coalesce is the
	// honest per-start dominant, NOT a fabricated point sweep).
	out := make([]*TriTemporalEvent, 0, len(rows))
	var lastStart int64
	first := true
	for _, r := range rows {
		if first || r.ValidTimeStart != lastStart {
			out = append(out, r)
			lastStart = r.ValidTimeStart
			first = false
		}
	}
	return out
}

// scanFile opens a single L0 Arrow IPC file and scans for matching records.
// Returns the best matching event within this file (latest SystemTime that
// satisfies the temporal predicates) and its SystemTime for dominance comparison.
//
// Zero-Copy Strategy:
//   - Uses ipc.NewFileReader to read Arrow IPC file format.
//   - Record batches are accessed via typed column accessors (no deserialization).
//   - Entity ID comparison uses raw byte slices (no string conversion).
//   - The returned TriTemporalEvent is constructed from Arrow column values.
func (r *Resolver) scanFile(
	ctx context.Context,
	key string,
	hashPrefix [16]byte,
	entityIDBytes []byte,
	validTimeNs int64,
	txTimeNs int64,
) (*TriTemporalEvent, int64, error) {

	// Download the Arrow IPC file from S3.
	rc, err := r.downloader.Download(ctx, r.bucket, key)
	if err != nil {
		return nil, 0, fmt.Errorf("download %s: %w", key, err)
	}
	defer func() { _ = rc.Close() }()

	// SECURITY AUDIT FIX - PASS 0: Use jemalloc-backed buffer to keep it off Go heap.
	var alloc = memory.DefaultAllocator
	if r.allocator != nil {
		alloc = r.allocator
	}

	// Dynamically grow the off-heap buffer to prevent OOM on large files and
	// avoid massive memory churn for small files.
	capacity := 32 * 1024 // 32KB initial
	dataBuf := alloc.Allocate(capacity)
	defer func() {
		if dataBuf != nil {
			alloc.Free(dataBuf)
		}
	}()

	var n int
	for {
		if n == capacity {
			capacity *= 2
			dataBuf = alloc.Reallocate(capacity, dataBuf)
		}
		readBytes, err := rc.Read(dataBuf[n:])
		n += readBytes
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, 0, fmt.Errorf("read %s: %w", key, err)
		}
	}

	if n == 0 {
		return nil, 0, nil
	}

	reader, err := ipc.NewFileReader(bytes.NewReader(dataBuf[:n]), ipc.WithAllocator(alloc))
	if err != nil {
		return nil, 0, fmt.Errorf("open arrow reader %s: %w", key, err)
	}
	defer func() { _ = reader.Close() }()

	// Validate schema compatibility.
	schema := reader.Schema()
	if schema.NumFields() != ArrowSchema.NumFields() {
		return nil, 0, fmt.Errorf("schema mismatch in %s: expected %d fields, got %d", key, ArrowSchema.NumFields(), schema.NumFields())
	}

	// SECURITY AUDIT FIX - PASS 3: Per-field type validation
	for i := 0; i < schema.NumFields(); i++ {
		if !arrow.TypeEqual(schema.Field(i).Type, ArrowSchema.Field(i).Type) {
			return nil, 0, fmt.Errorf("type mismatch at field %d in %s: expected %s, got %s",
				i, key, ArrowSchema.Field(i).Type, schema.Field(i).Type)
		}
	}

	var bestMatch *TriTemporalEvent
	var bestSystemTime int64

	// Iterate over all record batches in the file.
	numRecords := reader.NumRecords()
	for i := 0; i < numRecords; i++ {
		if err := ctx.Err(); err != nil {
			return bestMatch, bestSystemTime, nil // Return best so far on cancellation
		}

		rec, err := reader.Record(i)
		if err != nil {
			continue // Skip corrupted record batch
		}

		match, sysTime := r.scanRecordBatch(rec, hashPrefix, entityIDBytes, validTimeNs, txTimeNs, bestSystemTime)
		if match != nil && sysTime > bestSystemTime {
			bestMatch = match
			bestSystemTime = sysTime
		}
	}

	return bestMatch, bestSystemTime, nil
}

// scanWindowFile (Day 19, ADR-0024) opens a single Arrow IPC file and scans for
// EVERY matching record in the valid-time window — the N-row sibling of scanFile.
// It mirrors scanFile's download + growable off-heap buffer + schema-validation
// path BYTE-IDENTICALLY (the SAME off-heap jemalloc buffer growth, the SAME per-
// field type-assertion, the SAME reader.NumRecords loop, the SAME continue-on-
// corrupted-record + return-best-on-cancel discipline). The ONLY structural
// difference is the inner per-batch call: it calls scanWindowRecordBatch (which
// appends EVERY window-intersecting row into the caller's slice) instead of
// scanRecordBatch (which tracks ONE bestRowIndex).
//
// The cap (MaxRangeRows) is enforced INSIDE scanWindowRecordBatch, BEFORE each
// append — so this function OVER-ALLOCATES neither the per-file scan buffer nor
// the returned slice past the cap. The `stop` bool is the per-file cap-hit
// signal: when scanWindowRecordBatch hits the cap, it returns stop=true so the
// file loop in Range can break (the cap is the safety contract, not a hint).
//
// On a download/read error (the SAME class scanFile handles), it returns the
// error; Range surfaces it via continue-on-error (one corrupt file does NOT
// break the window — the SAME discipline AsOf carries).
func (r *Resolver) scanWindowFile(
	ctx context.Context,
	key string,
	hashPrefix [16]byte,
	entityIDBytes []byte,
	validLoNs int64,
	validHiNs int64,
	txTimeNs int64,
	collected []*TriTemporalEvent,
	cap int,
) ([]*TriTemporalEvent, bool, error) {
	rc, err := r.downloader.Download(ctx, r.bucket, key)
	if err != nil {
		return collected, false, fmt.Errorf("download %s: %w", key, err)
	}
	defer func() { _ = rc.Close() }()

	// SECURITY AUDIT FIX - PASS 0: Use jemalloc-backed buffer to keep it off Go heap
	// (byte-identical to scanFile's buffer discipline — Range is a READ path, the
	// SAME off-heap growth the single-row path uses).
	var alloc = memory.DefaultAllocator
	if r.allocator != nil {
		alloc = r.allocator
	}
	capacity := 32 * 1024 // 32KB initial
	dataBuf := alloc.Allocate(capacity)
	defer func() {
		if dataBuf != nil {
			alloc.Free(dataBuf)
		}
	}()

	var n int
	for {
		if n == capacity {
			capacity *= 2
			dataBuf = alloc.Reallocate(capacity, dataBuf)
		}
		readBytes, err := rc.Read(dataBuf[n:])
		n += readBytes
		if err == io.EOF {
			break
		}
		if err != nil {
			return collected, false, fmt.Errorf("read %s: %w", key, err)
		}
	}

	if n == 0 {
		return collected, false, nil
	}

	reader, err := ipc.NewFileReader(bytes.NewReader(dataBuf[:n]), ipc.WithAllocator(alloc))
	if err != nil {
		return collected, false, fmt.Errorf("open arrow reader %s: %w", key, err)
	}
	defer func() { _ = reader.Close() }()

	// Schema validation — byte-identical to scanFile (the SAME mismatch + per-field
	// type-equality guards; a corrupt schema is a corrupt file → continue-on-error
	// at the Range file loop, NOT a silent wrong-typed read).
	schema := reader.Schema()
	if schema.NumFields() != ArrowSchema.NumFields() {
		return collected, false, fmt.Errorf("schema mismatch in %s: expected %d fields, got %d", key, ArrowSchema.NumFields(), schema.NumFields())
	}
	for i := 0; i < schema.NumFields(); i++ {
		if !arrow.TypeEqual(schema.Field(i).Type, ArrowSchema.Field(i).Type) {
			return collected, false, fmt.Errorf("type mismatch at field %d in %s: expected %s, got %s",
				i, key, ArrowSchema.Field(i).Type, schema.Field(i).Type)
		}
	}

	stop := false
	numRecords := reader.NumRecords()
	for i := 0; i < numRecords; i++ {
		if err := ctx.Err(); err != nil {
			// Return collected-so-far on cancellation (mirror scanFile's
			// "return best so far on cancellation" — a partial window is honest
			// under cancel, the caller sees truncated from ctx cancellation, NOT
			// silently-dropped tail).
			return collected, stop, nil
		}
		rec, err := reader.Record(i)
		if err != nil {
			continue // Skip corrupted record batch (byte-identical to scanFile)
		}
		collected, stop = r.scanWindowRecordBatch(rec, hashPrefix, entityIDBytes, validLoNs, validHiNs, txTimeNs, collected, cap)
		if stop {
			return collected, stop, nil
		}
	}
	return collected, stop, nil
}

// scanRecordBatch scans a single Arrow record batch for matching records.
// This is the hot inner loop — optimized for zero-allocation column access.
//
// Column Layout (from ArrowSchema in l0_flusher.go) — 9 columns, [0..8]:
//
//	[0] entity_id_hash   — FixedSizeBinary(16)
//	[1] system_time      — Timestamp(ns, UTC)
//	[2] valid_time_start — Timestamp(ns, UTC)
//	[3] valid_time_end   — Timestamp(ns, UTC)
//	[4] assertion_time   — Timestamp(ns, UTC)
//	[5] h3_index         — Uint64
//	[6] payload_digest   — FixedSizeBinary(32)
//	[7] entity_id        — LargeBinary
//	[8] payload          — LargeBinary
//
// D3 FIX (docs-vs-code): the prior comment listed only 8 columns and put
// entity_id at [6] / payload at [7], omitting payload_digest (now at [6]) and
// h3_index. The scanRecordBatch code has ALWAYS indexed columns [0..8]
// correctly (payloadDigestCol := rec.Column(6) (FixedSizeBinary), entityIDCol
// := rec.Column(7), payloadCol := rec.Column(8)); only the docstring drifted.
//
// Filtering Strategy (columnar predicate pushdown):
//  1. Hash prefix filter on column[0] — eliminates >99.99% of rows.
//  2. Full entity ID verification on column[7] — eliminates 128-bit hash collisions.
//  3. SystemTime filter: column[1] <= txTimeNs.
//  4. ValidTime range filter: column[2] <= validTimeNs < column[3].
//  5. Dominance selection: max(SystemTime) among qualifying records.
func (r *Resolver) scanRecordBatch(
	rec arrow.Record,
	hashPrefix [16]byte,
	entityIDBytes []byte,
	validTimeNs int64,
	txTimeNs int64,
	currentBestSysTime int64,
) (*TriTemporalEvent, int64) {

	nRows := int(rec.NumRows())
	if nRows == 0 {
		return nil, 0
	}

	// Type-assert columns once (amortized over all rows).
	hashCol := rec.Column(0).(*array.FixedSizeBinary)
	sysTimeCol := rec.Column(1).(*array.Timestamp)
	validStartCol := rec.Column(2).(*array.Timestamp)
	validEndCol := rec.Column(3).(*array.Timestamp)
	assertTimeCol := rec.Column(4).(*array.Timestamp)
	h3Col := rec.Column(5).(*array.Uint64)
	payloadDigestCol := rec.Column(6).(*array.FixedSizeBinary)
	entityIDCol := rec.Column(7).(*array.LargeBinary)
	payloadCol := rec.Column(8).(*array.LargeBinary)

	var bestMatch *TriTemporalEvent
	var bestSysTime int64
	bestRowIndex := -1

	for row := 0; row < nRows; row++ {
		// Filter 1: Hash prefix match (128-bit, O(1) memory comparison).
		rowHash := hashCol.Value(row)
		if !bytes.Equal(rowHash, hashPrefix[:]) {
			continue
		}

		// Filter 2: SystemTime <= transactionTime (record must be visible at query time).
		sysTimeVal := int64(sysTimeCol.Value(row))
		if sysTimeVal > txTimeNs {
			continue
		}

		// Filter 3: ValidTime range contains query point.
		// validTimeStart <= validTimeNs < validTimeEnd
		validStart := int64(validStartCol.Value(row))
		validEnd := int64(validEndCol.Value(row))
		if validTimeNs < validStart || validTimeNs >= validEnd {
			continue
		}

		// Filter 4: Full entity ID verification (prevents hash collision false positives).
		// Security Audit Fix V3: This is MANDATORY. Without this check, a 128-bit
		// hash collision would return data for the WRONG entity.
		rowEntityID := entityIDCol.Value(row)
		if !bytes.Equal(rowEntityID, entityIDBytes) {
			continue
		}

		// Dominance Selection: Latest SystemTime wins.
		if sysTimeVal <= currentBestSysTime || sysTimeVal <= bestSysTime {
			continue
		}

		// SECURITY AUDIT FIX - PASS 1: Track index, do not allocate here
		bestRowIndex = row
		bestSysTime = sysTimeVal
	}

	// Single allocation after loop exits
	if bestRowIndex >= 0 {
		row := bestRowIndex
		assertTimeVal := int64(assertTimeCol.Value(row))
		h3Val := h3Col.Value(row)
		payloadBytes := payloadCol.Value(row)
		rowEntityID := entityIDCol.Value(row)

		payloadCopy := make([]byte, len(payloadBytes))
		copy(payloadCopy, payloadBytes)

		entityIDCopy := make([]byte, len(rowEntityID))
		copy(entityIDCopy, rowEntityID)

		payloadDigestBytes := payloadDigestCol.Value(row)
		var pd [32]byte
		copy(pd[:], payloadDigestBytes)

		bestMatch = &TriTemporalEvent{
			EntityID:       unsafe.String(unsafe.SliceData(entityIDCopy), len(entityIDCopy)),
			SystemTime:     bestSysTime,
			ValidTimeStart: int64(validStartCol.Value(row)),
			ValidTimeEnd:   int64(validEndCol.Value(row)),
			AssertionTime:  assertTimeVal,
			H3Index:        h3Val,
			Payload:        payloadCopy,
			PayloadDigest:  pd,
		}
	}

	return bestMatch, bestSysTime
}

// scanWindowRecordBatch (Day 19, ADR-0024) scans a single Arrow record batch and
// appends EVERY row passing the window predicate (W1)-(W4) into the caller's
// slice. It is the N-row sibling of scanRecordBatch: the SAME 4 filters, the
// SAME column type-assertions, the SAME zero-allocation-in-the-loop discipline.
// The ONLY structural differences are (a) the terminal action (append-to-slice
// vs track-best-index) and (b) the MaxRangeRows cap enforcement (the unbounded-
// amplification guard — the cap is checked BEFORE each append so the slice NEVER
// carries >cap rows, and the marshal downstream NEVER sees >cap).
//
// Column Layout (identical to scanRecordBatch — see its docstring):
//
//	[0] entity_id_hash   — FixedSizeBinary(16)
//	[1] system_time      — Timestamp(ns, UTC)
//	[2] valid_time_start — Timestamp(ns, UTC)
//	[3] valid_time_end   — Timestamp(ns, UTC)
//	[4] assertion_time   — Timestamp(ns, UTC)
//	[5] h3_index         — Uint64
//	[6] payload_digest   — FixedSizeBinary(32)
//	[7] entity_id        — LargeBinary
//	[8] payload          — LargeBinary
//
// Filters (byte-identical IN SPIRIT to scanRecordBatch's Filter 1-4):
//   - Filter 1: Hash prefix match (column[0] == hashPrefix[:], the 128-bit O(1)
//     memory compare that eliminates >99.99% of rows).
//   - Filter 2: SystemTime <= transactionTime (column[1] <= txTimeNs — the row is
//     VISIBLE at the query's transaction horizon; byte-identical to scanRecordBatch).
//   - Filter 3 WINDOW VARIANT: the query is a WINDOW [vLo, vHi), not a POINT. The
//     row INTERSECTS the window iff R.validTimeStart < vHi (W1) AND R.validTimeEnd >
//     vLo (W2). The skip rule — `rowValidStart >= vHi || rowValidEnd <= vLo` — is
//     the inverse of (W1)&&(W2) and carries Filter 3's EXACT half-open bound
//     discipline (validEnd <= vLo is the strict-low mirror of scanRecordBatch's
//     `validTimeNs >= validEnd`; validStart >= vHi is the strict-high mirror of
//     scanRecordBatch's `validTimeNs < validStart` read at the window's high end).
//     DO NOT weaken this to a point-in-window test — interval-intersection is the
//     load-bearing semantic (§1.1): a row [100,200) answers a window query [120,180).
//   - Filter 4: Full entity ID verification (column[7] == entityIDBytes). MANDATORY
//     — byte-identical to scanRecordBatch's collision guard (Security Audit Fix V3).
//     WithOUT this, a 128-bit hash collision on the FIRST 8 bytes (the l0/<hex8>/
//     dir co-locates two entities) would leak the WRONG entity's rows into the
//     Range window. The T3 tooth seeds exactly that collision + asserts no leak.
//
// SINGLE-alloc-per-row discipline: scanRecordBatch defers its ONE allocation to
// after the loop (tracking bestRowIndex). Range cannot defer — it must emit every
// matching row — so the alloc-per-row is the honest cost of the N-row window
// (this is NOT the single-point hot path; AsOf's defer-to-end is the path where
// the zero-alloc property holds, and Range does NOT pollute it — scanRecordBatch
// is byte-untouched). The payload + entityID copies are the SAME 2-heap-alloc
// pattern scanRecordBatch uses post-loop (the unsafe.String-to-heap-copied-slice
// idiom); Range simply does it per-row instead of once.
//
// CAP: cap == MaxRangeRows (0 = UNLIMITED, the disclosed sentinel). The check
// `cap > 0 && len(out) >= cap` runs BEFORE each append, so the slice is NEVER
// returned > cap. On a hit, `stop=true` propagates up to Range's file loop to
// break (the remaining files are NOT scanned — the cap is the safety contract).
func (r *Resolver) scanWindowRecordBatch(
	rec arrow.Record,
	hashPrefix [16]byte,
	entityIDBytes []byte,
	validLoNs int64,
	validHiNs int64,
	txTimeNs int64,
	collected []*TriTemporalEvent,
	cap int,
) ([]*TriTemporalEvent, bool) {
	nRows := int(rec.NumRows())
	if nRows == 0 {
		return collected, false
	}
	out := collected
	stop := false

	// Type-assert columns once (amortized over all rows) — byte-identical to
	// scanRecordBatch's column accessors.
	hashCol := rec.Column(0).(*array.FixedSizeBinary)
	sysTimeCol := rec.Column(1).(*array.Timestamp)
	validStartCol := rec.Column(2).(*array.Timestamp)
	validEndCol := rec.Column(3).(*array.Timestamp)
	assertTimeCol := rec.Column(4).(*array.Timestamp)
	h3Col := rec.Column(5).(*array.Uint64)
	payloadDigestCol := rec.Column(6).(*array.FixedSizeBinary)
	entityIDCol := rec.Column(7).(*array.LargeBinary)
	payloadCol := rec.Column(8).(*array.LargeBinary)

	for row := 0; row < nRows; row++ {
		// Filter 1: Hash prefix match (128-bit, O(1)) — byte-identical to scanRecordBatch.
		rowHash := hashCol.Value(row)
		if !bytes.Equal(rowHash, hashPrefix[:]) {
			continue
		}

		// Filter 2: SystemTime <= transactionTime — byte-identical to scanRecordBatch
		// (the row must be VISIBLE at the query's transaction horizon).
		sysTimeVal := int64(sysTimeCol.Value(row))
		if sysTimeVal > txTimeNs {
			continue
		}

		// Filter 3 WINDOW VARIANT: interval-INTERSECTION with [vLo, vHi).
		// (W1) validStart < vHi AND (W2) validEnd > vLo. Skip on the inverse:
		// validStart >= vHi (row starts AT-or-past the window's high end → no
		// intersection with the half-open window) OR validEnd <= vLo (row ends
		// AT-or-before the window's low end → no intersection). The strict/non-
		// strict bounds mirror scanRecordBatch's Filter 3 (validEnd is exclusive
		// at the high end; validStart is inclusive at the low end) — do NOT relax.
		validStart := int64(validStartCol.Value(row))
		validEnd := int64(validEndCol.Value(row))
		if validStart >= validHiNs || validEnd <= validLoNs {
			continue
		}

		// Filter 4: Full entity ID verification — MANDATORY (byte-identical to
		// scanRecordBatch's collision guard; Security Audit Fix V3). A 128-bit
		// hash collision on the FIRST 8 bytes (l0/<hex8>/ co-locates two entities)
		// would otherwise leak the WRONG entity's rows. The T3 tooth seeds that.
		rowEntityID := entityIDCol.Value(row)
		if !bytes.Equal(rowEntityID, entityIDBytes) {
			continue
		}

		// CAP — the unbounded-amplification guard. Checked BEFORE the append so
		// the slice NEVER carries > cap rows. 0 = UNLIMITED (the disclosed sentinel).
		// On a hit: emit `stop` so scanWindowFile returns it + Range's file loop
		// breaks. We do NOT append the cap-exceeding row (the cap is an inclusive
		// ceiling on returned rows, so a cap of 4 returns exactly 4).
		if cap > 0 && len(out) >= cap {
			stop = true
			return out, stop
		}

		// Terminal action: APPEND the matching row (the ONLY difference from
		// scanRecordBatch, which tracks bestRowIndex here). The 2-heap-alloc emit
		// pattern is byte-identical to scanRecordBatch's post-loop block.
		assertTimeVal := int64(assertTimeCol.Value(row))
		h3Val := h3Col.Value(row)
		payloadBytes := payloadCol.Value(row)

		payloadCopy := make([]byte, len(payloadBytes))
		copy(payloadCopy, payloadBytes)

		entityIDCopy := make([]byte, len(rowEntityID))
		copy(entityIDCopy, rowEntityID)

		payloadDigestBytes := payloadDigestCol.Value(row)
		var pd [32]byte
		copy(pd[:], payloadDigestBytes)

		out = append(out, &TriTemporalEvent{
			EntityID:       unsafe.String(unsafe.SliceData(entityIDCopy), len(entityIDCopy)),
			SystemTime:     sysTimeVal,
			ValidTimeStart: validStart,
			ValidTimeEnd:   validEnd,
			AssertionTime:  assertTimeVal,
			H3Index:        h3Val,
			Payload:        payloadCopy,
			PayloadDigest:  pd,
		})
	}

	return out, stop
}

// loadSupersededL0Keys (Day 14, ADR-0019) lists the compaction manifests for
// an entity (compaction/{hex(hash8)}/) and returns the union of L0 keys listed
// across them — the L0 files ALREADY merged into an L1, so AsOf can SKIP them
// (their rows are in the L1; scanning them again is redundant, not wrong). A
// manifest that fails to download/parse is skipped (honest fallback: the L0
// remains scannable → worst case a superseded L0 is re-scanned, returning the
// SAME dominant the L1 already produced — no correctness loss, only redundant
// work).
//
// Day 25 (ADR-0030): the manifest-channel download skip. txTimeNs is the
// query's transactionTime in ns (in scope at BOTH call sites — AsOf:259,
// Range:512 — passed in to avoid a recompute; the read path has it). A
// manifest's filename-encoded firstSys (the LAST path segment before ".manifest",
// "{firstSys}.manifest") is the L1's MIN sysTime — the SAME field the Day-24
// file-skip reads on the L0/L1 channel, parsed by the SAME parseFirstSysFromKey
// helper (byte-verified: it returns ok=true for ".manifest" tails — the
// "{decimal}.{suffix}" grammar is shared, NOT a .arrow-specific shape). When
// EnableFirstSysSkip is true AND firstSys > txTimeNs (STRICT > — the Day-24
// boundary), the manifest's Download is SKIPPED:
//
//	manifest.firstSys > txTime
//	  ⟹ the L1 the manifest points at (manifest line 1) has firstSys ==
//	     manifest.firstSys (l1_compactor.go:736-737/793-794 — the manifest + L1
//	     share firstSysT) → the L1 is file-skipped by the Day-24 scan-loop skip.
//	  ⟹ every L0 the manifest lists was MERGED into that L1; the merged set's MIN
//	     sysTime == the L1's firstSys (l1_compactor.go:736 firstSysT=rows[0].sysT,
//	     rows ASC-sorted) → every listed L0 has firstSys >= manifest.firstSys >
//	     txTime → every listed L0 is file-skipped by the Day-24 scan-loop skip.
//	  ⟹ skipping the manifest DOWNLOAD leaves the superseded map WITHOUT those
//	     L0 keys → they REMAIN in tailKeys → they PASS INTO the scan loop →
//	     where the Day-24 file-skip SKIPS them anyway (firstSys > txTime).
//	  ⟹ the manifest skip preserves tailKeys' DOWNLOADED+SCANNED set IDENTICALLY
//	     w.r.t. the query's VISIBLE rows (Law II — byte-identical answer) AND
//	     cuts a manifest Download (+ the ParseManifest strings.Split alloc).
//
// The skip is gated on the EXISTING EnableFirstSysSkip flag (NOT a new flag —
// the manifest + file skips are the SAME elimination on two channels of the SAME
// query; a second flag would let an operator disable one while leaving the other
// on, a non-uniformity with NO production rationale). The bound is STRICT (>)
// for the SAME reason as Day-24: a manifest whose firstSys == txTime points at an
// L1 whose first row AT sysTime==txTime passes Filter2 (<=) → that L1 MIGHT
// qualify → its listed L0s MIGHT carry visible rows → DO NOT skip the manifest.
// FAILSAFE: a parse anomaly → ok=false → NO skip → the manifest IS downloaded +
// ParseManifest runs (a corrupt manifest filename is NEVER silently dropped —
// the SAME fallback the Day-24 file-skip carries). Counted via
// QueryManifestSkippedFirstSys (the disclosure, Law V).
//
// l0Prefix is the entity's L0 listing prefix (passed in to avoid a recompute);
// the manifests live under "compaction/" + the SAME hex(hash8) segment, derived
// from l0Prefix by replacing the leading "l0/" with "compaction/".
func (r *Resolver) loadSupersededL0Keys(ctx context.Context, l0Prefix string, txTimeNs int64) map[string]struct{} {
	// manifestPrefix = "compaction/" + hex(hash8) + "/"
	if !strings.HasPrefix(l0Prefix, "l0/") {
		return nil
	}
	manifestsPrefix := "compaction/" + l0Prefix[len("l0/"):]
	keys, err := r.lister.ListObjects(ctx, r.bucket, manifestsPrefix, 0)
	if err != nil {
		return nil
	}
	if len(keys) == 0 {
		return nil
	}
	superseded := make(map[string]struct{}, len(keys))
	for _, mk := range keys {
		// Day 25 (ADR-0030): the manifest-channel download skip — byte-identical
		// in SHAPE to the Day-24 AsOf/Range file-skip block (the SAME
		// EnableFirstSysSkip flag, the SAME parseFirstSysFromKey parser, the
		// SAME STRICT > bound). The mk is the manifest key
		// ("compaction/{hex8}/{firstSys}.manifest"); parseFirstSysFromKey reads
		// its "{firstSys}.manifest" tail the SAME way it reads an ".arrow" tail
		// (the "{decimal}.{suffix}" grammar is shared — VERIFIED ok=true). DO
		// NOT add a manifest-specific helper; reuse parseFirstSysFromKey EXACTLY.
		// The skip is a `continue` BEFORE the Download — it cuts the manifest
		// DOWNLOAD count (the cost center this fork closes), counted via
		// QueryManifestSkippedFirstSys. FAILSAFE: a parse anomaly → ok=false →
		// NO skip → the full manifest Download + ParseManifest runs (a corrupt
		// manifest filename is NEVER silently dropped).
		if r.config.EnableFirstSysSkip {
			if firstSys, ok := parseFirstSysFromKey(mk); ok && firstSys > txTimeNs {
				if telemetry.QueryManifestSkippedFirstSys != nil {
					telemetry.QueryManifestSkippedFirstSys.Inc()
				}
				continue
			}
		}
		rc, derr := r.downloader.Download(ctx, r.bucket, mk)
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

// countPrefix returns the number of keys sharing the prefix — used to emit the
// L1-files-scanned telemetry without a second list call.
func countPrefix(keys []string, prefix string) int {
	n := 0
	for _, k := range keys {
		if strings.HasPrefix(k, prefix) {
			n++
		}
	}
	return n
}

// parseFirstSysFromKey extracts the file's MIN sysTime (FirstSysTimeNs) from a
// durable Arrow key (Day 24, ADR-0029). Grammar (byte-verified against the
// writer at l0_flusher.go:314 + l1_compactor.go:950):
//
//	"<tier>/<hex(hash8)>/<int64-decimal>.arrow"
//
// where tier ∈ {"l0","l1"} and the int64 is the file's FIRST (= MIN) sysTime
// (the flush writes the SkipList ASC, l0_flusher.go:198; the compactor's
// firstSysT = rows[0].sysT, l1_compactor.go:736).
//
// Day 25 (ADR-0030): the parser is a PURE NUMERIC-TAIL reader (LastIndexByte('/')
// → LastIndexByte('.') → ParseInt base 10) — it is NOT an ".arrow"-specific
// reader. The "{decimal}.{suffix}" grammar is SHARED with the compaction
// manifest key ("compaction/{hex8}/{firstSys}.manifest"): the dot it finds is
// the one in "{firstSys}.manifest", the slice is the decimal, ParseInt base 10
// succeeds → it returns ok=true for a ".manifest" key with the EXACT int64
// (byte-verified by the Day-25 §0 probe + the T-MANIFEST-PARSER tooth). The
// manifest channel's loadSupersededL0Keys REUSES this helper EXACTLY (DO NOT
// add a ".manifest"-special case — the existing grammar already parses it).
// The prior Day-24 prose ("Manifests carry .manifest — NOT parsed by this
// helper") was a documentation error: the helper ALWAYS parsed ".manifest"
// (the grammar never excluded it); Day 25 merely USES that property. The
// docstring's "DO NOT validate the tier / hash prefix here" discipline is
// unchanged — the read path ALREADY scoped the list by manifest/l0/l1 prefix.
//
// Returns (firstSysNs int64, ok bool). ok=false on ANY parse anomaly — the
// honest fallback: do NOT skip (download + scan as today; Law II preserved; the
// disclosure counter does NOT fire). A garbage/corrupt/renamed file is NEVER
// silently dropped on a parse failure (T-SKIP-FAILSAFE-KEEPS-LAW-II +
// T-MANIFEST-FAILSAFE).
//
// ZERO-alloc: the suffix extraction is a strings.LastIndexByte(key, '/') slice +
// a strconv.ParseInt(base 10) on the trimmed tail — NO strings.Split, NO regexp.
// The numeric string is < 40 bytes (an int64 fits in 20 chars); ParseInt does
// NOT allocate. A negative tail returns ok=false (the §1.a landmine disarm —
// negative sysTime would be a corrupt/key-suffix collision, never a production
// UnixNano; do NOT skip it).
//
// The skip the parser enables is a TRANSITIVELY-SAFE elimination (§0.e): for a
// query at txTime T and a file F with min(F) > T, every row r in F has
// r.sysTime >= min(F) > T, so every row fails Filter2 (sysTime<=txTime) ⟹
// F contributes ZERO qualifying rows ⟹ skipping F's download preserves the
// answer set IDENTICALLY (Law II). The bound is STRICT (>), because a row AT
// sysTime==txTime passes Filter2 (<=), so firstSys==txTime means the file's
// first row MIGHT qualify → DO NOT skip (T-SKIP-OFF-BY-SKIP-BOUNDARY).
//
// DO NOT validate the tier / hash prefix here — the read path ALREADY scoped
// the list by l0Prefix/l1Prefix (query.go:232/264/278); the parser is a pure
// numeric-tail reader. The lexical-scan-order landmine (M5: the reverse-lexical
// sort at query.go:348/512) is orthOGONAL — the skip is order-INDEPENDENT, so
// the parser uses strconv.ParseInt (base 10), NEVER a lexical compare.
func parseFirstSysFromKey(key string) (int64, bool) {
	slash := strings.LastIndexByte(key, '/')
	if slash < 0 || slash == len(key)-1 {
		return 0, false
	}
	tail := key[slash+1:]
	dot := strings.LastIndexByte(tail, '.')
	if dot <= 0 {
		return 0, false
	}
	n, err := strconv.ParseInt(tail[:dot], 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

// liveRowKey is the dedup key for the Range live merge (Day 27, ADR-0032). The
// live HAMT is append-only → live ⊇ durable, so after a checkpoint a live row
// is the twin of a durable row; appending both would duplicate → a Law II break.
// The key is (SystemTime, PayloadDigest): the Arrow schema carries NO dot
// columns (dot-dedup is impossible at the row level), and PayloadDigest is a
// 32-byte content hash (the no-recompute law, control.go:441) — so two rows
// with the same (sysTime, digest) ARE the same row. The [32]byte digest makes
// the key a value-typed map key (no pointer aliasing, no escape — the map is
// per-query, freed at the merge's end; fieldalignment is irrelevant for a local
// map key, but the struct is 40 bytes, naturally aligned).
type liveRowKey struct {
	sys    int64
	digest [32]byte
}

// ErrEntityNotFound is returned when no matching event exists for the given
// (entityID, validTime, transactionTime) coordinates.
var ErrEntityNotFound = fmt.Errorf("query: entity not found at specified temporal coordinates")

// Ensure unused imports don't cause compilation errors.
var _ = binary.BigEndian
