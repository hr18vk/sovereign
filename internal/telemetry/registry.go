// registry.go binds the engine's package-level counters to the OpenTelemetry
// Meter provided by Init. The Counter types and their lock-free mechanics live
// in telemetry.go; this file is the singleton configuration surface so that
// callers (internal/database/l0_flusher.go, internal/database/memtable.go)
// can use zero-argument package-level vars without plumbing a Meter through
// the hot path.
//
// All allocation here happens at package init or at Init() — never on the
// data plane.
package telemetry

import (
	"log"
	"sync/atomic"

	"go.opentelemetry.io/otel/metric"
)

// meter holds the OTel Meter set by Init. nil means "in-process counters only"
// — the counters still work as plain LongAdders; no OTel instruments are
// registered. This is the default when Init is never called (e.g. unit tests).
var meter atomic.Pointer[metric.Meter]

// Init binds the OTel Meter used to register Observable instruments and
// constructs the package-level counters against it. STRICTLY ONCE PER PROCESS:
//
// There is a window in which data-plane goroutines concurrently Add() on the
// package-level *Counter pointers (internal/database/l0_flusher.go,
// internal/database/memtable.go). A second Init that non-atomically reassigns
// those globals while a hot-path reader holds the OLD pointer in a register
// splits the Add traffic across two LongAdders — silent counter drift.
//
// R1 FIX: Init is now once-only. The first call binds the counters; any
// subsequent call is rejected (logged) and leaves the existing counters in
// place. The comment in the prior revision that called repeat Init "safe
// because the OTel SDK deduplicates" was wrong about the data plane: the
// orphaned Go-side LongAdder still loses its accumulated total. Threading an
// atomic.Pointer[Counter] through every data-plane call site would add an
// atomic load on every hot-path Add — unacceptable against the Zero-GC
// mandate — so the rigorous guard is once-only initiation, applied here.
func Init(m metric.Meter) {
	if initDone.Swap(true) {
		// A second Init would non-atomically swap the package-level *Counter
		// pointers out from under concurrent data-plane Add callers. Reject it.
		log.Printf("[telemetry] Init called more than once; existing counters left in place (once-per-process contract)")
		return
	}
	meter.Store(&m)
	rebuildCounters(m)
}

// initDone guards the once-per-process Init contract (R1 FIX).
var initDone atomic.Bool

// Package-level counters consumed by the data plane. Constructed lazily on
// first import against whatever Meter is bound (or nil). These are the only
// symbols referenced by internal/database/*.
var (
	ArrowSerialBytes      *Counter
	MemTableFlushTotal    *Counter
	OffHeapAllocatedBytes *Counter
	QueryL0ListCapped     *Counter
	// Day 14 (ADR-0019): the L0→L1 per-entity compaction counters.
	QueryL1FilesScanned *Counter
	CompactionMerged    *Counter
	CompactionL1Written *Counter
	// Day 15 (ADR-0020): the Level-2 superseded-row prune counter — the
	// disclose-it counter (Law V): every row the DominancePrune pass drops at
	// the compaction merge seam under the (C1)&&(C2)&&(C3) SAFE-DROP rule is
	// MEASURED, not asserted. Preserve-All (EnableDominancePruning=false) never
	// touches it.
	CompactionRowsPruned *Counter
	// Day 16 (ADR-0021): the L0 reaper counters — the cross-entity superseded-
	// L0 disk-reclaim sweep. The reaper deletes manifest-listed L0 files ONLY
	// after it has verified the L1 still exists (Stage C safety guard); these
	// counters make the reaper's disk reclamation OBSERVABLE (Law V).
	L0ReapSweeps          *Counter // sweeper runs
	L0ReapL0Deleted       *Counter // total L0 files deleted
	L0ReapManifestsReaped *Counter // manifests whose L0s were all deleted + the manifest reaped
	L0ReapSkippedOrphan   *Counter // manifests whose L1 was missing (the L0s preserved as the backstop)
	// Day 22 (ADR-0027): the T_gc auto-inference counters — the engine tracks the
	// observed live-query txTime frontier (queried at AsOf-entry) and feeds
	// max(operatorFloor, observedFrontier - backoff) back into the DominancePrune
	// (C3) floor. Two gauges surface the inferrer's state on /metrics (the operator-
	// visible audit trail the static-knob Day 15 lacked); one counter is the LOUD
	// retreat-refuse signal (the §0.c monotone-clamp contract). All three are
	// constructed in BOTH init() AND rebuildCounters() AND allCounters() (the
	// Day-21 fill discipline — a counter missing from rebuildCounters() silently
	// drops to nil under --otel, the §0.f construction-vs-distinct trap).
	QueryTxTimeHighWaterMark     *Counter // modeGauge — observed live-query txTime frontier (the atomic the Resolver stores)
	PruningHorizonEffective      *Counter // modeGauge — the effective horizon fed to DominancePrune (max(operatorFloor, observed - backoff))
	PruningHorizonRetreatRefused *Counter // modeCounter — times SetInferredHorizon refused a retreat (the §0.c loud-path signal)
	// Day 24 (ADR-0029): the filename-bounded download-skip disclosure counter —
	// the transitively-safe elimination the durable read path (AsOf + Range)
	// applies BEFORE the Download: a file whose filename-encoded FirstSysTimeNs
	// (the file's MIN sysTime, written by the flush since Day-13) exceeds the
	// query's txTime carries ZERO rows visible at txTime (every row fails
	// Filter2) → the download+decode is skipped (Law II preserved). The counter
	// is the disclosure (Law V): every skip is MEASURED, not asserted. Constructed
	// in BOTH init() AND rebuildCounters() AND allCounters() (the Day-21 fill
	// discipline — a counter missing from rebuildCounters() silently drops to nil
	// under --otel, the §0.f construction-vs-distinct trap).
	QueryDownloadSkippedFirstSys *Counter // modeCounter — L0/L1 files whose download was skipped because FirstSysTimeNs > txTime
	// Day 25 (ADR-0030): the manifest-channel download-skip disclosure counter —
	// the SAME transitively-safe elimination the Day-24 file-skip applies, on the
	// SECOND channel the durable read path opens: loadSupersededL0Keys downloads +
	// decodes EVERY compaction manifest per query (one per compaction job,
	// compaction/{hex8}/{firstSys}.manifest) to mark L0 keys superseded before the
	// tail cap. The manifest's filename-encoded firstSys is the L1's MIN sysTime
	// (the SAME field Day-24 skips on the file channel, parsed by the SAME
	// parseFirstSysFromKey helper — byte-verified ok=true for ".manifest" tails).
	// When firstSys > the query's txTime (STRICT >, the Day-24 boundary), the L1
	// the manifest points at is file-skipped (Day-24 scan loop) AND every L0 the
	// manifest lists is file-skipped (its firstSys >= manifest.firstSys > txTime)
	// → skipping the manifest DOWNLOAD leaves the superseded set intersecting
	// ONLY files the scan loop skips anyway → the tailKeys + the dominant are
	// byte-identical for the query's VISIBLE rows (Law II) AND a manifest Download
	// (+ the ParseManifest strings.Split alloc) is cut. The counter is the
	// disclosure (Law V): every manifest skip is MEASURED, not asserted. Constructed
	// in BOTH init() AND rebuildCounters() AND allCounters() (the Day-21 fill
	// discipline — a counter missing from rebuildCounters() silently drops to nil
	// under --otel, the §0.f construction-vs-distinct trap). Gated on the EXISTING
	// EnableFirstSysSkip flag (NOT a new flag — the manifest + file skips are the
	// SAME elimination on two channels of the SAME query). FAILSAFE: a parse
	// anomaly → no skip → the full manifest download runs (a corrupt manifest
	// filename is NEVER silently dropped).
	QueryManifestSkippedFirstSys *Counter // modeCounter — compaction manifests whose download was skipped because the manifest's filename-encoded FirstSysTimeNs (the L1's MIN sysTime) exceeds the query's txTime
	// Day 27 (ADR-0032): the read-your-writes live-source disclosure counter —
	// the Law V surface for the live-source consult the Resolver performs AFTER
	// its durable Arrow scan. The Resolver consults the live δ-CRDT HAMT (via a
	// LiveSource interface — internal/database owns it; it does NOT import
	// pkg/sync, so the seam is an interface, NOT a concrete engine) to merge the
	// live dominant under the SAME bitemporal dominance AsOf already computes,
	// closing the "POST /v1/insert → immediate GET /v1/query → 404 until the
	// bridge's periodic AppendCheckpoint flushes SnapshotToLSM→L0" gap (the
	// read-your-writes gap Day-26 verification empirically confirmed —
	// --wal-checkpoint-interval=1 was REQUIRED for the durable read path to work
	// at all). The counter discloses the LIVE-PATH was taken (NOT every live HIT
	// — a live read can return zero entries; the count is the path disclosure,
	// the SAME Law V class the download-skip + manifest-skip counters carry).
	// Constructed in BOTH init() AND rebuildCounters() AND allCounters() (the
	// Day-21 fill discipline — a counter missing from rebuildCounters() silently
	// drops to nil under --otel, the §0.f construction-vs-distinct trap).
	QueryLiveSourceReads *Counter // modeCounter — AsOf/Range queries that consulted the live δ-CRDT HAMT (read-your-writes path)

	// Day 29 (ADR-0034): the stratified-anti-entropy fallback disclosure counter.
	// The 19th distinct counter. It fires every time the mesh's digest-exchange
	// phase (the M3 two-phase StrataEstimator round) falls back to the FULL-DELTA
	// oversend path — a digest timeout (the peer did not return its estimator
	// within digestWaitTimeout), a malformed digest (UnmarshalStrataEstimator
	// ErrMalformedStrata), a peel failure inside GenerateDelta
	// (crdt.go:1603 — diff==nil || peelErr!=nil || shouldSend yields EVERY entry
	// = FULL oversend-equivalent, NEVER nil/empty), or a Publish failure (the peer
	// dropped mid-round). The fallback is the M5 honest path: the convergence
	// guarantee HOLDS (the signed delta path is unchanged; oversend is a strict
	// superset the CRDT-idempotent Join absorbs), the counter is the Law V
	// DISCLOSURE that lets the operator SEE the mesh converging via oversend vs
	// via the stratified cut. A node with stratified OFF (the opt-IN default)
	// never fires it (the oversend path is the baseline, not a fallback). A nil
	// reporter (the --selftest path, the in-memory test path) leaves the fallback
	// a silent oversend (the SetRoundReporter precedent — the counter is the
	// DISCLOSURE, not the mechanism). Constructed in BOTH init() AND
	// rebuildCounters() AND allCounters() (the Day-21 fill discipline — a counter
	// missing from rebuildCounters() silently drops to nil under --otel).
	StratifiedAntiEntropyFallback *Counter // modeCounter — mesh digest-exchange rounds that fell back to oversend (timeout/malformed/peel-failure)

	// Day 30 (ADR-0035): the PKI leaf-rotation + revocation-reject disclosure
	// counters — the Law V surfaces for the dormant security gate Day 30 wires.
	// (1) CertRotationTriggered fires every time the automated rotation goroutine
	// (StartRotationManager, the --cert-rotation-enable opt-IN trigger) mints a
	// NEW leaf + Reloads — the operator SEES the trigger fired (the blueprint
	// Track 5.2 "zero-downtime leaf cert rotation every 30 days" gate is a NUMBER,
	// not an adjective; the count is the audit trail). (2) CertRevokedRejected
	// fires every time the VerifyPeerCertificate callback rejects a presented leaf
	// whose serial is in the CRL — the security-gate-PROVEN-disclosure (the
	// blueprint Track 5.2 "a node presenting an expired or revoked cert is
	// rejected at the TLS handshake" gate's REVOKED claw, byte-proven by
	// T-PKI-REVOKED-REJECTED). Both are modeCounter (NOT gauges — the gauge count
	// STAYS 3). Constructed in BOTH init() AND rebuildCounters() AND allCounters()
	// (the Day-21 fill discipline — a counter missing from rebuildCounters()
	// silently drops to nil under --otel, the §0.f construction-vs-distinct trap).
	CertRotationTriggered *Counter // modeCounter — automated leaf-rotation trigger firings (the operator-visible audit trail)
	CertRevokedRejected   *Counter // modeCounter — handshakes rejected because the presented leaf serial is in the CRL (the security-gate disclosure)
	// Day 31 (ADR-0036): the post-quantum KEM-negotiated disclosure counter.
	// A modeCounter (NOT a gauge — the gauge count STAYS 3). Constructed in
	// BOTH init() AND rebuildCounters() AND allCounters() (the Day-21 fill
	// discipline — a counter missing from rebuildCounters() silently drops to
	// nil under --otel, the §0.f construction-vs-distinct trap).
	PQHandshakeNegotiated *Counter // modeCounter — completed TLS handshakes that negotiated the X25519MLKEM768 hybrid post-quantum KEM (the PQ-readiness disclosure)

	// Day 32 (ADR-0037): the hybrid-PQ SIGN-WIRE accept disclosure counter.
	// HybridFrameAccepted fires every time the receiver's HandleHybridFrame
	// gate accepts a hybrid-PQ batch that passed the BOTH-verify
	// (VerifyBatchHybrid — the Ed25519 + ML-DSA-65 both-required gate over the
	// 120-byte SHAKE256 pad). It is the operator-VISIBLE proof the PQ moat is in
	// USE, not just wired — Day 31 wired the VERIFY + the KEM; Day 32 wires the
	// SIGN + the frame + the directory provisioning + the dispatch, so a hybrid
	// frame is now PRODUCED (under --hybrid-sign) AND ACCEPTED (under
	// --hybrid-verify) end-to-end. A modeCounter (NOT a gauge — the gauge count
	// STAYS 3). Constructed in BOTH init() AND rebuildCounters() AND allCounters()
	// (the Day-21 fill discipline — a counter missing from rebuildCounters()
	// silently drops to nil under --otel, the §0.f construction-vs-distinct
	// trap). The counter value is 0 on a single-node --selftest run (NO mesh peer
	// dials — a hybrid frame is produced only when --hybrid-sign arms the sweep
	// AND a peer is present to receive it); the RUNTIME /verify proves PRESENCE
	// on /metrics (the bridge auto-surface §0.f — PRESENCE not value, the SAME
	// discipline Day-29/30/31 used).
	HybridFrameAccepted *Counter // modeCounter — hybrid-PQ batches accepted by the BOTH-verify gate (the moat-in-USE disclosure)

	// Day 34 (ADR-0039): the region-aware gossip inter-region-envelope
	// disclosure counter. InterRegionEnvelopesShipped fires every time the
	// AntiEntropySweep's region-aware fan-out selector routes a CRDT-delta
	// envelope to a CROSS-region peer (an inter-region fan-out selection). It
	// is the operator-VISIBLE proof the region-aware data-plane path is in USE
	// (not just wired) — Day 34 wires the selector + the TopologyManager + the
	// fan-out-N iteration source, so a delta is now ROUTED cross-region (under
	// --region-aware) instead of broadcast full-mesh. A modeCounter (NOT a gauge
	// — the gauge count STAYS 3). Constructed in BOTH init() AND
	// rebuildCounters() AND allCounters() (the Day-21 fill discipline — a
	// counter missing from rebuildCounters() silently drops to nil under
	// --otel, the §0.f construction-vs-distinct trap). The counter value is 0
	// on a single-node --selftest run (NO mesh peer dials — an inter-region
	// envelope is shipped only when --region-aware arms the sweep AND a
	// cross-region peer is in the fan-out selection); the RUNTIME /verify proves
	// PRESENCE on /metrics (the bridge auto-surface §0.f — PRESENCE not value,
	// the SAME discipline Day-29/30/31/32 used). Fires ONLY on the inter-region
	// arm (intra-region full-mesh is the SAME-AZ baseline, NOT disclosure-worthy
	// — the disclosure is the CROSS-region fan-out the blueprint's O(log N)
	// convergence depends on).
	InterRegionEnvelopesShipped *Counter // modeCounter — inter-region CRDT-delta envelopes shipped by the region-aware fan-out selector (the data-plane-in-USE disclosure)
)

// allCounters returns the single source of truth for every constructed
// *Counter in this package. CALLED FROM both init() and rebuildCounters()
// (the only two construction sites), so the SSoT slice is ONE literal list,
// not a per-newCounter append. Day 21 (ADR-0026) CLOSED the two
// QueryL0ListCapped construction-site landmines ADR-0023 §6 had named: init()
// built QueryL0ListCapped twice (the first object orphaned on reassignment),
// and rebuildCounters built it zero times (so an Init(realMeter) call would
// reassign the var to nil → the use-site guard at query.go:253 silently stops
// counting the cap-hit disclosure counter). Day 21 dedups the init()
// construction (2 → 1) and fills rebuildCounters (0 → 1) at the SAME position
// (after MemTableFlushTotal, before OffHeapAllocatedBytes) so the registered-
// instrument order under the OTel Meter is stable across the two sites. The
// construction itself is now consistent with its siblings (each is built in
// BOTH init and rebuildCounters — QueryL0ListCapped was the lone exception).
// Appending inside newCounter would still emit a duplicate
// "supremum.l0.query_list_capped" name into the slice -> the prometheus
// bridge's Registry.MustRegister would PANIC at boot on the duplicate Desc.
// Building the slice from the distinct package vars (one *Counter per slot)
// yields exactly the distinct counters, NOT the newCounter INVOCATION
// count. The var-slice is the unwavering gate; the dedup is at the
// construction SITE, not the slice, so the bridge's series-count property
// survives byte-identical (T2 stays GREEN without a bridge edit).
//
// The slice is append-only-after-construction: once package init + Init
// complete (both behind the program-start barrier, before the first
// /metrics scrape fires at startLivecheck), it is frozen and read by the
// bridge WITHOUT a mutex. There is exactly ONE list — the bridge enumerates
// telemetry.Counters() and NEVER maintains a duplicate hardcoded copy (which
// would drift the instant a future Day adds a counter).
//
// OffHeapAllocatedBytes + the two Day-22 inferrer gauges
// (QueryTxTimeHighWaterMark, PruningHorizonEffective) are the modeGauges; the
// rest are modeCounter. Day 24 (ADR-0029) grew the slice 15 -> 16: the
// filename-bounded download-skip disclosure counter
// (QueryDownloadSkippedFirstSys). Day 25 (ADR-0030) grew it 16 -> 17: the
// manifest-channel download-skip disclosure counter
// (QueryManifestSkippedFirstSys) — the SAME elimination on the manifest
// channel, gated on the SAME EnableFirstSysSkip flag. Day 27 (ADR-0032) grew
// it 17 -> 18: the read-your-writes live-source disclosure counter
// (QueryLiveSourceReads) — the Law V surface for the live-HAMT consult the
// Resolver performs after its durable scan.
func allCounters() []*Counter {
	// Exactly the 21 DISTINCT package-level *Counter vars, in stable order.
	// Day 22 (ADR-0027) grew the slice 12 -> 15: the three T_gc auto-inference
	// counters (QueryTxTimeHighWaterMark, PruningHorizonEffective,
	// PruningHorizonRetreatRefused). Day 24 (ADR-0029) grew it 15 -> 16: the
	// filename-bounded download-skip disclosure counter
	// (QueryDownloadSkippedFirstSys). Day 25 (ADR-0030) grew it 16 -> 17: the
	// manifest-channel download-skip disclosure counter
	// (QueryManifestSkippedFirstSys). The bridge enumerates this slice
	// automatically (the §0.f SSoT-grows-auto property) — a new counter added
	// here is surfaced on /metrics with ZERO bridge edit, IF it is constructed
	// in BOTH init() AND rebuildCounters() (the Day-21 fill discipline; a counter
	// missing from rebuildCounters() silently drops to nil under --otel).
	return []*Counter{
		ArrowSerialBytes,
		MemTableFlushTotal,
		OffHeapAllocatedBytes,
		QueryL0ListCapped,
		QueryL1FilesScanned,
		CompactionMerged,
		CompactionL1Written,
		CompactionRowsPruned,
		L0ReapSweeps,
		L0ReapL0Deleted,
		L0ReapManifestsReaped,
		L0ReapSkippedOrphan,
		QueryTxTimeHighWaterMark,
		PruningHorizonEffective,
		PruningHorizonRetreatRefused,
		// Day 24 (ADR-0029): the 16th distinct counter — the filename-bounded
		// download-skip disclosure counter. Day 22 grew the slice 12 -> 15; Day 24
		// grows it 15 -> 16. The bridge auto-surfaces it (the §0.f SSoT-grows-auto
		// property) — a 16th supremum_* series appears on /metrics with NO bridge
		// edit, IF it is constructed in BOTH init() AND rebuildCounters() (the
		// Day-21 fill discipline).
		QueryDownloadSkippedFirstSys,
		// Day 25 (ADR-0030): the 17th distinct counter — the manifest-channel
		// download-skip disclosure counter. Day 24 grew the slice 15 -> 16; Day 25
		// grows it 16 -> 17. The bridge auto-surfaces it (the §0.f SSoT-grows-auto
		// property) — a 17th supremum_* series appears on /metrics with NO bridge
		// edit, IF it is constructed in BOTH init() AND rebuildCounters() (the
		// Day-21 fill discipline). The manifest skip is a modeCounter (NOT a
		// gauge — the gauge count STAYS 3), the SAME mode class as Day-24's
		// QueryDownloadSkippedFirstSys.
		QueryManifestSkippedFirstSys,
		// Day 27 (ADR-0032): the 18th distinct counter — the read-your-writes
		// live-source disclosure counter. Day 25 grew the slice 16 -> 17; Day 27
		// grows it 17 -> 18. The bridge auto-surfaces it (the §0.f SSoT-grows-auto
		// property) — an 18th supremum_* series appears on /metrics with NO bridge
		// edit, IF it is constructed in BOTH init() AND rebuildCounters() (the
		// Day-21 fill discipline). The live-source consult is a modeCounter (NOT a
		// gauge — the gauge count STAYS 3), the SAME mode class as Day-24's
		// QueryDownloadSkippedFirstSys + Day-25's QueryManifestSkippedFirstSys.
		QueryLiveSourceReads,
		// Day 29 (ADR-0034): the 19th distinct counter — the stratified-anti-
		// entropy fallback disclosure counter. Day 27 grew the slice 17 -> 18;
		// Day 29 grows it 18 -> 19. The bridge auto-surfaces it (the §0.f SSoT-
		// grows-auto property) — a 19th supremum_* series appears on /metrics with
		// NO bridge edit, IF it is constructed in BOTH init() AND rebuildCounters()
		// (the Day-21 fill discipline). The fallback is a modeCounter (NOT a
		// gauge — the gauge count STAYS 3), the SAME mode class as the prior
		// modeCounter siblings.
		StratifiedAntiEntropyFallback,
		// Day 30 (ADR-0035): the 20th + 21st distinct counters — the PKI
		// leaf-rotation + revocation-reject disclosure counters. Day 29 grew the
		// slice 18 -> 19; Day 30 grows it 19 -> 21 (TWO counters, the honest
		// disclosure discipline the M6 prompt names). The bridge auto-surfaces
		// them (the §0.f SSoT-grows-auto property) — a 20th + 21st supremum_*
		// series appear on /metrics with NO bridge edit, IF both are constructed
		// in BOTH init() AND rebuildCounters() (the Day-21 fill discipline). Both
		// are modeCounter (NOT gauges — the gauge count STAYS 3), the SAME mode
		// class as the prior modeCounter siblings.
		CertRotationTriggered,
		CertRevokedRejected,
		// Day 31 (ADR-0036): the 22nd distinct counter — constructed in BOTH
		// init() AND rebuildCounters() (the Day-21 fill discipline). A
		// modeCounter (NOT a gauge — the gauge count STAYS 3), the SAME mode
		// class as the prior modeCounter siblings.
		PQHandshakeNegotiated,
		// Day 32 (ADR-0037): the 23rd distinct counter — the hybrid-PQ SIGN-WIRE
		// accept disclosure counter. Day 31 grew the slice 21 -> 22; Day 32 grows
		// it 22 -> 23. The bridge auto-surfaces it (the §0.f SSoT-grows-auto
		// property) — a 23rd supremum_* series appears on /metrics with NO bridge
		// edit, IF it is constructed in BOTH init() AND rebuildCounters() (the
		// Day-21 fill discipline). The hybrid-frame accept is a modeCounter (NOT
		// a gauge — the gauge count STAYS 3), the SAME mode class as the prior
		// modeCounter siblings. The counter is the operator-VISIBLE proof the PQ
		// moat is in USE (not just wired) — Day 31 wired the VERIFY + the KEM;
		// Day 32 wires the SIGN + the frame + the directory provisioning + the
		// dispatch, so a hybrid frame is now PRODUCED (under --hybrid-sign) AND
		// ACCEPTED (under --hybrid-verify) end-to-end.
		HybridFrameAccepted,
		// Day 34 (ADR-0039): the 24th distinct counter — the region-aware
		// gossip inter-region-envelope disclosure counter. Day 32 grew the slice
		// 22 -> 23; Day 34 grows it 23 -> 24. The bridge auto-surfaces it (the
		// §0.f SSoT-grows-auto property) — a 24th supremum_* series appears on
		// /metrics with NO bridge edit, IF it is constructed in BOTH init() AND
		// rebuildCounters() (the Day-21 fill discipline). The inter-region
		// envelope ship is a modeCounter (NOT a gauge — the gauge count STAYS 3),
		// the SAME mode class as the prior modeCounter siblings. The counter is
		// the operator-VISIBLE proof the region-aware data-plane is in USE (not
		// just wired) — the Law V surface for the inter-region fan-out the
		// blueprint's O(log N) convergence depends on.
		InterRegionEnvelopesShipped,
	}
}

// counters is the bridge's snapshot of every constructed *Counter, frozen
// once after construction completes. Populated by init() and (if boot calls
// telemetry.Init) rebuildCounters. The prometheus bridge reads this slice at
// scrape time; it is NEVER mutated on the scrape path. See allCounters above.
var counters []*Counter

// Counters returns the snapshot of every constructed *Counter in this
// package, in stable construction order. The prometheus bridge enumerates
// this slice (the single source of truth — there is no duplicate list). The
// slice is frozen after package-init + Init complete (both run before the
// first scrape); the bridge reads it without a lock. The slice carries 21
// DISTINCT counters (Day 22: 12 -> 15; Day 24: 15 -> 16; Day 25: 16 -> 17;
// Day 27: 17 -> 18; Day 29: 18 -> 19; Day 30: 19 -> 21 — TWO counters, the
// PKI leaf-rotation + revocation-reject disclosure). Day 21 (ADR-0026) deduped
// the init() QueryL0ListCapped double (2 → 1) and filled rebuildCounters
// (0 → 1), so the newCounter INVOCATION count dropped from 24 to 12 (init) +
// 12 (rebuildCounters) = 24 total across the two sites — but the DISTINCT
// package vars stay 21, so the bridge still exposes 21 series (the var-slice
// is the unwavering gate).
func Counters() []*Counter { return counters }

func init() {
	var m metric.Meter
	if p := meter.Load(); p != nil {
		m = *p
	}
	ArrowSerialBytes = newCounter(m,
		"supremum.l0.arrow_serial_bytes",
		"Bytes serialized into Arrow IPC during L0 flush",
		"By",
		modeCounter,
	)
	MemTableFlushTotal = newCounter(m,
		"supremum.memtable.flush_total",
		"Total number of MemTable L0 flushes",
		"1",
		modeCounter,
	)
	QueryL0ListCapped = newCounter(m,
		"supremum.l0.query_list_capped",
		"AsOf queries that hit the MaxL0Files list cap (older per-entity files may have been silently dropped from the scan — see ADR-0018 §6. Compaction is the future fix.)",
		"1",
		modeCounter,
	)
	OffHeapAllocatedBytes = newCounter(m,
		"supremum.memtable.offheap_allocated_bytes",
		"Bytes currently allocated off-heap by the jemalloc allocator",
		"By",
		modeGauge,
	)
	QueryL1FilesScanned = newCounter(m,
		"supremum.l1.query_files_scanned",
		"L1 (compacted) Arrow IPC files scanned by AsOf per query (Day 14 ADR-0019)",
		"1",
		modeCounter,
	)
	CompactionMerged = newCounter(m,
		"supremum.compaction.l0_files_merged",
		"L0 files merged into L1 by the per-entity compaction (Day 14 ADR-0019)",
		"1",
		modeCounter,
	)
	CompactionL1Written = newCounter(m,
		"supremum.compaction.l1_files_written",
		"L1 files written by the per-entity compaction (Day 14 ADR-0019)",
		"1",
		modeCounter,
	)
	CompactionRowsPruned = newCounter(m,
		"supremum.compaction.l1_rows_pruned",
		"Rows dropped by the Level-2 superseded-row DominancePrune at the compaction merge seam (Day 15 ADR-0020). The (C1)&&(C2)&&(C3) SAFE-DROP rule; Preserve-All (EnableDominancePruning=false) never touches it.",
		"1",
		modeCounter,
	)
	L0ReapSweeps = newCounter(m,
		"supremum.compaction.l0_reap_sweeps",
		"Times the L0 reaper swept the compaction/ manifest tier (Day 16 ADR-0021). The reaper reclaims manifest-listed L0 files AFTER verifying the L1 still exists.",
		"1",
		modeCounter,
	)
	L0ReapL0Deleted = newCounter(m,
		"supremum.compaction.l0_reap_l0_files_deleted",
		"L0 files deleted by the L0 reaper across all sweeps (Day 16 ADR-0021). A delete is issued ONLY for an L0 whose compaction manifest listed it AND whose L1 is verified present. Counted as a Delete that returned nil — INCLUDES the idempotent already-absent path (a prior sweep/manual operator reclaimed the file); the reaper does NOT pre-Stat.",
		"1",
		modeCounter,
	)
	L0ReapManifestsReaped = newCounter(m,
		"supremum.compaction.l0_reap_manifests_reaped",
		"Compaction manifests fully reaped (every listed L0 deleted + the manifest itself deleted) by the L0 reaper (Day 16 ADR-0021).",
		"1",
		modeCounter,
	)
	L0ReapSkippedOrphan = newCounter(m,
		"supremum.compaction.l0_reap_manifests_skipped_orphan",
		"Compaction manifests the L0 reaper SKIPPED because the L1 they point at was missing (Day 16 ADR-0021). The manifest's L0s are PRESERVED as the crash-recovery backstop — the load-bearing safety guard.",
		"1",
		modeCounter,
	)
	// Day 22 (ADR-0027): the T_gc auto-inference counters — constructed in BOTH
	// init() AND rebuildCounters() (the Day-21 fill discipline; a counter
	// missing from rebuildCounters() silently drops to nil under --otel).
	QueryTxTimeHighWaterMark = newCounter(m,
		"supremum.query_txtime_high_water_mark_ns",
		"Observed live-query transactionTime frontier (the MAX txTime an AsOf call has served) in nanoseconds (Day 22 ADR-0027). The data source the HorizonInferrer reads to compute the effective DominancePrune floor. The operator-visible 'the engine sees queries up to HERE' signal — absent before Day 22.",
		"ns",
		modeGauge,
	)
	PruningHorizonEffective = newCounter(m,
		"supremum.compaction.pruning_horizon_effective_ns",
		"Effective DominancePrune (C3) floor T_gc the inferrer computed + fed to the prune: max(operatorFloor, observedFrontier - backoff) in nanoseconds (Day 22 ADR-0027). The audit-trail pair with the observed frontier: the gap is the backoff in operation. The operator floor dominates only when it exceeds the inferred (the §0.a inferrer-FLOORS-the-knob contract).",
		"ns",
		modeGauge,
	)
	PruningHorizonRetreatRefused = newCounter(m,
		"supremum.compaction.pruning_horizon_retreat_refused",
		"Times SetInferredHorizon refused a RETREAT (a horizon less than the current) — the §0.c monotone-clamp loud-path signal (Day 22 ADR-0027). ZERO under correct operation (the live-query txTime frontier is monotone non-decreasing); non-zero = a txTime REGRESSION in the query stream (a correctness smell, NOT a relaxation) OR a bug. A rising counter = investigate the query stream's txTime monotonicity.",
		"1",
		modeCounter,
	)
	// Day 24 (ADR-0029): the filename-bounded download-skip disclosure counter —
	// constructed in BOTH init() AND rebuildCounters() (the Day-21 fill discipline;
	// a counter missing from rebuildCounters() silently drops to nil under --otel).
	QueryDownloadSkippedFirstSys = newCounter(m,
		"supremum.l0.query_download_skipped_first_sys",
		"L0/L1 Arrow files whose Download was SKIPPED because the file's filename-encoded FirstSysTimeNs (the file's MIN sysTime, written by the flush since Day-13) exceeds the query's txTime (Day 24 ADR-0029). A transitively-safe elimination: the file carries ZERO rows visible at txTime (every row fails Filter2 sysTime<=txTime) so the skip preserves Law II. The disclosure counter (Law V): every skip is MEASURED. FAILSAFE: a parse anomaly → no skip → no counter fire → the full download runs (a corrupt/renamed file is NEVER silently dropped).",
		"1",
		modeCounter,
	)
	// Day 25 (ADR-0030): the manifest-channel download-skip disclosure counter —
	// constructed in BOTH init() AND rebuildCounters() (the Day-21 fill discipline;
	// a counter missing from rebuildCounters() silently drops to nil under --otel).
	QueryManifestSkippedFirstSys = newCounter(m,
		"supremum.compaction.query_manifest_skipped_first_sys",
		"Compaction manifests whose Download was SKIPPED because the manifest's filename-encoded FirstSysTimeNs (the L1's MIN sysTime, shared with the L1 key the manifest points at) exceeds the query's txTime (Day 25 ADR-0030). The Day-24 tautology on the manifest channel: the L1 it points at is skipped (Day-24 file-skip) AND every L0 it lists is skipped (Day-24 file-skip) -> the manifest's superseded-set intersects ONLY files the scan loop skips anyway -> skipping the manifest download preserves the tailKeys byte-identically for the query's visible rows (Law II). The disclosure counter (Law V): every skip is MEASURED. FAILSAFE: a parse anomaly -> no skip -> the full manifest download runs (a corrupt manifest is NEVER silently dropped).",
		"1",
		modeCounter,
	)
	// Day 27 (ADR-0032): the read-your-writes live-source disclosure counter —
	// constructed in BOTH init() AND rebuildCounters() (the Day-21 fill
	// discipline; a counter missing from rebuildCounters() silently drops to nil
	// under --otel).
	QueryLiveSourceReads = newCounter(m,
		"supremum.query.live_source_reads",
		"AsOf/Range queries that CONSULTED the live δ-CRDT HAMT (the read-your-writes path, Day 27 ADR-0032). After the durable Arrow scan, the Resolver merges the live dominant under the SAME bitemporal dominance (Filter2 sysTime<=txTime + Filter3 validTime window + max-SystemTime selection) so an entry a write placed in the live HAMT is visible to /v1/query IMMEDIATELY, before the bridge's periodic AppendCheckpoint flushes SnapshotToLSM→L0. The counter discloses the LIVE-PATH was taken (NOT every live HIT — a live read can return zero entries; the count is the path disclosure, the SAME Law V class the download-skip + manifest-skip counters carry). A query WITHOUT a live source configured (nil — the research-node default, --lsm-root absent) does NOT increment it (the nil-guard).",
		"1",
		modeCounter,
	)
	// Day 29 (ADR-0034): the stratified-anti-entropy fallback disclosure
	// counter — constructed in BOTH init() AND rebuildCounters() (the Day-21
	// fill discipline; a counter missing from rebuildCounters() silently drops
	// to nil under --otel).
	StratifiedAntiEntropyFallback = newCounter(m,
		"supremum.mesh.stratified_fallback",
		"Anti-entropy sweep rounds where the stratified digest-exchange phase (Day 29 ADR-0034, the M3 two-phase StrataEstimator round) FELL BACK to the full-delta oversend path: a digest timeout (the peer did not return its estimator within digestWaitTimeout), a malformed digest (UnmarshalStrataEstimator ErrMalformedStrata), a peel failure inside GenerateDelta (crdt.go:1603 yields EVERY entry = full oversend-equivalent), or a Publish failure (the peer dropped mid-round). The fallback is the M5 honest path: the convergence guarantee HOLDS (the signed delta path is unchanged; oversend is a strict superset the CRDT-idempotent Join absorbs), the counter is the Law V DISCLOSURE that lets the operator SEE the mesh converging via oversend vs via the stratified cut. A node with stratified OFF (the opt-IN default) never fires it (the oversend path is the baseline, not a fallback).",
		"1",
		modeCounter,
	)
	// Day 30 (ADR-0035): the PKI leaf-rotation + revocation-reject disclosure
	// counters — constructed in BOTH init() AND rebuildCounters() (the Day-21
	// fill discipline; a counter missing from rebuildCounters() silently drops
	// to nil under --otel).
	CertRotationTriggered = newCounter(m,
		"supremum.pki.cert_rotation_triggered",
		"Times the automated leaf-rotation goroutine (Day 30 ADR-0035, StartRotationManager — the --cert-rotation-enable opt-IN trigger) minted a NEW leaf + Reloaded the transport. The blueprint Track 5.2 'zero-downtime leaf cert rotation every 30 days' gate is a NUMBER, not an adjective: the count is the operator-visible audit trail that the trigger fired (a node with --cert-rotation-enable=false — the DEFAULT — never fires it; the manual SIGHUP seam does NOT fire it either, only the automated goroutine).",
		"1",
		modeCounter,
	)
	CertRevokedRejected = newCounter(m,
		"supremum.pki.cert_revoked_rejected",
		"TLS handshakes rejected because the presented peer leaf's serial is in the CRL (Day 30 ADR-0035, the VerifyPeerCertificate callback consult). The blueprint Track 5.2 'a node presenting an expired or revoked cert is rejected at the TLS handshake' gate's REVOKED claw — byte-proven by T-PKI-REVOKED-REJECTED (a revoked serial is REJECTED; a SIBLING non-revoked serial PASSES — the CRL is serial-scoped, not CA-scoped). The EXPIRED claw is met by default Go-tls chain validation (NOT counted here — that is NOT new work this fork claims). A node with NO CRL loaded (the opt-OUT default) never fires it (the consult returns nil on an empty revoked set = byte-identical pre-Day-30).",
		"1",
		modeCounter,
	)
	PQHandshakeNegotiated = newCounter(m,
		"supremum.pki.pq_handshake_negotiated",
		"Completed TLS handshakes that negotiated the X25519MLKEM768 hybrid post-quantum key exchange (Day 31 ADR-0036, the TLS.RecordHandshake seam reading ConnectionState().CurveID==4588). The post-quantum-transport-readiness gate is a NUMBER, not an adjective: the count is the operator-visible PROOF the PQ KEM is happening (the engine ALREADY negotiates it by Go 1.24+ default — Day 31 PROVES, NOT enables; a classical-CurveID fallback for a non-MLKEM peer does NOT increment — the counter is PQ-KEM-only, NOT every handshake). The 4c loopback KEM is byte-proven by T-PQ-KEM-NEGOTIATED (CurveID==4588) with the T-PQ-KEM-CLASSICAL-CONTROL BUG-INJECT (forced CurvePreferences=[X25519] -> CurveID==29, the cut vanishes). The counter fires on the production dial seam (transport.Dial → RecordHandshake); the server-side control-port accept does NOT fire it (the client-side ConnectionState is the load-bearing proof — disclosed ADR-0036 §6).",
		"1",
		modeCounter,
	)
	HybridFrameAccepted = newCounter(m,
		"supremum.hybrid.frame_accepted",
		"Hybrid-PQ CRDT-delta batches ACCEPTED by the receiver's BOTH-verify gate (Day 32 ADR-0037, the Receiver.HandleHybridFrame seam firing on a frame that passed VerifyBatchHybrid — the Ed25519 + ML-DSA-65 both-required gate over the 120-byte SHAKE256 pad of batchWire). The post-quantum SIGN moat is a NUMBER, not an adjective: the count is the operator-visible PROOF the PQ moat is in USE (not just wired) — Day 31 wired the VERIFY + the KEM; Day 32 wires the SIGN + the frame + the directory provisioning + the dispatch, so a hybrid frame is now PRODUCED (under --hybrid-sign) AND ACCEPTED (under --hybrid-verify) end-to-end. A node with --hybrid-sign=false (the DEFAULT) never produces a hybrid frame so the counter stays 0 (a peer that dials it sends a v1 BatchEnvelope, NOT a hybrid frame); a node with --hybrid-verify=false (the DEFAULT) REJECTS a hybrid frame (the symmetric STRICT mode) so the counter stays 0. The counter value is 0 on a single-node --selftest run (NO mesh peer dials); the RUNTIME /verify proves PRESENCE on /metrics (the bridge auto-surface §0.f — PRESENCE not value, the SAME discipline Day-29/30/31 used). The 23rd SSoT distinct counter.",
		"1",
		modeCounter,
	)
	// Day 34 (ADR-0039): the region-aware gossip inter-region-envelope disclosure
	// counter — constructed in BOTH init() AND rebuildCounters() (the Day-21 fill
	// discipline; a counter missing from rebuildCounters() silently drops to nil
	// under --otel).
	InterRegionEnvelopesShipped = newCounter(m,
		"supremum.mesh.inter_region_envelopes",
		"Inter-region CRDT-delta envelopes SHIPPED by the AntiEntropySweep's region-aware fan-out selector (Day 34 ADR-0039, the Gossiper.interRegionReporter seam firing once per peer the sweep routes a delta to whose region differs from the self-region — the inter-region fan-out arm of topology.Select). The region-aware gossip data-plane moat is a NUMBER, not an adjective: the count is the operator-visible PROOF the region-aware path is in USE (not just wired) — the blueprint's Track 5.1 data-plane half turns the per-sweep full-mesh O(N²) iteration (every peer every round) into the intra-region full-mesh + inter-region fan-out-N O(log N) rounds convergence (intra-region peers full-mesh, inter-region fan-out-N prefer-cross-region seeded-deterministic). A node with --region-aware=false (the DEFAULT) never routes a fan-out selection so the counter stays 0 (the full-mesh peers.Peers() path has NO inter-region arm — every peer is SAME-region by the sameRegion-default-to-true discipline, so IsInterRegion returns false for every peer); a node with --region-aware=true but ALL peers SAME-region (the N=2 no-op) also stays 0 (the fan-out selector returns intra-only). The counter value is 0 on a single-node --selftest run (NO mesh peer dials); the RUNTIME /verify proves PRESENCE on /metrics (the bridge auto-surface §0.f — PRESENCE not value, the SAME discipline Day-29/30/31/32 used). Fires ONLY on the inter-region arm (intra-region full-mesh is the SAME-AZ baseline, NOT disclosure-worthy — the disclosure is the CROSS-region fan-out the O(log N) convergence depends on). The 24th SSoT distinct counter.",
		"1",
		modeCounter,
	)
	// SSoT snapshot for the prometheus bridge (single list, frozen after
	// construction; see allCounters). Built here from the distinct vars so
	// the QueryL0ListCapped duplicate-construction above does not duplicate
	// the name in the slice (which would panic MustRegister at boot).
	counters = allCounters()
}

// rebuildCounters constructs the package-level counters against `m` exactly
// once, the first time Init is invoked. Because Init is now strictly
// once-per-process (R1 FIX), no data-plane goroutine can observe the pointer
// reassignment this performs.
func rebuildCounters(m metric.Meter) {
	ArrowSerialBytes = newCounter(m,
		"supremum.l0.arrow_serial_bytes",
		"Bytes serialized into Arrow IPC during L0 flush",
		"By",
		modeCounter,
	)
	MemTableFlushTotal = newCounter(m,
		"supremum.memtable.flush_total",
		"Total number of MemTable L0 flushes",
		"1",
		modeCounter,
	)
	// Day 21 (ADR-0026): the fill. rebuildCounters now constructs
	// QueryL0ListCapped — the SAME single construction as init(), placed at the
	// SAME position (after MemTableFlushTotal, before OffHeapAllocatedBytes) so
	// the registered-instrument order under the OTel Meter is stable across the
	// two construction sites (a drift in order is a registered-instrument-order
	// drift observable to a collector — disclosed ADR-0026 §3). This closes the
	// omission landmine ADR-0023 §6 named: without it, an Init(realMeter) call
	// reassigns QueryL0ListCapped to nil → the use-site guard at query.go:253
	// silently stops counting the cap-hit disclosure counter.
	QueryL0ListCapped = newCounter(m,
		"supremum.l0.query_list_capped",
		"AsOf queries that hit the MaxL0Files list cap (older per-entity files may have been silently dropped from the scan — see ADR-0018 §6. Compaction is the future fix.)",
		"1",
		modeCounter,
	)
	OffHeapAllocatedBytes = newCounter(m,
		"supremum.memtable.offheap_allocated_bytes",
		"Bytes currently allocated off-heap by the jemalloc allocator",
		"By",
		modeGauge,
	)
	QueryL1FilesScanned = newCounter(m,
		"supremum.l1.query_files_scanned",
		"L1 (compacted) Arrow IPC files scanned by AsOf per query (Day 14 ADR-0019)",
		"1",
		modeCounter,
	)
	CompactionMerged = newCounter(m,
		"supremum.compaction.l0_files_merged",
		"L0 files merged into L1 by the per-entity compaction (Day 14 ADR-0019)",
		"1",
		modeCounter,
	)
	CompactionL1Written = newCounter(m,
		"supremum.compaction.l1_files_written",
		"L1 files written by the per-entity compaction (Day 14 ADR-0019)",
		"1",
		modeCounter,
	)
	CompactionRowsPruned = newCounter(m,
		"supremum.compaction.l1_rows_pruned",
		"Rows dropped by the Level-2 superseded-row DominancePrune at the compaction merge seam (Day 15 ADR-0020). The (C1)&&(C2)&&(C3) SAFE-DROP rule; Preserve-All (EnableDominancePruning=false) never touches it.",
		"1",
		modeCounter,
	)
	L0ReapSweeps = newCounter(m,
		"supremum.compaction.l0_reap_sweeps",
		"Times the L0 reaper swept the compaction/ manifest tier (Day 16 ADR-0021).",
		"1",
		modeCounter,
	)
	L0ReapL0Deleted = newCounter(m,
		"supremum.compaction.l0_reap_l0_files_deleted",
		"L0 files deleted by the L0 reaper across all sweeps (Day 16 ADR-0021). Counted as a DELETE that returned nil — which INCLUDES the idempotent already-absent path (a prior sweep or manual operator reclaimed the file). A successful Delete call counts regardless of whether a file was physically removed THIS sweep; the reaper does NOT pre-Stat (the idempotent-nil contract makes a pre-Stat an IO the safety contract does not require).",
		"1",
		modeCounter,
	)
	L0ReapManifestsReaped = newCounter(m,
		"supremum.compaction.l0_reap_manifests_reaped",
		"Compaction manifests fully reaped by the L0 reaper (Day 16 ADR-0021).",
		"1",
		modeCounter,
	)
	L0ReapSkippedOrphan = newCounter(m,
		"supremum.compaction.l0_reap_manifests_skipped_orphan",
		"Compaction manifests the L0 reaper SKIPPED because the L1 was missing (Day 16 ADR-0021) — the L0s preserved as the backstop.",
		"1",
		modeCounter,
	)
	// Day 22 (ADR-0027): the T_gc auto-inference counters — the rebuildCounters
	// fill (the Day-21 discipline: a counter missing HERE silently drops to nil
	// under --otel because an Init(realMeter) call reassigns the var to the
	// newCounter result; without THIS block the new assignment is nil). Same
	// names/descriptions/modes as init() so the registered-instrument order
	// under the OTel Meter is stable across the two construction sites.
	QueryTxTimeHighWaterMark = newCounter(m,
		"supremum.query_txtime_high_water_mark_ns",
		"Observed live-query transactionTime frontier (the MAX txTime an AsOf call has served) in nanoseconds (Day 22 ADR-0027). The data source the HorizonInferrer reads to compute the effective DominancePrune floor. The operator-visible 'the engine sees queries up to HERE' signal — absent before Day 22.",
		"ns",
		modeGauge,
	)
	PruningHorizonEffective = newCounter(m,
		"supremum.compaction.pruning_horizon_effective_ns",
		"Effective DominancePrune (C3) floor T_gc the inferrer computed + fed to the prune: max(operatorFloor, observedFrontier - backoff) in nanoseconds (Day 22 ADR-0027). The audit-trail pair with the observed frontier: the gap is the backoff in operation. The operator floor dominates only when it exceeds the inferred (the §0.a inferrer-FLOORS-the-knob contract).",
		"ns",
		modeGauge,
	)
	PruningHorizonRetreatRefused = newCounter(m,
		"supremum.compaction.pruning_horizon_retreat_refused",
		"Times SetInferredHorizon refused a RETREAT (a horizon less than the current) — the §0.c monotone-clamp loud-path signal (Day 22 ADR-0027). ZERO under correct operation (the live-query txTime frontier is monotone non-decreasing); non-zero = a txTime REGRESSION in the query stream (a correctness smell, NOT a relaxation) OR a bug. A rising counter = investigate the query stream's txTime monotonicity.",
		"1",
		modeCounter,
	)
	// Day 24 (ADR-0029): the rebuildCounters fill for the download-skip
	// disclosure counter (the Day-21 discipline: a counter missing HERE silently
	// drops to nil under --otel because an Init(realMeter) call reassigns the
	// var to the newCounter result; without THIS block the new assignment is
	// nil). Same name/description/mode as init() so the registered-instrument
	// order under the OTel Meter is stable across the two construction sites.
	QueryDownloadSkippedFirstSys = newCounter(m,
		"supremum.l0.query_download_skipped_first_sys",
		"L0/L1 Arrow files whose Download was SKIPPED because the file's filename-encoded FirstSysTimeNs (the file's MIN sysTime, written by the flush since Day-13) exceeds the query's txTime (Day 24 ADR-0029). A transitively-safe elimination: the file carries ZERO rows visible at txTime (every row fails Filter2 sysTime<=txTime) so the skip preserves Law II. The disclosure counter (Law V): every skip is MEASURED. FAILSAFE: a parse anomaly → no skip → no counter fire → the full download runs (a corrupt/renamed file is NEVER silently dropped).",
		"1",
		modeCounter,
	)
	// Day 25 (ADR-0030): the rebuildCounters fill for the manifest-channel
	// download-skip disclosure counter (the Day-21 discipline: a counter
	// missing HERE silently drops to nil under --otel because an Init(realMeter)
	// call reassigns the var to the newCounter result; without THIS block the
	// new assignment is nil — the omission landmine). Same name/description/mode
	// as init() so the registered-instrument order under the OTel Meter is
	// stable across the two construction sites.
	QueryManifestSkippedFirstSys = newCounter(m,
		"supremum.compaction.query_manifest_skipped_first_sys",
		"Compaction manifests whose Download was SKIPPED because the manifest's filename-encoded FirstSysTimeNs (the L1's MIN sysTime, shared with the L1 key the manifest points at) exceeds the query's txTime (Day 25 ADR-0030). The Day-24 tautology on the manifest channel: the L1 it points at is skipped (Day-24 file-skip) AND every L0 it lists is skipped (Day-24 file-skip) -> the manifest's superseded-set intersects ONLY files the scan loop skips anyway -> skipping the manifest download preserves the tailKeys byte-identically for the query's visible rows (Law II). The disclosure counter (Law V): every skip is MEASURED. FAILSAFE: a parse anomaly -> no skip -> the full manifest download runs (a corrupt manifest is NEVER silently dropped).",
		"1",
		modeCounter,
	)
	// SSoT snapshot for the prometheus bridge (single list, frozen after
	// construction; see allCounters). Day 21 (ADR-0026) made rebuildCounters
	// construct QueryL0ListCapped too (the fill at the same position as
	// init), so BOTH construction sites now build all distinct counters —
	// the slice carries the same distinct *Counter pointers under either
	// site, and an Init(realMeter) call no longer reassigns QueryL0ListCapped
	// to nil (the omission landmine is closed). Day 22 (ADR-0027) extends the
	// same discipline to the three new inferrer counters (12 -> 15 distinct).
	// Day 24 (ADR-0029) extends it to the download-skip counter (15 -> 16).
	// Day 25 (ADR-0030) extends it to the manifest-skip counter (16 -> 17).
	// Day 27 (ADR-0032): the rebuildCounters fill for the read-your-writes
	// live-source disclosure counter (the Day-21 discipline: a counter missing
	// HERE silently drops to nil under --otel because an Init(realMeter) call
	// reassigns the var to the newCounter result; without THIS block the new
	// assignment is nil — the omission landmine). Same name/description/mode as
	// init() so the registered-instrument order under the OTel Meter is stable
	// across the two construction sites.
	QueryLiveSourceReads = newCounter(m,
		"supremum.query.live_source_reads",
		"AsOf/Range queries that CONSULTED the live δ-CRDT HAMT (the read-your-writes path, Day 27 ADR-0032). After the durable Arrow scan, the Resolver merges the live dominant under the SAME bitemporal dominance (Filter2 sysTime<=txTime + Filter3 validTime window + max-SystemTime selection) so an entry a write placed in the live HAMT is visible to /v1/query IMMEDIATELY, before the bridge's periodic AppendCheckpoint flushes SnapshotToLSM→L0. The counter discloses the LIVE-PATH was taken (NOT every live HIT — a live read can return zero entries; the count is the path disclosure, the SAME Law V class the download-skip + manifest-skip counters carry). A query WITHOUT a live source configured (nil — the research-node default, --lsm-root absent) does NOT increment it (the nil-guard).",
		"1",
		modeCounter,
	)
	// Day 29 (ADR-0034): the rebuildCounters fill for the stratified-anti-entropy
	// fallback disclosure counter (the Day-21 discipline: a counter missing HERE
	// silently drops to nil under --otel because an Init(realMeter) call
	// reassigns the var to the newCounter result; without THIS block the new
	// assignment is nil — the omission landmine). Same name/description/mode as
	// init() so the registered-instrument order under the OTel Meter is stable
	// across the two construction sites.
	StratifiedAntiEntropyFallback = newCounter(m,
		"supremum.mesh.stratified_fallback",
		"Anti-entropy sweep rounds where the stratified digest-exchange phase (Day 29 ADR-0034, the M3 two-phase StrataEstimator round) FELL BACK to the full-delta oversend path: a digest timeout (the peer did not return its estimator within digestWaitTimeout), a malformed digest (UnmarshalStrataEstimator ErrMalformedStrata), a peel failure inside GenerateDelta (crdt.go:1603 yields EVERY entry = full oversend-equivalent), or a Publish failure (the peer dropped mid-round). The fallback is the M5 honest path: the convergence guarantee HOLDS (the signed delta path is unchanged; oversend is a strict superset the CRDT-idempotent Join absorbs), the counter is the Law V DISCLOSURE that lets the operator SEE the mesh converging via oversend vs via the stratified cut. A node with stratified OFF (the opt-IN default) never fires it (the oversend path is the baseline, not a fallback).",
		"1",
		modeCounter,
	)
	// Day 30 (ADR-0035): the rebuildCounters fill for the PKI leaf-rotation +
	// revocation-reject disclosure counters (the Day-21 discipline: a counter
	// missing HERE silently drops to nil under --otel because an Init(realMeter)
	// call reassigns the var to the newCounter result; without THIS block the
	// new assignment is nil — the omission landmine). Same name/description/mode
	// as init() so the registered-instrument order under the OTel Meter is
	// stable across the two construction sites.
	CertRotationTriggered = newCounter(m,
		"supremum.pki.cert_rotation_triggered",
		"Times the automated leaf-rotation goroutine (Day 30 ADR-0035, StartRotationManager — the --cert-rotation-enable opt-IN trigger) minted a NEW leaf + Reloaded the transport. The blueprint Track 5.2 'zero-downtime leaf cert rotation every 30 days' gate is a NUMBER, not an adjective: the count is the operator-visible audit trail that the trigger fired (a node with --cert-rotation-enable=false — the DEFAULT — never fires it; the manual SIGHUP seam does NOT fire it either, only the automated goroutine).",
		"1",
		modeCounter,
	)
	CertRevokedRejected = newCounter(m,
		"supremum.pki.cert_revoked_rejected",
		"TLS handshakes rejected because the presented peer leaf's serial is in the CRL (Day 30 ADR-0035, the VerifyPeerCertificate callback consult). The blueprint Track 5.2 'a node presenting an expired or revoked cert is rejected at the TLS handshake' gate's REVOKED claw — byte-proven by T-PKI-REVOKED-REJECTED (a revoked serial is REJECTED; a SIBLING non-revoked serial PASSES — the CRL is serial-scoped, not CA-scoped). The EXPIRED claw is met by default Go-tls chain validation (NOT counted here — that is NOT new work this fork claims). A node with NO CRL loaded (the opt-OUT default) never fires it (the consult returns nil on an empty revoked set = byte-identical pre-Day-30).",
		"1",
		modeCounter,
	)
	PQHandshakeNegotiated = newCounter(m,
		"supremum.pki.pq_handshake_negotiated",
		"Completed TLS handshakes that negotiated the X25519MLKEM768 hybrid post-quantum key exchange (Day 31 ADR-0036, the TLS.RecordHandshake seam reading ConnectionState().CurveID==4588). The post-quantum-transport-readiness gate is a NUMBER, not an adjective: the count is the operator-visible PROOF the PQ KEM is happening (the engine ALREADY negotiates it by Go 1.24+ default — Day 31 PROVES, NOT enables; a classical-CurveID fallback for a non-MLKEM peer does NOT increment — the counter is PQ-KEM-only, NOT every handshake). The 4c loopback KEM is byte-proven by T-PQ-KEM-NEGOTIATED (CurveID==4588) with the T-PQ-KEM-CLASSICAL-CONTROL BUG-INJECT (forced CurvePreferences=[X25519] -> CurveID==29, the cut vanishes). The counter fires on the production dial seam (transport.Dial → RecordHandshake); the server-side control-port accept does NOT fire it (the client-side ConnectionState is the load-bearing proof — disclosed ADR-0036 §6).",
		"1",
		modeCounter,
	)
	HybridFrameAccepted = newCounter(m,
		"supremum.hybrid.frame_accepted",
		"Hybrid-PQ CRDT-delta batches ACCEPTED by the receiver's BOTH-verify gate (Day 32 ADR-0037, the Receiver.HandleHybridFrame seam firing on a frame that passed VerifyBatchHybrid). The Day-21 fill discipline: this rebuildCounters() site mirrors init() so the counter does NOT silently drop to nil under --otel (the §0.f construction-vs-distinct trap). See init() for the full description.",
		"1",
		modeCounter,
	)
	// Day 34 (ADR-0039): the rebuildCounters fill for the region-aware gossip
	// inter-region-envelope disclosure counter (the Day-21 discipline: a counter
	// missing HERE silently drops to nil under --otel because an Init(realMeter)
	// call reassigns the var to the newCounter result; without THIS block the
	// new assignment is nil — the omission landmine). Same name/description/mode
	// as init() so the registered-instrument order under the OTel Meter is stable
	// across the two construction sites.
	InterRegionEnvelopesShipped = newCounter(m,
		"supremum.mesh.inter_region_envelopes",
		"Inter-region CRDT-delta envelopes SHIPPED by the AntiEntropySweep's region-aware fan-out selector (Day 34 ADR-0039, the Gossiper.interRegionReporter seam firing once per peer the sweep routes a delta to whose region differs from the self-region — the inter-region fan-out arm of topology.Select). The region-aware gossip data-plane moat is a NUMBER, not an adjective: the count is the operator-visible PROOF the region-aware path is in USE (not just wired) — the blueprint's Track 5.1 data-plane half turns the per-sweep full-mesh O(N²) iteration (every peer every round) into the intra-region full-mesh + inter-region fan-out-N O(log N) rounds convergence (intra-region peers full-mesh, inter-region fan-out-N prefer-cross-region seeded-deterministic). A node with --region-aware=false (the DEFAULT) never routes a fan-out selection so the counter stays 0 (the full-mesh peers.Peers() path has NO inter-region arm — every peer is SAME-region by the sameRegion-default-to-true discipline, so IsInterRegion returns false for every peer); a node with --region-aware=true but ALL peers SAME-region (the N=2 no-op) also stays 0 (the fan-out selector returns intra-only). The counter value is 0 on a single-node --selftest run (NO mesh peer dials); the RUNTIME /verify proves PRESENCE on /metrics (the bridge auto-surface §0.f — PRESENCE not value, the SAME discipline Day-29/30/31/32 used). Fires ONLY on the inter-region arm (intra-region full-mesh is the SAME-AZ baseline, NOT disclosure-worthy — the disclosure is the CROSS-region fan-out the O(log N) convergence depends on). The Day-21 fill discipline: this rebuildCounters() site mirrors init() so the counter does NOT silently drop to nil under --otel (the §0.f construction-vs-distinct trap). See init() for the full lineage.",
		"1",
		modeCounter,
	)
	counters = allCounters()
}
