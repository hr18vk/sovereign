// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

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
// constructs the package-level counters against it. It is a startup operation
// and must be called at most once per process, before data-plane goroutines use
// the counters.
//
// Data-plane callers access the package-level *Counter pointers directly. A
// later rebind could split Add traffic between the old and new LongAdders and
// strand the total accumulated by an orphaned counter. The first call binds
// the counters; later calls are logged and leave the existing counters in
// place.
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

// initDone guards the once-per-process Init contract.
var initDone atomic.Bool

// Package-level counters consumed by the data plane. Package initialization
// constructs them without a Meter; Init reconstructs them when a Meter is
// supplied. Data-plane callers reference the pointers directly.
var (
	ArrowSerialBytes      *Counter
	MemTableFlushTotal    *Counter
	OffHeapAllocatedBytes *Counter
	QueryL0ListCapped     *Counter
	// L0→L1 per-entity compaction counters (ADR-0019).
	QueryL1FilesScanned *Counter
	CompactionMerged    *Counter
	CompactionL1Written *Counter
	// Superseded-row pruning counter (ADR-0020): counts rows dropped by
	// DominancePrune during compaction merge when C1, C2, and C3 hold.
	// Disabled when EnableDominancePruning is false.
	CompactionRowsPruned *Counter
	// L0 reaper counters (ADR-0021): tracks manifest-listed L0 files deleted
	// after verifying their target L1 object still exists.
	L0ReapSweeps          *Counter // sweeper runs
	L0ReapL0Deleted       *Counter // total L0 files deleted
	L0ReapManifestsReaped *Counter // manifests whose L0s and manifest entry were deleted
	L0ReapSkippedOrphan   *Counter // manifests skipped because the target L1 was missing
	// T_gc auto-inference counters (ADR-0027): tracks the live-query txTime
	// frontier observed at AsOf entry and feeds max(operatorFloor,
	// observedFrontier - backoff) into DominancePrune's C3 floor. All counters
	// must be built in both init() and rebuildCounters() so Init(meter) never
	// reassigns a counter to nil.
	QueryTxTimeHighWaterMark     *Counter // modeGauge — observed live-query txTime frontier
	PruningHorizonEffective      *Counter // modeGauge — effective horizon fed to DominancePrune
	PruningHorizonRetreatRefused *Counter // modeCounter — count of SetInferredHorizon calls rejecting a backward step
	// Filename-bounded download-skip counter (ADR-0029): counts L0/L1 Arrow
	// downloads skipped when filename-encoded FirstSysTimeNs exceeds query
	// txTime, because no row in the file can satisfy SystemTime <= txTime.
	QueryDownloadSkippedFirstSys *Counter // modeCounter — L0/L1 files skipped because FirstSysTimeNs > txTime
	// Manifest-channel download-skip counter (ADR-0030): counts compaction
	// manifest downloads skipped in loadSupersededL0Keys when FirstSysTimeNs >
	// query txTime (strict inequality). The target L1 and every listed L0 have
	// firstSys >= manifest.firstSys > txTime, so the scan skips them regardless.
	// Gated on EnableFirstSysSkip; parse errors fall back to full download.
	QueryManifestSkippedFirstSys *Counter // modeCounter — compaction manifests skipped because FirstSysTimeNs > txTime
	// Read-your-writes live-source counter (ADR-0032): counts AsOf and Range
	// queries that consulted LiveSource after reading durable storage so
	// uncheckpointed writes are visible immediately.
	QueryLiveSourceReads *Counter // modeCounter — AsOf/Range queries that consulted the live CRDT HAMT

	// Stratified anti-entropy fallback counter (ADR-0034): increments when a
	// two-phase StrataEstimator digest round falls back to full-delta oversend
	// due to digest timeout, malformed estimator, peel failure in GenerateDelta,
	// or publish failure. Remains zero when stratified anti-entropy is off.
	StratifiedAntiEntropyFallback *Counter // modeCounter — mesh digest-exchange rounds that fell back to oversend

	// PKI leaf-rotation and revocation counters (ADR-0035):
	// CertRotationTriggered counts automated rotations minted and reloaded by
	// StartRotationManager (--cert-rotation-enable). CertRevokedRejected counts
	// TLS handshakes rejected by VerifyPeerCertificate when a peer certificate
	// serial appears in the loaded CRL.
	CertRotationTriggered *Counter // modeCounter — automated leaf-rotation trigger firings
	CertRevokedRejected   *Counter // modeCounter — handshakes rejected because the presented leaf serial is in the CRL
	// Post-quantum KEM-negotiated counter (ADR-0036).
	PQHandshakeNegotiated *Counter // modeCounter — completed TLS handshakes that negotiated X25519MLKEM768

	// Hybrid post-quantum batch acceptance counter (ADR-0037): increments in
	// Receiver.HandleHybridFrame when an incoming frame passes Ed25519 and
	// ML-DSA-65 verification under VerifyBatchHybrid. Zero on single-node runs.
	HybridFrameAccepted *Counter // modeCounter — hybrid-PQ batches accepted after dual signature verification

	// Region-aware gossip inter-region envelope counter (ADR-0039): increments
	// when AntiEntropySweep's region-aware selector routes a CRDT delta
	// envelope to a peer in another region (--region-aware). Same-region
	// full-mesh deliveries are not counted.
	InterRegionEnvelopesShipped *Counter // modeCounter — inter-region CRDT-delta envelopes shipped by the region-aware fan-out selector

	// Mesh write-deadline counter (ADR-0059): increments when a mesh TLS frame
	// write exceeds --mesh-write-timeout. The connection is closed (Go
	// crypto/tls write timeouts leave connection state unusable) and the peer
	// enters write-stall suspect backoff so the serial sweep avoids blocking
	// behind a half-open peer.
	MeshWriteTimeouts *Counter // modeCounter — mesh frame writes that exceeded the write deadline
)

// allCounters returns every constructed *Counter in stable bridge-enumeration
// order. Both init and rebuildCounters populate the package-level pointers and
// then snapshot this list, so TelemetryBridge exposes one series per metric and
// Init does not leave any counter nil.
//
// The slice is immutable after package init and Init complete and read by
// TelemetryBridge without locking. OffHeapAllocatedBytes,
// QueryTxTimeHighWaterMark, and PruningHorizonEffective use modeGauge; all
// other entries use modeCounter.
func allCounters() []*Counter {
	// All 25 package-level *Counter vars in registration order.
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
		QueryDownloadSkippedFirstSys,
		QueryManifestSkippedFirstSys,
		QueryLiveSourceReads,
		StratifiedAntiEntropyFallback,
		CertRotationTriggered,
		CertRevokedRejected,
		PQHandshakeNegotiated,
		HybridFrameAccepted,
		InterRegionEnvelopesShipped,
		MeshWriteTimeouts,
	}
}

// counters caches allCounters() for TelemetryBridge scrapes after construction
// completes in init() or rebuildCounters().
var counters []*Counter

// Counters returns the immutable slice of all constructed *Counter metrics in
// stable order for TelemetryBridge enumeration.
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
		"AsOf queries that hit the MaxL0Files list cap (older uncompacted per-entity L0 files may be excluded from the scan; see ADR-0018).",
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
		"L1 (compacted) Arrow IPC files scanned by AsOf per query (ADR-0019)",
		"1",
		modeCounter,
	)
	CompactionMerged = newCounter(m,
		"supremum.compaction.l0_files_merged",
		"L0 files merged into L1 by the per-entity compaction (ADR-0019)",
		"1",
		modeCounter,
	)
	CompactionL1Written = newCounter(m,
		"supremum.compaction.l1_files_written",
		"L1 files written by the per-entity compaction (ADR-0019)",
		"1",
		modeCounter,
	)
	CompactionRowsPruned = newCounter(m,
		"supremum.compaction.l1_rows_pruned",
		"Rows dropped by DominancePrune during compaction merge when C1, C2, and C3 hold (ADR-0020); disabled when EnableDominancePruning is false.",
		"1",
		modeCounter,
	)
	L0ReapSweeps = newCounter(m,
		"supremum.compaction.l0_reap_sweeps",
		"Times the L0 reaper swept the compaction manifest tier (ADR-0021) to reclaim manifest-listed L0 files after verifying the target L1 still exists.",
		"1",
		modeCounter,
	)
	L0ReapL0Deleted = newCounter(m,
		"supremum.compaction.l0_reap_l0_files_deleted",
		"L0 files deleted by the L0 reaper across all sweeps (ADR-0021). Deletes are issued only for manifest-listed L0 files whose target L1 is verified present; counts successful Delete calls including idempotent already-absent paths without pre-Stat.",
		"1",
		modeCounter,
	)
	L0ReapManifestsReaped = newCounter(m,
		"supremum.compaction.l0_reap_manifests_reaped",
		"Compaction manifests fully reaped (every listed L0 deleted + the manifest itself deleted) by the L0 reaper (ADR-0021).",
		"1",
		modeCounter,
	)
	L0ReapSkippedOrphan = newCounter(m,
		"supremum.compaction.l0_reap_manifests_skipped_orphan",
		"Compaction manifests skipped by the L0 reaper because the target L1 was missing (ADR-0021); their listed L0s are preserved for crash recovery.",
		"1",
		modeCounter,
	)
	QueryTxTimeHighWaterMark = newCounter(m,
		"supremum.query_txtime_high_water_mark_ns",
		"Observed live-query transactionTime frontier (maximum txTime served by AsOf) in nanoseconds (ADR-0027), read by HorizonInferrer to compute the DominancePrune floor.",
		"ns",
		modeGauge,
	)
	PruningHorizonEffective = newCounter(m,
		"supremum.compaction.pruning_horizon_effective_ns",
		"Effective DominancePrune (C3) floor T_gc fed to pruning: max(operatorFloor, observedFrontier - backoff) in nanoseconds (ADR-0027); operatorFloor dominates when larger than the inferred horizon.",
		"ns",
		modeGauge,
	)
	PruningHorizonRetreatRefused = newCounter(m,
		"supremum.compaction.pruning_horizon_retreat_refused",
		"Count of SetInferredHorizon calls that refused a retreating horizon (ADR-0027); remains zero while live-query txTime is monotonically non-decreasing.",
		"1",
		modeCounter,
	)
	QueryDownloadSkippedFirstSys = newCounter(m,
		"supremum.l0.query_download_skipped_first_sys",
		"L0/L1 Arrow files whose download was skipped because their filename-encoded FirstSysTimeNs exceeds query txTime (ADR-0029); falls back to full download on parse anomaly.",
		"1",
		modeCounter,
	)
	QueryManifestSkippedFirstSys = newCounter(m,
		"supremum.compaction.query_manifest_skipped_first_sys",
		"Compaction manifests whose download was skipped because their filename-encoded FirstSysTimeNs exceeds query txTime (ADR-0030); falls back to full download on parse anomaly.",
		"1",
		modeCounter,
	)
	// Keep this construction mirrored in rebuildCounters so Init preserves the
	// read-your-writes live-source counter (ADR-0032).
	QueryLiveSourceReads = newCounter(m,
		"supremum.query.live_source_reads",
		"AsOf and Range queries that consulted the live CRDT HAMT when LiveSource is configured (ADR-0032).",
		"1",
		modeCounter,
	)
	StratifiedAntiEntropyFallback = newCounter(m,
		"supremum.mesh.stratified_fallback",
		"Anti-entropy sweep rounds where stratified digest exchange fell back to full-delta oversend on timeout, malformed estimator, peel failure, or publish error (ADR-0034).",
		"1",
		modeCounter,
	)
	CertRotationTriggered = newCounter(m,
		"supremum.pki.cert_rotation_triggered",
		"Automated TLS leaf certificate rotations triggered and reloaded by StartRotationManager (ADR-0035); zero when automatic rotation is disabled.",
		"1",
		modeCounter,
	)
	CertRevokedRejected = newCounter(m,
		"supremum.pki.cert_revoked_rejected",
		"TLS handshakes rejected because the presented peer leaf serial appeared in the loaded CRL (ADR-0035); expired certificates are handled by standard TLS chain validation.",
		"1",
		modeCounter,
	)
	PQHandshakeNegotiated = newCounter(m,
		"supremum.pki.pq_handshake_negotiated",
		"Completed TLS handshakes that negotiated X25519MLKEM768 hybrid post-quantum key exchange on outbound dials (ADR-0036).",
		"1",
		modeCounter,
	)
	HybridFrameAccepted = newCounter(m,
		"supremum.hybrid.frame_accepted",
		"Hybrid post-quantum CRDT delta batches accepted by Receiver.HandleHybridFrame after Ed25519 + ML-DSA-65 verification (ADR-0037).",
		"1",
		modeCounter,
	)
	InterRegionEnvelopesShipped = newCounter(m,
		"supremum.mesh.inter_region_envelopes",
		"Inter-region CRDT delta envelopes sent via the region-aware fan-out selector during AntiEntropySweep (ADR-0039); zero when region-aware routing is disabled or all peers share one region.",
		"1",
		modeCounter,
	)
	MeshWriteTimeouts = newCounter(m,
		"supremum.mesh.write_timeouts",
		"Mesh TLS frame writes that exceeded --mesh-write-timeout, forcing connection close and write-stall suspect backoff (ADR-0059).",
		"1",
		modeCounter,
	)
	counters = allCounters()
}

// rebuildCounters constructs the package-level counters against m when Init is
// invoked. Init must finish before data-plane goroutines use the counters.
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
	QueryL0ListCapped = newCounter(m,
		"supremum.l0.query_list_capped",
		"AsOf queries that hit the MaxL0Files list cap (older uncompacted per-entity L0 files may be excluded from the scan; see ADR-0018).",
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
		"L1 (compacted) Arrow IPC files scanned by AsOf per query (ADR-0019)",
		"1",
		modeCounter,
	)
	CompactionMerged = newCounter(m,
		"supremum.compaction.l0_files_merged",
		"L0 files merged into L1 by the per-entity compaction (ADR-0019)",
		"1",
		modeCounter,
	)
	CompactionL1Written = newCounter(m,
		"supremum.compaction.l1_files_written",
		"L1 files written by the per-entity compaction (ADR-0019)",
		"1",
		modeCounter,
	)
	CompactionRowsPruned = newCounter(m,
		"supremum.compaction.l1_rows_pruned",
		"Rows dropped by DominancePrune during compaction merge when C1, C2, and C3 hold (ADR-0020); disabled when EnableDominancePruning is false.",
		"1",
		modeCounter,
	)
	L0ReapSweeps = newCounter(m,
		"supremum.compaction.l0_reap_sweeps",
		"Times the L0 reaper swept the compaction manifest tier (ADR-0021).",
		"1",
		modeCounter,
	)
	L0ReapL0Deleted = newCounter(m,
		"supremum.compaction.l0_reap_l0_files_deleted",
		"L0 files deleted by the L0 reaper across all sweeps (ADR-0021); counts successful Delete calls including idempotent already-absent paths without pre-Stat.",
		"1",
		modeCounter,
	)
	L0ReapManifestsReaped = newCounter(m,
		"supremum.compaction.l0_reap_manifests_reaped",
		"Compaction manifests fully reaped by the L0 reaper (ADR-0021).",
		"1",
		modeCounter,
	)
	L0ReapSkippedOrphan = newCounter(m,
		"supremum.compaction.l0_reap_manifests_skipped_orphan",
		"Compaction manifests skipped by the L0 reaper because the target L1 was missing (ADR-0021); their listed L0s are preserved.",
		"1",
		modeCounter,
	)
	QueryTxTimeHighWaterMark = newCounter(m,
		"supremum.query_txtime_high_water_mark_ns",
		"Observed live-query transactionTime frontier (maximum txTime served by AsOf) in nanoseconds (ADR-0027), read by HorizonInferrer to compute the DominancePrune floor.",
		"ns",
		modeGauge,
	)
	PruningHorizonEffective = newCounter(m,
		"supremum.compaction.pruning_horizon_effective_ns",
		"Effective DominancePrune (C3) floor T_gc fed to pruning: max(operatorFloor, observedFrontier - backoff) in nanoseconds (ADR-0027); operatorFloor dominates when larger than the inferred horizon.",
		"ns",
		modeGauge,
	)
	PruningHorizonRetreatRefused = newCounter(m,
		"supremum.compaction.pruning_horizon_retreat_refused",
		"Count of SetInferredHorizon calls that refused a retreating horizon (ADR-0027); remains zero while live-query txTime is monotonically non-decreasing.",
		"1",
		modeCounter,
	)
	QueryDownloadSkippedFirstSys = newCounter(m,
		"supremum.l0.query_download_skipped_first_sys",
		"L0/L1 Arrow files whose download was skipped because their filename-encoded FirstSysTimeNs exceeds query txTime (ADR-0029); falls back to full download on parse anomaly.",
		"1",
		modeCounter,
	)
	QueryManifestSkippedFirstSys = newCounter(m,
		"supremum.compaction.query_manifest_skipped_first_sys",
		"Compaction manifests whose download was skipped because their filename-encoded FirstSysTimeNs exceeds query txTime (ADR-0030); falls back to full download on parse anomaly.",
		"1",
		modeCounter,
	)
	QueryLiveSourceReads = newCounter(m,
		"supremum.query.live_source_reads",
		"AsOf and Range queries that consulted the live CRDT HAMT when LiveSource is configured (ADR-0032).",
		"1",
		modeCounter,
	)
	StratifiedAntiEntropyFallback = newCounter(m,
		"supremum.mesh.stratified_fallback",
		"Anti-entropy sweep rounds where stratified digest exchange fell back to full-delta oversend on timeout, malformed estimator, peel failure, or publish error (ADR-0034).",
		"1",
		modeCounter,
	)
	CertRotationTriggered = newCounter(m,
		"supremum.pki.cert_rotation_triggered",
		"Automated TLS leaf certificate rotations triggered and reloaded by StartRotationManager (ADR-0035); zero when automatic rotation is disabled.",
		"1",
		modeCounter,
	)
	CertRevokedRejected = newCounter(m,
		"supremum.pki.cert_revoked_rejected",
		"TLS handshakes rejected because the presented peer leaf serial appeared in the loaded CRL (ADR-0035); expired certificates are handled by standard TLS chain validation.",
		"1",
		modeCounter,
	)
	PQHandshakeNegotiated = newCounter(m,
		"supremum.pki.pq_handshake_negotiated",
		"Completed TLS handshakes that negotiated X25519MLKEM768 hybrid post-quantum key exchange on outbound dials (ADR-0036).",
		"1",
		modeCounter,
	)
	HybridFrameAccepted = newCounter(m,
		"supremum.hybrid.frame_accepted",
		"Hybrid post-quantum CRDT delta batches accepted by Receiver.HandleHybridFrame after Ed25519 + ML-DSA-65 verification (ADR-0037); mirrors init().",
		"1",
		modeCounter,
	)
	InterRegionEnvelopesShipped = newCounter(m,
		"supremum.mesh.inter_region_envelopes",
		"Inter-region CRDT delta envelopes sent via the region-aware fan-out selector during AntiEntropySweep (ADR-0039); mirrors init().",
		"1",
		modeCounter,
	)
	MeshWriteTimeouts = newCounter(m,
		"supremum.mesh.write_timeouts",
		"Mesh TLS frame writes that exceeded --mesh-write-timeout, forcing connection close and write-stall suspect backoff (ADR-0059); mirrors init().",
		"1",
		modeCounter,
	)
	counters = allCounters()
}
