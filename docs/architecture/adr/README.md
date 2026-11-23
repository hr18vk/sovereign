# Architecture Decision Records

Every consequential design decision in Sovereign Engine is recorded here with its context,
the options considered, the decision, and the evidence. Rejected designs remain alongside
accepted ones so later readers can see why an approach was not pursued.

Measurements identify the layer they exercise, the conditions under which they were taken,
and their limits. The records are grouped by theme for orientation; their numbers determine
the order in which they were written.

## Core data structure & the merge law

- [ADR-0001: Reject TrueTime commit-wait in the CRDT join path](0001_reject_truetime_commit_wait.md) — Accepted.
- [ADR-0004: Reject per-entry physical-time tuples in the CRDT core](0004_reject_tuple_surgery.md) — Rejected.
- [ADR-0015: Pool the Join hot path's incoming buffer and per-block merge scratch](0015_join_unfreeze_pool.md) — Accepted.
- [ADR-0022: The zero-allocation Join sort step](0022_zero_alloc_join.md) — Accepted.
- [ADR-0028: SkipListArena.Seek — Window Lower-Bound Iterator](0028_skiplist_seek_window_lower_bound.md) — Accepted.
- [ADR-0051: A per-shard PointGet retires the production read-path OOM](0051_pointget_readpath_oom.md) — Accepted.
- [ADR-0052: Free resliced jemalloc buffers by usable size](0052_jemalloc_wrongsize_free.md) — Accepted.
- [ADR-0060: Size the scaling-gate pool for parked surplus](0060_pool_sizing_for_parked_surplus.md) — Accepted.
- [ADR-0074: Variable-size free-list ABA protection and v2 digest requests](0074_var_freelist_aba_and_v2_digest_requests.md) — Accepted.

## Durability, storage & recovery

- [ADR-0013: WAL write-through and recovery bootstrap](0013_durability_wal_recovery.md) — Accepted; the replay-seed contract is superseded by [ADR-0045](0045_mesh_transport_invariants.md).
- [ADR-0016: The LSM–Durability Seam — Bounded Recovery](0016_lsm_durability_seam.md) — Accepted; recovery mechanics are superseded by [ADR-0045](0045_mesh_transport_invariants.md), [ADR-0050](0050_checkpoint_decouple_delta.md), and [ADR-0053](0053_wal_snapshot_crc32c.md).
- [ADR-0018: Per-entity L0 split-merge](0018_per_entity_l0_split.md) — Accepted.
- [ADR-0019: L0 to L1 Per-Entity Compaction](0019_l0_l1_per_entity_compaction.md) — Accepted.
- [ADR-0020: Level-2 Superseded-Row Pruning](0020_level2_superseded_row_pruning.md) — Accepted.
- [ADR-0021: L0 Reaping and Recovery Timestamp Fixes](0021_l0_reaper.md) — Accepted.
- [ADR-0025: The DominancePrune interval sweep](0025_dominance_prune_interval_sweep.md) — Accepted.
- [ADR-0029: Filename-Bounded Download Skip](0029_filename_bounded_download_skip.md) — Accepted.
- [ADR-0030: Manifest-Channel Download Skip](0030_manifest_channel_download_skip.md) — Accepted.
- [ADR-0031: Streaming ParseManifest Without Per-Line Copies](0031_zero_alloc_streaming_parsemanifest.md) — Accepted.
- [ADR-0033: Remove the unused TOKI conflict resolver](0033_toki_closure_ghost_exorcism.md) — Accepted; the proposed TOKI integration is rejected.
- [ADR-0044: WAL group commit for the convergence objective](0044_wal_group_commit.md) — Accepted; the initial hardware run did not converge.
- [ADR-0048: Complete the WAL fsync lock-scope split](0048_wal_split_completion.md) — Accepted; [ADR-0049](0049_causation_checkpoint_flush.md) disproved the proposed cause of the stall.
- [ADR-0049: Checkpoint-flush causation in the multi-region mesh](0049_causation_checkpoint_flush.md) — Accepted.
- [ADR-0050: Decouple and delta-batch checkpoint flushes](0050_checkpoint_decouple_delta.md) — Accepted.
- [ADR-0053: WAL + snapshot CRC32C integrity that fails loud](0053_wal_snapshot_crc32c.md) — Accepted.

## Transport, security & post-quantum

- [ADR-0002: Route ingress by the plaintext origin node ID](0002_epoll_sockhash_reuseport_fanout.md) — Accepted.
- [ADR-0003: Kernel SO_REUSEPORT steering on Linux 6.18](0003_kernel_sk_reuseport_silicon.md) — Accepted, scoped to BPF socket steering.
- [ADR-0006: TLS 1.3 transport and node binary](0006_tls13_transport_default_tier.md) — Accepted.
- [ADR-0007: Real-socket mesh with signed-envelope gossip over TLS 1.3](0007_real_socket_mesh.md) — Accepted.
- [ADR-0035: Rotate TLS leaves and enforce CRL revocation](0035_pki_leaf_rotation_crl_revocation.md) — Accepted.
- [ADR-0036: Post-Quantum Transport and Hybrid Signature Verification](0036_post_quantum_transport_readiness.md) — Accepted.
- [ADR-0037: Hybrid Post-Quantum Batch Signing](0037_hybrid_pq_sign_wire.md) — Accepted.
- [ADR-0067: Ordered ingress and two-layer relay resolution](0067_ingress_admission_and_relay_resolution.md) — Accepted; the pre-apply clock advance is superseded by [ADR-0069](0069_trust_quintet.md).
- [ADR-0068: Gateway identity verification](0068_gateway_anchor_pinning.md) — Accepted; amended by [ADR-0069](0069_trust_quintet.md), [ADR-0070](0070_receive_path_admission_and_attribution.md), and [ADR-0072](0072_ebr_hoist_mesh_dial_and_digest_gating.md).
- [ADR-0069: Admission bounds for unauthenticated work](0069_trust_quintet.md) — Accepted; amended by [ADR-0070](0070_receive_path_admission_and_attribution.md).
- [ADR-0070: Receive-path admission and attribution](0070_receive_path_admission_and_attribution.md) — Accepted.

## Ingest, query & observability

- [ADR-0005: Close the epoll, real-NIC, benchmark, and receiver-wiring gaps](0005_close_four_movea_gaps.md) — Accepted with negative single-host performance.
- [ADR-0008: Prometheus metrics and ingest-latency histograms](0008_prometheus_metrics.md) — Accepted.
- [ADR-0010: Batched delta wire v1](0010_batched_delta_wire_v1.md) — Accepted; subset admission and acceptance accounting are amended by [ADR-0069](0069_trust_quintet.md).
- [ADR-0011: SDK and mutually authenticated control port](0011_sdk_control_port.md) — Accepted.
- [ADR-0012: Measure batched ingest on Graviton4](0012_silicon_1m_sector_bench.md) — Accepted.
- [ADR-0014: Ingest-path allocation hardening: value-return seam and zero-copy payload read](0014_ingest_alloc_hardening.md) — Accepted.
- [ADR-0017: The Query Resolver — the Read Half of the Durability Tier (/v1/query over Resolver.AsOf)](0017_query_resolver_read_half.md) — Accepted.
- [ADR-0023: Bridge internal telemetry to Prometheus](0023_otel_prometheus_bridge.md) — Accepted.
- [ADR-0024: Range reads over bitemporal history](0024_resolver_range.md) — Accepted.
- [ADR-0026: Arm `telemetry.Init` at boot; deduplicate and rebuild counters](0026_otel_init_dedup_query_list_capped.md) — Accepted.
- [ADR-0027: Infer the GC floor from the observed live-query frontier](0027_t_gc_auto_inference.md) — Accepted.
- [ADR-0032: Read your writes through a live HAMT source](0032_live_source_read_your_writes.md) — Accepted.
- [ADR-0057: Cross-entity secondary index design](0057_secondary_index_design.md) — Proposed; implemented by [ADR-0058](0058_secondary_index_production_wiring.md).
- [ADR-0058: Wire the cross-entity secondary index into production paths](0058_secondary_index_production_wiring.md) — Accepted.
- [ADR-0061: Parallelize the race-test suite and gate ingest throughput](0061_parallel_ci_and_ingest_benchmark_floor.md) — Accepted.

## Mesh, convergence & hardening

- [ADR-0009: Partition probe and convergence after healing](0009_chaos_partition_probe.md) — Accepted.
- [ADR-0034: Exchange full IBLT digests for stratified anti-entropy](0034_stratified_anti_entropy_mesh_wiring.md) — Accepted.
- [ADR-0038: Wire-Protocol Fuzz Harness](0038_wire_protocol_fuzz_harness.md) — Accepted.
- [ADR-0039: Region-Aware Gossip Data Plane](0039_region_aware_gossip_data_plane.md) — Accepted.
- [ADR-0040: OOB Peer-Directory Pubkey Provisioning](0040_oob_peer_directory_provisioning.md) — Accepted.
- [ADR-0041: 100-node, three-region convergence on real hardware](0041_100_node_silicon_convergence.md) — Accepted; the first hardware run did not meet the convergence target.
- [ADR-0045: Mesh transport correctness invariants](0045_mesh_transport_invariants.md) — Accepted.
- [ADR-0047: Quiescent close and monotone Lamport flushing](0047_close_quiesce.md) — Accepted.
- [ADR-0054: Merkle-root digest change gate](0054_digest_change_gate.md) — Accepted.
- [ADR-0055: Deterministic cross-process IBLT hashing](0055_deterministic_cross_process_iblt_hash.md) — Accepted.
- [ADR-0056: Digest receive-state eviction](0056_digest_receive_eviction.md) — Accepted.
- [ADR-0059: Bound mesh writes and suspect peers after write failures](0059_write_deadline_close_on_error_suspect_breaker.md) — Accepted.
- [ADR-0062: Reconciliation scale limits](0062_reconciliation_scale_limits.md) — Accepted.
- [ADR-0063: Partial intra-region view](0063_partial_intra_view.md) — Accepted.
- [ADR-0064: Bounded-bytes IBLT reconciliation](0064_iblt_reconciliation.md) — Accepted.
- [ADR-0065: Reconciliation scale-test design](0065_reconciliation_campaign_test_design.md) — Accepted.
- [ADR-0066: Sweep phase jitter](0066_sweep_phase_jitter.md) — Accepted.
- [ADR-0071: Bounded saturation crossover](0071_saturation_crossover.md) — Accepted; later exchange changes appear in [ADR-0072](0072_ebr_hoist_mesh_dial_and_digest_gating.md), [ADR-0073](0073_hierarchical_gateway_topology_and_boot_dial.md), and [ADR-0074](0074_var_freelist_aba_and_v2_digest_requests.md).
- [ADR-0072: EBR hazard-snapshot hoist, mesh dialing, and digest gating](0072_ebr_hoist_mesh_dial_and_digest_gating.md) — Accepted.
- [ADR-0073: Hierarchical gateway topology and boot dialing](0073_hierarchical_gateway_topology_and_boot_dial.md) — Accepted; the remaining allocator and request-leg hazards are resolved by [ADR-0074](0074_var_freelist_aba_and_v2_digest_requests.md).

## Numbering gap

ADR-0042 (`MerkleRootFromShards`), ADR-0043 (durable configuration), and ADR-0046 (seed
cold-cache handling) are referenced in code and other documents, but those ADRs were never
written. There are no index entries for them.

---

These records are append-only. A later ADR supersedes or amends an earlier decision without
erasing the reasoning that led to it.
