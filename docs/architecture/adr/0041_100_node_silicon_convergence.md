# ADR-0041: 100-node, three-region convergence on real hardware

- **Status:** Accepted. The loopback changes were implemented; the first hardware run did not meet the convergence target. Later resolutions are recorded below.
- **Date:** 2026-08-13; harness corrections followed on 2026-08-14
- **Scope:** 100 node processes across three AWS regions, a 10,000-key delta, a convergence target below 10 seconds, and partition healing within five rounds

## Context

[ADR-0039](0039_region_aware_gossip_data_plane.md) added region-aware peer selection: a full mesh within a region and bounded fan-out between regions. [ADR-0040](0040_oob_peer_directory_provisioning.md) supplied peer identities out of band. This decision tested those mechanisms with 100 node processes on three machines, one in each region, rather than treating an in-process round count as a wide-area measurement.

The acceptance criteria were convergence of a 10,000-key delta in less than 10 seconds and, separately, isolation of an inter-region divergence followed by convergence within five rounds after healing. The work had an in-process tier and a hardware tier:

- The loopback tier drove 100 `DeltaCRDTEngine` instances through `VirtualNet` using the real `TopologyManager.Select` fan-out-3 selector on a 4-core machine. It checked convergence logic, round counts, partition isolation, and healing.
- The hardware tier ran 100 processes in a 34/33/33 split on three c8g.8xlarge instances. The initial launch plan named us-east-1, eu-west-1, and ap-southeast-1; the executed run used ap-southeast-2. It measured mTLS boot, convergence time, partition behavior, and inter-region traffic.

## Decision

### Bound IBLT allocation by heap size

`UnmarshalIBLT` rejects a bucket count above `maxIBLTBuckets = maxFrameSizeBytes / unsafe.Sizeof(Bucket{})` with `ErrIBLTTooLarge` before `NewIBLTWithSeed` can allocate the bucket slice.

The denominator is the 24-byte in-memory `Bucket`, not the 20-byte wire bucket. The resulting limit is 699,050 buckets. A wire-size denominator would permit 838,860; in particular, 838,859 buckets occupy 16,777,180 wire bytes before the header, within the 16 MiB frame cap, but require 20,131,616 heap bytes, about 19.2 MiB and 1.2 times the wire payload. The heap-size bound rejects that input. The 16 MiB limit is expressed locally as `16 << 20` to avoid adding another package dependency to the receive/sync import graph. Deriving the bound with `unsafe.Sizeof` keeps it tied to the allocation layout.

Tests accepted 0 buckets, the 80-bucket strata digest, and 699,050 buckets; they rejected `n=699051`, `n=838859`, and `n=0xFFFFFFFF`. The current decoder also rejects a negative `int` produced by a 32-bit `uint32` conversion before either allocation or size multiplication. That closes the negative-count path in `UnmarshalIBLT`; it is not a blanket claim about other decoders.

### Use an external, per-entry loopback harness

The loopback suite uses package `mesh_test`. An internal `chaos` test importing `pkg/mesh` would close the existing `pkg/mesh → pkg/durability → internal/chaos` import cycle. The external package can import both the real mesh topology and the exported chaos orchestrator without a cycle, following the pattern in `pkg/transport/fanout_test.go`. It owns the engine map and keeps a local reference rather than depending on the orchestrator's unexported field.

The in-process receiver's `decodeDeltagram` consumes only the first entity and entry in a message. The harness therefore emits one deltagram per delta entry instead of one buffer containing the whole delta. Without that shape, repeated sends would keep delivering the first entry. The earlier 32-node, 64-event suite could converge through repeated full-mesh rounds; a 1,000-key delta exposed the difference.

### Keep loopback memory tiers separate from the hardware target

The original loopback oracle called `State().MerkleRoot()`. Each `State()` constructed a merged HAMT view; for a 10,000-key live set this was about 20 MiB per engine. Reclamation advanced on `Join` and `InsertLocal` every 64 operations, not on `State()`. A probe with interleaved `Join` and `State()` survived 1,000 keys with a 24 MiB arena; 64 MiB provided 2.6 times that observed footprint. One hundred 10,000-key engines implied about 2.4 GiB of live arena before the repeated merged views, beyond the 4-core machine's resident budget.

The suite therefore used three configurations:

- `TestLoopbackConverges100`: 100 nodes with 1,000 keys each, 64 MiB arenas, and a limit of 10 rounds.
- `TestLoopbackConverges10K`: 8 nodes with 10,000 keys each, 256 MiB arenas, normally converging in 1–2 rounds. The arenas reserved 2 GiB in total.
- `TestLoopbackPartition*`: 100 nodes with 1,000 keys each to test isolation and healing, not throughput.

`buildEngines` takes the arena size as a parameter through `convArenaSize` and `join10KArenaSize`. `buildTopologies` uses `regionFor` for the 34/33/33 split and `balancedRegionFor` to distribute the eight-node case across regions as `{1,2,3,1,2,3,1,2}`; otherwise all eight would land in one full-mesh region and skip inter-region fan-out.

The tiering was a loopback harness constraint, not a hardware convergence result. [ADR-0051](0051_pointget_readpath_oom.md) later established the more precise defect: `State()` retains path-copied arena nodes and can leak monotonically. Production point reads now use `PointGet`; `/v1/merkle`, convergence stamping, and the orchestrator's `MerkleRoots` use `MerkleRootFromShards` without constructing a merged view. `State()` remains for tests and probes. The earlier explanation based only on EBR delay was therefore incomplete.

### Measure wide-area behavior on separate processes

The hardware harness looked up AMIs and created key pairs and security groups separately in each region. It terminated resources created by a failed launch rather than continuing with an asymmetric fleet. `MeshCA.IssueLeafWithIP` added host addresses to the leaf's IP subject alternative names because `splitHostPort` in `pkg/mesh/peer.go` uses the dial address host as the TLS server name. A localhost-only DNS name did not verify a dial to `127.0.0.1` or a host IP.

An `iptables` drop rule implemented the partition instead of revoking a security-group rule shared by 33 processes, avoiding security-group propagation delay in the measurement. Healing removed the rule. The convergence poll read `supremum_convergence_roots_equal`; round counts came from `supremum_gossip_rounds_total`; `supremum_mesh_inter_region_envelopes` showed inter-region traffic. The partition clock began with the first gossip round after datapath restoration, not when the heal command returned.

Loopback rounds and hardware wall time answer different questions. The 100-node and eight-node loopback cases took three and two rounds respectively with no WAN delay; hardware runs included approximately 50-150ms inter-region round trips. On hardware, each process evaluated its own root once per sweep rather than one process constructing 100 merged views for each oracle loop. Neither measurement can be substituted for the other. The decision left the merge-law and wire-schema files byte-identical and did not reorder struct layouts.

## Consequences

- `UnmarshalIBLT` now rejects counts above 699,050 and negative counts before allocation. The crafted digest with `n=838859` fails decoding instead of requesting about 19.2 MiB of bucket storage.
- The batch-insert gap identified by the first hardware run was addressed by [ADR-0044](0044_wal_group_commit.md). Transport and relay correctness were subsequently addressed by [ADR-0045](0045_mesh_transport_invariants.md).
- The untracked VirtualNet mailbox goroutine described by the original record was later fixed as part of [ADR-0047](0047_close_quiesce.md): `AddNode` adds each mailbox goroutine to `vn.wg`, prioritizes the stop signal, and `Stop` waits for those goroutines before engine teardown.
- [ADR-0049](0049_causation_checkpoint_flush.md) identified the long origin commit stall as synchronous checkpoint flushing, and [ADR-0050](0050_checkpoint_decouple_delta.md) moved that work off the commit path. Those results supersede this record's open convergence status; they do not turn its failed run into a pass.
- The Raft metadata plane remained outside this data-plane decision. The inter-region envelope counter was observed rather than added, so this change did not alter the telemetry registry's distinct-counter count.

## Evidence

### Loopback results

The suite built and the touched packages passed formatting and vet checks. On the 4-core machine, `TestLoopbackConverges100` first converged under `-race` in one round at 255.37 seconds and then crashed in `HAMT.hashKey` during race-detector teardown. A second run converged and exited cleanly at 215.21 seconds with no reported data race. The codec and two IBLT-bound tests completed together under `-race` in 1.033 seconds. The untracked mailbox goroutine explained the teardown crash and was later fixed as described above.

The complete race-instrumented suite could not fit on that machine. The negative control, round-count, and partition-isolation tests each pump up to `convRoundCap=10` rounds. The test binary reserved about 12.6 GiB of virtual address space; the host had 15 GiB RAM, no swap, and about 3–5 GiB available with the editor running. Resident memory reached about 3.8 GiB before the kernel killed the test. The kernel report gave `total-vm:12573656kB`. The clean 100-engine race shard, the three light race tests, and inspection of the mutex-protected `AddNode` state supplied race coverage without treating the out-of-memory kill as a convergence failure.

The non-race suite completed in 45.5 seconds before the harness corrections and 44.9 seconds afterward. The current file contains nine `TestLoopback*` tests.

The functional results were:

- `TestLoopbackConverges100`: all 100 nodes reached root `d48334a99481d2c952272a06dc0e3c061de94acf2c3446e855732e384284c9f4` after 3 rounds, with a non-empty root and the last key present on the last node.
- `TestLoopbackConverges100NegativeControl`: the black-holed mesh did not converge after 10 rounds and node 99 remained empty, showing that the oracle could detect divergence.
- `TestLoopbackConverges10K`: all 8 nodes accepted the 10,000-key delta and reached root `e2c557ccfa0de53b0f7e3649781792d87c3b378a6504932d7bf5dee0005b76e5` after 2 rounds.
- `TestLoopbackRoundCount`: fan-out-3 converged in 3 rounds against a 6-round limit, using 35 peer edges per round instead of 9,900 full-mesh edges and 2,000 inter-region edges per round.
- `TestLoopbackPartitionIsolates`: region 1 stayed isolated from regions 2 and 3; removing the partition in the negative control allowed the divergence to propagate.
- `TestLoopbackPartitionHeals5Rounds`: convergence resumed within 5 rounds after `SetPartitions(nil)`.
- `TestLoopbackDeltagramCodecRoundTrip`: the per-entry wire representation round-tripped correctly.
- `TestLoopbackIBLTBound`: 0 and 80 buckets were accepted; 838,859 and `0xFFFFFFFF` were rejected with `ErrIBLTTooLarge`.
- `TestLoopbackIBLTBoundLockstep`: 699,050 buckets were accepted and 699,051 rejected, pinning the 24-byte heap denominator rather than the 20-byte wire size.

The three- and two-round results establish loopback behavior only. They include no WAN round-trip time and do not establish the 100-process, 10,000-key wall-time target.

### Hardware run on 2026-08-13

The executed fleet used three c8g.8xlarge instances in us-east-1, eu-west-1, and ap-southeast-2. `cmd/mesh-bootstrap` created the CA, 100 IP-SAN leaves, peer directories, seeds, and `peers.txt`; `cmd/convergence-gate` used mTLS for inserts, Merkle polls, and liveness checks. The metrics endpoint used plain HTTP.

All 100 nodes answered `/livecheck` over mTLS in 0.63 seconds across the three regions. The inter-region envelope counter read 1,098 in eu-west-1 and 724 in ap-southeast-2; us-east-1 was 0 at boot and increased afterward. A seed log reported a payload miss for `convergence-key-385` followed by oversend recovery on a later sweep. That showed deltas entering the gossip path, not convergence of the fleet.

The convergence target was not met, for two independent reasons:

1. The gate sent 10,000 serial `/v1/insert` requests over the WAN, each paying roughly 50-150ms to the remote regions. A 1,000-key attempt took 54.7 seconds with a 4,096 MiB arena. The clock began at the first insert, so injection alone exceeded the 10-second budget and prevented a clean measurement of gossip convergence. The single-entry endpoint was a harness limitation later addressed by group commit.
2. `/v1/merkle` and `stampConvergence` both used `State()` at the time. With 100 nodes and 10,000 keys each, merged HAMT views intermittently exhausted the arena. Increasing `--arena-mib` from 64 to 1,024 and then 4,096 reduced the failure rate: node 0 survived the 1500-key load at 4,096 MiB, with 23 GiB touched of 61 GiB host memory, but 2 of 100 nodes still exhausted their arenas during sustained polling. The later `MerkleRootFromShards` and `PointGet` changes removed these production uses of merged state.

The partition test was not run because the mesh had not converged first. Partitioning an already divergent fleet would not answer the acceptance question. The three instances were terminated after the run.

This run established a 100-process, three-region mTLS boot and live inter-region traffic. It did not establish convergence within 10 seconds, and its loopback round counts cannot fill that gap.

### Harness corrections and later result

The 2026-08-14 follow-up corrected the hardware harness without re-running the fleet:

- Security groups opened the complete per-node ranges for `NODES_PER_HOST=34`: mesh ports 7373 through 7406, control ports 8443 through 8476, and metrics ports 9100 through 9133. SSH used port `22`. The initial single-port configuration was `22/7373/9100`, omitting control port `8443` and the per-node ranges.
- The orchestrator captured `PIPESTATUS[0]` around the gate pipeline so a non-converged exit 1 did not abort result recording and a shell workaround did not reset the status to 0. It also supplied a default work directory and aligned examples on ap-southeast-2.
- The convergence clock began after injection. An empty-seed-root and `injectFail < numKeys` check prevented a failed injection from looking successful. Cross-region queries skipped the seed's own region, and `tx_time` used `now+1h` so `AsOf` admitted recent writes despite clock skew.
- Node indices came from the manifest's `idx` field, metric requests had a 10-second timeout, and every gate call received `-metrics-port-base`.
- The partition step verified that each `iptables` rule was installed instead of accepting a zero rule count, and an `EXIT` trap flushed rules on failures as well as normal completion. The `-merkle-only` check compared roots during isolation. Certificate output names were corrected to `cert.pem` and `key.pem`.

Build, formatting, vet, script syntax, and the nine non-race loopback tests passed after these corrections; the loopback time was 44.9 seconds as recorded above. These were harness checks, not a substitute for another hardware run.

[ADR-0050](0050_checkpoint_decouple_delta.md) and its published [100-node convergence receipt](../../evidence/convergence-100-node.txt) provide the later result. On 2026-09-13, 100 processes on three c7gd.8xlarge machines with production checkpointing and integrity checks enabled reached identical roots 8.950 seconds after origin quiescence. End-to-end time including injection was 12.139 seconds. This is a different run with a different clock start and does not alter the 2026-08-13 outcome.

