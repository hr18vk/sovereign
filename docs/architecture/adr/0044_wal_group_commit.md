# ADR-0044: WAL group commit for the convergence objective

- **Status:** Accepted. Group commit reduced injection time, but the 2026-08-15 hardware run still did not converge. Later transport and checkpoint decisions completed the diagnosis.
- **Date:** 2026-08-15; the replay amendment is dated 2026-08-31
- **Scope:** `internal/chaos/wal.go`, `pkg/durability/bridge.go`, `pkg/mesh/gossip.go`, `pkg/mesh/control.go`, and `cmd/convergence-gate`

## Context

The preceding three-machine c7gd.8xlarge run placed the WAL and LSM on NVMe and enabled durable writes on every node. Boot liveness took 0.62 seconds and region isolation worked, but a 10,000-key injection took 272.89 seconds against a 10-second convergence objective.

The gate divided the write into 10 batches of 1,000. Each `/v1/batch-insert` handler called `InsertLocalEvents` for every entry, which reached `PutLocal` and `AppendMutation` per entry and forced one fsync per entry: 1,000 fsyncs per batch and 10,000 overall. At the measured NVMe cost of about 2.1 ms per fsync, the barriers alone accounted for about 21 seconds. The 272.89-second figure was total injection wall time, not a measurement of fsync alone. Inter-region envelope counts in that run were `us=2344`, `eu=7156`, and `ap=6858`.

The binding cost inside the WAL was therefore the number of durability barriers, not a change in the cost of each barrier.

## Decision

### Append a batch with one fsync

`WAL.AppendMutations` writes all mutation records under one `w.mu` critical section and issues one fsync for the batch. A 1,000-entry batch changes from 1,000 fsyncs to one; sending the gate's 10,000 keys as one batch instead of 10 batches changes the complete injection from 10,000 fsyncs to one.

At the time of this decision, each record used the existing `encodeMutationRecord`, 13-byte sequence/type/length header, and `WALRecMutation` type. Replay encountered the same sequence of individual mutation records as it did after repeated `AppendMutation` calls. [ADR-0045](0045_mesh_transport_invariants.md) later replaced scalar-counter re-minting with restoration of each recorded `(DotNodeID, DotCounter)` and selection of the recovery tail by WAL sequence. Group commit remains compatible with that rule: record and byte order are fixed under the mutex, while fsync order is not a recovery ordering primitive.

The original change routed single-record fsyncs through `sync()` and added a test-only `syncHook`, installed by `SetSyncHookForTest` and nil in production. [ADR-0048](0048_wal_split_completion.md) subsequently completed the captured-file `syncFile(f)` lock-scope split on every append path. [ADR-0053](0053_wal_snapshot_crc32c.md) later made CRC32C-framed type `0x06` records the default; the historical 13-byte outer header remains, but the record payload and replay rules described above are not the current complete format.

### Carry batch semantics through the write path

`Bridge.PutLocals` performs `InsertLocal` for each item, builds each WAL mutation from the dot returned by that insert, and then calls `AppendMutations` once. The checkpoint mutation count advances by `len(items)`, not by one. The current bridge also feeds the secondary index synchronously after each insert and schedules periodic checkpoint flushing in the background under [ADR-0050](0050_checkpoint_decouple_delta.md); neither changes the one-fsync batch contract.

`Gossiper.InsertLocalEventsBatch` uses `Bridge.PutLocals` when durability is configured and the existing per-item in-memory path when `--wal-path=""` selects the non-durable research mode. Payloads enter the gossip cache only after a successful WAL append. `handleBatchInsert` applies the single-insert temporal defaults and validation to each entry, assigning HTTP 400 to invalid entries before the batch call. Valid entries receive HTTP 200 and their dots on success; any write or sync failure assigns HTTP 503 to every valid entry. `/v1/insert` retains its single-entry behavior.

The gate changed `batchSize` from the constant 1,000 to `*numKeys`, making one request for a 10,000-key run and a one-item request for `-keys 1`. The estimated fsync contribution fell from about 21 seconds to one approximately 2.1 ms barrier, plus HTTP/TLS and processing costs. A measured WAN round trip was ~50-150ms; the estimate was not presented as the measured total injection time.

### Make acknowledgment batch-wide

Before this change, a failed entry could receive HTTP 503 while other entries in its request received HTTP 200. Group commit cannot establish durability for a subset after a failed batch sync. Entries before a write failure may remain only in the OS page cache, and entries after it were never written. `PutLocals` therefore returns an error for the batch, and the handler returns 503 for every valid entry. The response is not sent until `PutLocals` returns; an unacknowledged batch can be retried as a unit. This is an all-or-none acknowledgment contract, not a rollback of bytes already written.

The existing `TestBatchInsertWALFailPerEntry` remained valid because it posts separate homogeneous batches: one successful one-entry request, then a failed two-entry request. It does not distinguish per-entry from per-batch failure within a mixed batch. The group-commit acknowledgment test added that distinction with five valid entries and one injected sync failure: all five receive 503 and sync is called once.

The current regression tests are `TestMeshGroupCommitCount`, `TestMeshGroupCommitAck`, and `TestMeshGroupCommitDeterminism` in `pkg/mesh/mesh_group_commit_test.go`:

- The count test measures one fsync for `AppendMutations` with 1,000 entries against 1,000 fsyncs for repeated `AppendMutation` calls.
- The acknowledgment test checks the five-entry failure case above.
- The determinism test replays a 64-entry batch and compares the recovered and live Merkle roots. Reversing the physical order so dots are minted before insertion makes that check fail. `TestWALRecoveryDeterminism` covers the single-append counterpart.

### Count durable configurations by file

The durability check originally used `grep -c` over all node logs. With multiple files, that prints one count per file rather than one fleet-wide integer. The subsequent integer comparison failed on the multiline value, its error was discarded, and the check could still report success with 95 nodes durable and 5 in memory.

The replacement uses `grep -l ... | wc -l`, which counts files containing the durable-configuration line. A simulated two-of-three partial configuration produced one multiline value under the old command and the integer 2 under the new one, allowing the expected mismatch to fail the check. On the hardware run, this check counted 100 of 100 nodes with durability enabled.

## Consequences

- Batch inserts use one WAL fsync and batch-wide acknowledgment; single inserts keep their existing per-entry semantics.
- A sync failure does not prove that already-written prefix records survived a crash. Clients must retry the whole failed batch rather than treating a prefix as durable.
- The test hook is not a production configuration path. Production calls the real file sync.
- Exact-dot replay in [ADR-0045](0045_mesh_transport_invariants.md) supersedes the original scalar-counter replay contract, not group commit itself.
- The unlocked-fsync completion in [ADR-0048](0048_wal_split_completion.md), asynchronous checkpointing in [ADR-0050](0050_checkpoint_decouple_delta.md), and CRC32C framing in [ADR-0053](0053_wal_snapshot_crc32c.md) are later changes. Statements in the original record about byte-identical single-append code or unframed records are historical, not descriptions of the current implementation.
- The 2026-08-15 non-convergence observation did not by itself prove one receive-side root cause. [ADR-0045](0045_mesh_transport_invariants.md) records the connection-symmetry and foreign-payload relay fixes, while [ADR-0049](0049_causation_checkpoint_flush.md) identifies the independent checkpoint-flush stall.

## Evidence

### Loopback and 2026-08-15 hardware run

The group-commit tests passed under `-race`, as did the relevant `pkg/mesh`, `pkg/durability`, and `internal/chaos` regression runs. At the time, vet also reported three pre-existing warnings in `internal/chaos/probe.go`; this change did not touch that file.

The hardware run used 100 node processes in a 34/33/33 split on three c7gd.8xlarge machines in us-east-1, eu-west-1, and ap-southeast-2, with WAL and LSM files on instance-store NVMe:

- All 100 nodes passed mTLS `/livecheck` in 0.62 seconds.
- Injection fell from 272.89 seconds to 21.87 seconds, a 12.5-times reduction. The loopback profile measured `AppendMutations` with 10,000 entries at 0.58 µs per key and the complete `PutLocals` call at 28.2 ms. The remaining hardware injection time included HTTP/TLS and 100-process contention; it was not attributed to fsync alone.
- Durability was enabled in 100 of 100 node configurations. The seed WAL contained 1,348,951 bytes, and all three regions used `/dev/nvme1n1` rather than the EBS root filesystem.
- The seed held the 10,000 keys while the other 99 nodes retained zero roots throughout the 10-second convergence window and a further 30-second healing window. The latter covered 95 polls at roughly 0.5-second intervals. A cross-region query for `convergence-key-0` from nodes `34..66` returned HTTP 404; propagation also failed to the other 33 nodes in the seed's region.
- Region isolation produced different roots during the partition. Healing did not re-converge the mesh within 30 seconds; the recorded elapsed value was 40,930ms.
- `supremum_mesh_inter_region_envelopes` read `476/914/614` in us-east-1/eu-west-1/ap-southeast-2 order, increasing to `530/2516/2216` after healing. Envelopes were crossing regions, but envelope counts alone could not identify why state did not converge.
- All three instances were terminated after the run.

The convergence clock for this run started after injection. That distinguishes the 21.87-second injection measurement from the convergence objective and prevents the earlier serial-injection bottleneck from being counted as gossip time.

The non-zero envelope counts and zero peer roots motivated investigation of payload reconstruction, verification keys, Merkle sharding, and large-delta joins. They did not prove that any one of those hypotheses was the sole cause. The later transport and checkpoint records linked above provide the resolutions without retrofitting them into this run's evidence.

### Later convergence evidence

[ADR-0050](0050_checkpoint_decouple_delta.md) records seven consecutive runs after checkpoint decoupling: six passed and one missed the 10-second target. Its published [100-node convergence receipt](../../evidence/convergence-100-node.txt) is a separate run on 2026-09-13 using 100 processes on three c7gd.8xlarge machines with production checkpointing and integrity checks enabled. All 100 roots matched 8.950 seconds after origin quiescence; end-to-end time including injection was 12.139 seconds. This later result meets the target under its stated conditions, while the tail miss remains part of the record.

