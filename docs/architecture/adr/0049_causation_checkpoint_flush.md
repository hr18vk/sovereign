# ADR-0049: Checkpoint-flush causation in the multi-region mesh

**Status:** Accepted  
**Date:** 2026-09-07

## Context

In a run of 100 node processes on three machines in three AWS regions, the seed's
`commit_in_flight` stayed at 1 for more than 300 s. The origin-quiescence probe therefore never
fired, and the convergence run was invalid. ADR-0048 had fixed one candidate mechanism: the WAL
reverse-convoy in which `AppendClockAdvance`, `AppendMutation`, and `AppendCheckpoint` held `w.mu`
across fsync and starved the origin's `AppendMutations`.

A local reproduction could not distinguish that convoy from NVMe contention as the cause of the
300 s stall. The distinction required a stack capture from the running seed. The 2026-09-04 run
could provide only a destructive `kill -QUIT` dump, so it could not capture the stall and let the
run continue.

## Decision

Attribute the stall to synchronous checkpoint I/O only if the running seed's stack shows that path,
and compare the result against configurations with the WAL convoy restored, lower storage density,
and periodic checkpoints disabled. Add a non-destructive pprof listener so the experiment can
capture stacks without terminating the node.

Do not treat the ADR-0048 WAL change as the cause of the convergence improvement, and do not claim
that the convergence objective is met at the normal checkpoint configuration.

## Consequences

The synchronous checkpoint flush is the established cause of this stall. The ADR-0048 WAL change
remains valid on its own, but restoring the old convoy changed quiescence by only 0.14 s. At the
normal checkpoint configuration there were still no clean runs toward the three-consecutive-pass
objective. Disabling checkpoints was a diagnostic arm, not an acceptable configuration, because it
leaves replay unbounded.

ADR-0050 subsequently moved the checkpoint flush off the commit path and delta-batched the query
tier. The stack and counts below describe the earlier synchronous path.

## Evidence

### Loopback profiling

`startPprof` serves `/debug/pprof/{,goroutine,mutex,block}` on a dedicated `http.Server`, separate
from the `0.0.0.0` metrics mux used for cross-host scrapes. `pprofBindAddr` discards any configured
non-loopback host, binds `127.0.0.1`, and defaults to `metrics-port+1000`, which avoids collisions
at 34 nodes per host.

Mutex and block collection are disabled by default because of their runtime cost. `--diag-profile`
or `SOVEREIGN_DIAG_PROFILE=1` enables them; goroutine capture needs no toggle.

The pprof tests verify a loopback capture with HTTP 200 and a non-empty dump containing a known frame,
and a surviving process. A dead-port case checks that capture failures are visible, and seven
address cases check loopback binding. Stack matching uses library frames because the deployed
binary names the server frame `main.startPprof`, while a test binary qualifies it with the package
import path.

### Multi-region A/B

The experiment ran 100 node processes on three c7gd.8xlarge machines (Graviton3E with
instance-store NVMe), one per AWS region, with integrity verification enabled. The pprof watcher
captured the seed's goroutine, mutex, and block profiles every 8 s throughout the gate window.

| Configuration | Injection | Quiescence | Convergence | Result | Crash recovery |
|---|---|---|---|---|---|
| WAL fix, 34/host | 30.10 s, 1 hard timeout | 300.19 s (cap) | 3.691 s | Not quiesced | Passed |
| WAL convoy restored, 34/host | 30.10 s, 1 hard timeout | 300.05 s (cap) | 4.900 s | Not quiesced | Passed |
| WAL fix, 8/host (24 nodes) | 30.10 s, 1 hard timeout | 259.78 s | 0.228 s | Injection failed | Passed |
| WAL fix, 34/host, `ckpt=0` | 0.11 s, 0 timeouts | 3.14 s | 8.323 s | Passed | Full replay passed |

### Commit-path stack

Across approximately 38 captures at 34/host and 33 at 8/host, the seed's origin commit goroutine
was parked in this path:

```
os.(*File).Sync ← LocalFS.Upload ← L0Flusher.UploadPartition
  ← L0Flusher.FlushArenaToIPC ← MemTable.Flush ← SnapshotToLSM ← AppendCheckpoint
  ← drainCheckpoints ← designateCheckpoint ← noteMutations ← PutLocals ← handleBatchInsert
```

No capture in any arm, including the arm with the WAL convoy restored, contained
`sync.(*Mutex).Lock` or `SemacquireMutex` under `internal/chaos.(*WAL).AppendMutations`.
`AppendMutations` completed before the observed park. The mutex profile likewise confined WAL
`w.mu` contention to the short critical sections left by ADR-0048; the dominant stack was the
checkpoint flush.

The periodic checkpoint ran synchronously in the origin's commit path through inline
`drainCheckpoints`. Its L0 flush emitted one fsync'd Arrow file per entity. For 10,000 keys at
interval 1000 there were ten checkpoints and 1,000+2,000+…+10,000 = 55,000 files on the commit path.
Each file upload synchronized both the file and its parent directory. The cumulative I/O count,
not WAL mutex acquisition, explains the stall.

### Causation findings

The stack and the configuration arms support three conclusions:

- The WAL reverse-convoy did not cause this stall. Restoring it changed quiescence from 300.19 to
  300.05 s, a difference of 0.14 s. The earlier choice between `w.mu.Lock` and `syncFile` missed
  the actual third site: checkpoint LSM-image fsync.
- Storage density did not explain it. Reducing placement to 8/host gave 24 nodes, no CPU
  oversubscription, and four times less NVMe contention, yet quiescence still took 259.78 s.
- `--wal-checkpoint-interval=0` removed the synchronous flush. The 100-node configuration moved
  from not quiescing within 300 s to quiescence in 3.14 s and convergence in 8.323 s, with crash
  recovery passing under integrity verification.
