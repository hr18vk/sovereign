# ADR-0049: Checkpoint-flush causation at silicon (the synchronous checkpoint flush, not the WAL convoy)

- **Status:** ACCEPTED (causation RESOLVED; the convergence SLO stays OPEN pending the checkpoint-flush fix)
- **Date:** 2026-09-07
- **Frozen files:** NONE touched — all five core merge-law/wire-schema files are unchanged (crdt.go, crdt_apply.go, envelope.go, schema.capnp, schema.capnp.go)

## 1. Context — the open causation question

The release-gate convergence SLO was blocked: at 100-node 3-region silicon the seed's
`commit_in_flight` pinned at 1 for >300 s, so the origin-quiescence probe never fired and the
convergence SLO was INVALID. ADR-0048 fixed the *candidate* mechanism — the WAL
reverse-convoy (`AppendClockAdvance`/`AppendMutation`/`AppendCheckpoint` held `w.mu` across their
fsync, starving the origin's `AppendMutations`). But the 300 s **causation** (convoy-dominant vs
NVMe-density) was not decidable from a benchtop repro; it had to be settled at silicon,
**and only if the wedged seed's park site was observable.** The 2026-09-04 run was a 300 s black
box because the node's only stack dump was `kill -QUIT` (destructive — no capture-then-continue).

## 2. The observability fix (the instrument)

I added a **non-destructive loopback-only pprof endpoint** to the node so a wedged seed can
be stack-captured *while the run continues*:

- `startPprof` serves `/debug/pprof/{,goroutine,mutex,block}` on a **dedicated loopback-ONLY
  listener**, a separate `http.Server` from the `0.0.0.0` metrics mux (whose bind is load-bearing
  for the cross-host `/metrics` scrape and is left untouched).
- `pprofBindAddr` **structurally** forces `127.0.0.1` (a non-loopback `--pprof-addr` host is dropped,
  not honored) and defaults the port to `metrics-port+1000` (collision-free at 34 nodes/host).
- `--diag-profile` / `SOVEREIGN_DIAG_PROFILE=1` arms the expensive mutex+block collection,
  **default OFF** (hot-path cost). The goroutine endpoint needs no toggle.

Tests (bug-injection-proven, `-race` green): a real loopback capture returns 200 + a non-empty dump
with a known frame + the process survives; a dead port fails (the anti-tautology control); the
bind-addr is loopback for all 7 cases. **One caveat the tests surfaced:** the dump qualifies frames
by full import path, so the deployed binary shows `main.startPprof` while the test binary shows
`…/cmd/sovereign-node.startPprof`; the discriminator frames are library packages and match in both.

## 3. The silicon A/B — the verdict matrix

100 nodes, 3× c7gd.8xlarge (Graviton3E + instance-store NVMe), the integrity oracle armed, the
pprof watcher capturing the seed's goroutine+mutex+block every 8 s for the whole gate window.
Four arms:

| Arm | Inject | Quiesce wall | Convergence | Verdict | Crash leg |
|---|---|---|---|---|---|
| **fix, 34/host** | 30.10 s, 1 hard-timeout | **300.19 s (cap)** | 3.691 s | NOT-QUIESCED | PASS (oracle) |
| **no-fix, 34/host** (WAL convoy restored) | 30.10 s, 1 hard-timeout | **300.05 s (cap)** | 4.900 s | NOT-QUIESCED | PASS (oracle) |
| **fix, 8/host** (24 nodes) | 30.10 s, 1 hard-timeout | **259.78 s** | 0.228 s | INJECT-HARD-FAIL | PASS (oracle) |
| **fix, 34/host, ckpt=0** (no periodic ckpt) | **0.11 s, 0 timeouts** | **3.14 s** | **8.323 s** | **PASS (SLO MET)** | PASS (full-replay, oracle) |

## 4. The evidence — where the seed is actually parked

Across ~38 (34/host) + ~33 (8/host) captures, the seed's origin commit goroutine is parked at:

```
os.(*File).Sync  ← LocalFS.Upload (localfs.go:150)  ← L0Flusher.UploadPartition
  ← L0Flusher.FlushArenaToIPC ← MemTable.Flush ← SnapshotToLSM ← AppendCheckpoint
  ← drainCheckpoints (bridge.go:575) ← designateCheckpoint (bridge.go:553)
  ← noteMutations (bridge.go:529) ← PutLocals (bridge.go:381)  ← handleBatchInsert
```

`sync.(*Mutex).Lock`/`SemacquireMutex` under `internal/chaos.(*WAL).AppendMutations`: **0 occurrences
in every capture of every arm, including the no-fix arm with the convoy deliberately restored.**
The WAL commit (`AppendMutations`, bridge.go:370) *completes*; the park is *after* it, in the
checkpoint flush. The mutex profile corroborates: WAL `w.mu` contention is confined to the short
critical sections left by the ADR-0048 fix (fsync already outside the lock); the dominant
contention stack is the checkpoint flush.

**The mechanism, atoms-up:** the periodic checkpoint runs *synchronously* in the origin's commit
path (the inline `drainCheckpoints`), and the L0 flush emits **one fsync'd Arrow file per entity**.
10,000 keys at interval 1000 ⇒ 10 checkpoints ⇒ 1,000+2,000+…+10,000 = **55,000 synchronous fsyncs**
blocking commits. That count (not per-fsync latency, not a mutex) is the stall.

## 5. Decision (the causation verdict, framed exactly as the evidence supports)

**The stall is caused by the synchronous per-entity-fsync checkpoint flush in the origin commit path.**

- **NOT the WAL reverse-convoy.** The ADR-0048 fix is correct durability hygiene but *orthogonal*
  to this stall — the WAL append is never the park site, and removing+restoring the convoy moved
  the quiesce wall by 0.14 s (300.19 → 300.05). The original `w.mu.Lock`-vs-`syncFile` binary
  hypothesis is superseded: the park is a *third* site the binary did not model (the checkpoint
  LSM-image fsync).
- **NOT NVMe density.** 8/host (no CPU oversubscription, 4× less NVMe contention) still stalls at
  259.78 s. The fsync *count* is set by the per-entity-flush design, not by contention.
- **Proven by causation, the strongest form:** `--wal-checkpoint-interval=0` removes the synchronous
  flush and the 100-node gate goes from NOT-QUIESCED (300 s) to a clean PASS (3.14 s quiesce,
  8.323 s convergence — **the SLO is achievable**), crash leg PASS with the integrity oracle armed.

**The convergence SLO is NOT met at production config** (checkpoints on): the clean-run count against
the 3-consecutive-pass bar is still ZERO. The SLO re-opens only after the checkpoint flush is fixed,
not merely disabled (ckpt=0 is a diagnostic config — unbounded replay).

## 6. Consequences

- **Causation: CLOSED** (checkpoint flush). **Convergence SLO: still OPEN**, now with a known,
  byte-evidenced mechanism and a measured path to green (8.3 s once the flush is off the commit path).
- **Follow-up fix (P1):** (1) decouple the checkpoint flush from the commit path (background it;
  the commit returns after the WAL fsync — the checkpoint is a replay-length optimization,
  bridge.go:566, with no business blocking the ACK); (2) batch the fsync (one per checkpoint, or a
  single compacted image, instead of one-per-entity). A separate change, to keep the blast radius
  attributable.
- **The pprof endpoint is a permanent capability** — the next stall at silicon is attributable in
  minutes, not a black box. This is the instrument the 2026-09-04 run lacked.
- **The ADR-0048 fix stands** (correct, regression-guarded) — but the record is now honest that it
  did NOT resolve the stall, and why.
