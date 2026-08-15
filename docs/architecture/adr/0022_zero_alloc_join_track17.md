# ADR-0022: The Zero-Alloc Join Sort Step — `sort.Slice` → `slices.SortFunc` (No-Capture Comparator); Change B (Capnp Entity-ID Cache) Rejected

**Status:** Accepted
**Date:** 2026-08-04
**Phase:** 3, Day 17
**Author:** Sovereign Executor (Opus-class executor — single-agent impl of the dictated fork, with the dictation's mechanistic premise corrected against byte-verified escape analysis before any line shipped)
**Builds on:** ADR-0015 (Day-10 — UNFROZE crdt.go for the JOIN-buffer pool; §5 named the residual ceiling this track attacks, §7(a) named the `sort.Slice` escape this track kills, §7(f) established the re-pin/re-gate/8-resync discipline every subsequent crdt.go edit follows), the Day-8.5 receiver.go re-pin precedent (re-pin WITH disclosure, NOT silence), ADR-0021 (Day-16 — the 8-pin re-sync this track re-executes).

---

## §0. The dictation, the premise audit, and what actually shipped

The Day-17 executor prompt dictated two changes to `pkg/sync/crdt.go`'s `Join`:

- **Change A (shipped, corrected mechanism):** remove the `sort.Slice(incoming, ...)` closure and replace it with a `stabilizeNearlySorted` insertion-sort walk that assumes the sender's `Entries` Seq yields entries already in (entityID ASC, DotCounter ASC) order.
- **Change B (REJECTED — phantom on the gate + a latent UAF):** add a `lastEntityID string` cache to `joinBuffers` so consecutive same-entity yields in one Join share a string-header reference rather than "re-catching the string `ReconstructEntry`'s `ev.EntityId()` already allocated."

The prompt's headline claim was a `6 → 3` allocs/op drop on `BenchmarkCRDTEngine_JoinParallel`.

**Premise audit (before any edit):** Law II (`UNIVERSAL_CODEX.md`) — prose is suspect until byte-verified. The audit found the prompt's mechanism wrong on three load-bearing points:

1. **The escaping closure is NOT the `sort.Slice` comparator.** `go build -gcflags=-m=2` proves the `sort.Slice` comparator (`func3`) is **inlined** (`func literal does not escape` at the comparator site). The closure that escapes is **`func2` — the `delta.Entries(func(entityID, entry) bool {...})` yield callback** (`crdt.go:1085: func literal escapes to heap`), which captures `incoming` at line 1087 and escapes because it is passed into the `Seq` call. `sort.Slice`'s real cost is NOT a closure alloc — it is an **`incoming (spill)` via the reflect-path call parameter** (`incoming escapes to heap ... from sort.Slice(incoming, func literal) (call parameter)`). Change A's *honest* win is that spill, not a closure.
2. **The sender's Seq does NOT yield entityID-ASC.** The production `Entries` Seq (`crdt.go:353`) walks `shardRoots` in **HAMT-hash order** (entityID hash order, NOT lexical), so multi-entity batches arrive in hash order, not in entityID-sorted runs. `stabilizeNearlySorted`'s premise is false → it would leave cross-entity disorder in place → the adjacent-equal dedup (step 3) and the contiguous-equal run grouping of the shard-partition (step 4) would silently corrupt state on real traffic. It is also O(N²) worst-case on a reverse-injected dot sequence (a receiver CPU-amplification DoS the O(N log N) sort avoids). Merkle determinism does NOT depend on the sort (`hamt.go:282` `MerkleRoot` re-sorts the dot pairs itself), so keeping a real O(N log N) sort costs no determinism.
3. **Change B is alloc-neutral on the gate AND a latent UAF.** The bench builds its delta directly via `makeSeq([]seqEntry{{entityID: entityID, ...}})` (`phase2j_test.go:126`) — **no capnp decode, no `ReconstructEntry`** (the 29.8% the prompt §0.b attributes to "the Join path" is the *ingest*-path `capnp.Ptr.Text` `string(b)` retain, made OUTSIDE Join, in `ReconstructEntry`/`crdt_reconstruct.go:276`; ADR-0015 §5 already disclosed this as "Day 11 (arena-pooled PreSorted Seq)" — the JoinParallel bench never traverses it). Caching a string-header reference (`buf.lastEntityID = entityID`) saves zero bytes: appending `entityID` vs `buf.lastEntityID` is the same ptr+len string-header copy — there is no alloc to elide because the string was allocated UPSTREAM (capnp on ingest; `fmt.Sprintf` on bench). Worse, `joinBuffers` has **no `Reset()`** and the Join defer only truncates `buf.incoming` (`crdt.go:1080-1083`; the forensic agent confirmed `lastEntityID` would leak stale across Join calls), so on any path where the yield entityID is a transient *view* (arena/capnp-backed, not a fresh heap copy) the cache would dangle — a use-after-free. On current heap-copy paths it is merely a no-op; shipping it is a net hazard for zero win. This is the honest closure of the ADR-0014-style triple-mix that the Sovereign-stack history already punished once (Day-9 FIX A claimed a zero-copy win that was alloc-neutral).

**What shipped:** Change A, rehabilitated — kill the `sort.Slice` reflect-path slice-header spill via `slices.SortFunc(incoming, cmpIncomingEntries)` where `cmpIncomingEntries` is a **package-level comparator taking `incomingEntry` elements BY VALUE** (no `incoming` capture → no spill), preserving byte-identical order (lex entityID, then `compareDots` ASC) so dedup step 3 and shard-partition step 4 are unchanged, at O(N log N) (no DoS). Change B rejected; documented here not silently dropped.

The prompt's `6 → 3` headline is **honestly corrected to a verified `4 → 3`** on the path the headline bench actually measures (see §5) — the prompt double-counted (it blamed `sort.Slice` for ~2 allocs; reality: exactly the one reflect-path spill).

---

## §1. Context

ADR-0015 §5 set the post-Day-10 honest residual ceiling for the Join path — five surviving per-Join alloc sources NOT eliminated by the Day-10 pool:

| Source | Alloc % | ADR-0015 forward target |
|--------|---------|------------------------|
| `capnp.Ptr.Text` (EntityId string retain) | 29.8% | Day 11 (arena-pooled PreSorted Seq) |
| `ReconstructEntry` string(`payloadBytes`) | 7.5% | Day-9 FIX A residual (production path discards) |
| `circl` verify | 2% | amortized |
| Slice-header escape (`sort.Slice` capture) | irreducible | Day 11 removes the sort |
| Pool cold-start (first Join after GC) | 1-2% | `sync.Pool` GC-weak (documented) |

ADR-0015 §7(a) identified the `sort.Slice` closure-escape as the irreducible residual this track closes. Day 17 closes the **slice-header spill** at the sort step (the ADR-0015 §5/§7(a) residual), NOT the `func2` yield-callback escape (which survives and remains the honest residual — see §5).

---

## §2. The 3 Proven Contracts (re-gated per ADR-0015 §7(f))

### C1 — Determinism
`Join` never touches `stateViewMu`. The determinism contract is `routeShard` (pure `maphash` over a fixed `routeSeed`) + `sort.Ints(shardOrder)` (deterministic shard order) + the per-shard dot-merge + **`MerkleRoot` (hamt.go:282) re-sorts the dot pairs itself**, so the batch arrival/sort order is NOT load-bearing for the Merkle root. `slices.SortFunc` produces byte-identical ordering to the prior `sort.Slice` (lex entityID, then `compareDots` ASC), so the dedup (step 3) and shard-partition (step 4) see the same sorted stream. **PROVEN-CONTRACT SAFE** — `TestJoinDeterminism_PooledVsUnpooledMerkleEqual` PASS (Merkle equal), `TestPhase2J_BenchArenaGreen` PASS.

### C2 — EBR Reclamation
`maybeAdvanceEpoch()` once per Join + `Retire` per successful per-shard CAS. The sort change touches neither; no pool buffer is Retire'd. **PROVEN-CONTRACT SAFE** — `TestJoinPool_DoesNotRetirePoolBuffers` PASS (the source-parse tooth found my new `slices.SortFunc` + comparator and confirmed still ZERO Retire of pool buffers; the static audit survived the comment + call additions).

### C3 — 57.6M ops/s
The 57.6M contract is per-shard `atomic.Pointer` CAS linearizability (`shardRoot`, `CacheLinePad`-padded). The sort step is on the CALLER side of the CAS; it cannot change the CAS. **PROVEN-CONTRACT SAFE** — `TestPhase2J_JoinParallelContentionCurve` PASS.

### C4 — Alignment
`CRDTEntry`, `shardRoot`, `incomingEntry`, `joinBuffers` layouts unchanged. The edit adds a package-level **function** (`cmpIncomingEntries`) + a call site + comments — no struct fields. `fieldalignment` reports only the three pre-existing crdt.go findings (`shardRoot`, `DeltaCRDTEngine`, `CRDTDelta` at lines 72/135/1407 — the deliberate CacheLinePad layouts), none at the new lines. **PROVEN-CONTRACT SAFE** — `TestCRDTEngine_SizeAndAlignment` PASS.

---

## §3. The Decision (one change shipped, one rejected)

### CHANGE A (shipped) — `sort.Slice` → `slices.SortFunc` with a no-capture comparator

`crdt.go` Join step 2, before:
```go
sort.Slice(incoming, func(i, j int) bool {
    if incoming[i].entityID != incoming[j].entityID {
        return incoming[i].entityID < incoming[j].entityID
    }
    return compareDots(incoming[i].entry.Dot(), incoming[j].entry.Dot()) < 0
})
```
after:
```go
slices.SortFunc(incoming, cmpIncomingEntries)
```
with the package-level comparator (defined near `compareDots`):
```go
func cmpIncomingEntries(a, b incomingEntry) int {
    if a.entityID != b.entityID {
        if a.entityID < b.entityID {
            return -1
        }
        return 1
    }
    return compareDots(a.entry.Dot(), b.entry.Dot())
}
```

**The mechanism (byte-verified by `go build -gcflags=-m=2`):**
- BEFORE: `crdt.go:1097:13: incoming escapes to heap ... from sort.Slice(incoming, func literal) (call parameter)` — the reflect-path `sort.Slice` boxes `incoming` (a `[]incomingEntry`) through an `interface{}` call parameter, spilling the slice header.
- AFTER: the 1097 spill is **gone**. `slices.SortFunc` is generic + **inlined at the call site** (the `-m=2` log shows `inlining call to slices.SortFunc[...]` at crdt.go:1152); `cmpIncomingEntries` receives `incomingEntry` elements BY VALUE and captures NO `incoming` reference, so the comparator needs no `incoming` spill and the call sites of the surviving escapes (`crdt.go:1104 moved to heap: incoming`, `1105 func literal escapes`, `1107 append escapes`) are ALL `func2`'s — not the sort.

`slices` was already imported (`crdt.go:10`, in use for `slices.Sort(sendKeys)` in `GenerateDelta`); `sort` STAYS imported (`sort.Ints(shardOrder)` at the shard-order step + `sort.Search` in the delta Entries iterator both remain live — dropping `sort` would break the build). No new imports.

### CHANGE B (REJECTED) — the capnp entity-ID cache

Not shipped. Three reasons:
1. **Phantom on the gate.** `BenchmarkCRDTEngine_JoinParallel` builds its delta via `makeSeq([]seqEntry{...})` with a `fmt.Sprintf` entityID (`phase2j_test.go:117-128`), 1 entry/Join, distinct entityID each iteration. It never calls capnp or `ReconstructEntry`. The 29.8% `capnp.Ptr.Text` retain the prompt §0.b targets is the *ingest* path, outside Join — ADR-0015 §5 already forwarded it to "Day 11 (arena-pooled PreSorted Seq)" (a `Seq`-signature change), not a Join-body cache.
2. **Alloc-neutral even on the ingest path.** Caching `buf.lastEntityID = entityID` stores a string-header reference (ptr+len) to a string allocated UPSTREAM (`ev.EntityId()` / `fmt.Sprintf`). Appending `entityID` vs `buf.lastEntityID` is the same string-header copy — zero allocs elided, because the alloc already happened at the upstream `string(b)`. The cache shares a reference to an already-allocated string; it does not prevent the allocation.
3. **Latent UAF + a hygiene defect.** `joinBuffers` has no `Reset()`; the Join defer (`crdt.go:1080`) truncates only `buf.incoming`. `lastEntityID` would leak stale across Join calls (pool-zeroes it only on `New`, not on reuse). On any future path where the yield entityID is a transient *view* (arena/capnp-backed, not a fresh heap copy), the stale cache dangles — a use-after-free. On current heap-copy paths it is merely a no-op. Shipping it is a net hazard for zero win.

Disclosed in this ADR, NOT silently dropped (the ADR-0015 §7(f) honesty discipline; the Day-8.5 receiver.go precedent).

### md5 Re-Pin

`crdt.go` transitions `a50fee8f → 835350a8` (full `835350a899f250947773ee805ef68235`). All 8 teeth re-synced with a Day-17/ADR-0022 citation. The OTHER FROZEN files stay byte-identical at their Day-16 pins (see §6 for the corrected FROZEN set).

---

## §4. The 8-Pin Re-Sync (ADR-0015 §7(f) discipline — the third execution)

`crdt.go`'s md5 is pinned in 8 test teeth across the repo (no centralized registry — the "registry-truth" name in `UNIVERSAL_CODEX.md` refers to the commit-c4e5b9b *event* of re-syncing scattered pins, not a file). Day 17 re-syncs all 8:

| # | Tooth | Pin shape | Was → Now |
|---|-------|-----------|-----------|
| T1 | `pkg/authorization/cedar_bench_test.go:269` | full 32-char | `a50fee8f...` → `835350a8...` |
| T2 | `internal/database/l1_compaction_track16_test.go:59` | 8-char prefix | `a50fee8f` → `835350a8` |
| T3 | `pkg/receive/bench_test.go:789` | full 32-char | `a50fee8f...` → `835350a8...` |
| T4 | `pkg/receive/gate_test.go:49` | full 32-char | `a50fee8f...` → `835350a8...` |
| T5 | `internal/database/l1_compaction_track15_test.go:394` | 8-char prefix | `a50fee8f` → `835350a8` |
| T6 | `pkg/transport/transport_test.go:31` (`const crdtFrozenMD5`) | full 32-char | `a50fee8f...` → `835350a8...` |
| T7 | `internal/database/l1_compaction_track14_test.go:201` | 8-char prefix | `a50fee8f` → `835350a8` |
| T8 | `pkg/sync/crdt_reconstruct_test.go:405` | 8-char prefix | `a50fee8f` → `835350a8` |

Each edit was a surrounding-context exact match (no blind `replace_all` — T6 is a `const` value, not a slice entry; T8's trailing disclosure-comment prose embeds the literal `705ac671 -> a50fee8f` which must NOT be touched by the re-pin). The G3.5.c md5-contract tooth (`pkg/receive/gate_test.go`) now reads `835350a8...` and PASSes.

---

## §5. The Honest Bench (the real delta, not the dictated headline)

Measured on this box (ARM64, GOMAXPROCS=4), **identical flags pre/post**, `crdt.go` stashed to `a50fee8f` for the PRE read and popped for the POST read (no cross-contamination):

### Serial `BenchmarkCRDTEngine_Join` (the lower-noise path, -benchtime=5000x -count=6)

| | PRE (`sort.Slice`) | POST (`slices.SortFunc`) | Delta |
|---|---|---|---|
| allocs/op | **4** | **3** | **−1 (−25%)** |
| B/op | **99** | **75** | **−24 (−24%)** |
| ns/op | 2837 | 2771 | −66 (−2.3%, within noise) |

### Parallel `BenchmarkCRDTEngine_JoinParallel` (the contention-honest path, -benchtime=3000x -count=8)

| | PRE | POST | Delta |
|---|---|---|---|
| allocs/op (steady) | 5–6 | 4–5 | −1 (corroborates serial; parallel tail noisier) |
| B/op | 127–184 | 102–136 | reduced |
| ns/op | 1.6–2.0 µs | 1.6–2.3 µs | noise-floor (parallel jitter dominates) |

**Reading the bench honestly:**
- The escape-analysis prediction is borne out **exactly**: removing the `sort.Slice` reflect-path spill kills **one** alloc (~the slice-header spill + reflect boxing ≈ 24 B) on the steady-state serial path. The prompt's claimed `6 → 3` **double-counts** — it blamed `sort.Slice` for ~2 allocs; the verified mechanism shows `sort.Slice` contributed exactly the one reflect-path spill (`func3`'s comparator is inlined and escapes nothing).
- The **3 remaining steady-state serial allocs** are the `func2` yield-callback escape (the `delta.Entries` callback value, which captures `incoming` at line 1107 and escapes because it is passed into the `Seq` call — `crdt.go:1105 func literal escapes to heap`) + the append growth. This is the **honest residual that survives this change** and matches ADR-0015 §5's naming of the closure escape as irreducible-by-pooling. Removing it requires the ADR-0015 §5 "Day 11 / arena-pooled PreSorted Seq" change (a `Seq`-signature change to a value-receiver callback -> no captured `incoming`, no escaping closure) — that is the next seam, NOT Change B's cache.
- The **B/op drop (~24 B)** is the spilled slice header + reflect boxing — the precise fingerprint of the killed spill.
- The N=1 cold-start reads (42–48 allocs/op, 4–6.4 KB/op) are the growth+escape regime (the pool never warms with one iteration) and are NOT the steady-state `4/3` — calibrating to steady state (`-benchtime=3000x+`) is what surfaces the honest signal.

---

## §6. Gate Log

| Gate | Test | Verdict |
|------|------|---------|
| G17.a | `go build ./...` | PASS (exit 0) |
| G17.b | `go vet ./pkg/sync/` | PASS (only pre-existing `unsafe.Pointer` misuse findings at `crdt.go:712`/`hamt_arena.go`/`iblt.go` — none at the new lines; baseline) |
| G17.c | `gofmt -l` on all 9 touched files | clean (no drift) |
| G17.d (C1) | `TestJoinDeterminism_PooledVsUnpooledMerkleEqual` (-race) | PASS — Merkle equal |
| G17.d (C2) | `TestJoinPool_DoesNotRetirePoolBuffers` (-race) | PASS — ZERO pool-buffer Retire (source-parse tooth survived the edit) |
| G17.d (C3) | `TestHotPathZeroAllocations` (no-race) | PASS — gates `HAMT.Set` (the Join hot path delegates, per ADR-0015 G10.d; SKIPs under -race by design) |
| G17.d (C4) | `TestCRDTEngine_SizeAndAlignment` | PASS — no struct fields added |
| G17.d | `TestPhase2J_BenchArenaGreen` (-race) | PASS (19.94s, byte-identical to HEAD) |
| G17.d | `TestPhase2J_JoinParallelContentionCurve` (-race) | PASS (23.77s, byte-identical to HEAD) |
| G17.f | crdt.go md5 `a50fee8f → 835350a8` | PASS — all 8 teeth re-synced |
| G17.f | OTHER FROZEN md5s unchanged | PASS |
| G17.f | `fieldalignment ./pkg/sync/` | PASS — only the 3 pre-existing crdt.go findings (shardRoot/DeltaCRDTEngine/CRDTDelta deliberate cache-pad layouts); none at new lines |
| **transient** | `TestGate_UntouchedFrozenAndOutOfScope` (pkg/receive) | **FAIL pre-commit, PASS post-commit** — git-HEAD-vs-working-tree scope tooth; trips on the in-flight re-pin (crdt.go is in its `untouchedFiles` set). Verified: PASSES at true HEAD (stash), FAILS with edits, flips green on commit. Identical to the Day-10/Day-16 documented post-commit transient. |
| **transient** | `TestTrack36_ScopeTooth` (pkg/receive) | **FAIL pre-commit, PASS post-commit** — the Track36 scope guard; trips on the 4 FROZEN-pin teeth I re-synced (cedar_bench/crdt.go/crdt_reconstruct_test/transport_test, all in Track36's forbidden set). Verified: PASSES at true HEAD (stash). Same post-commit-transient class. |

The two `transient` rows are **not regressions** — they are the git-HEAD scope teeth that by construction pass once the re-pin is committed (the documented Day-10/Day-16 behavior). Both pass at true HEAD (all Day-17 edits stashed) and pass post-commit; they fail only while the re-pin is in flight in the working tree.

---

## §7. Prompt Factual Corrections (disclosed, not papered)

The dictated prompt contained several factual errors, corrected in execution (Law II — byte-verified, not prompt-trusted):

| # | Prompt claim | Verified reality | Consequence |
|---|---|---|---|
| 1 | "`sort.Slice` captures `incoming` → the closure escapes to heap (~2 allocs/op)" | Escape analysis: the comparator (`func3`) is **inlined** (`does not escape`); the escaping closure is `func2` (the `Entries` yield callback), not the sort. `sort.Slice`'s cost is the reflect-path `incoming (spill)` call parameter = **exactly 1 alloc, not ~2**. | Headline `6→3` honestly corrected to verified `4→3` serial. |
| 2 | "the `Delta.Entries` Seq ALREADY yields entries in (entityID ASC, DotCounter ASC) order" | FALSE. The production `Entries` Seq (`crdt.go:353`) yields in **HAMT-hash order**, not lexical. `stabilizeNearlySorted`'s premise is wrong → silent state corruption on multi-entity batches. | `stabilizeNearlySorted` rejected; `slices.SortFunc` (real O(N log N) sort) shipped instead. |
| 3 | "`stabilizeNearlySorted` is O(N) amortized, worst-case O(N·D), D≤2" | Even accepting D≤2 within an entity, the design fails on the cross-entity case (premise #2), and a malicious reverse-injected dot sequence gives O(N²) — a receiver CPU-amplification DoS. | O(N log N) `slices.SortFunc` chosen (no DoS, no false premise). |
| 4 | "ReconstructEntry's `ev.EntityId()` is the 29.8% residual in the Join path" | That retain is in `ReconstructEntry`/**ingest** (`crdt_reconstruct.go:276`), OUTSIDE Join; the `JoinParallel` bench never calls it. ADR-0015 §5 already scoped it to "Day 11 (arena-pooled PreSorted Seq)". | Change B rejected (phantom on gate + the cache is a UAF hazard + alloc-neutral). |
| 5 | "re-pin from `help50fee8f` → New" | The real prior pin is `a50fee8f` (`help50fee8f` is a typo; the prompt line is itself corrupt). | Correct prior value `a50fee8f` used for the 8-pin re-sync. |
| 6 | "4 OTHER FROZEN files stay untouched: `crdt_apply.go`, `schema.capnp`, `schema.capnp.go`, `enclose.go`" | `enclose.go` **does not exist anywhere in the repo** (`find -name enclose.go` empty — phantom). The real OTHER-FROZEN set is `{pkg/sync/crdt_apply.go (ed9132a2), api/capnp/api/capnp/schema.capnp (47d2796a), api/capnp/api/capnp/schema.capnp.go (590af228)}` — 3 files, and `schema.capnp`/`schema.capnp.go` live under `api/capnp/api/capnp/`, NOT `pkg/sync/`. | ADR lists the verified 3-file FROZEN sibling set + `pkg/attribution/envelope.go` (the 5th pinned file, in `pkg/attribution`, a sibling only to the crdt_reconstruct tooth); `enclose.go` not listed. |
| 7 | "the `sort` import is removed" (then self-corrected at §2.6 to "stays") | `sort` MUST stay — `sort.Ints(shardOrder)` (shard-order determinism) + `sort.Search` (delta iterator) both remain live. | `sort` import preserved (removing it breaks the build). |

---

## §8. Self-Adversarial (the attacks on this specific fork)

### ATTACK 1 — `slices.SortFunc`'s pdqsort allocates internally (a hidden cost replacing the spill).
`slices.SortFunc` calls `slices.pdqsortCmpFunc` which is in-place (no grows); the `-m=2` log shows it inlines at the call site with no introduced escape and the bench CONFIRMS a net alloc/op DROP, not a rise. If pdqsort had a hidden alloc, the steady-state serial path would read ≥4, not 3. **Bench-refuted.**

### ATTACK 2 — `cmpIncomingEntries` not being inlined reintroduces the spill (the comparator closure passing).
`cmpIncomingEntries` is NOT inlined (`cost 95 > budget 80`), but it does not need to be: it is passed BY VALUE to the inlined `slices.SortFunc` as a `func(incomingEntry, incomingEntry) int` value — a function VALUE, not a closure capturing `incoming` (it captures nothing; it takes elements by value). The `-m=2` log confirms NO `incoming (spill)` from the comparator. The function value lives on the stack of the inlined `slices.SortFunc` frame. **Safe — bench-confirmed (no spill).**

### ATTACK 3 — `incoming` still escapes via `func2`, so this change does nothing.
TRUE that `func2`'s escape survives — that is the honest residual disclosed in §5. FALSE that the change does nothing: the reflect-path spill at the `sort.Slice` call parameter was a SEPARATE escape (`incoming (spill) from sort.Slice(incoming, func literal) (call parameter)`), verified present BEFORE and absent AFTER. The bench shows the spill's contribution: serial 4→3, −24 B. **Honest partial win; the surviving `func2` escape is the next (PreSorted Seq) seam.**

### ATTACK 4 — the transient teeth `TestGate_UntouchedFrozenAndOutOfScope` / `TestTrack36_ScopeTooth` FAIL, so the gate is red.
Both are git-HEAD-vs-working-tree scope teeth (their contract is "these files must be byte-identical to HEAD"). They FAIL pre-commit by construction for ANY in-flight re-pin of crdt.go (crdt.go is in their guard sets). Verified: both PASS at true HEAD (all edits stashed) and flip green on commit. This is the documented Day-10/Day-16 post-commit transient, byte-identical in mechanism. **Not a regression; green post-commit.**

### ATTACK 5 — Change B was silently dropped (no disclosure).
This ADR §0/§3/§7 document the rejection with the three reasons (phantom on gate, alloc-neutral, latent UAF + stale-cache hygiene defect). Disclosed per the ADR-0015 §7(f) discipline + Day-8.5 receiver.go precedent — NOT silently dropped.

### MEDIOCRITY 1 — the dictated headline (`6→3`) becomes a verified `4→3`.
The prompt overstated the win by ~2 allocs (blamed `sort.Slice` for the `func2` yield-callback escape too). The honest result is a real, escape-analysis-confirmed `4→3` (−1 alloc, −24 B) on the path the headline bench measures. Shipping the dictated `stabilizeNearlySorted`/Change-B on faith would have been the ADR-0014-style triple-mix the Sovereign history already punished. **Mitigation: Law II audit before the edit; the bench is the arbiter.**

---

## §9. References

- `ADR-0015` — Day-10 Join-buffer pool (§5 residual ceiling; §7(a) the sort escape; §7(f) the re-pin/re-gate/8-resync discipline).
- `ADR-0014` — Day-9 ingest alloc hardening (the triple-mix precedent this track's premise-audit prevented a repeat of).
- `ADR-0021` — Day-16 8-pin re-sync precedent (the `TestGate_UntouchedFrozenAndOutOfScope` post-commit-transient mechanism).
- `pkg/sync/hamt.go:282` — `MerkleRoot` re-sorts the dot pairs (the sort step is NOT load-bearing for Merkle determinism).
- `pkg/sync/crdt.go:353` — production `Entries` Seq (HAMT-hash-order yield — the false-premise evidence).
- `pkg/sync/crdt_reconstruct.go:276` — `ReconstructEntry` `ev.EntityId()` (the actual capnp retain, ingest-path, the Day-11 PreSorted-Seq target NOT a Join-body cache).
- `pkg/sync/phase2j_test.go:117-128` — `BenchmarkCRDTEngine_JoinParallel` body (`makeSeq` + `fmt.Sprintf`, no capnp — Change B's phantom evidence).
- `UNIVERSAL_CODEX.md` Law II — prose is suspect until byte-verified.
- The Day-8.5 receiver.go re-pin precedent (re-pin WITH disclosure, NOT silence).
