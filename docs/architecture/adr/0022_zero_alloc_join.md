# ADR-0022: The Zero-Alloc Join Sort Step — `sort.Slice` → `slices.SortFunc` (No-Capture Comparator); Change B (Capnp Entity-ID Cache) Rejected

**Status:** Accepted
**Date:** 2026-08-04
**Author:** Harsh Rawat
**Builds on:** ADR-0015 (which made a disclosed edit to `crdt.go` for the Join-buffer pool; its §5 named the residual allocation ceiling this change attacks, §7(a) named the `sort.Slice` escape this change kills, and §7(f) established the disclose-and-re-verify discipline every subsequent `crdt.go` edit follows), and ADR-0021 (the previous comment-only `crdt.go` edit).

---

## §0. The plan, the premise audit, and what actually shipped

The plan for `pkg/sync/crdt.go`'s `Join` had two changes:

- **Change A (shipped, with a corrected mechanism):** remove the `sort.Slice(incoming, ...)` closure and replace it with a `stabilizeNearlySorted` insertion-sort walk that assumes the sender's `Entries` Seq yields entries already in (entityID ASC, DotCounter ASC) order.
- **Change B (REJECTED — phantom on the gate + a latent UAF):** add a `lastEntityID string` cache to `joinBuffers` so consecutive same-entity yields in one Join share a string-header reference rather than "re-catching the string `ReconstructEntry`'s `ev.EntityId()` already allocated."

The headline estimate was a `6 → 3` allocs/op drop on `BenchmarkCRDTEngine_JoinParallel`.

**Premise audit (before any edit).** My standing rule: prose is suspect until byte-verified. The audit found the plan's mechanism wrong on three load-bearing points:

1. **The escaping closure is NOT the `sort.Slice` comparator.** `go build -gcflags=-m=2` proves the `sort.Slice` comparator (`func3`) is **inlined** (`func literal does not escape` at the comparator site). The closure that escapes is **`func2` — the `delta.Entries(func(entityID, entry) bool {...})` yield callback** (`crdt.go:1085: func literal escapes to heap`), which captures `incoming` at line 1087 and escapes because it is passed into the `Seq` call. `sort.Slice`'s real cost is NOT a closure alloc — it is an **`incoming (spill)` via the reflect-path call parameter** (`incoming escapes to heap ... from sort.Slice(incoming, func literal) (call parameter)`). Change A's *honest* win is that spill, not a closure.
2. **The sender's Seq does NOT yield entityID-ASC.** The production `Entries` Seq (`crdt.go:353`) walks `shardRoots` in **HAMT-hash order** (entityID hash order, NOT lexical), so multi-entity batches arrive in hash order, not in entityID-sorted runs. `stabilizeNearlySorted`'s premise is false → it would leave cross-entity disorder in place → the adjacent-equal dedup (step 3) and the contiguous-equal run grouping of the shard-partition (step 4) would silently corrupt state on real traffic. It is also O(N²) worst-case on a reverse-injected dot sequence (a receiver CPU-amplification DoS the O(N log N) sort avoids). Merkle determinism does NOT depend on the sort (`hamt.go:282` `MerkleRoot` re-sorts the dot pairs itself), so keeping a real O(N log N) sort costs no determinism.
3. **Change B is alloc-neutral on the gate AND a latent UAF.** The bench builds its delta directly via `makeSeq([]seqEntry{{entityID: entityID, ...}})` (`join_parallel_contention_test.go:132`) — **no capnp decode, no `ReconstructEntry`** (the 29.8% attributed to "the Join path" is the *ingest*-path `capnp.Ptr.Text` `string(b)` retain, made OUTSIDE Join, in `ReconstructEntry`/`crdt_reconstruct.go:266`; ADR-0015 §5 already disclosed this as deferred to the arena-pooled PreSorted Seq change — the JoinParallel bench never traverses it). Caching a string-header reference (`buf.lastEntityID = entityID`) saves zero bytes: appending `entityID` vs `buf.lastEntityID` is the same ptr+len string-header copy — there is no alloc to elide because the string was allocated UPSTREAM (capnp on ingest; `fmt.Sprintf` on bench). Worse, `joinBuffers` has **no `Reset()`** and the Join defer only truncates `buf.incoming` (`crdt.go:1080-1083`), so `lastEntityID` would leak stale across Join calls; on any path where the yield entityID is a transient *view* (arena/capnp-backed, not a fresh heap copy) the cache would dangle — a use-after-free. On current heap-copy paths it is merely a no-op; shipping it is a net hazard for zero win. This is the same failure shape as an earlier ingest change that claimed a zero-copy win that was alloc-neutral — I was not going to repeat it.

**What shipped:** Change A, rehabilitated — kill the `sort.Slice` reflect-path slice-header spill via `slices.SortFunc(incoming, cmpIncomingEntries)` where `cmpIncomingEntries` is a **package-level comparator taking `incomingEntry` elements BY VALUE** (no `incoming` capture → no spill), preserving byte-identical order (lex entityID, then `compareDots` ASC) so dedup step 3 and shard-partition step 4 are unchanged, at O(N log N) (no DoS). Change B rejected; documented here, not silently dropped.

The `6 → 3` headline is **honestly corrected to a verified `4 → 3`** on the path the headline bench actually measures (see §5) — the estimate double-counted (it blamed `sort.Slice` for ~2 allocs; reality: exactly the one reflect-path spill).

---

## §1. Context

ADR-0015 §5 set the honest post-pool residual ceiling for the Join path — five surviving per-Join alloc sources NOT eliminated by the pool:

| Source | Alloc % | ADR-0015 forward target |
|--------|---------|------------------------|
| `capnp.Ptr.Text` (EntityId string retain) | 29.8% | arena-pooled PreSorted Seq |
| `ReconstructEntry` string(`payloadBytes`) | 7.5% | earlier ingest-hardening residual (production path discards) |
| `circl` verify | 2% | amortized |
| Slice-header escape (`sort.Slice` capture) | irreducible | removed here |
| Pool cold-start (first Join after GC) | 1-2% | `sync.Pool` GC-weak (documented) |

ADR-0015 §7(a) identified the `sort.Slice` closure-escape as the irreducible residual this change closes. What actually closes here is the **slice-header spill** at the sort step (the ADR-0015 §5/§7(a) residual), NOT the `func2` yield-callback escape (which survives and remains the honest residual — see §5).

---

## §2. The 3 Proven Contracts (re-verified per ADR-0015 §7(f))

### C1 — Determinism
`Join` never touches `stateViewMu`. The determinism contract is `routeShard` (pure `maphash` over a fixed `routeSeed`) + `sort.Ints(shardOrder)` (deterministic shard order) + the per-shard dot-merge + **`MerkleRoot` (hamt.go:282) re-sorts the dot pairs itself**, so the batch arrival/sort order is NOT load-bearing for the Merkle root. `slices.SortFunc` produces byte-identical ordering to the prior `sort.Slice` (lex entityID, then `compareDots` ASC), so the dedup (step 3) and shard-partition (step 4) see the same sorted stream. **PROVEN-CONTRACT SAFE** — `TestJoinDeterminism_PooledVsUnpooledMerkleEqual` PASS (Merkle equal), `TestBenchArenaGreen` PASS.

### C2 — EBR Reclamation
`maybeAdvanceEpoch()` once per Join + `Retire` per successful per-shard CAS. The sort change touches neither; no pool buffer is Retire'd. **PROVEN-CONTRACT SAFE** — `TestJoinPool_DoesNotRetirePoolBuffers` PASS (the source-parse tooth found the new `slices.SortFunc` + comparator and confirmed still ZERO Retire of pool buffers; the static audit survived the comment + call additions).

### C3 — 57.6M ops/s
The 57.6M contract is per-shard `atomic.Pointer` CAS linearizability (`shardRoot`, `CacheLinePad`-padded). The sort step is on the CALLER side of the CAS; it cannot change the CAS. **PROVEN-CONTRACT SAFE** — `TestJoinParallelContentionCurve` PASS.

### C4 — Alignment
`CRDTEntry`, `shardRoot`, `incomingEntry`, `joinBuffers` layouts unchanged. The edit adds a package-level **function** (`cmpIncomingEntries`) + a call site + comments — no struct fields. `fieldalignment` reports only the three pre-existing crdt.go findings (`shardRoot`, `DeltaCRDTEngine`, `CRDTDelta` at lines 72/135/1407 — the deliberate CacheLinePad layouts), none at the new lines. **PROVEN-CONTRACT SAFE** — `TestCRDTEntry_SizeAndAlignment` PASS.

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
1. **Phantom on the gate.** `BenchmarkCRDTEngine_JoinParallel` builds its delta via `makeSeq([]seqEntry{...})` with a `fmt.Sprintf` entityID (`join_parallel_contention_test.go:117-132`), 1 entry/Join, distinct entityID each iteration. It never calls capnp or `ReconstructEntry`. The 29.8% `capnp.Ptr.Text` retain it targets is the *ingest* path, outside Join — ADR-0015 §5 already forwarded it to the arena-pooled PreSorted Seq change (a `Seq`-signature change), not a Join-body cache.
2. **Alloc-neutral even on the ingest path.** Caching `buf.lastEntityID = entityID` stores a string-header reference (ptr+len) to a string allocated UPSTREAM (`ev.EntityId()` / `fmt.Sprintf`). Appending `entityID` vs `buf.lastEntityID` is the same string-header copy — zero allocs elided, because the alloc already happened at the upstream `string(b)`. The cache shares a reference to an already-allocated string; it does not prevent the allocation.
3. **Latent UAF + a hygiene defect.** `joinBuffers` has no `Reset()`; the Join defer (`crdt.go:1080`) truncates only `buf.incoming`. `lastEntityID` would leak stale across Join calls (the pool zeroes it only on `New`, not on reuse). On any future path where the yield entityID is a transient *view* (arena/capnp-backed, not a fresh heap copy), the stale cache dangles — a use-after-free. On current heap-copy paths it is merely a no-op. Shipping it is a net hazard for zero win.

Disclosed in this ADR, NOT silently dropped (the ADR-0015 §7(f) honesty discipline).

---

## §4. Scope — one frozen file edited, the rest untouched

This change edits `crdt.go` (the Join sort step) and no other frozen file.
`pkg/sync/crdt_apply.go`, `api/capnp/api/capnp/schema.capnp`,
`api/capnp/api/capnp/schema.capnp.go`, and `pkg/attribution/envelope.go` are byte-identical
before and after. The frozen-set correction (the phantom `enclose.go` in an early draft of
this change's notes — no such file exists) is recorded in §7.

---

## §5. The Honest Bench (the real delta, not the headline estimate)

Measured on this box (ARM64, GOMAXPROCS=4), **identical flags pre/post**, `crdt.go` reverted to its pre-change state for the PRE read and restored for the POST read (no cross-contamination):

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
- The escape-analysis prediction is borne out **exactly**: removing the `sort.Slice` reflect-path spill kills **one** alloc (~the slice-header spill + reflect boxing ≈ 24 B) on the steady-state serial path. The estimated `6 → 3` **double-counts** — it blamed `sort.Slice` for ~2 allocs; the verified mechanism shows `sort.Slice` contributed exactly the one reflect-path spill (`func3`'s comparator is inlined and escapes nothing).
- The **3 remaining steady-state serial allocs** are the `func2` yield-callback escape (the `delta.Entries` callback value, which captures `incoming` at line 1107 and escapes because it is passed into the `Seq` call — `crdt.go:1105 func literal escapes to heap`) + the append growth. This is the **honest residual that survives this change** and matches ADR-0015 §5's naming of the closure escape as irreducible-by-pooling. Removing it requires the arena-pooled PreSorted Seq change (a `Seq`-signature change to a value-receiver callback → no captured `incoming`, no escaping closure) — that is the next seam, NOT Change B's cache.
- The **B/op drop (~24 B)** is the spilled slice header + reflect boxing — the precise fingerprint of the killed spill.
- The N=1 cold-start reads (42–48 allocs/op, 4–6.4 KB/op) are the growth+escape regime (the pool never warms with one iteration) and are NOT the steady-state `4/3` — calibrating to steady state (`-benchtime=3000x+`) is what surfaces the honest signal.

---

## §6. Verification results

| Gate | Test | Verdict |
|------|------|---------|
| Build | `go build ./...` | PASS (exit 0) |
| Vet | `go vet ./pkg/sync/` | PASS (only pre-existing `unsafe.Pointer` misuse findings at `crdt.go:712`/`hamt_arena.go`/`iblt.go` — none at the new lines; baseline) |
| Format | `gofmt -l` on all 9 touched files | clean (no drift) |
| C1 | `TestJoinDeterminism_PooledVsUnpooledMerkleEqual` (-race) | PASS — Merkle equal |
| C2 | `TestJoinPool_DoesNotRetirePoolBuffers` (-race) | PASS — ZERO pool-buffer Retire (source-parse tooth survived the edit) |
| C3 | `TestHotPathZeroAllocations` (no-race) | PASS — gates `HAMT.Set` (the Join hot path delegates, per ADR-0015; SKIPs under -race by design) |
| C4 | `TestCRDTEntry_SizeAndAlignment` | PASS — no struct fields added |
| Bench | `TestBenchArenaGreen` (-race) | PASS (19.94s, byte-identical to HEAD) |
| Bench | `TestJoinParallelContentionCurve` (-race) | PASS (23.77s, byte-identical to HEAD) |
| — | the four other frozen files byte-identical | PASS |
| Alignment | `fieldalignment ./pkg/sync/` | PASS — only the 3 pre-existing crdt.go findings (shardRoot/DeltaCRDTEngine/CRDTDelta deliberate cache-pad layouts); none at new lines |

---

## §7. Corrections to the Initial Plan (disclosed, not papered)

The plan as drafted contained several factual errors, corrected in execution (byte-verified, not taken on faith):

| # | Initial claim | Verified reality | Consequence |
|---|---|---|---|
| 1 | "`sort.Slice` captures `incoming` → the closure escapes to heap (~2 allocs/op)" | Escape analysis: the comparator (`func3`) is **inlined** (`does not escape`); the escaping closure is `func2` (the `Entries` yield callback), not the sort. `sort.Slice`'s cost is the reflect-path `incoming (spill)` call parameter = **exactly 1 alloc, not ~2**. | Headline `6→3` honestly corrected to verified `4→3` serial. |
| 2 | "the `Delta.Entries` Seq ALREADY yields entries in (entityID ASC, DotCounter ASC) order" | FALSE. The production `Entries` Seq (`crdt.go:353`) yields in **HAMT-hash order**, not lexical. `stabilizeNearlySorted`'s premise is wrong → silent state corruption on multi-entity batches. | `stabilizeNearlySorted` rejected; `slices.SortFunc` (real O(N log N) sort) shipped instead. |
| 3 | "`stabilizeNearlySorted` is O(N) amortized, worst-case O(N·D), D≤2" | Even accepting D≤2 within an entity, the design fails on the cross-entity case (premise #2), and a malicious reverse-injected dot sequence gives O(N²) — a receiver CPU-amplification DoS. | O(N log N) `slices.SortFunc` chosen (no DoS, no false premise). |
| 4 | "ReconstructEntry's `ev.EntityId()` is the 29.8% residual in the Join path" | That retain is in `ReconstructEntry`/**ingest** (`crdt_reconstruct.go:266`), OUTSIDE Join; the `JoinParallel` bench never calls it. ADR-0015 §5 already scoped it to the arena-pooled PreSorted Seq change. | Change B rejected (phantom on gate + the cache is a UAF hazard + alloc-neutral). |
| 5 | "4 other frozen files stay untouched: `crdt_apply.go`, `schema.capnp`, `schema.capnp.go`, `enclose.go`" | `enclose.go` **does not exist anywhere in the repo** (`find -name enclose.go` empty — phantom). The real other-frozen set is `{pkg/sync/crdt_apply.go, api/capnp/api/capnp/schema.capnp, api/capnp/api/capnp/schema.capnp.go}` — 3 files, and `schema.capnp`/`schema.capnp.go` live under `api/capnp/api/capnp/`, NOT `pkg/sync/`. | This ADR lists the verified 3-file frozen sibling set + `pkg/attribution/envelope.go` (the 5th frozen file, in `pkg/attribution`); `enclose.go` not listed. |
| 6 | "the `sort` import is removed" (then self-corrected to "stays") | `sort` MUST stay — `sort.Ints(shardOrder)` (shard-order determinism) + `sort.Search` (delta iterator) both remain live. | `sort` import preserved (removing it breaks the build). |

---

## §8. Objections Considered

### 1 — `slices.SortFunc`'s pdqsort allocates internally (a hidden cost replacing the spill).
`slices.SortFunc` calls `slices.pdqsortCmpFunc` which is in-place (no grows); the `-m=2` log shows it inlines at the call site with no introduced escape and the bench CONFIRMS a net alloc/op DROP, not a rise. If pdqsort had a hidden alloc, the steady-state serial path would read ≥4, not 3. **Bench-refuted.**

### 2 — `cmpIncomingEntries` not being inlined reintroduces the spill (the comparator closure passing).
`cmpIncomingEntries` is NOT inlined (`cost 95 > budget 80`), but it does not need to be: it is passed BY VALUE to the inlined `slices.SortFunc` as a `func(incomingEntry, incomingEntry) int` value — a function VALUE, not a closure capturing `incoming` (it captures nothing; it takes elements by value). The `-m=2` log confirms NO `incoming (spill)` from the comparator. The function value lives on the stack of the inlined `slices.SortFunc` frame. **Safe — bench-confirmed (no spill).**

### 3 — `incoming` still escapes via `func2`, so this change does nothing.
TRUE that `func2`'s escape survives — that is the honest residual disclosed in §5. FALSE that the change does nothing: the reflect-path spill at the `sort.Slice` call parameter was a SEPARATE escape (`incoming (spill) from sort.Slice(incoming, func literal) (call parameter)`), verified present BEFORE and absent AFTER. The bench shows the spill's contribution: serial 4→3, −24 B. **Honest partial win; the surviving `func2` escape is the next (PreSorted Seq) seam.**

### 4 — Change B was silently dropped (no disclosure).
Sections §0/§3/§7 document the rejection with the three reasons (phantom on gate, alloc-neutral, latent UAF + stale-cache hygiene defect). Disclosed per the ADR-0015 §7(f) discipline — NOT silently dropped.

On the corrected headline: the estimated `6→3` became a verified `4→3`. The estimate overstated the win by ~2 allocs (it blamed `sort.Slice` for the `func2` yield-callback escape too). The honest result is a real, escape-analysis-confirmed `4→3` (−1 alloc, −24 B) on the path the headline bench measures. Shipping `stabilizeNearlySorted`/Change B on faith would have repeated the earlier alloc-neutral-zero-copy mistake. The mitigation was the byte-level premise audit before the edit; the bench is the arbiter.

---

## §9. References

- `ADR-0015` — the Join-buffer pool (§5 residual ceiling; §7(a) the sort escape; §7(f) the disclose-and-re-verify discipline).
- `ADR-0014` — ingest-path allocation hardening (the alloc-neutral-claim precedent this change's premise audit avoided repeating).
- `ADR-0021` — the previous comment-only `crdt.go` edit.
- `pkg/sync/hamt.go:282` — `MerkleRoot` re-sorts the dot pairs (the sort step is NOT load-bearing for Merkle determinism).
- `pkg/sync/crdt.go:353` — production `Entries` Seq (HAMT-hash-order yield — the false-premise evidence).
- `pkg/sync/crdt_reconstruct.go:266` — `ReconstructEntry` `ev.EntityId()` (the actual capnp retain, ingest-path, the PreSorted-Seq target NOT a Join-body cache).
- `pkg/sync/join_parallel_contention_test.go:117-132` — `BenchmarkCRDTEngine_JoinParallel` body (`makeSeq` + `fmt.Sprintf`, no capnp — Change B's phantom evidence).
