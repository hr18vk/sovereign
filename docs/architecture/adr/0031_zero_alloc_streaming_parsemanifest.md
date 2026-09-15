# ADR-0031: The Zero-Alloc-Line Streaming ParseManifest — Closing the ADR-0030 §6.a Deferred Item

**Status:** ACCEPTED (2026-08-09) — §5 conditionally approved: this is a read-path + reaper pure refactor; it does not touch the single-writer root-equality qualifier or the core `crdt.go`. No core file touched.

**Closes:** the ADR-0030 §6.a residual: `ParseManifest` (`l1_compactor.go`) used `strings.Split(string(body), "\n")` — an intermediate `[]string` of N+1 entries the parser allocated in addition to the `l0Keys` slice. ADR-0030 cut the parse for skipped manifests (the download skip); for the non-skipped (downloaded) manifests the per-parse intermediate-slice residual stood open. This change closes it: a single-pass `strings.IndexByte` scan over `string(body)` (substring-appending the `l0Keys` — 0 per-line copy, aliasing the one `string(body)` copy) drops the Split slice; the three caller sites' `io.ReadAll` → a single-grow `readManifestBody` drops the `io.ReadAll` 512B-start doublings. Both byte-identical.

## §1. Context (the named residual; ADR-0030 §6.a opened it)

ADR-0030 §6.a named the residual explicitly: *"a zero-alloc `ParseManifest` (streaming line reader, no `strings.Split`). The download-skip change cuts the `ParseManifest` alloc by skipping the download; it does NOT zero it for the non-skipped manifests. A streaming line reader (the §6.a future work) is OUT OF SCOPE there."* This ADR is that follow-up — closing a named residual with a precise byte target rather than opening new work.

The blast radius is the lowest of any open line: one pure function (`ParseManifest`) + its three caller sites (`query.go` `loadSupersededL0Keys` — per-query; `l0_reaper.go` — per-sweep maintenance, off the hot path; `l1_compactor.go` `SupersededL0Keys` — the compactor's idempotency re-read). All in the read path + the reaper. Zero write-path touch. No core file touched. The five core files are unchanged. The durable-read producer files stay byte-unchanged except `l1_compactor.go` (the one edited file — the reader changed; the writer `buildManifest` + `manifestKeyFor` are byte-unchanged).

## §2. The root cause + the byte-verified constraints (the premise-audit, measured before code)

**ROOT CAUSE (one sentence):** `ParseManifest` materialized the body into an intermediate `[]string` of N+1 entries via `strings.Split` (in addition to the `l0Keys` slice it returns), and the three callers materialized the body via `io.ReadAll` (a 512B-start doubling grow), when the manifest grammar is a LF-delimited prefix-classified sequence a single-pass `strings.IndexByte` scan can yield from with one `string(body)` copy (the substring appends alias it — 0 per-line alloc) and a single 4096B-start growable read can absorb in one alloc for the observed production sizes.

**The premise-audit — measured before code; the headline follows the measurement, not the initial guess:**

- **§0.a — M1 (load-bearing): my initial candidate is refuted by the measurement.** The candidate I first considered was a single-pass `bytes.IndexByte` scan with a per-L0-line `string(line)` copy. The old `strings.Split(string(body), "\n")` path copies the body once via `string(body)` (1 alloc), then every `ln` is a substring aliasing that one copy (0 per-line allocs). The candidate calls `string([]byte)` per L0 line — a `[]byte`→`string` conversion copies (strings are immutable) → N per-line allocs. Measured (`testing.AllocsPerRun`, the `T-STREAM-ALLOC` tooth — the honest headline made executable):

  | N | OLD `strings.Split` (parse-only) | Candidate (`bytes.IndexByte`+`string(line)`/L0) | Verdict |
  |---|---|---|---|
  | 1   | 3  | 3   | tie |
  | 16  | 5  | **20**  | 4× worse |
  | 64  | 7  | **70**  | 10× worse |
  | 256 | 9  | **264** | 29× worse |

  The honesty gate kills the candidate — I do not ship it. The candidate is byte-identical to the reference on output (it is only worse on allocs, not on correctness — pinned by the `T-STREAM-BYTE-IDENTITY` fuzz, which asserts the candidate matches the reference); the rejection is an alloc decision, not a correctness one. The `T-STREAM-ALLOC` tooth's `require.Greater(refutedParse, oldParse)` for N>1 makes the rejection executable: a future "optimization" that reintroduces the per-line `string([]byte)` copy must fail this tooth.

- **§0.b — the honest replacement keeps the one `string(body)` copy (irreducible) + drops the Split slice.** The `l0Keys` must outlive the `[]byte` body the caller `readManifestBody`'d into (the callers store `l0Keys` as `map[string]struct{}` keys — they need stable, comparable strings, not sub-slices of a buffer the caller frees). So the `string(body)` copy is irreducible. The substring appends (`l0Keys = append(l0Keys, ln)` where `ln` is a sub-string of `string(body)`) alias that one copy → 0 per-line alloc. The Split intermediate `[]string` (N+1 entries) is eliminated. Measured: **−1 alloc/run at every N on the parse axis** (the Split slice was the only overhead the old path paid that the new path does not; the l0Key copies were never there — the old substrings aliased the same `string(body)`).

- **§0.c — M2:** `strings.TrimSpace` on a string returns a sub-string (0 alloc); `bytes.TrimSpace` on a `[]byte` returns a sub-slice. The trimmed-line step is not the alloc source — the `strings.Split` slice + (for the refuted candidate only) the per-line `string([]byte)` copies are. The new impl uses `strings.TrimSpace` (sub-string) — byte-identical to the old `strings.TrimSpace(ln)`.

- **§0.d — M3: the malformed-body behavior is preserved exactly (the `first`-line unconditional-set).** The old code: `if i == 0 || (l1Key == "" && strings.HasPrefix(ln, "l1/"))` — line 0 is set as `l1Key` unconditionally when non-empty (even an `"l0/..."`-prefixed line 0, a malformed manifest the compactor never writes but a torn write might), then `continue` (so the line-0 key is not appended to `l0Keys`); lines 1+ use the prefix check. The new impl's `first` flag mirrors this byte-identically. A line that is neither `"l1/"` nor `"l0/"` prefixed is ignored (defense in depth — a stray line is dropped, not fatal). The reaper's `if l1Key == ""` guard (`l0_reaper.go:186`) depends on this. Pinned by `T-STREAM-BYTE-IDENTITY` (the fuzz injects `l0/`-prefixed line 0 + stray lines + CR-terminated lines + empty lines) + `T-STREAM-RED-CONTROL` (the malformed-edge catcher: a prefix-gated variant without the `first` flag returns `l1Key == ""` + double-counts the line-0 key into `l0Keys` → diverges → the `first` flag is load-bearing).

- **§0.e — the read axis:** `io.ReadAll` starts at 512B and doubles; `readManifestBody` starts at 4096B (covers the observed max 2990B in one alloc) + reads directly into the growable buffer (no separate scratch — a separate `tmp` alloc would undo the win, M1-measured). `Download` returns only `io.ReadCloser` (no size hint at the call site), so a pre-sized read is impossible; the 4096B-start single-grow is the byte-honest minimum. Grows on demand for the rare larger manifest.

- **§0.f — M4 (count-growth): this change adds no telemetry counter. The counter set stays at 17 distinct (no count-assertion update).** This is a pure refactor (an implementation swap, not a new disclosure surface) — the earlier pure-refactor pass (the SkipList `Seek`) likewise added no counter, so the counter-count teeth (`wantDistinct=17`) are unchanged. The telemetry bridge is unchanged (no new series to surface). The `T-STREAM-UNCHANGED` tooth pins this in-package.

**The measured E2E win (the honest headline, `T-STREAM-ALLOC`):**

| N | OLD (`io.ReadAll`+`strings.Split`) E2E | NEW (`readManifestBody`+`stringScan`) E2E | Δ |
|---|---|---|---|
| 1   | 6  | **5**  | −1 |
| 16  | 10 | **7**  | −3 |
| 64  | 15 | **9**  | **−6 (−40%), per-query** |
| 256 | 21 | 13 | −8 |

At the production-relevant N=64 (the `loadSupersededL0Keys` caller is hit per query), the E2E alloc is **15 → 9 (−6, −40%)**. The N=256 case grows (`8370B > 4096B` → one extra grow) — but manifests never reach that in production (2990B observed max, ADR-0021 §3).

## §3. The mechanism design (decided before code, per §1)

Two byte-identical swaps, both measured:

- **EDIT 1 — `ParseManifest` body → `stringScan`.** Replace `strings.Split(string(body), "\n")` + the `for i, ln := range lines` loop with a single-pass `strings.IndexByte(s, '\n')` scan over `s := string(body)`, substring-appending `l0Keys`. The `first` flag mirrors the old `i == 0` (the malformed-edge byte-identity, §0.d). The signature `(l1Key string, l0Keys []string)` is byte-identical (the 3 callers + the contract teeth depend on it).

- **EDIT 2 — the 3 caller sites' `io.ReadAll(rc)` → `readManifestBody(rc)`.** A new package-level `readManifestBody(r io.Reader) ([]byte, error)` in `l1_compactor.go` (same package as all 3 callers): a single-grow 4096B-start buffer, reads directly into the growable slice (no separate scratch). The reaper (`l0_reaper.go`) drops its now-orphaned `"io"` import (the swap removed its only `io.` reference).

- **EDIT 3 — zero telemetry edits.** No counter added (§0.f). The bridge is byte-unchanged.

**Refuted (not shipped):** the initial candidate (`bytes.IndexByte` + `string(line)` per L0) — 3–29× worse on allocs (§0.a). The `T-STREAM-ALLOC` tooth makes the rejection executable.

## §4. The byte chain

Every cite below is the post-edit line:

- **`internal/database/l1_compactor.go` — `readManifestBody` (new) + `ParseManifest` (replaced body).** `readManifestBody(r io.Reader) ([]byte, error)` (the single-grow 4096B-start read, §0.e). `ParseManifest(body []byte) (l1Key string, l0Keys []string)` — the `stringScan` body (§0.b) + the `first`-line unconditional-set (§0.d). The writer `buildManifest` (`l1_compactor.go`) + the manifest key writer `manifestKeyFor` are byte-unchanged (this change edits the reader only — the writer functions are byte-verified unchanged).
- **`internal/database/query.go:1283` — caller site 1 (`loadSupersededL0Keys`, per-query).** `io.ReadAll(rc)` → `readManifestBody(rc)`. Discards `l1Key` (only needs `l0Keys` for the superseded set).
- **`internal/database/l0_reaper.go:175` — caller site 2 (the reaper, per-sweep).** `io.ReadAll(rc)` → `readManifestBody(rc)`. Uses `l1Key` (the L1-exists probe) — the streaming read returns it byte-identical. The `"io"` import is dropped (the swap removed the only `io.` reference). The reaper is off the hot path (one probe per manifest per 5-min sweep, ADR-0021 §3) — the alloc-zeroing there is honest hygiene, not a latency win (§6.b).
- **`internal/database/l1_compactor.go:1097` — caller site 3 (`SupersededL0Keys`, the compactor's idempotency re-read).** `io.ReadAll(rc)` → `readManifestBody(rc)`. Discards `l1Key`.

## §5. The teeth (the gate) — all green

Five teeth in `internal/database` + one composition tooth in `pkg/durability`. Determinism note: the `T-STREAM-BYTE-IDENTITY` fuzz uses `rand.New(rand.NewPCG(26, 0))` (deterministic); the parse is single-threaded.

- **T-STREAM-BYTE-IDENTITY (load-bearing, `internal/database`):** a differential-equivalence fuzz — 2000 manifests (seed=26) with a varied l1Key + l0Keys + stray "garbage" lines + empty lines + CR-terminated lines + a sometimes-dropped trailing LF. Parse with the reference (`parseManifestReference` — the exact old `strings.Split` impl) and the new `ParseManifest`. Assert byte-identical (`l1Key` string-equal, `l0Keys` deep-equal). The fuzz also asserts the refuted candidate (`parseManifestStreamingCandidate`) is byte-identical to the reference on output (the §0.b rejection was an alloc decision, not a correctness one). 0 divergences. Green.
- **T-STREAM-ALLOC (measured, honest, `internal/database`):** `testing.AllocsPerRun` over the new `ParseManifest` + `readManifestBody` vs the old `parseManifestReference` + `io.ReadAll` at N=1/16/64/256. Assert `new < old` on both axes (parse + E2E). Assert the refuted candidate is `> old` for N>1 (the §0.b rejection's evidence, made executable). Discloses the actual numbers (the tables in §2) — does not assert "0 allocs" (the `string(body)` copy + the `l0Keys` slice + the read buffer are irreducible). Green.
- **T-STREAM-RED-CONTROL (`internal/database`):** the malformed-edge catcher. A manifest whose line 0 is an `"l0/..."` key — the reference sets `l1Key = "l0/..."` (the `i==0` unconditional-set) + the line-0 key is not in `l0Keys` (the `continue`). The new impl matches byte-identically. The red control: a prefix-gated variant (no `first` flag) returns `l1Key == ""` + double-counts the line-0 key into `l0Keys` → diverges on both → proves the `first` flag + the `continue` are load-bearing. Green.
- **T-STREAM-READ-BODY (`internal/database`):** `readManifestBody` over a real `io.Reader` byte-identical to `io.ReadAll` across empty/tiny/fits-4096/grow-8000/grow-20000 bodies + a fragmenting reader (7 bytes/Read). The read-axis byte-identity guard (composes with the parse-axis `T-STREAM-BYTE-IDENTITY`). Green.
- **T-STREAM-UNCHANGED (`internal/database`):** `Counters()` still 17 distinct (this change adds no counter — a pure refactor, like the earlier `Seek` pass, which also added none). The earlier `wantDistinct` counter teeth stay at 17 with no update. The bridge auto-surfaces no new series. Green.
- **T-STREAM-LOADSUPERSEDED-REALLocalFS (`pkg/durability`, the composition tooth):** a real `Compaction()` over a real `*LocalFS` → 1 L1 + 1 manifest (firstSys==base). An `AsOf` at txTime=base+1500 (manifest not skipped — firstSys==base <= base+1500) drives `loadSupersededL0Keys`: the manifest is downloaded (the `manifestCountingLocalFS` wrapper's `manifestDLs==1` — the new `readManifestBody`+`ParseManifest` ran, not the ADR-0030 skip) + parsed → the 4 L0s are marked superseded (`l0DLs==0`, the supersession contract through the new parse) → the dominant is `base+1000` `"row-1"`, byte-identical to the pre-change baseline. Green.

**The writer-unchanged guards:** `l1_compactor.go` is the one edited durable-read file — the reader changed; the writer (`buildManifest` + `manifestKeyFor`) is byte-unchanged (verified by substring guards over the writer functions, finer than a whole-file hash). The other durable-read files (`l0_flusher.go`, `skiplist_arena.go`, `telemetry_bridge.go`) stay byte-unchanged. Green.

## §6. Future work (the honest deferred work, not this change)

- **§6.a — the `l0Key` string copies are irreducible if the API stays `[]string`.** The callers store `l0Keys` as `map[string]struct{}` keys — slices are not comparable, so `[][]byte` (sub-slices of the body buffer) cannot be the map key. A `[][]byte` return + a string-key-ified intermediate at the use site would add allocs + change the API — net worse (the §0.b analysis). This change keeps `[]string` + the one `string(body)` copy (the substring appends alias it). Disclosed: the headline is the parse-overhead + read-overhead elimination, not "0 allocs" — the `string(body)` copy + the `l0Keys` slice + the read buffer are the irreducible minimum.
- **§6.b — the reaper's parse was never a hot surface.** The reaper (`l0_reaper.go`) is a 5-min-sweep maintenance job (ADR-0021 §3) — one probe per manifest per sweep. The alloc-zeroing there is honest hygiene, not a latency win. The latency win is the `loadSupersededL0Keys` caller (per-query), disclosed honestly. This change swaps the reaper's caller for API consistency (one parser, one reader) + the hygiene win, not a claimed hot-path win.
- **§6.c — the zero-buffer variant (scan over a `memory.Allocator`-backed buffer, no Go-heap body) is future work if the manifest bodies grow large — they don't (2990B observed).** YAGNI. This change targets the parse-alloc-to-minimum + the read-alloc-to-minimum, the honest minimum; it does not build the speculative zero-Go-heap variant.
- **§6.d — the `Seek` primitive stays dormant.** Its first production consumer (the live cross-entity tail — the Resolver↔MemTable seam) is future work: it touches the write-path freeze/Free lifecycle and is accordingly the higher-risk change, deferred in favor of closing this read-path residual first.

## §7. The premise-audit (the measured-before-code record)

- **M1 (load-bearing — the §0.b honesty gate, measured before code):** the initial candidate (`bytes.IndexByte` + `string(line)` per L0) is refuted — 3–29× worse on allocs (§0.a). The honesty gate kills it; the honest replacement (`stringScan` — keep the one `string(body)` copy, drop the Split slice) is what shipped. The `T-STREAM-ALLOC` tooth makes the rejection executable.
- **M2:** `strings.TrimSpace`/`bytes.TrimSpace` are zero-alloc (sub-string/sub-slice). The trimmed-line step is not the alloc source.
- **M3:** the malformed-body behavior (the `first`-line unconditional-set + the stray-line defense-in-depth) is preserved exactly — pinned by `T-STREAM-BYTE-IDENTITY` + `T-STREAM-RED-CONTROL`.
- **M4 (count-growth):** this change adds no counter — the counter set stays at 17 (a pure refactor; the earlier `Seek` pure-refactor likewise added none). No count-assertion update. The bridge is byte-unchanged.

## §8. The gate (byte-verified)

`go build ./...` exit 0; `gofmt` clean on all touched files; `go vet` clean on `internal/database` (the edited function is vet-safe — no new `unsafe`). `fieldalignment`: `internal/database == 11` findings unchanged (`ParseManifest` + `readManifestBody` are funcs, not structs — zero field change; the 11==11 baseline holds), `internal/telemetry == 1` unchanged, `pkg/metrics == 0` unchanged — zero new debt across all three packages. **The five core files unchanged**; the durable-read producer files byte-unchanged except `l1_compactor.go` (the reader changed, the writers byte-unchanged). `TestHotPathZeroAllocations` green (this change is read path + reaper, not the write path). The existing byte-identity suites over real `*LocalFS` green (the `stringScan` `ParseManifest` is byte-identical to the old `strings.Split` across the full read path). `-race` per-package clean (measured on a 4-core box).

§5 stays conditionally approved: no core file touched, and the follow-on Resolver↔MemTable work — which does touch the write path — is disclosed as the higher-risk change this one deferred.

## §9. The decision

1. `feat(database)`: zero-alloc-line streaming `ParseManifest` (`l1_compactor.go` `ParseManifest` `stringScan` body + `readManifestBody` + the 3 caller-site `io.ReadAll` swaps + the teeth).
2. `docs`: this ADR (the ADR-0030 §6.a residual closed; the Resolver↔MemTable tail remains the open item; `fieldalignment` `internal/database == 11` unchanged).

**No behavioral flip in this change:** it replaces an implementation + swaps the 3 callers' read helper; the `ParseManifest` signature is byte-identical; the `buildManifest` writer + the `manifestKeyFor` key writer are byte-unchanged; the ADR-0030 manifest-skip contract is preserved (the skip is byte-identical — the non-skipped parse is the one this change zeroed). The bridge is byte-unchanged (§0.f — no new series to surface). The `l1_compactor.go` reader is the only durable-read file that changed (the writers byte-unchanged).
