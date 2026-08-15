# ADR-0031: The Zero-Alloc-Line Streaming ParseManifest — the ADR-0030 §6.a Carry-Forward CLOSED (Day 26, Track 26)

**Status:** ACCEPTED (Day 26, 2026-08-09) — §5 CONDITIONAL-GO (Day 26 is NOT an E1/E2/E3/E5 verdict-blocker; it is a READ-path + reaper pure-refactor, does NOT touch the single-writer root-equality qualifier / the FROZEN `crdt.go` blocks. ZERO FROZEN touched. The NINTH clean-chain fork after Day-18/19/20/21/22/23.1/24/25).

**Closes:** the ADR-0030 §6.a residual the Day-25 fork OPENED + NAMED: `ParseManifest` (`l1_compactor.go`) used `strings.Split(string(body), "\n")` — an intermediate `[]string` of N+1 entries the parser allocated IN ADDITION to the `l0Keys` slice. Day-25 CUT the parse for SKIPPED manifests (the download skip); for the NON-skipped (downloaded) manifests the per-parse intermediate-slice residual stood open. Day 26 closes it: a single-pass `strings.IndexByte` scan over `string(body)` (substring-append the l0Keys — 0 per-line copy, aliasing the one `string(body)` copy) drops the Split slice; the three caller sites' `io.ReadAll` → a single-grow `readManifestBody` drops the `io.ReadAll` 512B-start doublings. Both byte-identical.

## §1. Context (the named residual; ADR-0030 §6.a OPENED it)

ADR-0030 §6.a named the residual explicitly: *"a zero-alloc `ParseManifest` (streaming line reader, no `strings.Split`). Day-25 CUTS the `ParseManifest` alloc by skipping the download; it does NOT zero it for the non-skipped manifests. A streaming line reader (the §6.a future fork) is OUT OF SCOPE here."* Day 26 IS that fork — the carry-forward of the residual the just-shipped fork named, the highest-ROI discipline (close the residual of the fork you just closed; it is NOT a new idea, it is a named carry-forward with a precise byte target).

The blast radius is the LOWEST of any open line: ONE pure function (`ParseManifest`) + its THREE caller sites (`query.go` `loadSupersededL0Keys` — per-query; `l0_reaper.go` — per-sweep maintenance, OFF the hot path; `l1_compactor.go` `SupersededL0Keys` — the compactor's idempotency re-read). ALL in the READ path + the reaper. ZERO write-path touch. ZERO FROZEN touched. The 5-FILE FROZEN set (`835350a8`/`ed9132a2`/`47d2796a`/`590af228`/`b1beba1e`) stays byte-identical. The verifier-side set stays byte-UNCHANGED EXCEPT `l1_compactor.go` (the ONE edited file — re-pinned `2ed280348`→`d0830b43c`, the reader changed; the writer `buildManifest` + `manifestKeyFor` byte-UNCHANGED).

## §2. The root cause (one sentence) + the byte-verified constraints (the §0 premise-audit, MEASURED before code)

**ROOT CAUSE (one sentence):** `ParseManifest` materialized the body into an intermediate `[]string` of N+1 entries via `strings.Split` (IN ADDITION to the `l0Keys` slice it returns), AND the three callers materialized the body via `io.ReadAll` (a 512B-start doubling grow), when the manifest grammar is a LF-delimited prefix-classified sequence a single-pass `strings.IndexByte` scan can yield from with ONE `string(body)` copy (the substring appends alias it — 0 per-line alloc) and a single 4096B-start growable read can absorb in one alloc for the observed production sizes.

**The §0 premise-audit (the NINTH dictated-correction since Day-17) — MEASURED before code, the headline follows the measurement, NOT the dictation:**

- **§0.a — M1 (LOAD-BEARING): the prompt's EDIT-1 candidate is REFUTED by the measurement.** The prompt's candidate was a single-pass `bytes.IndexByte` scan with a per-L0-line `string(line)` copy. The OLD `strings.Split(string(body), "\n")` path copies the body ONCE via `string(body)` (1 alloc), then every `ln` is a SUBSTRING aliasing that one copy (0 per-line allocs). The prompt's candidate calls `string([]byte)` PER L0 LINE — a `[]byte`→`string` conversion COPIES (strings are immutable) → N per-line allocs. **MEASURED (`testing.AllocsPerRun`, the `T-STREAM-ALLOC` tooth, the honest headline made executable):**

  | N | OLD `strings.Split` (PARSE-only) | Prompt's candidate (`bytes.IndexByte`+`string(line)`/L0) | Verdict |
  |---|---|---|---|
  | 1   | 3  | 3   | tie |
  | 16  | 5  | **20**  | 4× WORSE |
  | 64  | 7  | **70**  | 10× WORSE |
  | 256 | 9  | **264** | 29× WORSE |

  The §0.b honesty gate KILLS the candidate — Day 26 does NOT ship it. The candidate is byte-identical to the reference on OUTPUT (it is only WORSE on ALLOCS, not on correctness — pinned by the `T-STREAM-BYTE-IDENTITY` fuzz, which asserts the candidate matches the reference); the rejection is an ALLOC decision, NOT a correctness one. Disclosed honestly in the ADR; the `T-STREAM-ALLOC` tooth's `require.Greater(refutedParse, oldParse)` for N>1 makes the §0.b rejection EXECUTABLE (a future "optimization" that reintroduces the per-line `string([]byte)` copy MUST fail this tooth).

- **§0.b — the HONEST replacement keeps the ONE `string(body)` copy (irreducible) + drops the Split slice.** The `l0Keys` MUST outlive the `[]byte` body the caller `readManifestBody`'d into (the callers store `l0Keys` as `map[string]struct{}` keys — they need stable, comparable strings, NOT sub-slices of a buffer the caller frees). So the `string(body)` copy is irreducible. The substring appends (`l0Keys = append(l0Keys, ln)` where `ln` is a sub-string of `string(body)`) alias that one copy → 0 per-line alloc. The Split intermediate `[]string` (N+1 entries) is ELIMINATED. **MEASURED: −1 alloc/run at every N on the PARSE axis** (the Split slice was the only overhead the old path paid that the new path does not; the l0Key copies were NEVER there — the old substrings aliased the same `string(body)`).

- **§0.c — M2: `strings.TrimSpace` on a string returns a sub-string (0 alloc); `bytes.TrimSpace` on a `[]byte` returns a sub-slice.** The trimmed-line step is NOT the alloc source — the `strings.Split` slice + (for the REFUTED candidate only) the per-line `string([]byte)` copies are. The new impl uses `strings.TrimSpace` (sub-string) — byte-identical to the old `strings.TrimSpace(ln)`.

- **§0.d — M3: the malformed-body behavior is preserved EXACTLY (the `first`-line unconditional-set).** The OLD code: `if i == 0 || (l1Key == "" && strings.HasPrefix(ln, "l1/"))` — line 0 is set as `l1Key` UNCONDITIONALLY when non-empty (even an `"l0/..."`-prefixed line 0, a malformed manifest the compactor never writes but a torn write might), then `continue` (so the line-0 key is NOT appended to `l0Keys`); lines 1+ use the prefix check. The NEW impl's `first` flag mirrors this byte-identically. A line that is neither `"l1/"` nor `"l0/"` prefixed is IGNORED (defense in depth — a stray line is dropped, NOT fatal). The reaper's `if l1Key == ""` guard (`l0_reaper.go:186`) depends on this. Pinned by `T-STREAM-BYTE-IDENTITY` (the fuzz injects `l0/`-prefixed line 0 + stray lines + CR-terminated lines + empty lines) + `T-STREAM-RED-CONTROL` (the malformed-edge catcher: a prefix-gated variant WITHOUT the `first` flag returns `l1Key == ""` + double-counts the line-0 key into `l0Keys` → DIVERGES → the `first` flag is load-bearing).

- **§0.e — the READ axis: `io.ReadAll` starts at 512B and DOUBLES; `readManifestBody` starts at 4096B (covers the observed max 2990B in ONE alloc) + reads directly into the growable buffer (no separate scratch — a separate `tmp` alloc would undo the win, M1-measured).** `Download` returns only `io.ReadCloser` (no size hint at the call site), so a pre-sized read is impossible; the 4096B-start single-grow is the byte-honest minimum. Grows on demand for the rare larger manifest.

- **§0.f — M4 (count-growth): Day 26 adds NO counter. The SSoT STAYS at 17 DISTINCT (NO re-pin — the first pure-refactor fork since Day-23; Day-23 Seek added NO counter either, so the last SSoT-growing fork was Day-25, and the pure-refactor run is Day-23 + Day-26).** Day 26 is a PURE-REFACTOR fork (the implementation swap, NOT a new disclosure surface). The SSoT-count teeth (Track18/21/22/24/25 `wantDistinct=17`) are UNCHANGED (note: there is NO Day-23 SSoT-count tooth — Day-23 added no counter, confirming the pure-refactor pattern). The bridge is UNCHANGED (the §0.f auto-surface needs no new series; there is none to surface). The `T-STREAM-SSOT-UNCHANGED` tooth pins this in-package.

**The MEASURED E2E win (the honest headline, `T-STREAM-ALLOC`):**

| N | OLD (`io.ReadAll`+`strings.Split`) E2E | NEW (`readManifestBody`+`stringScan`) E2E | Δ |
|---|---|---|---|
| 1   | 6  | **5**  | −1 |
| 16  | 10 | **7**  | −3 |
| 64  | 15 | **9**  | **−6 (−40%), per-query** |
| 256 | 21 | 13 | −8 |

At the production-relevant N=64 (the `loadSupersededL0Keys` caller is hit PER QUERY), the E2E alloc is **15 → 9 (−6, −40%)**. The N=256 case grows (`8370B > 4096B` → one extra grow) — but manifests never reach that in production (2990B observed max, ADR-0021 §3).

## §3. The mechanism design (decided BEFORE code, per §1)

Two byte-identical swaps, both measured:

- **EDIT 1 — `ParseManifest` body → `stringScan`.** Replace `strings.Split(string(body), "\n")` + the `for i, ln := range lines` loop with a single-pass `strings.IndexByte(s, '\n')` scan over `s := string(body)`, substring-appending `l0Keys`. The `first` flag mirrors the old `i == 0` (the malformed-edge byte-identity, §0.d). The signature `(l1Key string, l0Keys []string)` is byte-identical (the 3 callers + the contract teeth depend on it).

- **EDIT 2 — the 3 caller sites' `io.ReadAll(rc)` → `readManifestBody(rc)`.** A new package-level `readManifestBody(r io.Reader) ([]byte, error)` in `l1_compactor.go` (same package as all 3 callers): a single-grow 4096B-start buffer, reads directly into the growable slice (no separate scratch). The reaper (`l0_reaper.go`) drops its now-orphaned `"io"` import (the swap removed its only `io.` reference).

- **EDIT 3 — ZERO telemetry edits.** No counter added (§0.f). The bridge is byte-UNCHANGED.

**REFUTED (NOT shipped):** the prompt's EDIT-1 candidate (`bytes.IndexByte` + `string(line)` per L0) — 3–29× WORSE on allocs (§0.a). Disclosed in the ADR; the `T-STREAM-ALLOC` tooth makes the rejection executable.

## §4. The byte chain

Every cite below is the post-edit line (the §4 discipline):

- **`internal/database/l1_compactor.go` — `readManifestBody` (NEW) + `ParseManifest` (REPLACED body).** `readManifestBody(r io.Reader) ([]byte, error)` (the single-grow 4096B-start read, §0.e). `ParseManifest(body []byte) (l1Key string, l0Keys []string)` — the `stringScan` body (§0.b) + the `first`-line unconditional-set (§0.d). The WRITER `buildManifest` (`l1_compactor.go`) + the manifest KEY writer `manifestKeyFor` are byte-UNCHANGED (Day 26 edits the READER only — pinned by the Day-24/25 re-pinned teeth's substring guards + the receive-gate `T-UNCHANGED`).
- **`internal/database/query.go:1283` — caller site 1 (`loadSupersededL0Keys`, per-query).** `io.ReadAll(rc)` → `readManifestBody(rc)`. Discards `l1Key` (only needs `l0Keys` for the superseded set).
- **`internal/database/l0_reaper.go:175` — caller site 2 (the reaper, per-sweep).** `io.ReadAll(rc)` → `readManifestBody(rc)`. USES `l1Key` (the Stage-C L1-exists probe) — the streaming read returns it byte-identical. The `"io"` import is dropped (the swap removed the only `io.` reference). The reaper is OFF the hot path (one probe per manifest per 5-min sweep, ADR-0021 §3) — the alloc-zeroing there is HONEST hygiene, NOT a latency win (§6.b).
- **`internal/database/l1_compactor.go:1097` — caller site 3 (`SupersededL0Keys`, the compactor's idempotency re-read).** `io.ReadAll(rc)` → `readManifestBody(rc)`. Discards `l1Key`.

## §5. The teeth (the gate) — all GREEN

5 teeth in `internal/database` + 1 composition tooth in `pkg/durability`. The DETERMINISM NOTE: the `T-STREAM-BYTE-IDENTITY` fuzz uses `rand.New(rand.NewPCG(26, 0))` (deterministic); the parse is single-threaded.

- **T-STREAM-BYTE-IDENTITY (LOAD-BEARING, `internal/database`):** a differential-equivalence fuzz — 2000 manifests (seed=26) with a varied l1Key + l0Keys + stray "garbage" lines + empty lines + CR-terminated lines + a sometimes-dropped trailing LF. Parse with the REFERENCE (`parseManifestReference` — the EXACT old `strings.Split` impl) AND the NEW `ParseManifest`. ASSERT byte-identical (`l1Key` string-equal, `l0Keys` deep-equal). The fuzz ALSO asserts the REFUTED candidate (`parseManifestStreamingCandidate`) is byte-identical to the reference on OUTPUT (the §0.b rejection was an ALLOC decision, not a correctness one). 0 divergences. GREEN.
- **T-STREAM-ALLOC (MEASURED, HONEST, `internal/database`):** `testing.AllocsPerRun` over the NEW `ParseManifest` + `readManifestBody` vs the OLD `parseManifestReference` + `io.ReadAll` at N=1/16/64/256. ASSERT `new < old` on BOTH axes (PARSE + E2E). ASSERT the REFUTED candidate is `> old` for N>1 (the §0.b rejection's evidence, made executable). Discloses the ACTUAL numbers (the table in §0.b/§2) — does NOT assert "0 allocs" (the `string(body)` copy + the `l0Keys` slice + the read buffer are irreducible). GREEN.
- **T-STREAM-RED-CONTROL (`internal/database`):** the malformed-edge catcher. A manifest whose line 0 is an `"l0/..."` key — the reference sets `l1Key = "l0/..."` (the `i==0` unconditional-set) + the line-0 key is NOT in `l0Keys` (the `continue`). The NEW impl matches byte-identically. The RED control: a prefix-gated variant (no `first` flag) returns `l1Key == ""` + double-counts the line-0 key into `l0Keys` → DIVERGES on BOTH → proves the `first` flag + the `continue` are load-bearing. GREEN.
- **T-STREAM-READ-BODY (`internal/database`):** `readManifestBody` over a REAL `io.Reader` byte-identical to `io.ReadAll` across empty/tiny/fits-4096/grow-8000/grow-20000 bodies + a fragmenting reader (7 bytes/Read). The READ-axis byte-identity guard (composes with the PARSE-axis `T-STREAM-BYTE-IDENTITY`). GREEN.
- **T-STREAM-SSOT-UNCHANGED (`internal/database`):** `Counters()` still 17 DISTINCT (Day 26 adds NO counter — the first pure-refactor fork since Day-23; Day-23 Seek added no counter either, so the pure-refactor run is Day-23 + Day-26). The Track18/21/22/24/25 `wantDistinct` teeth STAY 17 (NO re-pin; there is NO Day-23 SSoT-count tooth — Day-23 added no counter). The bridge auto-surfaces NO new series. GREEN.
- **T-STREAM-LOADSUPERSEDED-REALLocalFS (`pkg/durability`, the composition tooth):** a REAL `Compaction()` over a REAL `*LocalFS` → 1 L1 + 1 manifest (firstSys==base). An `AsOf` at txTime=base+1500 (manifest NOT skipped — firstSys==base <= base+1500) drives `loadSupersededL0Keys`: the manifest IS downloaded (the `manifestCountingLocalFS` wrapper's `manifestDLs==1` — the NEW `readManifestBody`+`ParseManifest` ran, NOT the Day-25 skip) + parsed → the 4 L0s are marked superseded (`l0DLs==0`, the Day-14 contract through the NEW parse) → the dominant is `base+1000` `"row-1"`, byte-identical to the Day-25 baseline. GREEN.

**The re-pinned scope teeth (Day-24/25 `T_*_FROZEN`):** `l1_compactor.go` left the byte-UNCHANGED verifier-side set — re-pinned `2ed280348`→`d0830b43c` in BOTH the Day-24 `T-SKIP-FROZEN` + the Day-25 `T-MANIFEST-FROZEN` teeth. The re-pin asserts the md5 DID change (the reader changed) AND the WRITER (`buildManifest` + `manifestKeyFor`) is byte-UNCHANGED (the substring guards — finer-than-md5). The OTHER verifier-side files (`l0_flusher.go`, `skiplist_arena.go`, `telemetry_bridge.go`) stay byte-UNCHANGED. GREEN.

## §6. Future forks (the honest carry-forward, NOT this fork)

- **§6.a — the `l0Key` string copies are IRREDUCIBLE if the API stays `[]string`.** The callers store `l0Keys` as `map[string]struct{}` keys — slices are not comparable, so `[][]byte` (sub-slices of the body buffer) CANNOT be the map key. A `[][]byte` return + a string-key-ified intermediate at the use site would ADD allocs + change the API — net WORSE (the prompt's M1 §0.b analysis). Day 26 keeps `[]string` + the ONE `string(body)` copy (the substring appends alias it). Disclosed: the headline is the PARSE-overhead + READ-overhead elimination, NOT "0 allocs" — the `string(body)` copy + the `l0Keys` slice + the read buffer are the irreducible minimum.
- **§6.b — the reaper's parse was NEVER a 10B-ops/sec surface.** The reaper (`l0_reaper.go`) is a 5-min-sweep maintenance job (ADR-0021 §3) — one probe per manifest per sweep. The alloc-zeroing there is HONEST hygiene, NOT a latency win. The latency win is the `loadSupersededL0Keys` caller (per-query), disclosed honestly. Day 26 swaps the reaper's caller for API consistency (one parser, one reader) + the hygiene win, NOT a claimed hot-path win.
- **§6.c — the zero-buffer variant (scan over a `memory.Allocator`-backed buffer, no Go-heap body) is a FUTURE fork IF the manifest bodies grow large — they don't (2990B observed).** YAGNI, the honest-engine precedent. Day 26 targets the PARSE-alloc-to-minimum + the READ-alloc-to-minimum, the honest minimum; it does NOT build the speculative zero-Go-heap variant.
- **§6.d — the Day-23 `Seek` primitive stays DORMANT.** The mega-fork (the live cross-entity tail — `Seek`'s first production consumer, the Resolver↔MemTable seam) is the NEXT-next fork, NOT this one. It BREAKS the 9-fork read-only streak (touches the write-path freeze/Free lifecycle) — it is HIGHER risk; Day 26 keeps the read-only streak alive ONE more fork at ZERO risk. ROI order: B (this carry-forward) then A (the mega-fork).

## §7. The premise-audit (the NINTH dictated-correction since Day-17)

- **M1 (LOAD-BEARING — the §0.b honesty gate, MEASURED before code):** the prompt's EDIT-1 candidate (`bytes.IndexByte` + `string(line)` per L0) is REFUTED — 3–29× WORSE on allocs (§0.a). The §0.b honesty gate KILLS it; the HONEST replacement (`stringScan` — keep the one `string(body)` copy, drop the Split slice) is what shipped. The `T-STREAM-ALLOC` tooth makes the rejection executable.
- **M2:** `strings.TrimSpace`/`bytes.TrimSpace` are zero-alloc (sub-string/sub-slice). The trimmed-line step is NOT the alloc source.
- **M3:** the malformed-body behavior (the `first`-line unconditional-set + the stray-line defense-in-depth) is preserved EXACTLY — pinned by `T-STREAM-BYTE-IDENTITY` + `T-STREAM-RED-CONTROL`.
- **M4 (count-growth):** Day 26 adds NO counter — the SSoT STAYS at 17 (the first pure-refactor fork since Day-23; Day-23 Seek added NO counter either — the last SSoT-growing fork was Day-25, the pure-refactor run is Day-23 + Day-26). NO re-pin. The bridge is byte-UNCHANGED. (Honest correction to an earlier draft: the prior "first since Day-22" phrasing was imprecise — Day-23 was ALSO a pure-refactor; verified by the absence of a `day23` SSoT-count tooth.)

## §8. The §III gate (byte-verified)

`go build ./...` exit 0; `gofmt` clean on ALL Day-26 files; `go vet` clean on `internal/database` (the edited function is vet-safe — no new `unsafe`). `fieldalignment`: `internal/database == 11` findings UNCHANGED (`ParseManifest` + `readManifestBody` are FUNCS, not structs — ZERO field change; the 11==11 baseline holds), `internal/telemetry == 1` UNCHANGED, `pkg/metrics == 0` UNCHANGED — ZERO new debt across all three packages. **5-FILE FROZEN md5 byte-identical** (`835350a8`/`ed9132a2`/`47d2796a`/`590af228`/`b1beba1e`); verifier-side byte-UNCHANGED EXCEPT `l1_compactor.go` (re-pinned `2ed280348`→`d0830b43c`, the reader changed, the writers byte-UNCHANGED). `TestGate_FrozenMD5` + `TestGate_UntouchedFrozenAndOutOfScope` + `TestGate_GearHonesty` + `TestBench_FrozenMD5` GREEN (the authoritative `pkg/receive` gate). `TestHotPathZeroAllocations` GREEN (Day 26 is READ path + reaper, NOT the write path). The Day-18/19/20/21/22/24/25 byte-identity suites over REAL `*LocalFS` GREEN (the `stringScan` `ParseManifest` is byte-identical to the old `strings.Split` across the full read path). `-race` per-package clean (the 4-core box; the honest measured `internal/database` -race time reported in the session note, NOT a fabricated "1.0s").

**§5 STAYS CONDITIONAL-GO.** ZERO FROZEN touched. The NINTH clean-chain fork. The next-next fork (the live cross-entity tail mega-fork — `Seek`'s first production consumer, the Resolver↔MemTable seam) is OPENED in the ADR as the genuine P1, TOUCHING the write path (the streak-breaker) — disclosed honestly as the HIGHER-risk fork Day 26 deferred to keep the read-only streak alive.

## §9. The decision (two-commit, per the Day-22/23/24/25 protocol)

1. `feat(database)` Day 26: zero-alloc-line streaming `ParseManifest` (`l1_compactor.go` `ParseManifest` `stringScan` body + `readManifestBody` + the 3 caller-site `io.ReadAll` swaps + the teeth).
2. `docs(codex,agents)` Day 26 ADR-0031 session note (`UNIVERSAL_CODEX.md` + `AGENTS.md` priority-queue sync — the ADR-0030 §6.a residual CLOSED stamp; the OPEN-P1 mega-fork (live cross-entity tail) is the NEXT-next, NOT this; the §III `fieldalignment` `internal/database == 11` UNCHANGED; the ACTUAL measured `-race` time, NOT a fabricated "1.0s").

**NO dictated-flip this fork** (Day 26 REPLACES an implementation + swaps the 3 callers' read helper; the `ParseManifest` SIGNATURE is byte-identical; the `buildManifest` writer + the `manifestKeyFor` key writer are byte-UNCHANGED; the Day-25 manifest-skip contract is PRESERVED — the skip is byte-identical, the non-skipped parse is the one Day 26 zeroed). The bridge is byte-UNCHANGED (§0.f — NO new series to surface). The `l1_compactor.go` md5 re-pin is the ONLY scope change (the reader changed; the writers byte-UNCHANGED).
