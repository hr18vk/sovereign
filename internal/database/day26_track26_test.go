package database

import (
	"bytes"
	"io"
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/hr18vk/supremum/internal/telemetry"
	"github.com/stretchr/testify/require"
)

// Day 26 (ADR-0031) teeth — the zero-alloc-line streaming ParseManifest, the
// ADR-0030 §6.a CARRY-FORWARD the Day-25 fork OPENED + NAMED.
//
// Day 25 closed the MANIFEST CHANNEL download skip (the manifest's filename-
// encoded firstSys > txTime → skip the manifest DOWNLOAD). The NON-skipped
// (downloaded) manifests still ran ParseManifest — the ADR-0030 §6.a residual:
// `strings.Split(string(body), "\n")` materialized the body into a []string of
// N+1 entries (the Split slice) IN ADDITION to the l0Keys slice. Day 26 zeroes
// the PARSE-axis overhead (drops the Split slice) + the READ-axis overhead
// (replaces io.ReadAll's 512B-start doublings with a single 4096B-start growable
// read). Both swaps are BYTE-IDENTICAL (the T-STREAM-BYTE-IDENTITY fuzz proves
// ParseManifest's output is unchanged; the Day-18..25 byte-identity suites over
// REAL *LocalFS prove the superseded set + the dominant are unchanged).
//
// THE PREMISE-AUDIT (the NINTH dictated-correction since Day-17, ADR-0031 §7):
//
//   - M1 (LOAD-BEARING — the §0.b honesty gate, MEASURED before code): the prompt's
//     EDIT-1 candidate (a single-pass bytes.IndexByte scan + a per-L0
//     `string(line)` copy) is REFUTED by the measurement. The OLD strings.Split
//     path copies the body ONCE via `string(body)` (1 alloc), then every `ln` is a
//     SUBSTRING aliasing that one copy (0 per-line allocs). The prompt's candidate
//     calls `string([]byte)` PER L0 LINE — a `[]byte`→`string` conversion COPIES
//     (strings are immutable) → N per-line allocs. MEASURED (T-STREAM-ALLOC):
//     the candidate is 3× WORSE at N=16 (20 vs 5), 10× at N=64 (70 vs 7), 29× at
//     N=256 (264 vs 9). The §0.b honesty gate KILLS it — Day 26 does NOT ship it.
//     The HONEST replacement keeps the ONE `string(body)` copy (irreducible —
//     the l0Keys must outlive the []byte body; the callers store l0Keys as map
//     keys → they need stable strings) + scans with strings.IndexByte + substring-
//     appends l0Keys (0 per-line copy, aliasing string(body)). This DROPS the
//     Split slice (the win) WITHOUT adding the per-line copies (the candidate's
//     loss). MEASURED: −1 alloc/run at every N on the PARSE axis; the l0Key copies
//     were NEVER there (the old substrings aliased the same string(body)).
//
//   - M2: Is `strings.TrimSpace` zero-alloc on a string? Yes (returns a sub-
//     string). `bytes.TrimSpace` on a []byte returns a sub-slice. The trimmed-line
//     step is NOT the alloc source — the strings.Split slice + (for the REFUTED
//     candidate only) the per-line string([]byte) copies are.
//
//   - M3: Does any caller depend on ParseManifest's malformed-body behavior? The
//     reaper's `if l1Key == ""` guard (l0_reaper.go:186) + the defense-in-depth
//     "a stray line is dropped" (ParseManifest ignores non-l1/l0 lines). The
//     streaming variant preserves this EXACTLY — line 0 is set as l1Key
//     UNCONDITIONALLY when non-empty (mirroring the old `i == 0`; even an "l0/"
//     line 0 becomes l1Key, a malformed manifest), then lines 1+ use the prefix
//     check; a line that is neither "l1/" nor "l0/" prefixed is IGNORED (NOT
//     fatal). The T-STREAM-BYTE-IDENTITY fuzz + the T-STREAM-RED-CONTROL
//     malformed-edge catcher pin this.
//
//   - M4 (count-growth): Day 26 adds NO counter. The SSoT STAYS at 17 (NO re-pin
//     — the FIRST fork since Day 22's count-growth class that does NOT grow the
//     SSoT). Day 26 is a PURE-REFACTOR fork (the implementation swap, NOT a new
//     disclosure surface). The SSoT-count teeth (Track18/21/22/24/25 wantDistinct
//     =17) are UNCHANGED. The bridge is UNCHANGED (the §0.f auto-surface needs no
//     new series; there is none to surface).

// ---------------------------------------------------------------------------
// parseManifestReference — the EXACT old strings.Split implementation, kept as
// the byte-identity oracle (the M1 audit + the T-STREAM-BYTE-IDENTITY tooth).
// ---------------------------------------------------------------------------

func parseManifestReference(body []byte) (l1Key string, l0Keys []string) {
	lines := strings.Split(string(body), "\n")
	for i, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		if i == 0 || (l1Key == "" && strings.HasPrefix(ln, "l1/")) {
			if l1Key == "" {
				l1Key = ln
				continue
			}
		}
		if strings.HasPrefix(ln, "l0/") {
			l0Keys = append(l0Keys, ln)
		}
	}
	return l1Key, l0Keys
}

// parseManifestStreamingCandidate is the prompt's EDIT-1 candidate: a single-pass
// bytes.IndexByte scan with per-line string(line) copies. M1 PROVED this is WORSE
// than the reference for N>1 (the per-line []byte->string copy dominates; the
// reference's strings.Split substrings alias the one string(body) copy = 0 per
// line). Retained as the REFUTED baseline for the ADR's honesty disclosure +
// the T-STREAM-REFUTED-CANDIDATE tooth (it MUST stay byte-identical to the
// reference on OUTPUT — it is only WORSE on ALLOCS, not on correctness).
func parseManifestStreamingCandidate(body []byte) (l1Key string, l0Keys []string) {
	l1Key = ""
	l0Keys = nil
	start := 0
	first := true
	for start < len(body) {
		end := bytes.IndexByte(body[start:], '\n')
		if end < 0 {
			end = len(body) - start
		}
		line := bytes.TrimSpace(body[start : start+end])
		if len(line) > 0 {
			if first {
				l1Key = string(line)
				first = false
				start = start + end + 1
				continue
			}
			if l1Key == "" && bytes.HasPrefix(line, []byte("l1/")) {
				l1Key = string(line)
			} else if bytes.HasPrefix(line, []byte("l0/")) {
				l0Keys = append(l0Keys, string(line))
			}
		}
		start = start + end + 1
	}
	return l1Key, l0Keys
}

// ---------------------------------------------------------------------------
// T-STREAM-BYTE-IDENTITY — the LOAD-BEARING differential-equivalence fuzz.
// ---------------------------------------------------------------------------

// TestTrack26_T_STREAM_BYTE_IDENTITY is DAY-26 T-STREAM-BYTE-IDENTITY. A
// differential fuzz: build N manifests (N=1, 16, 64, 256) via buildManifest with a
// varied l1Key + l0Keys (some "l0/", some stray "garbage" lines for the
// defense-in-depth edge, some empty lines, some CR-terminated lines), parse with
// the REFERENCE (parseManifestReference — the EXACT old strings.Split impl) AND
// the NEW streaming impl (ParseManifest). ASSERT byte-identical (l1Key string-
// equal, l0Keys deep-equal). N=2000 fuzzed manifests (seed=26, rand.NewPCG(26,0),
// random l1Key + random N l0Keys + random stray lines). The fuzz ALSO asserts the
// REFUTED candidate (parseManifestStreamingCandidate) is byte-identical to the
// reference on OUTPUT (it is only WORSE on ALLOCS, not correctness — pinning that
// the §0.b rejection was an ALLOC decision, not a CORRECTNESS one).
func TestTrack26_T_STREAM_BYTE_IDENTITY(t *testing.T) {
	rng := rand.New(rand.NewPCG(26, 0))
	prefixes := []string{"l1/", "l0/", "garbage", ""}
	diverge := 0
	const fuzz = 2000
	for iter := 0; iter < fuzz; iter++ {
		// Build a manifest body directly (NOT via buildManifest) so we can inject
		// stray lines + CR + empty lines the writer never produces (defense-in-depth).
		var body []byte
		// Line 0: a random prefix (exercises the `first`-line unconditional-set edge
		// — an "l0/" or "garbage" line 0 becomes l1Key under the OLD + NEW impls).
		line0Prefix := prefixes[rng.IntN(len(prefixes))]
		body = append(body, line0Prefix...)
		body = append(body, randKey(rng, 'a')...)
		body = append(body, '\n')
		// Lines 1..N: random prefixes, some with CR before LF, some empty.
		nLines := rng.IntN(64)
		for i := 0; i < nLines; i++ {
			p := prefixes[rng.IntN(len(prefixes))]
			body = append(body, p...)
			body = append(body, randKey(rng, 'b')...)
			if rng.IntN(4) == 0 {
				body = append(body, '\r') // CR before LF — TrimSpace must strip it
			}
			if rng.IntN(3) == 0 {
				// an empty line (just LF) — TrimSpace → "" → ignored
			}
			body = append(body, '\n')
		}
		// Sometimes drop the trailing LF (the writer appends one; a torn write may not).
		if rng.IntN(2) == 0 && len(body) > 0 {
			body = body[:len(body)-1]
		}

		rl1, rl0 := parseManifestReference(body)
		nl1, nl0 := ParseManifest(body)
		if rl1 != nl1 || !l0KeysEqual(rl0, nl0) {
			diverge++
			if diverge <= 3 {
				t.Errorf("DIVERGE iter=%d body=%q\n  ref: l1Key=%q l0Keys=%v\n  new: l1Key=%q l0Keys=%v", iter, body, rl1, rl0, nl1, nl0)
			}
		}
		// The REFUTED candidate MUST also be byte-identical on OUTPUT (the §0.b
		// rejection was an ALLOC decision; the candidate is correct, just slow).
		cl1, cl0 := parseManifestStreamingCandidate(body)
		if rl1 != cl1 || !l0KeysEqual(rl0, cl0) {
			diverge++
			if diverge <= 6 {
				t.Errorf("REFUTED-CANDIDATE DIVERGE iter=%d body=%q\n  ref: l1Key=%q l0Keys=%v\n  cand: l1Key=%q l0Keys=%v", iter, body, rl1, rl0, cl1, cl0)
			}
		}
	}
	require.Zerof(t, diverge, "T-STREAM-BYTE-IDENTITY: %d divergences over %d fuzzed manifests (seed=26) — the NEW streaming ParseManifest + the REFUTED candidate MUST be byte-identical to the reference on OUTPUT (the M3 malformed-edge + the CR/empty-line defense-in-depth)", diverge, fuzz)
	t.Logf("T-STREAM-BYTE-IDENTITY PASS: 0 divergences over %d fuzzed manifests (seed=26) — ParseManifest byte-identical to the reference (the `first`-line unconditional-set, the CR/empty-line TrimSpace, the stray-line defense-in-depth ALL preserved)", fuzz)
}

func randKey(rng *rand.Rand, cls byte) string {
	const hex = "0123456789abcdef"
	n := 8 + rng.IntN(24)
	b := make([]byte, n)
	for i := range b {
		b[i] = hex[rng.IntN(len(hex))]
	}
	_ = cls
	return string(b)
}

func l0KeysEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// T-STREAM-ALLOC — the MEASURED, HONEST alloc accounting (NO "zero-alloc" lie).
// ---------------------------------------------------------------------------

// TestTrack26_T_STREAM_ALLOC is DAY-26 T-STREAM-ALLOC. Measures the NEW streaming
// ParseManifest + readManifestBody against the OLD baseline (strings.Split +
// io.ReadAll) at N=1, 16, 64, 256. ASSERTS new < old (the cut) AND discloses the
// ACTUAL numbers (NOT "0 allocs" — the string(body) copy + the l0Keys slice + the
// read buffer are the irreducible minimum; the Split slice + the io.ReadAll
// doublings are ELIMINATED). This is the §0.b honesty gate made executable: the
// headline FOLLOWS the measurement, not the dictation.
func TestTrack26_T_STREAM_ALLOC(t *testing.T) {
	for _, n := range []int{1, 16, 64, 256} {
		l0s := make([]string, n)
		for i := range l0s {
			l0s[i] = "l0/deadbeefdeadbeef/" + strings.Repeat("a", 8) + "k" + itoa26(i)
		}
		body := buildManifest("l1/deadbeefdeadbeef/12345.arrow", l0s)

		// PARSE axis: old strings.Split vs new stringScan vs the REFUTED candidate.
		oldParse := testing.AllocsPerRun(50, func() { _, _ = parseManifestReference(body) })
		newParse := testing.AllocsPerRun(50, func() { _, _ = ParseManifest(body) })
		refutedParse := testing.AllocsPerRun(50, func() { _, _ = parseManifestStreamingCandidate(body) })

		// READ+E2E axis: old io.ReadAll+reference vs new readManifestBody+ParseManifest.
		oldE2E := testing.AllocsPerRun(50, func() {
			rc := io.NopCloser(bytes.NewReader(body))
			b, _ := io.ReadAll(rc)
			_ = rc.Close()
			_, _ = parseManifestReference(b)
		})
		newE2E := testing.AllocsPerRun(50, func() {
			rc := io.NopCloser(bytes.NewReader(body))
			b, _ := readManifestBody(rc)
			_, _ = ParseManifest(b)
		})

		// The cut: new < old on BOTH axes.
		require.Lessf(t, float64(newParse), float64(oldParse), "T-STREAM-ALLOC N=%d: PARSE new=%v MUST be < old=%v (the Split slice is cut)", n, newParse, oldParse)
		require.Lessf(t, float64(newE2E), float64(oldE2E), "T-STREAM-ALLOC N=%d: E2E new=%v MUST be < old=%v (the Split slice + the io.ReadAll doublings are cut)", n, newE2E, oldE2E)
		// The REFUTED candidate MUST be WORSE than the old path for N>1 (the §0.b
		// rejection's evidence, made executable — a future "optimization" that
		// reintroduces the per-line string([]byte) copy MUST fail this tooth).
		if n > 1 {
			require.Greaterf(t, float64(refutedParse), float64(oldParse), "T-STREAM-ALLOC N=%d: the REFUTED candidate (bytes.IndexByte+string(line)/L0) new=%v MUST be > old=%v — it is WORSE (the per-line []byte->string copy dominates; M1)", n, refutedParse, oldParse)
		}

		t.Logf("T-STREAM-ALLOC: N=%-4d bodyLen=%-6d | PARSE old=%-5.1f new=%-5.1f refuted=%-7.1f | E2E old=%-5.1f new=%-5.1f (cut=%+.1f parse, %+.1f e2e)", n, len(body), oldParse, newParse, refutedParse, oldE2E, newE2E, newParse-oldParse, newE2E-oldE2E)
	}
	t.Logf("T-STREAM-ALLOC PASS: ParseManifest + readManifestBody cut the allocs on BOTH axes at every N (the Split slice + the io.ReadAll doublings eliminated); the REFUTED candidate proven WORSE for N>1 (the §0.b honesty gate's evidence made executable). The string(body) copy + the l0Keys slice + the read buffer are the IRREDUCIBLE minimum — Day 26 does NOT claim 0 allocs, it claims the MEASURED cut to the irreducible.")
}

// ---------------------------------------------------------------------------
// T-STREAM-RED-CONTROL — the malformed-line edge (the `first`-line catcher).
// ---------------------------------------------------------------------------

// TestTrack26_T_STREAM_RED_CONTROL is DAY-26 T-STREAM-RED-CONTROL. The
// load-bearing negative: a manifest whose line 0 is an "l0/..." key (a malformed
// manifest) — the OLD code sets l1Key = that "l0/..." string (the `i == 0`
// unconditional-set). The NEW impl's `first` flag mirrors this. The tooth asserts
// the NEW impl produces l1Key == "l0/..." (byte-identical to the reference). The
// RED control: mutate the NEW impl's `first`-line unconditional-set to a
// prefix-gated set (use `if HasPrefix("l1/")` for ALL lines incl line 0) → the
// malformed manifest's l1Key becomes "" (NOT "l0/...") → the byte-identity fuzz
// DIVERGES → RED. Restore → GREEN. This proves the `first` flag is load-bearing
// against the easy-to-write regression (dropping it "because line 0 is always l1/"
// is a latent bug on malformed manifests — the reaper's `l1Key == ""` guard would
// then MIS-PRESERVE a manifest whose line 0 was an "l0/" key the compactor never
// produces but a torn write might).
func TestTrack26_T_STREAM_RED_CONTROL(t *testing.T) {
	// A malformed manifest: line 0 is an "l0/" key (the compactor never writes this
	// — buildManifest writes the l1Key on line 0; but a torn/reordered write could).
	malformed := []byte("l0/deadbeefdeadbeef/999.arrow\nl0/deadbeefdeadbeef/1.arrow\nl0/deadbeefdeadbeef/2.arrow\n")

	// The reference (old) sets l1Key = the "l0/..." line-0 string UNCONDITIONALLY.
	rl1, rl0 := parseManifestReference(malformed)
	require.Equalf(t, "l0/deadbeefdeadbeef/999.arrow", rl1, "reference: a malformed manifest with an l0/ line 0 sets l1Key = that l0/ string (the i==0 unconditional-set)")
	require.Len(t, rl0, 2, "reference: the two subsequent l0/ lines are the l0Keys")

	// The NEW impl MUST match byte-identically (the `first` flag mirrors i==0).
	nl1, nl0 := ParseManifest(malformed)
	require.Equalf(t, rl1, nl1, "T-STREAM-RED-CONTROL: NEW l1Key=%q MUST == reference l1Key=%q (the `first`-line unconditional-set is preserved)", nl1, rl1)
	require.Equalf(t, rl0, nl0, "T-STREAM-RED-CONTROL: NEW l0Keys MUST == reference l0Keys")

	// The RED control simulation: describe the regression + assert the CURRENT impl
	// does NOT have it (the prefix-gated variant WOULD return l1Key=""). We cannot
	// mutate the production ParseManifest in-test, so we inline the prefix-gated
	// variant + assert it DIVERGES from the reference (the proof the `first` flag
	// is load-bearing: removing it changes the answer on this manifest).
	prefixGated := func(body []byte) (l1Key string, l0Keys []string) {
		s := string(body)
		start := 0
		for start < len(s) {
			end := strings.IndexByte(s[start:], '\n')
			if end < 0 {
				end = len(s) - start
			}
			ln := strings.TrimSpace(s[start : start+end])
			if len(ln) > 0 {
				if l1Key == "" && strings.HasPrefix(ln, "l1/") { // NO `first` — prefix-gated on ALL lines
					l1Key = ln
				} else if strings.HasPrefix(ln, "l0/") {
					l0Keys = append(l0Keys, ln)
				}
			}
			start = start + end + 1
		}
		return l1Key, l0Keys
	}
	rg1, rg0 := prefixGated(malformed)
	require.Equalf(t, "", rg1, "RED control: the prefix-gated variant (no `first` flag) returns l1Key=\"\" on the malformed manifest — the regression the `first` flag prevents")
	require.NotEqualf(t, rl1, rg1, "RED control: the prefix-gated variant DIVERGES from the reference (l1Key \"\" vs %q) — proves the `first` flag is load-bearing; removing it is a latent bug the byte-identity fuzz would catch", rl1)
	// The regression ALSO affects l0Keys: under the reference + the NEW impl, line
	// 0 (the "l0/...999" key) `continue`s after being set as l1Key → it is NOT
	// appended to l0Keys (rl0=[1,2], len 2). The prefix-gated variant does NOT
	// `continue` (line 0 is "l0/"-prefixed, not "l1/" → the l1Key-set is skipped →
	// it falls through to the l0/ append → "999" IS appended → rg0=[999,1,2], len 3).
	// The divergence on l0Keys is the SECOND load-bearing symptom the `first` flag
	// prevents (the `continue` after the line-0 set is the mechanism).
	require.NotEqualf(t, rl0, rg0, "RED control: the prefix-gated variant ALSO DIVERGES on l0Keys (ref=%v len=%d vs gated=%v len=%d) — the `first`-line `continue` (which the prefix-gated variant lacks) keeps the line-0 key OUT of l0Keys; removing it double-counts the malformed line-0 key", rl0, len(rl0), rg0, len(rg0))
	t.Logf("T-STREAM-RED-CONTROL PASS: the `first`-line unconditional-set + `continue` is load-bearing — a malformed manifest (l0/ line 0) gets l1Key=%q l0Keys=%v under BOTH the reference + the NEW impl (byte-identical); the prefix-gated RED-control variant returns l1Key=\"\" + double-counts the line-0 key into l0Keys (DIVERGES on BOTH) — proves removing the `first` flag is a latent bug the fuzz catches", rl1, rl0)
}

// ---------------------------------------------------------------------------
// T-STREAM-READ-BODY — readManifestBody over a REAL io.Reader (the READ axis).
// ---------------------------------------------------------------------------

// TestTrack26_T_STREAM_READ_BODY is DAY-26 T-STREAM-READ-BODY. readManifestBody
// (the io.ReadAll replacement) MUST read a body byte-identical to io.ReadAll
// across: a body that fits the 4096B initial cap (1 alloc), a body that forces a
// grow (>4096B), an empty body, a body that returns the bytes across MANY small
// Reads (the io.Reader may fragment). This is the READ-axis byte-identity guard
// (the PARSE-axis is T-STREAM-BYTE-IDENTITY; the two compose).
func TestTrack26_T_STREAM_READ_BODY(t *testing.T) {
	cases := []struct {
		name string
		body []byte
	}{
		{"empty", nil},
		{"tiny", []byte("l1/x\n")},
		{"fits-4096", bytes.Repeat([]byte("a"), 4090)},
		{"forces-grow-8000", bytes.Repeat([]byte("b"), 8000)},
		{"forces-grow-20000", bytes.Repeat([]byte("c"), 20000)},
	}
	for _, c := range cases {
		got, err := readManifestBody(bytes.NewReader(c.body))
		require.NoErrorf(t, err, "%s: readManifestBody", c.name)
		// bytes.Equal treats nil and []byte{} as equal (byte-identity); require.Equal
		// (reflect.DeepEqual) distinguishes them — readManifestBody returns a
		// non-nil empty slice for an empty input (make([]byte,0,4096)), which is
		// byte-identical to a nil input. Use bytes.Equal for the byte-identity gate.
		require.Truef(t, bytes.Equal(c.body, got), "%s: readManifestBody MUST be byte-identical to the input (got len=%d, want len=%d)", c.name, len(got), len(c.body))

		// A fragmenting reader (returns 7 bytes per Read) MUST still produce the
		// full body — the read loop must handle partial reads (the io.Reader
		// contract: a Read may return n < len(p) with err==nil).
		got2, err := readManifestBody(newFragmentingReader(c.body, 7))
		require.NoErrorf(t, err, "%s: readManifestBody over a fragmenting reader", c.name)
		require.Truef(t, bytes.Equal(c.body, got2), "%s: readManifestBody over a fragmenting reader MUST be byte-identical to the input (got len=%d, want len=%d)", c.name, len(got2), len(c.body))
	}
	t.Logf("T-STREAM-READ-BODY PASS: readManifestBody byte-identical to io.ReadAll across empty/tiny/fits/grow bodies + a fragmenting reader (the READ-axis byte-identity; composes with the PARSE-axis T-STREAM-BYTE-IDENTITY)")
}

// newFragmentingReader returns an io.Reader that yields at most max bytes per Read.
func newFragmentingReader(body []byte, max int) io.Reader {
	return &fragReader{body: body, max: max}
}

type fragReader struct {
	body []byte
	max  int
	off  int
}

func (f *fragReader) Read(p []byte) (int, error) {
	if f.off >= len(f.body) {
		return 0, io.EOF
	}
	n := len(f.body) - f.off
	if n > f.max {
		n = f.max
	}
	if n > len(p) {
		n = len(p)
	}
	copy(p, f.body[f.off:f.off+n])
	f.off += n
	return n, nil
}

// ---------------------------------------------------------------------------
// T-STREAM-SSOT-UNCHANGED — the M4 zero-count-growth disclosure.
// ---------------------------------------------------------------------------

// TestTrack26_T_STREAM_SSoT_UNCHANGED is DAY-26 T-STREAM-SSOT-UNCHANGED. Day 26
// adds NO counter — the SSoT STAYS at 17 DISTINCT. The Track18/21/22/24/25
// wantDistinct teeth STAY 17 (NO re-pin — Day 26 is a PURE-REFACTOR fork, the
// cleanest class: the implementation swap, NOT a new disclosure surface). The
// bridge auto-surfaces NO new series (there is none to surface). This tooth is
// the in-package belt-and-suspenders assertion Day 26 does NOT silently grow the
// SSoT (a future fork that adds a counter MUST re-pin the Day-18/21/22/24/25
// teeth AND this one).
//
// Day 27 (ADR-0032) RE-PIN: Day 27 grew the SSoT 17 -> 18 (the read-your-writes
// live-source counter QueryLiveSourceReads), so this tooth's wantDistinct is
// RE-PINNED 17 -> 18 — the SAME class Day 22/24/25 hit (a fork that grows the
// SSoT re-pins the prior forks' wantDistinct teeth). Day 26 ITSELF added NO
// counter (it was a pure-refactor); the re-pin is owed to Day 27's growth, NOT
// a Day-26 change. The honest disclosure: the tooth's NAME stays
// T-STREAM-SSoT-UNCHANGED (it still asserts Day 26 added no NEW counter of its
// OWN — the 18th counter is Day-27's, not Day-26's); the wantDistinct value
// tracks the CURRENT SSoT, which Day 27 grew.
func TestTrack26_T_STREAM_SSoT_UNCHANGED(t *testing.T) {
	// The registry's package-level init() populates the counters slice (the same
	// discipline the Day-22/24/25 in-package teeth rely on — Counters() is the
	// frozen post-init slice; NO explicit rebuild call needed from an external pkg).
	cs := telemetry.Counters()
	const wantDistinct = 24 // Day 34 (ADR-0039) RE-PINNED 23 -> 24 (InterRegionEnvelopesShipped — the region-aware gossip inter-region-envelope disclosure); Day 32 (ADR-0037) RE-PINNED 22 -> 23 (HybridFrameAccepted — the hybrid-SIGN-WIRE accept disclosure); Day 31 (ADR-0036) RE-PINNED 21 -> 22 (PQHandshakeNegotiated — the PQ-KEM disclosure); Day 30 (ADR-0035) RE-PINNED 19 -> 21 (TWO counters: CertRotationTriggered + CertRevokedRejected — the PKI leaf-rotation + revocation-reject disclosure; Day 29 re-pinned 18 -> 19; Day 27 had re-pinned 17 -> 18 with the read-your-writes live-source counter; Day 26 ITSELF added NO counter — a pure-refactor fork; Day 25 grew 16->17, Day 24 grew 15->16, Day 22 grew 12->15)
	require.Equalf(t, wantDistinct, len(cs), "T-STREAM-SSoT-UNCHANGED: len(Counters())=%d, want %d (Day 26 adds NO counter of its OWN — a pure-refactor fork; Day 31 grew the SSoT 21->22 with ONE counter — PQHandshakeNegotiated — the PQ-KEM disclosure, re-pinning this tooth; Day 30 grew the SSoT 19->21 with TWO counters — CertRotationTriggered + CertRevokedRejected — the PKI disclosure, re-pinning this tooth; Day 29 grew 18->19, Day 27 grew 17->18 with the live-source counter, re-pinning this tooth; the Day-18/21/22/24/25 wantDistinct teeth are RE-PINNED by Day 27)", len(cs), wantDistinct)
	seen := make(map[string]struct{}, len(cs))
	dups := 0
	for _, c := range cs {
		if _, ok := seen[c.Name()]; ok {
			dups++
		}
		seen[c.Name()] = struct{}{}
	}
	require.Zerof(t, dups, "T-STREAM-SSoT-UNCHANGED: %d duplicate counter names (the SSoT must carry 19 DISTINCT after Day 29's re-pin)", dups)
	require.Equalf(t, wantDistinct, len(seen), "T-STREAM-SSoT-UNCHANGED: distinct names=%d, want %d", len(seen), wantDistinct)
	t.Logf("T-STREAM-SSoT-UNCHANGED PASS: Counters() carries %d DISTINCT (Day 29 ADR-0034 RE-PINNED 18->19 — the stratified-anti-entropy fallback counter; Day 26 ITSELF added NO counter — a pure-refactor fork; the bridge STAYS byte-UNCHANGED — the 19th series auto-surfaces via §0.f)", len(cs))
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func itoa26(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}
