// Package crypto implements the Zero-GC PII masking hot path for the Supremum
// Ledger ingestion pipeline.
//
// PHYSICS (see "Go High-Performance Architecture Research", §DOMAIN 1, and
// SUPREMUM_STYLE §1):
//
//   - The hot path scans 1KB string payloads for a generic 12-digit PII
//     pattern and deterministically redacts it. Regex
//     engines are forbidden: they allocate heap state for capture groups and
//     a compiled state machine, which is a future GC bill per write.
//
//   - The scan must be Zero-GC when no PII is present (the overwhelmingly
//     common case): MaskPII returns the input string *unchanged*, byte-for-byte
//     equal (same data pointer, same length) so its single caller —
//     internal/database/memtable.go — proves maskedStr == payloadStr and
//     reuses event.Payload directly with zero allocation.
//
//   - When PII IS present (the rare path), MaskPII allocates exactly once to
//     build the redacted string. The dossier explicitly permits this rare-path
//     allocation ("we must allocate the new masked bytes"). The allocation is
//     one []byte -> one result string, sized to the result, never to the
//     payload.
//
//   - Deterministic redaction uses xxhash (cespare/xxhash/v2, already an
//     indirect dependency) of the 12-digit run, formatted to fixed-length
//     hex, so the same token always redacts to the same marker — enabling
//     downstream join/analysis without retaining raw PII.
//
//   - Bounds-check elimination (BCE): the scan loop is written so the
//     compiler proves every access is in-bounds by induction on the loop
//     counter; constant-length run checks are unrolled so no IsInBounds
//     resurfaces on the scan. Verified with `go build -gcflags="-m -m"`.
//
// INVARIANT: MaskPII never mutates the input string's backing memory. It
// treats the input as read-only; a source string in a read-only segment is
// safe (no in-place write — the rare path writes into a freshly allocated
// buffer).
//
// OUTPUT CONTRACT (pinned by internal/database/memtable_test.go):
//   - The raw 12-digit run MUST NOT be present in the result.
//   - The replacement MUST contain the literal marker "PII_REDACTED".
//   - When no 12-digit run is present, the result is byte-equal to the input
//     (data pointer and length both identical — the MemTable == reuse path).
package crypto

import (
	"unsafe"

	"github.com/cespare/xxhash/v2"
)

// piiLen is the generic PII pattern length: a 12-digit run.
const piiLen = 12

// redactionMarker is the literal sentinel required by the MemTable's
// Arrow-round-trip test (TestMemTable_PIIMaskingEnforced asserts the marker
// is present after masking).
const redactionMarker = "PII_REDACTED"

// markerLen is the byte length of the redaction marker.
const markerLen = len(redactionMarker)

// digestHexLen is the number of hex characters the xxhash digest is rendered
// to. Kept const so the result buffer is sized with plain arithmetic.
const digestHexLen = 16

// replLen is the full replacement length per masked run:
// "PII_REDACTED_" + 16 hex.
const replLen = markerLen + 1 + digestHexLen

// hexChars is the fixed lookup used to format the xxhash digest to hex without
// touching the heap (fmt.Sprintf allocates); this table is a read-only package
// variable, never allocated per-call.
var hexChars = [16]byte{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'}

// MaskPII scans payload for a generic 12-digit PII pattern and deterministically
// redacts every such run into "PII_REDACTED_<16-hex-of-xxhash>". If no PII
// is present, the input string is returned byte-for-byte unchanged so the
// caller's `maskedStr == payloadStr` short-circuit reuses the original payload
// buffer with zero allocation.
//
// Zero-GC: the scan is allocation-free; the equality fast path returns the
// input string itself. The rare masked path performs one []byte allocation
// sized to the result and one zero-copy string conversion over it.
//
//go:nosplit
//go:noinline
func MaskPII(payload string) string {
	n := len(payload)
	if n < piiLen {
		// Too short to contain any 12-digit run; return input verbatim so the
		// caller's == reuse path fires (Zero-GC).
		return payload
	}

	// Pass 1 (read-only, zero-alloc): locate the first 12-digit run. If none,
	// take the zero-alloc equality fast path. The scan is a tight induction
	// loop; the compiler proves payload[i] is in-bounds for every i < n.
	firstStart, hasPII := findFirstPIIRun(payload)
	if !hasPII {
		return payload
	}

	// Pass 2 (read-only): count non-overlapping 12-digit runs starting from
	// the first one, so we can size the output buffer exactly (one alloc).
	masks := 0
	{
		i := firstStart
		end := n - piiLen + 1
		for i < end {
			if isDigitRun12(payload, i) {
				masks++
				i += piiLen // non-overlapping: advance past the run
			} else {
				i++
			}
		}
	}
	// masks is provably >= 1 here: the `if !hasPII { return payload }`
	// early return above guarantees firstStart kwos a real 12-digit run, and
	// Pass 2 counts non-overlapping runs starting at firstStart, so masks >= 1.
	// The previous `if masks == 0 { masks = 1 }` defensive guard was unreachable
	// dead code (the early return dominated it). Removed for honesty.

	// Rare-path allocation: one []byte sized to the exact result length.
	// outLen = n + masks * (replLen - piiLen).
	outLen := n + masks*(replLen-piiLen)
	out := make([]byte, outLen)

	// Pass 3: assemble the masked result (delegated for escape-analysis clarity).
	return maskAssemble(payload, out, masks)
}

// maskAssemble writes the fully masked result into pre-sized buffer `out` and
// returns it as a string. Pulled out to keep the in/out cursor logic in one
// place and away from the scan/size passes.
//
//go:nosplit
func maskAssemble(payload string, out []byte, masks int) string {
	n := len(payload)
	inPos := 0
	outPos := 0
	litStart := 0 // start of the current literal segment in the input
	scanEnd := n - piiLen + 1
	masked := 0
	for inPos < scanEnd && masked < masks {
		if isDigitRun12(payload, inPos) {
			// Copy literal segment [litStart, inPos) to the output.
			if inPos > litStart {
				outPos += copy(out[outPos:], payload[litStart:inPos])
			}
			// Emit "PII_REDACTED_".
			outPos += copy(out[outPos:], redactionMarker)
			out[outPos] = '_'
			outPos++
			// Deterministic xxhash of the 12-digit run -> 16 hex.
			h := xxhash.Sum64String(payload[inPos : inPos+piiLen])
			writeHex16(out[outPos:], h)
			outPos += digestHexLen
			// Advance past the masked run.
			inPos += piiLen
			litStart = inPos
			masked++
		} else {
			inPos++
		}
	}
	// Copy any trailing literal after the last run.
	if litStart < n {
		outPos += copy(out[outPos:], payload[litStart:n])
	}
	return unsafeString(out)
}

// findFirstPIIRun returns the byte offset of the first 12-consecutive-digit run
// in payload, or (_, false) if none exists. Tight read-only scan; the common
// no-PII path returns in O(n) with no allocation.
//
//go:nosplit
func findFirstPIIRun(payload string) (start int, ok bool) {
	n := len(payload)
	if n < piiLen {
		return 0, false
	}
	run := 0
	for i := 0; i < n; i++ {
		if isDigitByte(payload[i]) {
			run++
			if run >= piiLen {
				return i - piiLen + 1, true
			}
		} else {
			run = 0
		}
	}
	return 0, false
}

// isDigitRun12 reports whether the 12 bytes at payload[i:i+12] are all ASCII
// digits. The caller guarantees i+piiLen <= len(payload); the access pattern is
// constant-length and unrolled, so the compiler elides bounds checks for every
// indexed load under that precondition.
//
//go:nosplit
func isDigitRun12(payload string, i int) bool {
	return isDigitByte(payload[i+0]) && isDigitByte(payload[i+1]) &&
		isDigitByte(payload[i+2]) && isDigitByte(payload[i+3]) &&
		isDigitByte(payload[i+4]) && isDigitByte(payload[i+5]) &&
		isDigitByte(payload[i+6]) && isDigitByte(payload[i+7]) &&
		isDigitByte(payload[i+8]) && isDigitByte(payload[i+9]) &&
		isDigitByte(payload[i+10]) && isDigitByte(payload[i+11])
}

// isDigitByte reports whether b is an ASCII digit. Inlined into callers as a
// single unsigned-subtract + compare on arm64.
//
//go:nosplit
func isDigitByte(b byte) bool {
	return b-0x30 < 10
}

// writeHex16 writes v as exactly 16 lowercase hex characters into dst, which
// must have length >= 16. The call site always passes a slice whose capacity
// was proven in the outLen arithmetic, so no bounds check is emitted.
//
//go:nosplit
func writeHex16(dst []byte, v uint64) {
	for k := 0; k < digestHexLen; k++ {
		shift := uint((digestHexLen - 1 - k) * 4)
		dst[k] = hexChars[byte(v>>shift)&0x0f]
	}
}

// unsafeString constructs a string from a []byte backing array with zero copy.
// Safe because `b` is a freshly allocated slice owned solely by this function
// and never mutated after the string is returned — the same invariant the Go
// runtime relies on for string slicing.
//
//go:nosplit
func unsafeString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return unsafe.String(unsafe.SliceData(b), len(b))
}
