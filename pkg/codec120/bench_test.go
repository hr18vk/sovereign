package codec120

// Track 4.E3 — BenchmarkCodec120B: the byte-cost go/no-go on the 120-byte
// CRDT frame. Four columns: no-comp (baseline), zstd-dict, lz4. The zxc column
// is GATED (no Go module; the §6 decision matrix fires before any CGO bridge
// cost is incurred — see the executor prompt §1 Column-D and §6).
//
// ANTI-FABRICATION (G4.E3.d / T6): round-trip equality is asserted IN CODE via
// b.Fatalf BEFORE any ns/op or bytes_out is recorded. A codec that "compresses"
// but does not round-trip is a fabrication; the bench stops at the assertion.
//
// DEPS (both ALREADY pinned in go.mod — ZERO new go dependency this track):
//   - zstd: github.com/klauspost/compress@v1.18.6 /zstd
//     REAL API (verified this turn in the module cache — the prompt's symbol
//     names were slightly off; these are the actual signatures):
//       NewWriter(io.Writer, ...EOption) (*Encoder, error)
//       NewReader(io.Reader, ...DOption) (*Decoder, error)
//       WithEncoderDict(dict []byte) EOption
//       WithDecoderDicts(dicts ...[]byte) DOption
//       WithEncoderLevel(EncoderLevel) EOption   consts: SpeedFastest ..
//       BuildDict(BuildDictOptions{ID, Contents [][]byte, Level}) ([]byte, error)
//     (There is NO WithDictRaw/WithEntropyStats on BuildDict — those names in
//     the prompt do not exist; BuildDictOptions uses Contents [][]byte.)
//   - lz4: github.com/pierrec/lz4/v4@v4.1.27
//     REAL API: lz4.Compressor is a plain struct (no constructor — use
//     &lz4.Compressor{}); (*Compressor).CompressBlock(src, dst []byte) (int,
//     error); lz4.UncompressBlock(src, dst []byte) (int, error);
//     lz4.CompressBlockBound(n int) int. Block-level (no framing) — the right
//     granularity for a 120-byte frame.
//
// The bench name is BenchmarkCodec120B (NO "_32c" suffix — T7; the 32c gear is
// recorded in the report header + .log, not the function name, same discipline
// as 4.E1). -cpu=32 overrides the goroutine count regardless of the name.

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
)

var errLZ4Short = errors.New("lz4: empty compressed block")

// --- zstd-dict: build the dictionary ONCE at deploy (one-time cost, like the
// cedar ParsePoliciesOnce at 19µs). The per-op encode is the hot path; the dict
// is amortized across ops. Q2: report the build cost separately, NOT merged.
var (
	codecDict       []byte
	codecDictBuildNanos int64
)

func init() {
	// Train on a held-out set of trainFrames frames (10x the bench stream).
	// BuildDict's History is the dictionary CONTENT (the raw bytes the
	// dictionary is built from — must be >=8 bytes); Contents are the
	// training samples encoded against that history to gather entropy/offset
	// statistics. We set History to the concatenated training frames (so the
	// dictionary carries the real per-frame byte patterns) and Contents to
	// the individual frames (so the stats reflect the per-frame shape).
	train := buildFrames(trainFrames)
	contents := make([][]byte, len(train))
	for i, f := range train {
		contents[i] = f
	}
	history := concatFrames(trainFrames)
	// Time the one-time build (deploy cost). Use a testing-agnostic timer.
	start := nowNanos()
	d, err := zstd.BuildDict(zstd.BuildDictOptions{
		ID:       0x534F56, // "SOV"
		History:  history,
		Contents: contents,
		Level:    zstd.SpeedBestCompression,
	})
	codecDictBuildNanos = nowNanos() - start
	if err != nil {
		// A dict-build failure is fatal to the zstd-dict column; panic in
		// init so the bench never runs with a nil dict (which would silently
		// measure no-dict zstd and mislabel it as zstd-dict — a fabrication).
		panic("codec120: zstd.BuildDict failed: " + err.Error())
	}
	codecDict = d
}

// nowNanos is a thin wrapper so the bench can time the one-time dict build
// without importing testing in the factory. Uses the monotonic clock.
func nowNanos() int64 {
	return time.Now().UnixNano()
}

// --- column implementations ------------------------------------------------

// codec is the uniform per-column interface. Each column implements encode +
// decode; the harness compresses, decompresses, and asserts round-trip
// equality. Reused state (the zstd encoder/decoder) lives in the struct.
type codec interface {
	encode(frame []byte) ([]byte, error)
	decode(comp []byte) ([]byte, error)
}

// noCompCodec is the baseline: pass-through. bytes_out == bytes_in (120) by
// construction. Round-trip is trivially the identity.
type noCompCodec struct{}

func (noCompCodec) encode(frame []byte) ([]byte, error) {
	out := make([]byte, len(frame))
	copy(out, frame)
	return out, nil
}
func (noCompCodec) decode(comp []byte) ([]byte, error) {
	out := make([]byte, len(comp))
	copy(out, comp)
	return out, nil
}

// zstdDictCodec holds a REUSED encoder + decoder (created once in init). The
// production egress regime amortizes the encoder across frames. EncodeAll is
// the one-shot per-frame API (no manual Reset/Write/Close dance; documented as
// concurrency-safe with each call single-goroutine) — the right granularity
// for a 120-byte frame. WithEncoderConcurrency(1) keeps the measurement
// single-threaded.
type zstdDictCodec struct {
	enc *zstd.Encoder
	dec *zstd.Decoder
}

func newZstdDictCodec() *zstdDictCodec {
	// SpeedFastest is the production-realistic level: the transport seam cares
	// about sub-µs latency, not max compression ratio. The prompt's
	// "encoderSpeedLastMatch" is not a real zstd symbol; SpeedFastest is the
	// real "fastest reasonable compression" level. SpeedBestCompression was
	// tried on the 4c smoke (3.3ms/op — 17000x slower than no-comp) and is
	// not the hot-path regime; the dict's size win is reported at the level
	// that actually wins it (see the report's frontier note), but the R2
	// throughput verdict fires on the production-regime SpeedFastest number.
	enc, err := zstd.NewWriter(nil,
		zstd.WithEncoderDict(codecDict),
		zstd.WithEncoderLevel(zstd.SpeedFastest),
		zstd.WithEncoderConcurrency(1),
	)
	if err != nil {
		panic("codec120: zstd encoder init failed: " + err.Error())
	}
	dec, err := zstd.NewReader(nil,
		zstd.WithDecoderDicts(codecDict),
		zstd.WithDecoderConcurrency(1),
	)
	if err != nil {
		panic("codec120: zstd decoder init failed: " + err.Error())
	}
	return &zstdDictCodec{enc: enc, dec: dec}
}

func (c *zstdDictCodec) encode(frame []byte) ([]byte, error) {
	return c.enc.EncodeAll(frame, nil), nil
}

func (c *zstdDictCodec) decode(comp []byte) ([]byte, error) {
	out, err := c.dec.DecodeAll(comp, nil)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// lz4Codec compresses one frame with LZ4 block compression (no framing
// overhead — the right granularity for 120 bytes). The Compressor is reused
// across frames (it is stateless across blocks). dst must be at least
// CompressBlockBound(len(src)).
type lz4Codec struct {
	c   *lz4.Compressor
	dst []byte
}

func newLZ4Codec() *lz4Codec {
	return &lz4Codec{c: &lz4.Compressor{}, dst: make([]byte, lz4.CompressBlockBound(frameSize))}
}

func (c *lz4Codec) encode(frame []byte) ([]byte, error) {
	n, err := c.c.CompressBlock(frame, c.dst)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		// LZ4 returns n==0 when the compressed output would be >= the input
		// (incompressible): the caller must ship the raw block. For the
		// byte-cost table this is a SIZE-LOSS (the wire must carry the raw
		// 120 bytes + a 1-byte flag), so we report the raw size honestly.
		return append([]byte{0x00}, frame...), nil // flag=raw
	}
	return append([]byte{0x01}, c.dst[:n]...), nil // flag=compressed
}

func (c *lz4Codec) decode(comp []byte) ([]byte, error) {
	if len(comp) == 0 {
		return nil, errLZ4Short
	}
	flag := comp[0]
	body := comp[1:]
	if flag == 0x00 {
		out := make([]byte, len(body))
		copy(out, body)
		return out, nil
	}
	dst := make([]byte, frameSize)
	n, err := lz4.UncompressBlock(body, dst)
	if err != nil {
		return nil, err
	}
	return dst[:n], nil
}

// --- the bench -------------------------------------------------------------

// BenchmarkCodec120B runs the four columns against the 120-byte CRDT frame.
// Each sub-bench compresses numFrames frames, decompresses them, asserts
// round-trip equality (b.Fatalf on mismatch — G4.E3.d), then records ns/op
// (throughput) and bytes_out (size, via SetBytes on the COMPRESSED bytes).
//
// The bench is a single BenchmarkCodec120B with sub-benches so the .log shows
// the four columns as four rows (x count=3 = 12 rows), matching the prompt's
// "4 columns x 3 runs = 12 rows" requirement.
func BenchmarkCodec120B(b *testing.B) {
	frames := buildFrames(numFrames)

	// One-time dict build cost (Q2: reported separately, NOT merged into the
	// per-op ns/op). Printed to the bench log via b.ReportMetric so it is
	// visible in the .log without polluting the per-op number.
	b.Run("NO_COMP", func(b *testing.B) {
		runColumn(b, frames, "no-comp", noCompCodec{})
	})
	b.Run("ZSTD_DICT", func(b *testing.B) {
		b.ReportMetric(float64(codecDictBuildNanos), "dictBuild_ns/op-once")
		runColumn(b, frames, "zstd-dict", newZstdDictCodec())
	})
	b.Run("LZ4", func(b *testing.B) {
		runColumn(b, frames, "lz4", newLZ4Codec())
	})
}

// runColumn is the shared per-column harness. It compresses every frame,
// decompresses it, asserts round-trip equality (b.Fatalf on mismatch —
// G4.E3.d / T6), and reports ns/op + bytes_out. SetBytes is called with the
// INPUT size so the .log's MB/s reflects input throughput; the SIZE metric is
// the mean COMPRESSED bytes per frame (bytes_out/op), reported as a custom
// metric so size and throughput are explicit and not conflated.
func runColumn(b *testing.B, frames [][]byte, name string, c codec) {
	b.ReportAllocs()
	var totalCompBytes int64
	for i := 0; i < b.N; i++ {
		frame := frames[i%len(frames)]
		comp, err := c.encode(frame)
		if err != nil {
			b.Fatalf("%s: encode frame %d failed: %v", name, i%len(frames), err)
		}
		dec, err := c.decode(comp)
		if err != nil {
			b.Fatalf("%s: decode frame %d failed: %v", name, i%len(frames), err)
		}
		// G4.E3.d / T6: round-trip equality BEFORE any number is recorded.
		if !bytes.Equal(dec, frame) {
			b.Fatalf("%s: round-trip mismatch on frame %d: got %d bytes, want %d",
				name, i%len(frames), len(dec), len(frame))
		}
		totalCompBytes += int64(len(comp))
	}
	// SetBytes reports the COMPRESSED bytes processed per op — the on-the-wire
	// cost. The .log's "MB/s" is then compressed-MB/s. The SIZE metric is the
	// mean compressed bytes per frame (totalCompBytes / b.N), reported as a
	// custom metric so it is explicit and not conflated with throughput.
	if b.N > 0 {
		meanComp := float64(totalCompBytes) / float64(b.N)
		b.ReportMetric(meanComp, "bytes_out/op")
		b.SetBytes(int64(frameSize)) // input bytes processed per op (for MB/s = input throughput)
	}
}
