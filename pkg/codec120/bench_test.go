// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package codec120

// BenchmarkCodec120B compares the encoded size and round-trip cost of a
// 120-byte CRDT frame without compression, with a trained zstd dictionary,
// and with LZ4 block compression. Each codec must reproduce the input before
// the benchmark records timing or size metrics.
//
// The benchmark uses the existing klauspost/compress/zstd and pierrec/lz4/v4
// modules. LZ4 operates on individual blocks rather than framed streams.

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
)

var errLZ4Short = errors.New("lz4: empty compressed block")

// The zstd dictionary is built once during package initialization. Its build
// time is reported separately from per-frame encoding.
var (
	codecDict           []byte
	codecDictBuildNanos int64
)

func init() {
	// Train the dictionary on trainFrames frames from the same generator as
	// the benchmark stream. History supplies the concatenated frame bytes;
	// Contents supplies the individual samples used to gather encoding
	// statistics.
	train := buildFrames(trainFrames)
	contents := make([][]byte, len(train))
	for i, f := range train {
		contents[i] = f
	}
	history := concatFrames(trainFrames)
	// Measure construction separately from per-frame encoding.
	start := nowNanos()
	d, err := zstd.BuildDict(zstd.BuildDictOptions{
		ID:       0x534F56, // "SOV"
		History:  history,
		Contents: contents,
		Level:    zstd.SpeedBestCompression,
	})
	codecDictBuildNanos = nowNanos() - start
	if err != nil {
		// A nil dictionary would silently measure ordinary zstd instead.
		panic("codec120: zstd.BuildDict failed: " + err.Error())
	}
	codecDict = d
}

// nowNanos returns wall-clock nanoseconds for timing dictionary construction.
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

// zstdDictCodec reuses an encoder and decoder within its sub-benchmark.
// EncodeAll handles one complete frame without a streaming reset cycle.
// WithEncoderConcurrency(1) keeps encoding single-threaded.
type zstdDictCodec struct {
	enc *zstd.Encoder
	dec *zstd.Decoder
}

func newZstdDictCodec() *zstdDictCodec {
	// SpeedFastest favors encoding latency over maximum compression.
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

// lz4Codec compresses one frame per LZ4 block, without stream framing. The
// Compressor is reused across calls, and dst has CompressBlockBound(frameSize)
// capacity.
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
		// LZ4 returns n == 0 when compression would not shrink the input.
		// Prefix the raw frame with a flag so decoding can distinguish it
		// from a compressed block; the flag counts toward the encoded size.
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

// BenchmarkCodec120B compares the three codecs on 120-byte CRDT frames. Each
// sub-benchmark checks every decode against its input and reports mean encoded
// bytes per operation. The zstd sub-benchmark also reports the one-time
// dictionary construction cost.
func BenchmarkCodec120B(b *testing.B) {
	frames := buildFrames(numFrames)

	// Report dictionary construction separately from per-frame encoding cost.
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

// runColumn compresses and decompresses b.N frames selected from frames and
// checks round-trip equality. bytes_out/op is the mean encoded size; SetBytes
// uses the uncompressed frame size so testing's throughput metric counts input
// bytes.
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
		// Reject a failed round trip before recording its encoded size.
		if !bytes.Equal(dec, frame) {
			b.Fatalf("%s: round-trip mismatch on frame %d: got %d bytes, want %d",
				name, i%len(frames), len(dec), len(frame))
		}
		totalCompBytes += int64(len(comp))
	}
	// Keep encoded size separate from testing's input-throughput calculation.
	if b.N > 0 {
		meanComp := float64(totalCompBytes) / float64(b.N)
		b.ReportMetric(meanComp, "bytes_out/op")
		b.SetBytes(int64(frameSize)) // input bytes processed per op (for MB/s = input throughput)
	}
}
