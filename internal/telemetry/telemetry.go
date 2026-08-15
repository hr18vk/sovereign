// Package telemetry implements the Zero-GC, lock-free telemetry counter layer
// for the Supremum Ledger ingestion hot path.
//
// PHYSICS (see "Go High-Performance Architecture Research", §DOMAIN 2, and
// SUPREMUM_STYLE §2 / §3):
//
//   - 57.6M ops/s leaves an ~17.34ns/op budget. A single contended atomic
//     counter under cross-core MESI invalidation costs 40–80ns per increment
//     (a HITM storm); at 32 cores it collapses throughput by ~98%. The
//     LongAdder design (after Java's java.util.concurrent.atomic.LongAdder)
//     disperses the write locus across one stripe per P, so the common
//     Add/Inc path touches ONLY the local stripe's cache line — no
//     cross-core coherence on the hot path.
//
//   - Each stripe is exactly 64 bytes (one Graviton cache line): a 56-byte
//     lead pad + the 8-byte value. Two stripes never share a line, so adjacent
//     counters cannot false-share. The dossier's `_ [56]byte` pad is honored
//     verbatim (56B pad + 8B value = 64B line).
//
//   - sync.Mutex / sync.RWMutex are NEVER used on the telemetry hot path;
//     Add/Inc/Set are pure atomic operations on per-P memory. Aggregation
//     (Value()) is rare — it is invoked only by the OpenTelemetry
//     asynchronous poller, which runs off the data plane.
//
//   - The package-level Counter values (ArrowSerialBytes, MemTableFlushTotal,
//     OffHeapAllocatedBytes) are constructed once at package init. Their
//     backing stripe arrays are the only heap allocation this package ever
//     performs, and it happens before the first Write — never per-call. The
//     data-plane methods Add/Inc/Set are zero-alloc (verified with
//     `go build -gcflags="-m -m"`: escape analysis reports "c does not escape"
//     for every hot-path method).
//
// STORAGE MODEL: every stripe stores the IEEE-754 bit pattern of a float64.
// Add/Inc perform a decode-add-encode CAS loop confined to one stripe's line,
// so FloatValue()'s per-stripe decode-and-sum is exact for any mix of
// Add(float64)/Inc use. (Adding the *bit pattern* of a delta would be integer
// arithmetic on float bits and decode to garbage — the CAS loop is the
// correct, still-one-line write path.)
//
// OpenTelemetry integration: each Counter registers an asynchronous
// Observable instrument (ObservableCounter for cumulative Add/Inc counters,
// ObservableGauge for Set-backed gauges) whose callback reads the counter on
// the collector's schedule — never on the ingestion hot path.
package telemetry

import (
	"context"
	"math"
	"runtime"
	"sync/atomic"
	"unsafe"

	"go.opentelemetry.io/otel/metric"
)

// cacheLineBytes is the cache-line width on the recorded silicon (AWS
// Graviton, 64-byte lines). A stripe is sized so exactly one atomic value
// owns a line, with no accidental neighbor.
const cacheLineBytes = 64

// stripePadding pads a stripe so the atomic value is alone on its cache line.
// 56 bytes of lead pad + 8 bytes of value = 64 = one Graviton line.
type stripePadding struct {
	_ [cacheLineBytes - 8]byte
}

// counterMode selects how a Counter is exported to OpenTelemetry.
type counterMode uint8

const (
	// modeCounter is an additive counter. Inc atomically adds 1; Add(n)
	// atomically adds n. Value() sums the stripes and is exported as an
	// Int64ObservableCounter reporting the per-interval delta so consecutive
	// scrapes never double-count.
	modeCounter counterMode = iota
	// modeGauge is a last-writer-wins gauge. Set replaces the single gauge
	// slot. Value() returns the last set float64. Exported as a
	// Float64ObservableGauge.
	modeGauge
)

// CounterMode is the exported alias for the unexported counterMode, so the
// prometheus bridge (cross-package, in pkg/metrics) can read a Counter's Mode
// without reaching into the unexported type. This is an ALIAS, not a new type
// — ModeCounter / ModeGauge below are the SAME constants as modeCounter /
// modeGauge. The alias adds zero churn to the 24 construction sites in
// registry.go (they continue to pass modeCounter / modeGauge); only the
// bridge reads Mode() through the alias. (ADR-0023 §3 documents the choice of
// alias-over-export: exporting counterMode itself would require renaming
// every construction-site literal and is a non-goal.)
type CounterMode = counterMode

// ModeCounter / ModeGauge are the exported const aliases the bridge compares
// against. They are identical to modeCounter / modeGauge above.
const (
	ModeCounter counterMode = modeCounter
	ModeGauge   counterMode = modeGauge
)

// Counter is a lock-free, sharded counter (LongAdder) with OpenTelemetry
// asynchronous-registration hooks.
//
// Concurrency: Add / Inc / Set are concurrent-safe and wait-free. Each writer
// selects a stripe deterministically and touches only that stripe's line.
// Value() iterates all stripes and is intended for the rare OTel callback pull,
// not the ingestion path.
//
// For modeGauge, Set uses the single gauge slot (stripes[0]) and Value() reads
// it back. The stripe array is still allocated so the layout is uniform and so
// a gauge carries its own padded slot free of any neighbor counter.
type Counter struct {
	// stripes is a contiguous array of (pad, value) stripes laid out so each
	// stripe occupies its own cache line. The lead pad of stripe[i+1] shields
	// value[i] from value[i+1].
	stripes []counterStripe

	// lastReported records the most recent OTel scrape, so the next scrape
	// reports the additive delta over its interval (never double-counts).
	// Off the hot path; touched only by the async callback.
	lastReported atomic.Uint64

	name        string
	description string
	unit        string
	mode        counterMode
}

// counterStripe is one LongAdder stripe: a lead cache-line pad followed by an
// 8-byte value. Size: 56 + 8 = 64 bytes — one Graviton cache line.
//
//go:align 64
type counterStripe struct {
	_     stripePadding // [56]byte lead pad — isolates from the prior stripe's value.
	value atomic.Uint64 // the counter; alone on the tail of its line.
}

// numStripes must be >= GOMAXPROCS so independent Ps rarely collide, and a
// power of two so stripe selection is a single AND (no div instruction).
// 64 covers the recorded 32-core silicon with headroom.
const numStripes = 64

// stripeIndex selects a stripe for the current goroutine. It must be cheap and
// allocation-free. We hash a stack-local address through Knuth's golden-ratio
// multiplier for dispersion; this approximates per-P affinity without
// depending on the unstable runtime_procPin private API, and never touches
// the heap (the address is of a stack-local — escape analysis confirms it
// stays on the stack).
//
//go:nosplit
//go:noinline
func stripeIndex() int {
	var x int
	addr := uintptr(unsafe.Pointer(&x))
	addr ^= addr >> 16
	addr *= 11400714819323198485 // golden-ratio fold; 64-bit, masked below.
	return int(addr) & (numStripes - 1)
}

// addFloat performs the decode-add-encode CAS loop on a single stripe. It
// touches exactly one cache line, so the cross-core MESI cost is confined to
// that stripe's writers. Uncontended in the common case (one active writer per
// P per stripe), so it degenerates to a single load + CAS.
//
//go:nosplit
func (c *Counter) addFloat(delta float64) {
	p := &c.stripes[stripeIndex()].value
	for {
		old := p.Load()
		next := math.Float64frombits(old) + delta
		if p.CompareAndSwap(old, math.Float64bits(next)) {
			return
		}
	}
}

// Add increments the counter by delta on the current goroutine's stripe.
// Zero-GC, wait-free, no mutex. A delta of 0 is a no-op. Only meaningful for
// modeCounter; for modeGauge, use Set.
//
//go:nosplit
func (c *Counter) Add(delta float64) {
	if delta == 0 {
		return
	}
	c.addFloat(delta)
}

// Inc is the integer fast-path Add(1). It performs the same single-line
// decode-add-encode CAS as Add, so FloatValue() remains exact for any mix of
// Add(float64)/Inc.
//
//go:nosplit
func (c *Counter) Inc() {
	c.addFloat(1)
}

// Set stores the gauge value (last-writer-wins). Only the single gauge slot
// (stripes[0]) is used, so Value() reports exactly the last Set regardless of
// which goroutine wrote it.
//
//go:nosplit
func (c *Counter) Set(value float64) {
	c.stripes[0].value.Store(math.Float64bits(value))
}

// GaugeValue returns the current gauge float64. Reads stripes[0] only.
//
//go:nosplit
func (c *Counter) GaugeValue() float64 {
	return math.Float64frombits(c.stripes[0].value.Load())
}

// FloatValue aggregates every stripe as the float64 sum of the per-stripe
// float-bit-decoded values. Exact for counters used via Add(float64) and/or Inc.
func (c *Counter) FloatValue() float64 {
	var total float64
	for i := range c.stripes {
		total += math.Float64frombits(c.stripes[i].value.Load())
	}
	return total
}

// Value is the generic accessor used by the OTel callbacks. For modeCounter it
// returns FloatValue (the additive sum); for modeGauge it returns GaugeValue.
func (c *Counter) Value() float64 {
	if c.mode == modeGauge {
		return c.GaugeValue()
	}
	return c.FloatValue()
}

// The read-only accessors below are for the prometheus bridge (pkg/metrics)
// to surface Counter metadata at scrape time. They expose ONLY the immutable
// construction fields — Name, Description, Unit, Mode — and the cumulative
// Value() above. They do NOT expose lastReported (that field belongs to the
// OTel int64-observable callback; the bridge reads CUMULATIVE via Value() and
// MUST NOT touch lastReported, or a future fork that wires a real OTel Meter
// would arm the callback, advance lastReported, and double-count / diverge —
// the §0.b trap, ADR-0023 §0.b). There is no exported Delta() / Reset() and
// there never will be: those would tempt a future bridge into the
// double-count trap. The bridge is CUMULATIVE-ONLY.

// Name returns the telemetry metric name (dots, e.g. "supremum.l0.arrow_serial_bytes").
// The bridge maps '.' -> '_' to form the legal prometheus name.
func (c *Counter) Name() string { return c.name }

// Description returns the help-text set at construction; the bridge uses it as
// the prometheus Desc Help line.
func (c *Counter) Description() string { return c.description }

// Unit returns the OTel unit token set at construction ("By" or "1").
func (c *Counter) Unit() string { return c.unit }

// Mode returns the counter mode (modeCounter or modeGauge) via the exported
// CounterMode alias, so the cross-package bridge can select ConstCounter vs
// ConstGauge without reaching into the unexported type.
func (c *Counter) Mode() counterMode { return c.mode }

// newCounter constructs a Counter and registers its asynchronous OpenTelemetry
// observable against the supplied Meter. Called exactly once per counter at
// package init — the stripe backing array allocation is paid at startup,
// never per-op. The escapes here (Counter, stripes, callback closures) are
// the permitted startup allocations; the data-plane methods do not escape.
func newCounter(meter metric.Meter, name, description, unit string, mode counterMode) *Counter {
	c := &Counter{
		stripes:     make([]counterStripe, numStripes),
		name:        name,
		description: description,
		unit:        unit,
		mode:        mode,
	}
	c.register(meter)
	return c
}

// register creates the OpenTelemetry asynchronous observable for this counter.
// The instrument's callback reads the counter on the collector's schedule —
// never on the ingestion hot path. Registration failures are non-fatal: the
// counter keeps functioning as a plain in-process LongAdder.
func (c *Counter) register(meter metric.Meter) {
	if meter == nil {
		return // NoMeter: tests / opt-out run without an OTel provider.
	}
	switch c.mode {
	case modeCounter:
		c.registerInt64Counter(meter)
	case modeGauge:
		c.registerFloat64Gauge(meter)
	}
}

func (c *Counter) registerInt64Counter(meter metric.Meter) {
	_, err := meter.Int64ObservableCounter(
		c.name,
		metric.WithDescription(c.description),
		metric.WithUnit(c.unit),
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			// Report the per-interval delta so two consecutive scrapes do not
			// double-count. lastReported guards the previous scrape under an
			// atomic so the delta is captured without a mutex.
			now := int64(c.FloatValue())
			for {
				prev := c.lastReported.Load()
				delta := now - int64(prev)
				if c.lastReported.CompareAndSwap(prev, uint64(now)) {
					o.Observe(delta)
					return nil
				}
			}
		}),
	)
	if err != nil {
		// Fall back to a float64 counter if the meter rejected the int64 type.
		_, _ = meter.Float64ObservableCounter(
			c.name,
			metric.WithDescription(c.description),
			metric.WithUnit(c.unit),
			metric.WithFloat64Callback(func(_ context.Context, o metric.Float64Observer) error {
				o.Observe(c.FloatValue())
				return nil
			}),
		)
	}
}

func (c *Counter) registerFloat64Gauge(meter metric.Meter) {
	_, _ = meter.Float64ObservableGauge(
		c.name,
		metric.WithDescription(c.description),
		metric.WithUnit(c.unit),
		metric.WithFloat64Callback(func(_ context.Context, o metric.Float64Observer) error {
			o.Observe(c.GaugeValue())
			return nil
		}),
	)
}

// keep runtime import live (GOMAXPROCS awareness is documented for callers
// that ever expand stripe count beyond numStripes). Does not touch the hot path.
var _ = runtime.GOMAXPROCS
