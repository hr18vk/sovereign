// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// Package telemetry provides allocation-free counter and gauge updates for the
// ingestion path.
//
// Counter follows the LongAdder design: updates are distributed across padded
// stripes instead of invalidating one shared cache line on every write. Each
// 64-byte stripe contains a 56-byte pad and an 8-byte atomic value. A hash of a
// stack-local address selects the stripe, so different goroutines usually write
// to different lines; collisions are handled by the compare-and-swap loop.
//
// Add and Inc are lock-free and use no mutexes or heap allocations. Set and
// GaugeValue access a single stripe. Value aggregates the stripes for telemetry
// collection and is not intended for the ingestion path. Construction allocates
// the stripe arrays during package initialization and, when OpenTelemetry is
// enabled, during the single call to Init.
//
// Every stripe stores the IEEE-754 representation of a float64. Add and Inc
// decode the current value, add the delta, and store the new representation with
// compare-and-swap. FloatValue decodes and sums the stripes; ordinary float64
// rounding still applies.
//
// When Init supplies a Meter, counters register asynchronous OpenTelemetry
// instruments whose callbacks run on the collector's schedule. Int64 counter
// callbacks report per-interval deltas through lastReported. The Prometheus
// bridge independently reads cumulative values through Value.
package telemetry

import (
	"context"
	"math"
	"runtime"
	"sync/atomic"
	"unsafe"

	"go.opentelemetry.io/otel/metric"
)

// cacheLineBytes is the cache-line width on 64-byte cache hardware (AWS
// Graviton). A stripe is sized so exactly one atomic value owns a line with
// no adjacent neighbor sharing it.
const cacheLineBytes = 64

// stripePadding pads a stripe so the atomic value is alone on its cache line.
// 56 bytes of lead pad + 8 bytes of value = 64 = one cache line.
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
// without reaching into the unexported type. This is an alias, not a new type
// — ModeCounter / ModeGauge below are the same constants as modeCounter /
// modeGauge. The alias avoids churn at the construction sites in registry.go,
// which continue to pass modeCounter and modeGauge; only the bridge reads
// Mode() through the alias (ADR-0023 §3).
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
// Concurrency: Add / Inc / Set are concurrent-safe and lock-free. Each writer
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

	// lastReported is the cumulative integer value seen by the previous int64
	// OpenTelemetry callback. Only that callback reads and advances it.
	lastReported atomic.Uint64

	name        string
	description string
	unit        string
	mode        counterMode
}

// counterStripe is one LongAdder stripe: a lead cache-line pad followed by an
// 8-byte value. Size: 56 + 8 = 64 bytes — one cache line.
//
//go:align 64
type counterStripe struct {
	_     stripePadding // [56]byte lead pad — isolates from the prior stripe's value.
	value atomic.Uint64 // the counter; alone on the tail of its line.
}

// numStripes is a power of two so stripe selection needs only a bitwise AND.
// The fixed set of stripes spreads updates without sizing or reallocating the
// counter when GOMAXPROCS changes.
const numStripes = 64

// stripeIndex selects a stripe without allocating or pinning the goroutine to a
// P. It hashes a stack-local address with Knuth's golden-ratio multiplier. The
// local remains on the stack, and no private runtime API is required.
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

// addFloat performs the decode-add-encode CAS loop on one stripe. A writer
// retries only when another update changes that stripe between its load and
// compare-and-swap.
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

// Add increments the counter by delta on a stack-selected stripe. It allocates
// no memory and uses no mutex. A delta of zero is a no-op. Add is intended for
// modeCounter; use Set for modeGauge.
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

// FloatValue decodes and sums every stripe as a float64. The sum has ordinary
// floating-point rounding and is not a point-in-time snapshot during concurrent
// updates.
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

// The read-only accessors below allow the Prometheus bridge (pkg/metrics) to
// surface Counter metadata at scrape time. They expose the immutable fields —
// Name, Description, Unit, Mode — and cumulative Value(). They omit
// lastReported (owned by the OTel int64-observable callback; touching it from
// the bridge while an OTel Meter is active would advance lastReported out of
// cadence and double-count or drift per ADR-0023). There is no Delta() or
// Reset(); the bridge is cumulative-only.

// Name returns the telemetry metric name (dots, e.g. "supremum.l0.arrow_serial_bytes").
// The bridge maps '.' -> '_' to form the legal prometheus name.
func (c *Counter) Name() string { return c.name }

// Description returns the help-text set at construction; the bridge uses it as
// the prometheus Desc Help line.
func (c *Counter) Description() string { return c.description }

// Unit returns the OpenTelemetry unit token set at construction, such as "By",
// "ns", or "1".
func (c *Counter) Unit() string { return c.unit }

// Mode returns the counter mode (modeCounter or modeGauge) via the exported
// CounterMode alias, so the cross-package bridge can select ConstCounter vs
// ConstGauge without reaching into the unexported type.
func (c *Counter) Mode() counterMode { return c.mode }

// newCounter constructs a Counter and registers its asynchronous OpenTelemetry
// observable against meter. Package initialization and rebuildCounters call it
// during startup; data-plane updates do not allocate.
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
