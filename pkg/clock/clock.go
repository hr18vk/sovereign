// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package clock

import (
	"sync/atomic"
	"time"
)

// SyntheticClock is a deterministic WallClock for tests. It holds a physical
// time in microseconds that tests can set and advance without reading the OS
// clock. Its atomic storage allows a clock to be shared across goroutines.
type SyntheticClock struct {
	nowUSec atomic.Int64
}

// NewSyntheticClock pins the clock at nowUSec microseconds since the
// Unix epoch.
func NewSyntheticClock(nowUSec int64) *SyntheticClock {
	c := &SyntheticClock{}
	c.nowUSec.Store(nowUSec)
	return c
}

// PhysicalNowUSec returns the pinned physical time in microseconds.
func (c *SyntheticClock) PhysicalNowUSec() int64 {
	return c.nowUSec.Load()
}

// Advance moves the synthetic clock forward by deltaUSec microseconds.
// Tests use this to simulate local-clock progression between frames.
func (c *SyntheticClock) Advance(deltaUSec int64) {
	c.nowUSec.Add(deltaUSec)
}

// Set pins the synthetic clock at an absolute microsecond value.
func (c *SyntheticClock) Set(nowUSec int64) {
	c.nowUSec.Store(nowUSec)
}

// SystemClock is a WallClock backed by the operating system. It returns wall
// time only; it does not expose clock-synchronization status or uncertainty.
type SystemClock struct{}

// NewSystemClock returns a SystemClock reading the OS wall clock.
func NewSystemClock() *SystemClock { return &SystemClock{} }

// PhysicalNowUSec returns the OS wall time in microseconds.
func (c *SystemClock) PhysicalNowUSec() int64 {
	return time.Now().UnixMicro()
}
