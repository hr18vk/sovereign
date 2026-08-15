package clock

import (
	"sync/atomic"
	"time"
)

// SyntheticClock is a deterministic WallClock for tests. It holds a
// fixed physical time in microseconds that tests can pin and advance
// without touching the real clock. The read path (PhysicalNowUSec) is a
// single atomic load, so a shared SyntheticClock is safe for concurrent
// Admit callers (G3.0.k race gate).
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

// SystemClock is the production WallClock placeholder for Subphase 3.0.
// It reads the OS wall clock via time.Now().UnixMicro(). The real
// Amazon Time Sync / chrony reader lands in Subphase 9.0 and will
// replace this implementation; do NOT fabricate a chrony reader here.
type SystemClock struct{}

// NewSystemClock returns a SystemClock reading the OS wall clock.
func NewSystemClock() *SystemClock { return &SystemClock{} }

// PhysicalNowUSec returns the OS wall time in microseconds.
func (c *SystemClock) PhysicalNowUSec() int64 {
	return time.Now().UnixMicro()
}
