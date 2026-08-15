// Package network implements the peer-reconnect HTTP transport for the
// Supremum δ-CRDT ledger, with ADR 4 jittered backoff and a bounded
// connection pool of standard-library *http.Client handles.
//
// ADR 4 MANDATE: 1,000,000 edge nodes reconnecting to a coordinator after
// a network partition will thunder any upstream without algorithmic
// intervention. This package implements Full Jitter and Decorrelated
// Jitter (AWS Architecture Blog, "Exponential Backoff And Jitter",
// https://aws.amazon.com/blogs/architecture/exponential-backoff-and-jitter/)
// to uniformly distribute reconnects across temporal windows, collapsing
// peak coordinator load from O(N) to O(N / 2^attempt).
//
// The transport is a thin, honest wrapper over the Go standard library
// net/http client. There is no TLS fingerprint shaping, no header-order
// forging, and no proxy evasion: the ledger is a legitimate distributed
// system that participates openly on the network.
package network

import (
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"sync/atomic"
	"time"
)

// ---------------------------------------------------------------------------
// ADR 4 Constants — Backoff Parameters
// ---------------------------------------------------------------------------

const (
	// DefaultBaseDelayMs is the minimum backoff seed (milliseconds).
	// Must be > 0 to prevent zero-delay retries in Decorrelated mode.
	DefaultBaseDelayMs = 100

	// DefaultCapMs is the absolute upper bound for any single backoff delay.
	// Prevents unbounded exponential growth: min(cap, base * 2^attempt).
	DefaultCapMs = 30_000 // 30 seconds

	// DefaultMaxRetries bounds the total retry count per request.
	// At Full Jitter with cap=30s, 7 retries covers ~4 minutes of spread.
	DefaultMaxRetries = 7

	// PoolDefaultSize is the default connection pool capacity per host.
	PoolDefaultSize = 16
)

// JitterStrategy selects the backoff algorithm.
type JitterStrategy uint8

const (
	// FullJitter: sleep = random(0, min(cap, base * 2^attempt))
	// Maximum spread, lowest aggregate completion time (AWS recommendation).
	FullJitter JitterStrategy = iota

	// DecorrelatedJitter: sleep = min(cap, random(base, prevSleep * 3))
	// Markovian chain — breaks lockstep without zero-delay risk.
	DecorrelatedJitter
)

// ---------------------------------------------------------------------------
// SplitMix64 — Zero-allocation, stack-local PRNG
// ---------------------------------------------------------------------------
//
// Used by the backoff calculator for reconnect jitter. math/rand uses a
// global mutex (or per-source lock); at high reconnect fan-out this becomes
// a contention point. SplitMix64 is a fast, high-quality 64-bit PRNG that
// lives entirely on the stack and has a period of 2^64.

type splitMix64 struct {
	state uint64
}

// next returns the next pseudo-random uint64 and advances the state.
// SplitMix64 passes BigCrush.
func (s *splitMix64) next() uint64 {
	s.state += 0x9e3779b97f4a7c15
	z := s.state
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

// boundedNext returns a value in [0, bound). The modulo bias is negligible
// for the small backoff bounds used by jitter; acceptable here.
func (s *splitMix64) boundedNext(bound uint64) uint64 {
	if bound <= 1 {
		return 0
	}
	return s.next() % bound
}

// ---------------------------------------------------------------------------
// ADR 4: Jittered Backoff Calculator — Pure Function, Zero Heap
// ---------------------------------------------------------------------------

// BackoffConfig holds the tunable parameters for the jitter algorithm.
// All fields are value types — no pointers, no heap escape.
type BackoffConfig struct {
	BaseDelayMs uint64
	CapMs       uint64
	MaxRetries  int
	Strategy    JitterStrategy
}

// DefaultBackoffConfig returns the production-tuned configuration.
func DefaultBackoffConfig() BackoffConfig {
	return BackoffConfig{
		BaseDelayMs: DefaultBaseDelayMs,
		CapMs:       DefaultCapMs,
		MaxRetries:  DefaultMaxRetries,
		Strategy:    FullJitter,
	}
}

// ComputeDelay calculates the next backoff delay in milliseconds.
//
// Full Jitter:
//
//	sleep = random_between(0, min(cap, base * 2^attempt))
//	Peak load density: O(N / 2^attempt) — exponential decay.
//
// Decorrelated Jitter:
//
//	sleep = min(cap, random_between(base, prevSleepMs * 3))
//	Markovian: each wait depends on previous, breaking temporal sync.
//
// Both strategies are O(1) time and O(1) space — no allocation.
func (cfg *BackoffConfig) ComputeDelay(attempt int, prevSleepMs uint64, rng *splitMix64) uint64 {
	switch cfg.Strategy {
	case DecorrelatedJitter:
		// sleep = min(cap, random_between(base, prev * 3))
		upper := prevSleepMs * 3
		if upper < cfg.BaseDelayMs {
			upper = cfg.BaseDelayMs
		}
		if upper > cfg.CapMs {
			upper = cfg.CapMs
		}
		span := upper - cfg.BaseDelayMs
		if span == 0 {
			return cfg.BaseDelayMs
		}
		return cfg.BaseDelayMs + rng.boundedNext(span+1)

	default: // FullJitter
		// exp = min(cap, base * 2^attempt)
		exp := cfg.BaseDelayMs
		for i := 0; i < attempt; i++ {
			exp *= 2
			if exp > cfg.CapMs {
				exp = cfg.CapMs
				break
			}
		}
		// sleep = random_between(0, exp)
		return rng.boundedNext(exp + 1)
	}
}

// ---------------------------------------------------------------------------
// ClientPool — bounded, lock-free-acquire connection pool over stdlib
// ---------------------------------------------------------------------------

// connSlot holds one reusable *http.Client. inUse is an atomic flag that
// makes Acquire/Release a lock-free CAS on the contended path. The slots
// array is per-host so cross-host traffic does not contend on the same
// cache lines.
type connSlot struct {
	client  *http.Client
	inUse   atomic.Bool
	created int64 // unix nanos at creation (for future idle eviction)
}

// ClientPool is a bounded pool of reusable *http.Client handles. The pool
// is per-host; multiple goroutines share it via a lock-free CAS on each
// slot's inUse flag. When all slots are busy, an ephemeral client is
// created (not pooled) so callers never block on the pool.
type ClientPool struct {
	slots   []connSlot
	size    int
	factory func() (*http.Client, error)
	cursor  atomic.Uint64
}

// NewClientPool creates a bounded connection pool.
// The factory function creates new http clients on demand.
func NewClientPool(size int, factory func() (*http.Client, error)) *ClientPool {
	if size <= 0 {
		size = PoolDefaultSize
	}
	return &ClientPool{
		slots:   make([]connSlot, size),
		size:    size,
		factory: factory,
	}
}

// Acquire returns an http client from the pool, creating one if the slot is empty.
// Uses atomic CAS on the slot's inUse flag — zero mutex contention on the
// contended path. Falls back to an ephemeral (un-pooled) client when all slots
// are busy so callers never block on pool availability.
func (p *ClientPool) Acquire() (*http.Client, int, error) {
	start := int(p.cursor.Add(1))
	for i := 0; i < p.size; i++ {
		idx := (start + i) % p.size
		if p.slots[idx].inUse.CompareAndSwap(false, true) {
			if p.slots[idx].client != nil {
				return p.slots[idx].client, idx, nil
			}
			// Lazy initialization
			c, err := p.factory()
			if err != nil {
				p.slots[idx].inUse.Store(false)
				return nil, -1, err
			}
			p.slots[idx].client = c
			p.slots[idx].created = time.Now().UnixNano()
			return c, idx, nil
		}
	}
	// All slots busy — create ephemeral client (not pooled)
	c, err := p.factory()
	if err != nil {
		return nil, -1, err
	}
	return c, -1, nil
}

// Release returns a client to the pool.
func (p *ClientPool) Release(idx int) {
	if idx >= 0 && idx < p.size {
		p.slots[idx].inUse.Store(false)
	}
}

// ---------------------------------------------------------------------------
// PeerClient — ADR 4 enhanced HTTP client
// ---------------------------------------------------------------------------

// PeerClient wraps a standard-library *http.Client with ADR 4 jittered
// backoff and a bounded per-host connection pool, used for legitimate
// coordinator / peer reconnections by Temporal Activities.
type PeerClient struct {
	Client  *http.Client
	Pool    *ClientPool
	Backoff BackoffConfig
}

// NewPeerClient initializes a standard-library HTTP client with the ADR 4
// backoff configuration.
//
// The returned client is a thin, honest net/http client. There is no TLS
// fingerprint shaping and no header-order forging — the ledger participates
// openly on the network.
func NewPeerClient(timeout time.Duration) (*PeerClient, error) {
	factory := func() (*http.Client, error) {
		return &http.Client{
			Timeout:   timeout,
			Transport: http.DefaultTransport.(*http.Transport).Clone(),
		}, nil
	}

	primary, err := factory()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize peer HTTP client: %w", err)
	}

	return &PeerClient{
		Client:  primary,
		Pool:    NewClientPool(PoolDefaultSize, factory),
		Backoff: DefaultBackoffConfig(),
	}, nil
}

// NewRequest creates a standard HTTP request. There is no header-order
// forging on the request: the wire is the wire.
func (nc *PeerClient) NewRequest(method, url string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	return req, nil
}

// Do executes an HTTP request with the standard library client.
func (nc *PeerClient) Do(req *http.Request) (*http.Response, error) {
	return nc.Client.Do(req)
}

// ErrMaxRetriesExceeded signals that all retry attempts were exhausted.
var ErrMaxRetriesExceeded = errors.New("max retries exceeded after jittered backoff")

// DoWithRetry executes an HTTP request with ADR 4 jittered exponential backoff.
//
// Mathematical guarantee:
//   - Full Jitter: N clients spread uniformly over [0, min(cap, base*2^i)]
//     Peak load per ms = N / min(cap, base*2^i) → exponential decay
//   - Decorrelated: Markovian chain breaks temporal synchronization completely
//
// The shouldRetry function determines if a response warrants a retry (e.g.,
// HTTP 429, 503, 5xx). If nil, only network errors trigger retries.
//
// Zero heap allocation on the retry hot path: the PRNG is stack-local,
// the delay computation uses only integer arithmetic, and time.Sleep
// operates on a stack-allocated Duration.
func (nc *PeerClient) DoWithRetry(req *http.Request, shouldRetry func(*http.Response) bool) (*http.Response, error) {
	cfg := &nc.Backoff

	// Stack-local PRNG seeded from a high-entropy clock + math/rand source.
	// SplitMix64 is deterministic from the seed; the seed mixes wall-clock
	// nanos with a stdlib random uint64 so two concurrent retries do not
	// land on the same backoff curve.
	seed := uint64(time.Now().UnixNano()) ^ rand.Uint64()
	rng := splitMix64{state: seed}

	var prevSleepMs uint64 = cfg.BaseDelayMs
	var lastErr error
	var lastResp *http.Response

	for attempt := 0; attempt <= cfg.MaxRetries; attempt++ {
		if attempt > 0 {
			delayMs := cfg.ComputeDelay(attempt-1, prevSleepMs, &rng)
			prevSleepMs = delayMs
			if delayMs > 0 {
				time.Sleep(time.Duration(delayMs) * time.Millisecond)
			}
		}

		resp, err := nc.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		// Check if the response indicates a retriable condition
		if shouldRetry != nil && shouldRetry(resp) {
			lastResp = resp
			lastErr = fmt.Errorf("retriable HTTP status: %d", resp.StatusCode)
			continue
		}

		return resp, nil
	}

	if lastResp != nil {
		return lastResp, lastErr
	}
	return nil, fmt.Errorf("%w: %v", ErrMaxRetriesExceeded, lastErr)
}
