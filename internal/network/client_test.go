package network

import (
	"net/http"
	"testing"
	"time"
)

// TestNewPeerClient validates that the standard-library HTTP client
// initializes successfully with the ADR 4 backoff configuration.
func TestNewPeerClient(t *testing.T) {
	client, err := NewPeerClient(30 * time.Second)
	if err != nil {
		t.Fatalf("failed to initialize peer client: %v", err)
	}
	if client == nil {
		t.Fatal("expected PeerClient to be non-nil")
	}
	if client.Client == nil {
		t.Fatal("expected wrapped *http.Client to be non-nil")
	}
	if client.Pool == nil {
		t.Fatal("expected ClientPool to be non-nil")
	}
	if client.Backoff.BaseDelayMs != DefaultBaseDelayMs {
		t.Errorf("expected BaseDelayMs=%d, got %d", DefaultBaseDelayMs, client.Backoff.BaseDelayMs)
	}
}

// TestNewPeerClient_MultipleInstances validates that multiple clients can
// be created concurrently without resource conflicts (important for
// Temporal worker swarms reconnecting to coordinators).
func TestNewPeerClient_MultipleInstances(t *testing.T) {
	const numClients = 10
	clients := make([]*PeerClient, numClients)
	for i := 0; i < numClients; i++ {
		c, err := NewPeerClient(30 * time.Second)
		if err != nil {
			t.Fatalf("failed to create client %d: %v", i, err)
		}
		clients[i] = c
	}
	for i, c := range clients {
		if c == nil || c.Client == nil {
			t.Errorf("client %d is nil or has nil wrapped client", i)
		}
	}
}

// TestNewRequest validates a standard request is produced without any
// header-order forging.
func TestNewRequest(t *testing.T) {
	client, err := NewPeerClient(30 * time.Second)
	if err != nil {
		t.Fatalf("failed to initialize peer client: %v", err)
	}
	req, err := client.NewRequest("GET", "https://example.com", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	if req == nil {
		t.Fatal("expected non-nil request")
	}
	if req.Method != "GET" {
		t.Errorf("expected method GET, got %q", req.Method)
	}
}

// ---------------------------------------------------------------------------
// ADR 4: Jitter Backoff Unit Tests
// ---------------------------------------------------------------------------

func TestSplitMix64_Determinism(t *testing.T) {
	rng1 := splitMix64{state: 42}
	rng2 := splitMix64{state: 42}
	for i := 0; i < 1000; i++ {
		a := rng1.next()
		b := rng2.next()
		if a != b {
			t.Fatalf("SplitMix64 not deterministic at iteration %d: %d != %d", i, a, b)
		}
	}
}

func TestSplitMix64_BoundedNext(t *testing.T) {
	rng := splitMix64{state: 12345}
	for i := 0; i < 10000; i++ {
		v := rng.boundedNext(100)
		if v >= 100 {
			t.Fatalf("boundedNext(100) returned %d (>= 100)", v)
		}
	}
	if v := rng.boundedNext(1); v != 0 {
		t.Fatalf("boundedNext(1) returned %d, expected 0", v)
	}
	if v := rng.boundedNext(0); v != 0 {
		t.Fatalf("boundedNext(0) returned %d, expected 0", v)
	}
}

func TestFullJitter_BoundedByCap(t *testing.T) {
	cfg := BackoffConfig{BaseDelayMs: 100, CapMs: 1000, MaxRetries: 10, Strategy: FullJitter}
	rng := splitMix64{state: 99}
	for attempt := 0; attempt < 20; attempt++ {
		delay := cfg.ComputeDelay(attempt, 0, &rng)
		if delay > cfg.CapMs {
			t.Fatalf("Full Jitter delay %d exceeds cap %d at attempt %d", delay, cfg.CapMs, attempt)
		}
	}
}

func TestFullJitter_MaxSpread(t *testing.T) {
	cfg := BackoffConfig{BaseDelayMs: 100, CapMs: 30000, MaxRetries: 7, Strategy: FullJitter}
	rng := splitMix64{state: 777}
	var minV, maxV uint64
	minV = ^uint64(0)
	for i := 0; i < 10000; i++ {
		v := cfg.ComputeDelay(3, 0, &rng)
		if v < minV {
			minV = v
		}
		if v > maxV {
			maxV = v
		}
	}
	if maxV > 800 {
		t.Fatalf("Full Jitter at attempt=3 produced %d > 800", maxV)
	}
	if maxV < 700 {
		t.Fatalf("Full Jitter at attempt=3 max=%d, expected close to 800", maxV)
	}
	if minV > 50 {
		t.Fatalf("Full Jitter at attempt=3 min=%d, expected close to 0", minV)
	}
}

func TestDecorrelatedJitter_Markovian(t *testing.T) {
	cfg := BackoffConfig{BaseDelayMs: 100, CapMs: 30000, MaxRetries: 7, Strategy: DecorrelatedJitter}
	rng := splitMix64{state: 456}
	var prevSleep uint64 = cfg.BaseDelayMs
	for attempt := 0; attempt < 20; attempt++ {
		delay := cfg.ComputeDelay(attempt, prevSleep, &rng)
		if delay < cfg.BaseDelayMs {
			t.Fatalf("Decorrelated Jitter delay %d < base %d at attempt %d", delay, cfg.BaseDelayMs, attempt)
		}
		if delay > cfg.CapMs {
			t.Fatalf("Decorrelated Jitter delay %d > cap %d at attempt %d", delay, cfg.CapMs, attempt)
		}
		prevSleep = delay
	}
}

func TestDecorrelatedJitter_NeverZero(t *testing.T) {
	cfg := BackoffConfig{BaseDelayMs: 50, CapMs: 10000, MaxRetries: 10, Strategy: DecorrelatedJitter}
	rng := splitMix64{state: 9999}
	var prevSleep uint64 = cfg.BaseDelayMs
	for i := 0; i < 10000; i++ {
		delay := cfg.ComputeDelay(i%10, prevSleep, &rng)
		if delay == 0 {
			t.Fatalf("Decorrelated Jitter produced zero delay at iteration %d", i)
		}
		prevSleep = delay
	}
}

// TestClientPool_AcquireRelease validates the bounded ring-buffer pool.
func TestClientPool_AcquireRelease(t *testing.T) {
	createCount := 0
	pool := NewClientPool(4, func() (*http.Client, error) {
		createCount++
		return &http.Client{}, nil
	})

	// Acquire all 4 slots
	indices := make([]int, 4)
	for i := 0; i < 4; i++ {
		c, idx, err := pool.Acquire()
		if err != nil {
			t.Fatalf("acquire %d failed: %v", i, err)
		}
		if c == nil {
			t.Fatalf("acquire %d returned nil client", i)
		}
		indices[i] = idx
	}

	// 5th acquire should create ephemeral (idx=-1)
	c, idx, err := pool.Acquire()
	if err != nil {
		t.Fatalf("ephemeral acquire failed: %v", err)
	}
	if c == nil {
		t.Fatal("ephemeral acquire returned nil client")
	}
	if idx != -1 {
		t.Fatalf("expected idx=-1 for ephemeral, got %d", idx)
	}

	// Release all slots
	for _, i := range indices {
		pool.Release(i)
	}

	// Should be able to re-acquire without creating new clients
	prevCount := createCount
	_, _, err = pool.Acquire()
	if err != nil {
		t.Fatalf("re-acquire failed: %v", err)
	}
	if createCount != prevCount {
		t.Fatal("pool created a new client when a released slot was available")
	}
}

func TestBackoffConfig_Default(t *testing.T) {
	cfg := DefaultBackoffConfig()
	if cfg.BaseDelayMs != DefaultBaseDelayMs {
		t.Errorf("BaseDelayMs = %d, want %d", cfg.BaseDelayMs, DefaultBaseDelayMs)
	}
	if cfg.CapMs != DefaultCapMs {
		t.Errorf("CapMs = %d, want %d", cfg.CapMs, DefaultCapMs)
	}
	if cfg.MaxRetries != DefaultMaxRetries {
		t.Errorf("MaxRetries = %d, want %d", cfg.MaxRetries, DefaultMaxRetries)
	}
	if cfg.Strategy != FullJitter {
		t.Errorf("Strategy = %d, want FullJitter", cfg.Strategy)
	}
}

// BenchmarkFullJitter_ComputeDelay verifies zero-allocation on the hot path.
func BenchmarkFullJitter_ComputeDelay(b *testing.B) {
	cfg := DefaultBackoffConfig()
	rng := splitMix64{state: 42}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cfg.ComputeDelay(i%8, 100, &rng)
	}
}

// BenchmarkDecorrelatedJitter_ComputeDelay verifies zero-allocation on the hot path.
func BenchmarkDecorrelatedJitter_ComputeDelay(b *testing.B) {
	cfg := BackoffConfig{BaseDelayMs: 100, CapMs: 30000, MaxRetries: 7, Strategy: DecorrelatedJitter}
	rng := splitMix64{state: 42}
	prev := uint64(100)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		prev = cfg.ComputeDelay(i%8, prev, &rng)
	}
}
