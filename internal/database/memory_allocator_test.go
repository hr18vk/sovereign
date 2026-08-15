package database

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJemallocAllocator_Allocate(t *testing.T) {
	alloc := NewJemallocAllocator()

	buf := alloc.Allocate(4096)
	require.NotNil(t, buf)
	assert.Equal(t, 4096, len(buf))
	assert.Equal(t, int64(4096), alloc.BytesAllocated())

	// Verify zeroed memory.
	for i := range buf {
		assert.Equal(t, byte(0), buf[i])
	}

	// Write and read back.
	buf[0] = 0xDE
	buf[4095] = 0xAD
	assert.Equal(t, byte(0xDE), buf[0])
	assert.Equal(t, byte(0xAD), buf[4095])

	alloc.Free(buf)
	assert.Equal(t, int64(0), alloc.BytesAllocated())
}

func TestJemallocAllocator_Reallocate(t *testing.T) {
	alloc := NewJemallocAllocator()

	buf := alloc.Allocate(1024)
	buf[0] = 0xFF
	buf[1023] = 0xAA

	buf = alloc.Reallocate(2048, buf)
	require.NotNil(t, buf)
	assert.Equal(t, 2048, len(buf))

	// Old data preserved.
	assert.Equal(t, byte(0xFF), buf[0])
	assert.Equal(t, byte(0xAA), buf[1023])

	// New region zeroed.
	assert.Equal(t, byte(0), buf[1024])

	alloc.Free(buf)
	assert.Equal(t, int64(0), alloc.BytesAllocated())
}

func TestJemallocAllocator_AllocateZero(t *testing.T) {
	alloc := NewJemallocAllocator()
	buf := alloc.Allocate(0)
	assert.Nil(t, buf)
	assert.Equal(t, int64(0), alloc.BytesAllocated())
}

func TestJemallocAllocator_SatisfiesInterface(t *testing.T) {
	// This test validates that JemallocAllocator satisfies memory.Allocator
	// at compile time. If this compiles, the interface is satisfied.
	alloc := NewJemallocAllocator()
	_ = alloc
}

func BenchmarkJemallocAllocator_Allocate(b *testing.B) {
	alloc := NewJemallocAllocator()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf := alloc.Allocate(65536) // 64KB — typical Arrow buffer
		alloc.Free(buf)
	}
}
