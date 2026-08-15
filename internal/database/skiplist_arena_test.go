package database

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSkipListArena_PutAndIterate(t *testing.T) {
	alloc := NewJemallocAllocator()
	sl := NewSkipListArena(alloc, 1024*1024) // 1MB arena
	defer sl.Free()

	now := time.Now()
	keys := []string{"entity-c", "entity-a", "entity-b"}

	for _, id := range keys {
		key := makeTriTemporalKey(id, now, now, now)
		val := makePackedValue(id, 0x89283082803ffff, now.UnixNano(), [32]byte{}, []byte("payload-"+id))
		err := sl.Put(key, len(val), func(buf []byte) { copy(buf, val) })
		require.NoError(t, err)
	}

	assert.Equal(t, uint32(3), sl.Count())

	// Verify sorted iteration (keys are sorted by SHA-256 hash prefix).
	it := sl.NewIterator()
	var count int
	var prevKey []byte
	for it.Valid() {
		k := it.Key()
		v := it.Value()
		if prevKey != nil {
			assert.True(t, string(prevKey) <= string(k), "keys must be sorted")
		}
		prevKey = append([]byte{}, k...)

		// Verify value can be parsed back (O2.2 layout).
		entityIDLen := binary.LittleEndian.Uint16(v[0:2])
		assert.Greater(t, entityIDLen, uint16(0), "entity ID length must be > 0")
		entityID := string(v[2 : 2+entityIDLen])
		assert.Contains(t, entityID, "entity-")

		h3Off := 2 + int(entityIDLen)
		h3 := binary.LittleEndian.Uint64(v[h3Off : h3Off+8])
		assert.Equal(t, uint64(0x89283082803ffff), h3)

		count++
		it.Next()
	}
	assert.Equal(t, 3, count)
}

func TestSkipListArena_ArenaFull(t *testing.T) {
	alloc := NewJemallocAllocator()
	// Tiny arena: 1KB. Should fill up quickly.
	sl := NewSkipListArena(alloc, 1024)
	defer sl.Free()

	now := time.Now()
	var err error
	for i := 0; i < 100; i++ {
		key := makeTriTemporalKey("entity", now.Add(time.Duration(i)*time.Second), now, now)
		val := makePackedValue("entity", 0, now.UnixNano(), [32]byte{}, []byte("this is test payload data"))
		err = sl.Put(key, len(val), func(buf []byte) { copy(buf, val) })
		if err != nil {
			break
		}
	}

	assert.Error(t, err, "should error on arena full")
	assert.ErrorIs(t, err, ErrArenaFull)
}

func BenchmarkSkipListArena_Put(b *testing.B) {
	alloc := NewJemallocAllocator()
	sl := NewSkipListArena(alloc, 256*1024*1024) // 256MB
	defer sl.Free()

	now := time.Now()
	key := makeTriTemporalKey("bench-entity", now, now, now)
	val := makePackedValue("bench-entity", 0x89283082803ffff, now.UnixNano(), [32]byte{}, []byte("benchmark-payload-data-that-is-reasonably-sized"))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		binary.BigEndian.PutUint64(key[16:24], uint64(now.Add(time.Duration(i)*time.Nanosecond).UnixNano())) // Override 8.4: offset shifted
		_ = sl.Put(key, len(val), func(buf []byte) { copy(buf, val) })
	}
}
