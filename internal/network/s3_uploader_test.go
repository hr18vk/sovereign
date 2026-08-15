package network

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestShardedKey_Format(t *testing.T) {
	nodeID := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	txTimeNs := int64(1720612800000000000)
	suffix := "node123.arrow"

	key := ShardedKey(nodeID, txTimeNs, suffix)

	// Validate it has 4 hex chars + / + suffix
	assert.Len(t, key, 4+1+len(suffix))
	assert.Equal(t, "/", string(key[4]))
	assert.Equal(t, suffix, key[5:])

	// Validate hash manually
	var hashInput [24]byte
	copy(hashInput[:16], nodeID[:])
	hashInput[16] = byte(txTimeNs >> 56)
	hashInput[17] = byte(txTimeNs >> 48)
	hashInput[18] = byte(txTimeNs >> 40)
	hashInput[19] = byte(txTimeNs >> 32)
	hashInput[20] = byte(txTimeNs >> 24)
	hashInput[21] = byte(txTimeNs >> 16)
	hashInput[22] = byte(txTimeNs >> 8)
	hashInput[23] = byte(txTimeNs)

	digest := sha256.Sum256(hashInput[:])
	var hexPrefix [4]byte
	hex.Encode(hexPrefix[:], digest[:2])

	assert.Equal(t, string(hexPrefix[:]), key[:4])
}

func BenchmarkShardedKey(b *testing.B) {
	nodeID := [16]byte{1}
	txTimeNs := int64(1720612800000000000)
	suffix := "node123.arrow"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ShardedKey(nodeID, txTimeNs, suffix)
	}
}
