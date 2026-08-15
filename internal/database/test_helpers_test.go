package database

import (
	"crypto/sha256"
	"encoding/binary"
	"time"
)

// makeTriTemporalKey constructs a 40-byte composite key (Override 8.4: 128-bit hash).
func makeTriTemporalKey(entityID string, sysTime, validTime, assertTime time.Time) []byte {
	key := make([]byte, keySize)

	// First 16 bytes: truncated SHA-256 of entity ID (Override 8.4: was 8 bytes).
	h := sha256.Sum256([]byte(entityID))
	copy(key[0:16], h[:16])

	// Next 8 bytes: system time (nanoseconds).
	binary.BigEndian.PutUint64(key[16:24], uint64(sysTime.UnixNano()))

	// Next 8 bytes: valid time (nanoseconds).
	binary.BigEndian.PutUint64(key[24:32], uint64(validTime.UnixNano()))

	// Last 8 bytes: assertion time (nanoseconds).
	binary.BigEndian.PutUint64(key[32:40], uint64(assertTime.UnixNano()))

	return key
}

// makePackedValue creates a value with the 4.1 binary layout:
// [2B EntityID Len][EntityID String][8B H3Index][8B ValidTimeEnd][32B PayloadDigest][4B Payload Len][Payload Bytes]
func makePackedValue(entityID string, h3Index uint64, validTimeEnd int64, payloadDigest [32]byte, payload []byte) []byte {
	entityIDBytes := []byte(entityID)
	valLen := 2 + len(entityIDBytes) + 8 + 8 + 32 + 4 + len(payload)
	v := make([]byte, valLen)

	off := 0
	// 2B EntityID length
	binary.LittleEndian.PutUint16(v[off:off+2], uint16(len(entityIDBytes)))
	off += 2
	// EntityID string bytes
	copy(v[off:off+len(entityIDBytes)], entityIDBytes)
	off += len(entityIDBytes)
	// 8B H3Index
	binary.LittleEndian.PutUint64(v[off:off+8], h3Index)
	off += 8
	// 8B ValidTimeEnd
	binary.LittleEndian.PutUint64(v[off:off+8], uint64(validTimeEnd))
	off += 8
	// 32B PayloadDigest
	copy(v[off:off+32], payloadDigest[:])
	off += 32
	// 4B Payload length
	binary.LittleEndian.PutUint32(v[off:off+4], uint32(len(payload)))
	off += 4
	// Payload bytes
	copy(v[off:], payload)

	return v
}
