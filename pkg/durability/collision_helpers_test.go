// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package durability

// Helpers for tests that scan WAL records containing checkpoints.
//
// Production WAL records use a 0x06 CRC32C-framed wrapper containing the inner
// type, inner payload, and checksum. Test scanners look for bare checkpoint
// types 0x02 and 0x05, so they must unwrap 0x06 first. These helpers verify the
// checksum independently before returning the inner record; a damaged wrapper
// fails the test rather than passing silently through the scanner.

import (
	"encoding/binary"
	"hash/crc32"
	"testing"
)

// walRecordAtForTest returns the inner type and payload at data[off:], plus the
// outer record length that the caller must add to off. complete is false for a
// truncated header or payload. Bare and wrapped records use the same outer
// length calculation.
//
// A 0x06 record is accepted only after its CRC32C verifies over the inner type
// and payload. Legacy record types 0x01 through 0x05 are returned unchanged.
// Callers advance by recordLen and stop when complete is false.
func walRecordAtForTest(t *testing.T, data []byte, off int) (innerType byte, innerPayload []byte, recordLen int, complete bool) {
	t.Helper()
	if off+13 > len(data) {
		return 0, nil, 0, false // torn header — end of clean records (crash boundary)
	}
	recType := data[off+8]
	payloadLen := int(binary.BigEndian.Uint32(data[off+9 : off+13]))
	if off+13+payloadLen > len(data) {
		return 0, nil, 0, false // torn payload — end of clean records (crash boundary)
	}
	payload := data[off+13 : off+13+payloadLen]
	if recType == byte(WALRecChecksummed) {
		if payloadLen < 5 {
			t.Fatalf("0x06 record at offset %d too short for innerType+CRC (%d bytes)", off, payloadLen)
		}
		body := payload[:payloadLen-4] // innerType ‖ innerPayload
		want := binary.BigEndian.Uint32(payload[payloadLen-4:])
		got := crc32.Checksum(body, snapshotCastagnoliTable)
		if want != got {
			t.Fatalf("0x06 record at offset %d has invalid CRC32C: stored %08x, computed %08x", off, want, got)
		}
		return body[0], body[1:], 13 + payloadLen, true
	}
	return recType, payload, 13 + payloadLen, true
}
