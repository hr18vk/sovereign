// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package durability

// ═══════════════════════════════════════════════════════════════════════════
// — KNOWN-COLLISION test-apparatus helpers (C1).
//
// made every production WAL record a 0x06 CRC32C-framed wrapper
// (innerType ‖ innerPayload ‖ crc32c). The/#11/#12 test scanners walk
// the RAW WAL and match the BARE checkpoint type bytes (0x02/0x05); under 0x06
// they find ZERO checkpoints. This helper lets them keep working WITHOUT
// weakening what they prove: it recognizes 0x06, RE-DERIVES and VERIFIES the
// CRC (the code under test is never its own check — a wrapped record whose
// CRC does not verify is caught HERE, loudly), and unwraps to the inner
// type+payload so the scanners match the inner 0x02/0x05 exactly as before.
// ═══════════════════════════════════════════════════════════════════════════

import (
	"encoding/binary"
	"hash/crc32"
	"testing"
)

// walRecordAtForTest reads the record at data[off:] and returns its EFFECTIVE
// (inner) type, its EFFECTIVE (inner) payload, the OUTER record length
// (13 + outerPayloadLen, the amount the walk must advance — identical for a
// bare or a wrapped record), and complete=false iff the record is a torn tail
// (truncated header or payload — a crash boundary, not a record).
//
// For a 0x06 record it verifies the CRC32C over innerType‖innerPayload and
// Fatalf's on mismatch (a scanner that accepted a bad CRC would be a lying
// check). For a legacy record (0x01–0x05) it returns the raw type+payload
// unchanged. Callers advance `off += recordLen` and `break` on !complete.
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
			t.Fatalf("0x06 record at offset %d FAILED its CRC (the scanner is a real check): stored %08x, computed %08x", off, want, got)
		}
		return body[0], body[1:], 13 + payloadLen, true
	}
	return recType, payload, 13 + payloadLen, true
}
