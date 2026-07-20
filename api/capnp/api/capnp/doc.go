// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

// Package capnp contains the generated Cap'n Proto Go bindings for the
// Sovereign Engine ingestion wire format (see schema.capnp).
//
// The TriTemporalEvent struct is the unit ingested by the EPOLLET transport
// (internal/transport) and written into the off-heap MemTable
// (internal/database). It encodes a spatial event with a fixed 8-byte-aligned
// data section (Float64 latitude, Float64 longitude, UInt64 assertionTime)
// and two Text pointer fields (entityId, payload).
//
// This file is package documentation; the bindings themselves are generated
// into schema.capnp.go via:
//
//	capnp compile -ogo -I <capnp-go>/std api/capnp/api/capnp/schema.capnp
//
// and must not be hand-edited.
package capnp
