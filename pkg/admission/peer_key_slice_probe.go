// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

//go:build peer_key_slice_probe

// The peer_key_slice_probe build tag enables this negative compilation test.
// Normal and test builds exclude it. An explicit
// `go build -tags peer_key_slice_probe ./pkg/admission/` must fail because
// circl's ed25519.PublicKey is a slice, and slices cannot be map keys:
//
//	var _ map[ed25519.PublicKey]int
//
// The compiler rejects it with an invalid map key type error naming
// ed25519.PublicKey.
//
// TestPeerBucket_KeyIsArray32Byte checks the complementary positive case:
// [32]byte has the same underlying type as PeerBucketKey and is comparable.
package admission

import "github.com/cloudflare/circl/sign/ed25519"

// This declaration must fail with an invalid map key type error under the
// peer_key_slice_probe tag. The normal package remains independent of circl
// because only this excluded file imports it.
var _ map[ed25519.PublicKey]int
