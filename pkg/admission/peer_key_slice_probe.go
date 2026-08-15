//go:build peer_key_slice_probe

// This file is compiled ONLY under the `peer_key_slice_probe` build tag
// to verify the compile-error tooth (G3.1.f). It is NEVER compiled in
// the normal build, the test build, or the race build — the tag is set
// only by an explicit `go build -tags peer_key_slice_probe` invocation
// that is EXPECTED TO FAIL.
//
// THE TOOTH: the roadmap wording "map[ed25519.PublicKey]*PeerEWMA"
// (line 61) is a COMPILE ERROR. circl's ed25519.PublicKey is
// `type PublicKey []byte` (pubkey112.go:7); Go slices are non-comparable
// and CANNOT be map keys. The compiler rejects:
//
//	var _ map[ed25519.PublicKey]int
//
// with the EXACT error string:
//
//	invalid map key type ed25519.PublicKey
//
// (probe: `go build -tags peer_key_slice_probe ./pkg/admission/` ->
// "invalid map key type".) This file detector-bans the slice-key
// pattern from this package's source identity: if a future builder
// re-introduces `map[ed25519.PublicKey]X`, this probe (or the
// equivalent production line) fails to compile with that exact string.
//
// The POSITIVE assertion — that [32]byte IS a valid PeerBucketKey — is
// `var _ PeerBucketKey = [32]byte{}` in ewma.go's PeerBucketKey doc and
// in TestPeerBucket_KeyIsArray32Byte. The NEGATIVE assertion lives here
// so a slice key is compile-banned, not just test-banned.
package admission

import "github.com/cloudflare/circl/sign/ed25519"

// _sliceKeyProbe is the negative-compile guard. Under the
// peer_key_slice_probe tag, this line MUST fail to compile with
// "invalid map key type ed25519.PublicKey", proving the slice-key form
// is detector-banned. (circl is imported ONLY in this probe file, which
// is never compiled in production — pkg/admission stays circl-free on
// the hot path, satisfying the §3 scope rule.)
var _ map[ed25519.PublicKey]int
