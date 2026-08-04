// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

//go:build aws_lc_hedged

// aws_lc_hedged_stub.go is the CGO bridge scaffold for
// (hedged signing). It is build-tag-gated so the default build skips
// it; the real C linkage against github.com/awslabs/aws-lc v1.73.0
// lands in.
//
// The Go binding module github.com/aws/aws-lc-go is repo-not-found
// (git ls-remote exit 128, verified pre-execution).
// The bridge therefore targets the C library directly via #cgo
// directives (CFLAGS -I<path>, LDFLAGS -L<path> -lcrypto). No Go
// binding module exists; the scaffold is a Go-only stub that panics
// until 1.2 wires the real C calls.
//
// GATED: do NOT introduce a "hedged" claim into specs without a
// go-doc-proven call site. This stub exists only so the build tag and
// the future #cgo scaffold are inventoried in 1.0.
package identity

// HedgedSignAWSLC is a STUB. The real implementation links against
// awslabs/aws-lc v1.73.0 via #cgo CFLAGS -I<path> and calls the C
// Ed25519 hedged-signing API. GATED until the CGO bridge lands in
// .
func HedgedSignAWSLC(seed, msg []byte) ([]byte, error) {
	panic("aws_lc_hedged bridge not implemented — see ")
}
