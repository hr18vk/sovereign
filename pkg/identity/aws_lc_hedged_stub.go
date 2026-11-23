// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

//go:build aws_lc_hedged

// aws_lc_hedged_stub.go is a build-tag-gated stub for an eventual C-backed
// Ed25519 signing bridge against github.com/awslabs/aws-lc v1.73.0. Default
// builds exclude this file and use SignCRDTFrame in eddsa_hedge.go.
package identity

// HedgedSignAWSLC is a build-tagged stub; it panics until C linkage against
// aws-lc is implemented.
func HedgedSignAWSLC(seed, msg []byte) ([]byte, error) {
	panic("aws_lc_hedged bridge not implemented")
}
