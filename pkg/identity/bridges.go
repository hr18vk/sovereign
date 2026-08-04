// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package identity

// Bridge pins for the ML-DSA fallback and the Cedar bench.
//
// These blank imports ensure go.sum contains pinned hash lines for each
// module per the specification's dependency-pinning gate. The actual
// symbol calls land in their respective changes (out of scope here).
// go mod tidy records hashes for all imported modules regardless
// of whether their symbols are exercised, so a blank import is the
// mechanical way to keep the pin without polluting the default build
// with unused symbols.
//
// filippo.io/mldsa exposes ML-DSA-44/65/87 (FIPS 204) via
// mldsa.MLDSA44/65/87, mldsa.GenerateKey, mldsa.Verify,
// mldsa.PrivateKey, mldsa.PublicKey. The pinned version is a
// pseudo-version (v0.0.0-20260711112038-ff3f469cee29) because the
// upstream has not tagged a stable release; `go list -m -versions`
// prints only the module path. If upstream tags a real version, the
// pin may need re-resolution.
//
// github.com/koblas/cedar-go (package name `cedar`) exposes
// cedar.NewAuthorizer, cedar.ParsePolicies, cedar.Authorizer,
// cedar.Request, cedar.AuthDetail. v0.1.0 is the latest tagged
// version.
import (
	_ "filippo.io/mldsa"
	_ "github.com/koblas/cedar-go"
)
