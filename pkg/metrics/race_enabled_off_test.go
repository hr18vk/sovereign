// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

// raceEnabled is false in clean builds. The race-tagged companion file
// race_enabled_test.go declares the true form, selected only under
// `go test -race`. See race_enabled_test.go for the perturbation rationale.

//go:build !race
// +build !race

package metrics

const raceEnabled = false
