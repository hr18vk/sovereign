// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// Package sync exposes CRDTDelta peel outcomes to pkg/mesh. A non-nil delta
// can contain either an isolated difference or the full-keyset fallback used
// when subtraction or peeling fails. These accessors distinguish those cases;
// the mesh counters digestPeelOversends and digestRespondDropped record them.
package sync

// PeelErr returns ErrIncompletePeel when GenerateDelta could not peel the
// symmetric difference. The delta then falls back to the full keyset, which
// still converges through Join's merge-union but uses more bandwidth. A nil
// error means the peel completed and SendKeyCount is the exact send-set size.
func (d *CRDTDelta) PeelErr() error { return d.peelErr }

// DiffNil reports whether subtraction was skipped because the local and remote
// IBLTs have different bucket counts or k values. GenerateDelta then returns
// the full keyset instead of an isolated difference.
func (d *CRDTDelta) DiffNil() bool { return d.diffNil }

// SendKeyCount returns the number of keys in the sorted, arena-backed send set
// isolated by the peel. It is zero for an empty difference and for either
// full-keyset fallback, so callers use PeelErr and DiffNil to distinguish them.
// The count is not the number of entries shipped by a fallback delta.
func (d *CRDTDelta) SendKeyCount() int { return len(d.sendKeys) }
