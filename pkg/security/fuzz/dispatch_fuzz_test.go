// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package fuzz

import (
	"testing"

	"github.com/hr18vk/sovereign/pkg/mesh"
	"github.com/hr18vk/sovereign/pkg/receive"
)

// FuzzDispatchFrame drives mesh.DispatchFrame with arbitrary frame bytes and
// checks that routing returns without a panic.
//
// DispatchFrame's recv parameter has the unexported type mesh.frameSink. Go's
// structural interface rules still let this package supply an implementation:
// nopSink has the required HandleFrame, HandleBatchFrame, and HandleHybridFrame
// methods without naming the interface.
//
// The sink methods return a fixed verdict and do not invoke a receiver. This
// target consequently covers the frame discriminators and routing calls, not
// capnp decoding, signature verification, or CRDT apply. The separate
// per-unmarshaler targets cover the wire parsers directly.

// nopSink is the no-op frameSink stub passed to DispatchFrame. Its three methods
// return a fixed AcceptVerdict (the verdict value is irrelevant — the fuzz
// asserts the call returns, not what it returns). It implements mesh.frameSink
// structurally.
type nopSink struct{}

func (nopSink) HandleFrame([]byte) receive.AcceptVerdict {
	return receive.AcceptVerdict{Verdict: receive.Accept}
}
func (nopSink) HandleBatchFrame([]byte) receive.AcceptVerdict {
	return receive.AcceptVerdict{Verdict: receive.Accept}
}
func (nopSink) HandleHybridFrame([]byte) receive.AcceptVerdict {
	return receive.AcceptVerdict{Verdict: receive.Accept}
}

// nopDigester lets the digest branch call DeliverDigest rather than take the
// nil-sink drop path. The method accepts the complete frame without parsing it;
// digestFrameSplit belongs to the production Gossiper, outside this target.
type nopDigester struct{}

func (nopDigester) DeliverDigest([16]byte, []byte) {}

// This declaration checks nopDigester against the exported mesh.DigestSink
// interface. The unexported mesh.frameSink cannot appear in such a declaration;
// instead, the DispatchFrame call below checks nopSink when it compiles.
var _ mesh.DigestSink = nopDigester{}

// FuzzDispatchFrame seeds DispatchFrame with dispatchSeeds and accepts arbitrary
// mutations of those inputs. A panic fails the target; the returned verdict is
// deliberately ignored. Run it for a bounded interval with:
//
//	go test -run='^$' -fuzz=FuzzDispatchFrame -fuzztime=120s ./pkg/security/fuzz/
func FuzzDispatchFrame(f *testing.F) {
	for _, seed := range dispatchSeeds() {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, wire []byte) {
		// The no-op sinks keep the check at classification and routing.
		_ = mesh.DispatchFrame(wire, [16]byte{}, nopSink{}, nopDigester{})
	})
}
