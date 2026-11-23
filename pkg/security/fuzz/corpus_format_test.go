// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package fuzz

import (
	"errors"
	"strconv"
)

// These helpers parse the on-disk corpus format documented at readSeedFile.
// They are test-only; production code does not read the corpus.
//
// strconv.Unquote decodes the string literal body, including \xNN escapes, with
// the same Go syntax used by `go test -fuzz` when it writes a corpus entry.

// errCorruptSeed reports a corpus file whose []byte("...") wrapper or Go string
// literal cannot be parsed. TestSeedCorpusIsValid identifies the affected file.
var errCorruptSeed = errors.New("fuzz: corrupt go-fuzz corpus seed (want `go test fuzz v1\\n[]byte(\"...\")`)")

// unquoteGoString decodes the quoted body of []byte("...") with
// strconv.Unquote, preserving binary escapes exactly as Go defines them.
func unquoteGoString(literal string) ([]byte, error) {
	// strconv.Unquote expects the literal with surrounding quotes.
	out, err := strconv.Unquote(`"` + literal + `"`)
	if err != nil {
		return nil, errCorruptSeed
	}
	return []byte(out), nil
}
