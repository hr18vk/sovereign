package fuzz

import (
	"errors"
	"strconv"
)

// corpus_format_test.go holds the go-fuzz on-disk corpus-file parser helpers.
// Kept in a _test.go file (corpus parsing is a test-tier concern; no production
// code reads the corpus). The format is documented at readSeedFile.
//
// The parser uses strconv.Unquote for the string literal body — Go's OWN
// unquote rules — so binary seeds (with \xNN escapes) round-trip byte-identical
// to what `go test -fuzz` wrote. A hand-rolled unquoter would risk drift; the
// stdlib is the single source of truth for Go string-literal syntax.

// errCorruptSeed is returned when a committed corpus file does not match the
// go-fuzz format (missing header, missing the []byte("...") wrapper, or an
// unquote failure). A corrupt committed seed is a CI flake the
// TestSeedCorpusIsValid tooth catches (Law II).
var errCorruptSeed = errors.New("fuzz: corrupt go-fuzz corpus seed (want `go test fuzz v1\\n[]byte(\"...\")`)")

// unquoteGoString unquotes a Go double-quoted string literal (the body inside
// `[]byte("...")`) to its raw bytes via strconv.Unquote. strconv.Unquote
// handles \xNN (binary), \n, \t, \\, \", \uXXXX, and the full Go escape set —
// the faithful inverse of what `go test -fuzz` writes.
func unquoteGoString(literal string) ([]byte, error) {
	// strconv.Unquote expects the literal WITH surrounding quotes.
	out, err := strconv.Unquote(`"` + literal + `"`)
	if err != nil {
		return nil, errCorruptSeed
	}
	return []byte(out), nil
}
