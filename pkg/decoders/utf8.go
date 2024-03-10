package decoders

import (
	"unicode/utf8"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

type UTF8 struct{}

func (d *UTF8) Type() detectorspb.DecoderType {
	return detectorspb.DecoderType_PLAIN
}

func (d *UTF8) FromChunk(_ context.Context, chunk *sources.Chunk) *DecodableChunk {
	if chunk == nil || len(chunk.Data) == 0 {
		return nil
	}

	decodableChunk := &DecodableChunk{Chunk: chunk, DecoderType: d.Type()}

	if !utf8.Valid(chunk.Data) {
		chunk.Data = extractSubstrings(chunk.Data)
		return decodableChunk
	}

	return decodableChunk
}

// utf8ReplacementBytes holds the UTF-8 encoded form of the Unicode replacement character (U+FFFD).
// This is pre-computed since it's used frequently when replacing invalid UTF-8 sequences
// and control characters.
var utf8ReplacementBytes = []byte(string(utf8.RuneError))

// extractSubstrings sanitizes byte sequences to ensure consistent handling of malformed input
// while maintaining readable content. It handles ASCII and UTF-8 data as follows:
//
// For ASCII range (0-127): preserves printable characters (32-126) while replacing
// control characters with the UTF-8 replacement character.
// https://cs.opensource.google/go/go/+/refs/tags/go1.23.3:src/unicode/utf8/utf8.go;l=16
//
// For multi-byte sequences: preserves valid UTF-8 as-is, while invalid sequences
// are replaced with a single UTF-8 replacement character.
func extractSubstrings(b []byte) []byte {
	dataLen := len(b)
	buf := make([]byte, 0, dataLen)
	for idx := 0; idx < dataLen; {
		// If it's ASCII, handle separately.
		// This is faster than decoding for common cases.
		if b[idx] < utf8.RuneSelf {
			if isPrintableByte(b[idx]) {
				buf = append(buf, b[idx])
			} else {
				buf = append(buf, utf8ReplacementBytes...)
			}
			idx++
			continue
		}

		r, size := utf8.DecodeRune(b[idx:])
		if r == utf8.RuneError {
			// Collapse any malformed sequence into a single replacement character
			// rather than replacing each byte individually.
			buf = append(buf, utf8ReplacementBytes...)
			idx++
		} else {
			// Keep valid multi-byte UTF-8 sequences intact to preserve unicode characters.
			buf = append(buf, b[idx:idx+size]...)
			idx += size
		}
	}

	return buf
}

// isPrintableByte reports whether a byte represents a printable ASCII character
// using a fast byte-range check. This avoids the overhead of utf8.DecodeRune
// for the common case of ASCII characters (0-127), since we know any byte < 128
// represents a complete ASCII character and doesn't need UTF-8 decoding.
// This includes letters, digits, punctuation, and symbols, but excludes control characters.
// The upper bound is 127 (not 128) because 127 is the DEL control character.
//
// https://www.rapidtables.com/code/text/ascii-table.html
func isPrintableByte(c byte) bool { return c > 31 && c < 127 }
