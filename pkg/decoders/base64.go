package decoders

import (
	"bytes"
	"encoding/base64"
	"unicode"
	"unicode/utf8"
	"unsafe"

	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// Base64 is a decoder that identifies and decodes base64-encoded strings within text.
// It decodes both standard and URL-safe base64 strings.
type (
	Base64 struct{}
)

var (
	// b64Charset contains all valid base64 characters including padding and URL-safe variants.
	b64Charset = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-_=")
	// b64EndChars are characters that can appear at the end of base64 strings (padding and URL-safe chars)
	b64EndChars = "+/-_="

	// Pre-computed lookup sets for efficient character membership testing.
	b64CharsetSet  asciiSet
	b64EndCharsSet asciiSet
)

// asciiSet is a 256-bit value (8 * 32 bits), but we only use the lower 128 bits for ASCII.
// Each bit represents whether a given ASCII character is in the set.
// The lower 16 bytes represent all ASCII chars (0-127).
// Non-ASCII chars will map outside the 128-bit range and will be effectively "not in the set."
// This provides very efficient O(1) character membership testing using bitwise operations.
type asciiSet [8]uint32

// makeASCIISet creates a set of ASCII characters and reports whether all
// characters in chars are ASCII. It uses bit manipulation to create an efficient
// lookup table constructed at startup where each bit represents presence/absence of a character.
func makeASCIISet(chars string) (as asciiSet, ok bool) {
	for i := 0; i < len(chars); i++ {
		c := chars[i]
		if c >= utf8.RuneSelf { // non-ASCII char
			return as, false
		}
		// For each character, set the corresponding bit in the correct uint32.
		// c/32 determines which uint32 in the array.
		// c%32 determines which bit within that uint32.
		as[c/32] |= 1 << (c % 32)
	}
	return as, true
}

// contains reports whether c is inside the set by using bitwise operations
// to check if the corresponding bit is set in the lookup table.
// This approach was taken from the bytes package.
// https://cs.opensource.google/go/go/+/refs/tags/go1.23.4:src/bytes/bytes.go;l=899
func (as *asciiSet) contains(c byte) bool {
	return (as[c/32] & (1 << (c % 32))) != 0
}

func init() {
	var ok bool
	if b64CharsetSet, ok = makeASCIISet(string(b64Charset)); !ok {
		panic("b64Charset contains non-ASCII characters")
	}
	if b64EndCharsSet, ok = makeASCIISet(b64EndChars); !ok {
		panic("b64EndChars contains non-ASCII characters")
	}
}

// Type returns the decoder type for the Base64 decoder.
func (d *Base64) Type() detectorspb.DecoderType {
	return detectorspb.DecoderType_BASE64
}

// FromChunk attempts to identify and decode base64-encoded substrings within the given chunk of data.
// It returns a new chunk with any found base64 strings decoded, or nil if no valid base64 was found.
func (d *Base64) FromChunk(chunk *sources.Chunk) *DecodableChunk {
	decodableChunk := &DecodableChunk{Chunk: chunk, DecoderType: d.Type()}
	// Find potential base64 substrings that are at least 20 chars long.
	candidates := getSubstringsOfCharacterSet(chunk.Data, 20, b64CharsetSet, b64EndCharsSet)

	if len(candidates) == 0 {
		return nil
	}

	// Try to decode each candidate substring.
	var decodedCandidates []decodedCandidate
	for _, c := range candidates {
		data := chunk.Data[c.start:c.end]
		substring := bytesToString(data)

		// Heuristics: If substring contains '=', try StdEncoding first; otherwise, RawURLEncoding.
		// This avoids unnecessary decoding since:
		// 1. If a string contains '=', it's likely using standard base64 padding
		// 2. If a string can be decoded by both standard and URL-safe base64,
		//    both decodings would produce identical output (they only differ in
		//    how they encode '+/' vs '-_')
		// 3. Therefore, if we successfully decode with our first attempt, we can
		//    skip trying the other encoding.
		var dec []byte
		if bytes.Contains(data, []byte("=")) {
			// We ignore decode errors since we only care if we get valid output.
			// For invalid base64 input, DecodeString will return an empty result,
			// which we handle by trying the alternate encoding.
			dec, _ = base64.StdEncoding.DecodeString(substring)
			if len(dec) == 0 {
				dec, _ = base64.RawURLEncoding.DecodeString(substring)
			}
		} else {
			dec, _ = base64.RawURLEncoding.DecodeString(substring)
			if len(dec) == 0 {
				dec, _ = base64.StdEncoding.DecodeString(substring)
			}
		}

		// Only keep successfully decoded strings that are ASCII.
		if len(dec) > 0 && isASCII(dec) {
			decodedCandidates = append(decodedCandidates, decodedCandidate{
				start:   c.start,
				end:     c.end,
				decoded: dec,
			})
		}
	}

	if len(decodedCandidates) == 0 {
		return nil
	}

	// Rebuild the chunk data by replacing base64 strings with their decoded values.
	var result bytes.Buffer
	result.Grow(len(chunk.Data))

	lastPos := 0
	for _, dc := range decodedCandidates {
		if dc.start > lastPos {
			result.Write(chunk.Data[lastPos:dc.start])
		}
		result.Write(dc.decoded)
		lastPos = dc.end
	}

	if lastPos < len(chunk.Data) {
		result.Write(chunk.Data[lastPos:])
	}

	chunk.Data = result.Bytes()
	return decodableChunk
}

// bytesToString converts a byte slice to a string without copying the underlying data.
// Since the underlying byte slice is not being modified, we can safely use unsafe.Pointer.
func bytesToString(b []byte) string { return *(*string)(unsafe.Pointer(&b)) }

func isASCII(b []byte) bool {
	for _, c := range b {
		if c > unicode.MaxASCII {
			return false
		}
	}
	return true
}

// candidate represents a potential base64-encoded substring's position in the original data.
type candidate struct {
	start int
	end   int
}

// decodedCandidate represents a successfully decoded base64 substring and its position.
type decodedCandidate struct {
	start   int
	end     int
	decoded []byte
}

// getSubstringsOfCharacterSet finds substrings that consist primarily of base64 characters
// and are longer than the threshold.
func getSubstringsOfCharacterSet(data []byte, threshold int, charsetMapping asciiSet, endCharsMapping asciiSet) []candidate {
	if len(data) == 0 {
		return nil
	}

	// First pass: count potential base64 substrings to allocate correct slice size.
	count := 0
	substringsCount := 0
	for _, char := range data {
		if char < utf8.RuneSelf && charsetMapping.contains(byte(char)) {
			count++
		} else {
			if count > threshold {
				substringsCount++
			}
			count = 0
		}
	}
	if count > threshold {
		substringsCount++
	}

	if substringsCount == 0 {
		return nil
	}

	// Second pass: collect the actual substrings.
	candidates := make([]candidate, 0, substringsCount)

	count = 0
	start := 0
	for i, char := range data {
		if char < utf8.RuneSelf && charsetMapping.contains(byte(char)) {
			if count == 0 {
				start = i
			}
			count++
		} else {
			if count > threshold {
				candidates = appendB64Substring(data, start, count, candidates, endCharsMapping)
			}
			count = 0
		}
	}

	// Handle trailing substring if needed.
	if count > threshold {
		candidates = appendB64Substring(data, start, count, candidates, endCharsMapping)
	}
	return candidates
}

// appendB64Substring processes a potential base64 substring by trimming padding characters
// and handling special cases with '=' padding. It adds valid candidates to the slice.
func appendB64Substring(data []byte, start, count int, candidates []candidate, endCharsMapping asciiSet) []candidate {
	sub := data[start : start+count] // Original slice before trimming.

	// While bytes.TrimLeft/bytes.TrimRight let us remove characters using a cutset, they return a
	// subslice rather than just giving us the trimmed boundaries. In this context, we don't need a
	// fully trimmed subslice; we only need to identify the start and end indexes for subsequent logic.
	// By manually scanning from both ends and using a precomputed asciiSet (endCharsMapping), we can
	// determine those boundaries directly, avoid reprocessing the cutset for each trim, and maintain
	// control over the trimming logic without adding unnecessary slice operations.

	// Trim padding chars from the left.
	left := 0
	for left < len(sub) && sub[left] < utf8.RuneSelf && endCharsMapping.contains(sub[left]) {
		left++
	}
	substring := sub[left:] // substring after left trim
	substringLength := len(substring)

	// Trim padding chars from the right.
	right := substringLength - 1
	for right >= 0 && substring[right] < utf8.RuneSelf && endCharsMapping.contains(substring[right]) {
		right--
	}

	// If everything was trimmed, skip this candidate.
	if right < 0 {
		return candidates
	}

	trimmedRight := substring[:right+1]
	idx := bytes.IndexByte(trimmedRight, '=')

	// Handle special case where '=' is found mid-string.
	if idx != -1 {
		// Add substring after the '=' character.
		candidates = append(candidates, candidate{
			start: start + (count - substringLength) + idx + 1,
			end:   start + (count - substringLength) + substringLength,
		})
	} else {
		// Add the entire trimmed substring.
		candidates = append(candidates, candidate{
			start: start + (count - substringLength),
			end:   start + (count - substringLength) + substringLength,
		})
	}
	return candidates
}
