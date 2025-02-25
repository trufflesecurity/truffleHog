package decoders

import (
	"bytes"
	"regexp"
	"strconv"
	"unicode/utf8"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

type EscapedUnicode struct{}

var _ Decoder = (*EscapedUnicode)(nil)

// It might be advantageous to limit these to a subset of acceptable characters, similar to base64.
// https://dencode.com/en/string/unicode-escape
var (
	// Standard Unicode notation.
	// https://unicode.org/standard/principles.html
	codePointPat = regexp.MustCompile(`\bU\+([a-fA-F0-9]{4}).?`)

	// Common escape sequence used in programming languages.
	escapePat = regexp.MustCompile(`(?i:\\{1,2}u)([a-fA-F0-9]{4})`)
)

func (d *EscapedUnicode) Type() detectorspb.DecoderType {
	return detectorspb.DecoderType_ESCAPED_UNICODE
}

func (d *EscapedUnicode) FromChunk(_ context.Context, chunk *sources.Chunk) *DecodableChunk {
	if chunk == nil || len(chunk.Data) == 0 {
		return nil
	}

	var (
		// Necessary to avoid data races.
		chunkData = bytes.Clone(chunk.Data)
		matched   = false
	)
	if codePointPat.Match(chunkData) {
		matched = true
		chunkData = decodeCodePoint(chunkData)
	}
	if escapePat.Match(chunkData) {
		matched = true
		chunkData = decodeEscaped(chunkData)
	}

	if matched {
		return &DecodableChunk{
			DecoderType: d.Type(),
			Chunk: &sources.Chunk{
				Data:           chunkData,
				SourceName:     chunk.SourceName,
				SourceID:       chunk.SourceID,
				JobID:          chunk.JobID,
				SecretID:       chunk.SecretID,
				SourceMetadata: chunk.SourceMetadata,
				SourceType:     chunk.SourceType,
				Verify:         chunk.Verify,
			},
		}
	} else {
		return nil
	}
}

// Unicode characters are encoded as 1 to 4 bytes per rune.
const maxBytesPerRune = 4
const spaceChar = byte(' ')

func decodeCodePoint(input []byte) []byte {
	// Find all Unicode escape sequences in the input byte slice
	indices := codePointPat.FindAllSubmatchIndex(input, -1)

	// Iterate over found indices in reverse order to avoid modifying the slice length
	utf8Bytes := make([]byte, maxBytesPerRune)
	for i := len(indices) - 1; i >= 0; i-- {
		matches := indices[i]

		startIndex := matches[0]
		endIndex := matches[1]
		hexStartIndex := matches[2]
		hexEndIndex := matches[3]

		// If the input is like `U+1234 U+5678` we should replace `U+1234 `.
		// Otherwise, we should only replace `U+1234`.
		if endIndex != hexEndIndex && input[endIndex-1] != spaceChar {
			endIndex = endIndex - 1
		}

		// Extract the hexadecimal value from the escape sequence
		hexValue := string(input[hexStartIndex:hexEndIndex])

		// Parse the hexadecimal value to an integer
		unicodeInt, err := strconv.ParseInt(hexValue, 16, 32)
		if err != nil {
			// If there's an error, continue to the next escape sequence
			continue
		}

		// Convert the Unicode code point to a UTF-8 representation
		utf8Len := utf8.EncodeRune(utf8Bytes, rune(unicodeInt))

		// Replace the escape sequence with the UTF-8 representation
		input = append(input[:startIndex], append(utf8Bytes[:utf8Len], input[endIndex:]...)...)
	}

	return input
}

func decodeEscaped(input []byte) []byte {
	// Find all Unicode escape sequences in the input byte slice
	indices := escapePat.FindAllSubmatchIndex(input, -1)

	// Iterate over found indices in reverse order to avoid modifying the slice length
	utf8Bytes := make([]byte, maxBytesPerRune)
	for i := len(indices) - 1; i >= 0; i-- {
		matches := indices[i]
		startIndex := matches[0]
		hexStartIndex := matches[2]
		endIndex := matches[3]

		// Extract the hexadecimal value from the escape sequence
		hexValue := string(input[hexStartIndex:endIndex])

		// Parse the hexadecimal value to an integer
		unicodeInt, err := strconv.ParseInt(hexValue, 16, 32)
		if err != nil {
			// If there's an error, continue to the next escape sequence
			continue
		}

		// Convert the Unicode code point to a UTF-8 representation
		utf8Len := utf8.EncodeRune(utf8Bytes, rune(unicodeInt))

		// Replace the escape sequence with the UTF-8 representation
		input = append(input[:startIndex], append(utf8Bytes[:utf8Len], input[endIndex:]...)...)
	}

	return input
}
