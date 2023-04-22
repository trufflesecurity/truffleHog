package decoders

import (
	"bytes"
	"encoding/base64"

	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

type Base64 struct{}

var (
	b64Charset  = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
	b64EndChars = "+/="
)

func (d *Base64) FromChunk(chunk *sources.Chunk) *sources.Chunk {

	encodedSubstrings := getSubstringsOfCharacterSet(chunk.Data, 20)
	decodedSubstrings := make(map[string][]byte)

	for _, str := range encodedSubstrings {
		dec, err := base64.StdEncoding.DecodeString(str)
		if err == nil && len(dec) > 0 {
			decodedSubstrings[str] = dec
		}
	}

	if len(decodedSubstrings) > 0 {
		var result bytes.Buffer
		result.Grow(len(chunk.Data))

		start := 0
		for _, encoded := range encodedSubstrings {
			if decoded, ok := decodedSubstrings[encoded]; ok {
				end := bytes.Index(chunk.Data[start:], []byte(encoded))
				if end != -1 {
					result.Write(chunk.Data[start : start+end])
					result.Write(decoded)
					start += end + len(encoded)
				}
			}
		}
		result.Write(chunk.Data[start:])
		chunk.Data = result.Bytes()
		return chunk
	}

	return nil
}

func getSubstringsOfCharacterSet(data []byte, threshold int) []string {
	if len(data) == 0 {
		return nil
	}

	// Given characters are mostly ASCII, we can use a simple array to map.
	var b64CharsetMapping [128]bool
	// Build an array of all the characters in the base64 charset.
	for _, char := range b64Charset {
		b64CharsetMapping[char] = true
	}

	count := 0
	substringsCount := 0

	// Determine the number of substrings that will be returned.
	// Pre-allocate the slice to avoid reallocations.
	for _, char := range data {
		if char < 128 && b64CharsetMapping[char] {
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

	count = 0
	start := 0
	substrings := make([]string, 0, substringsCount)

	for i, char := range data {
		if char < 128 && b64CharsetMapping[char] {
			if count == 0 {
				start = i
			}
			count++
		} else {
			if count > threshold {
				substrings = appendB64Substring(data, start, count, substrings)
			}
			count = 0
		}
	}

	if count > threshold {
		substrings = appendB64Substring(data, start, count, substrings)
	}

	return substrings
}

func appendB64Substring(data []byte, start, count int, substrings []string) []string {
	substring := bytes.TrimLeft(data[start:start+count], b64EndChars)
	if idx := bytes.IndexByte(bytes.TrimRight(substring, b64EndChars), '='); idx != -1 {
		substrings = append(substrings, string(substring[idx+1:]))
	} else {
		substrings = append(substrings, string(substring))
	}
	return substrings
}
