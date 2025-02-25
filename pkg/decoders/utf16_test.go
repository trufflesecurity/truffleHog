package decoders

import (
	"bytes"
	"os"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func TestUTF16Decoder(t *testing.T) {
	testCases := []struct {
		name      string
		input     []byte
		expected  []byte
		expectNil bool
	}{
		{
			name:      "Valid UTF-16LE input",
			input:     []byte{72, 0, 101, 0, 108, 0, 108, 0, 111, 0, 32, 0, 87, 0, 111, 0, 114, 0, 108, 0, 100, 0},
			expected:  []byte("Hello World"),
			expectNil: false,
		},
		{
			name:      "Valid UTF-16BE input",
			input:     []byte{0, 72, 0, 101, 0, 108, 0, 108, 0, 111, 0, 32, 0, 87, 0, 111, 0, 114, 0, 108, 0, 100},
			expected:  []byte("Hello World"),
			expectNil: false,
		},
		{
			name:      "Invalid UTF-16 input (it's UTF-8)",
			input:     []byte("Hello World!"),
			expected:  nil,
			expectNil: true,
		},
		{
			name:      "Invalid UTF-16 input (odd length)",
			input:     []byte{72, 0, 101, 0, 108, 0, 108, 0, 111, 0, 32, 0, 87, 0, 111, 0, 114, 0, 108, 0, 0},
			expected:  []byte("Hello Worl"),
			expectNil: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			chunk := &sources.Chunk{Data: tc.input}
			decoder := &UTF16{}
			decodedChunk := decoder.FromChunk(context.Background(), chunk)

			if tc.expectNil {
				if decodedChunk != nil {
					t.Errorf("Expected nil, got chunk with data: %v", decodedChunk.Data)
				}
				return
			}
			if decodedChunk == nil {
				t.Errorf("Expected chunk with data, got nil")
				return
			}
			if !bytes.Equal(decodedChunk.Data, tc.expected) {
				t.Errorf("Expected decoded data: %s, got: %s", tc.expected, decodedChunk.Data)
			}
		})
	}
}

func TestDLL(t *testing.T) {
	data, err := os.ReadFile("utf16_test.dll")
	if err != nil {
		t.Errorf("Failed to read test data: %v", err)
		return
	}

	chunk := &sources.Chunk{Data: data}
	decoder := &UTF16{}
	decodedChunk := decoder.FromChunk(context.Background(), chunk)
	if decodedChunk == nil {
		t.Errorf("Expected chunk with data, got nil")
		return
	}
	if !bytes.Contains(decodedChunk.Data, []byte("aws_secret_access_key")) {
		t.Errorf("Expected chunk to have aws_secret_access_key")
		return
	}
}

func BenchmarkUtf16ToUtf8(b *testing.B) {
	// Example UTF-16LE encoded data
	data := []byte{72, 0, 101, 0, 108, 0, 108, 0, 111, 0, 32, 0, 87, 0, 111, 0, 114, 0, 108, 0, 100, 0}

	for n := 0; n < b.N; n++ {
		_, _ = utf16ToUTF8(data)
	}
}
