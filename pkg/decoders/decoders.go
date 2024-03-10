package decoders

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func DefaultDecoders() []Decoder {
	return []Decoder{
		// UTF8 must be first for duplicate detection
		&UTF8{},
		&Base64{},
		&UTF16{},
		&EscapedUnicode{},
		&HtmlEntity{},
	}
}

// DecodableChunk is a chunk that includes the type of decoder used.
// This allows us to avoid a type assertion on each decoder.
type DecodableChunk struct {
	*sources.Chunk
	DecoderType detectorspb.DecoderType
}

type Decoder interface {
	FromChunk(ctx context.Context, chunk *sources.Chunk) *DecodableChunk
	Type() detectorspb.DecoderType
}

// Fuzz is an entrypoint for go-fuzz, which is an AFL-style fuzzing tool.
// This one attempts to uncover any panics during decoding.
func Fuzz(data []byte) int {
	decoded := false
	ctx := context.Background()
	for i, decoder := range DefaultDecoders() {
		// Skip the first decoder (plain), because it will always decode and give
		// priority to the input (return 1).
		if i == 0 {
			continue
		}
		chunk := decoder.FromChunk(ctx, &sources.Chunk{Data: data})
		if chunk != nil {
			decoded = true
		}
	}
	if decoded {
		return 1 // prioritize the input
	}
	return -1 // Don't add input to the corpus.
}
