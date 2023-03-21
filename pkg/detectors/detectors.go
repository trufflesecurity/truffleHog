package detectors

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unicode"

	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"google.golang.org/protobuf/types/known/structpb"
)

// Detector defines an interface for scanning for and verifying secrets.
type Detector interface {
	// FromData will scan bytes for results, and optionally verify them.
	FromData(ctx context.Context, verify bool, data []byte) ([]Result, error)
	// Keywords are used for efficiently pre-filtering chunks using substring operations.
	// Use unique identifiers that are part of the secret if you can, or the provider name.
	Keywords() []string
	// Type returns the DetectorType number from detectors.proto for the given detector.
	Type() detectorspb.DetectorType
}

// Versioner is an optional interface that a detector can implement to
// differentiate instances of the same detector type.
type Versioner interface {
	Version() int
}

type Result struct {
	// DetectorType is the type of Detector.
	DetectorType detectorspb.DetectorType
	// DecoderType is the type of Decoder.
	DecoderType detectorspb.DecoderType
	Verified    bool
	// Raw contains the raw secret identifier data. Prefer IDs over secrets since it is used for deduping after hashing.
	Raw []byte
	// RawV2 contains the raw secret identifier that is a combination of both the ID and the secret.
	// This is used for secrets that are multi part and could have the same ID. Ex: AWS credentials
	RawV2 []byte
	// Redacted contains the redacted version of the raw secret identification data for display purposes.
	// A secret ID should be used if available.
	Redacted       string
	ExtraData      *structpb.Struct
	StructuredData *detectorspb.StructuredData
}

type ResultWithMetadata struct {
	// SourceMetadata contains source-specific contextual information.
	SourceMetadata *source_metadatapb.MetaData
	// SourceID is the ID of the source that the API uses to map secrets to specific sources.
	SourceID int64
	// SourceType is the type of Source.
	SourceType sourcespb.SourceType
	// SourceName is the name of the Source.
	SourceName string
	Result
}

// CopyMetadata returns a detector result with included metadata from the source chunk.
func CopyMetadata(chunk *sources.Chunk, result Result) ResultWithMetadata {
	return ResultWithMetadata{
		SourceMetadata: chunk.SourceMetadata,
		SourceID:       chunk.SourceID,
		SourceType:     chunk.SourceType,
		SourceName:     chunk.SourceName,
		Result:         result,
	}
}

// CleanResults returns all verified secrets, and if there are no verified secrets,
// just one unverified secret if there are any.
func CleanResults(results []Result) []Result {
	if len(results) == 0 {
		return results
	}

	var cleaned = make(map[string]Result, 0)

	for _, s := range results {
		if s.Verified {
			cleaned[s.Redacted] = s
		}
	}

	if len(cleaned) == 0 {
		return results[:1]
	}

	results = results[:0]
	for _, r := range cleaned {
		results = append(results, r)
	}

	return results
}

// PrefixRegex ensures that at least one of the given keywords is within
// 20 characters of the capturing group that follows.
// This can help prevent false positives.
func PrefixRegex(keywords []string) string {
	pre := `(?i)(?:`
	middle := strings.Join(keywords, "|")
	post := `)(?:.|[\n\r]){0,40}`
	return pre + middle + post
}

// KeyIsRandom is a Low cost check to make sure that 'keys' include a number to reduce FPs.
// Golang doesnt support regex lookaheads, so must be done in separate calls.
// TODO improve checks. Shannon entropy did not work well.
func KeyIsRandom(key string) bool {
	for _, ch := range key {
		if unicode.IsDigit(ch) {
			return true
		}
	}

	return false
}

func MustGetBenchmarkData() map[string][]byte {
	_, filename, _, _ := runtime.Caller(0)
	dir := filepath.Dir(filename)
	small := make([]byte, 0)
	medium, err := os.ReadFile(filepath.Join(dir, "detectors.go"))
	if err != nil {
		panic(err)
	}
	big := make([]byte, 0)
	for i := 0; i < 25; i++ {
		big = append(big, medium...)
	}

	return map[string][]byte{
		"small":  small,
		"medium": medium,
		"big":    big,
	}
}
