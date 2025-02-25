package ahocorasick

import (
	"bytes"
	"strings"

	ahocorasick "github.com/BobuSumisu/aho-corasick"

	"github.com/trufflesecurity/trufflehog/v3/pkg/custom_detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

// DetectorKey is used to identify a detector in the keywordsToDetectors map.
// Multiple detectors can have the same detector type but different versions.
// This allows us to identify a detector by its type and version. An
// additional (optional) field is provided to disambiguate multiple custom
// detectors. This type is exported even though none of its fields are so
// that the AhoCorasickCore can populate passed-in maps keyed on this type
// without exposing any of its internals to consumers.
type DetectorKey struct {
	detectorType       detectorspb.DetectorType
	version            int
	customDetectorName string
}

func (k DetectorKey) Loggable() map[string]any {
	res := map[string]any{"type": k.detectorType.String()}
	if k.version > 0 {
		res["version"] = k.version
	}
	if k.customDetectorName != "" {
		res["name"] = k.customDetectorName
	}
	return res
}

// Type returns the detector type of the key.
func (k DetectorKey) Type() detectorspb.DetectorType { return k.detectorType }

// spanCalculator is an interface that defines a method for calculating a match span
// in the chunk data. This allows for different strategies to be used without changing the core logic.
type spanCalculator interface {
	calculateSpan(params spanCalculationParams) matchSpan
}

// spanCalculationParams provides the necessary context for calculating match spans,
// including the keyword index in the chunk, the chunk data itself, and the detector being used.
type spanCalculationParams struct {
	keywordIdx int64 // Index of the keyword in the chunk data
	chunkData  []byte
	detector   detectors.Detector
}

// adjustableSpanCalculator is a strategy that calculates match spans. It uses a default offset magnitude
// or values provided by specific detectors to adjust the start and end indices of the span, allowing
// for more granular control over the match.
type adjustableSpanCalculator struct{ offsetMagnitude int64 }

// newAdjustableSpanCalculator creates a new instance of adjustableSpanCalculator with the
// specified offset magnitude.
func newAdjustableSpanCalculator(offsetRadius int64) *adjustableSpanCalculator {
	return &adjustableSpanCalculator{offsetMagnitude: offsetRadius}
}

// calculateSpan computes the match span based on the keyword index and the offset magnitude.
// If the detector provides an override value, it uses that instead of the default offset magnitude to
// calculate the maximum size of the span.
// The start index of the span is also adjusted if the detector provides a start offset.
func (m *adjustableSpanCalculator) calculateSpan(params spanCalculationParams) matchSpan {
	keywordIdx := params.keywordIdx

	maxSize := keywordIdx + m.offsetMagnitude
	startOffset := keywordIdx - m.offsetMagnitude

	// Check if the detector implements each interface and update values accordingly.
	// This CAN'T be done in a switch statement because a detector can implement multiple interfaces.
	if provider, ok := params.detector.(detectors.MultiPartCredentialProvider); ok {
		maxSize = provider.MaxCredentialSpan() + keywordIdx
		startOffset = keywordIdx - provider.MaxCredentialSpan()
	}
	if provider, ok := params.detector.(detectors.MaxSecretSizeProvider); ok {
		maxSize = provider.MaxSecretSize() + keywordIdx
	}
	if provider, ok := params.detector.(detectors.StartOffsetProvider); ok {
		startOffset = keywordIdx - provider.StartOffset()
	}

	startIdx := max(startOffset, 0)
	endIdx := min(maxSize, int64(len(params.chunkData)))

	// Ensure the start index is not greater than the end index to prevent invalid spans.
	// In rare cases where the calculated start index exceeds the end index (possibly due to
	// detector-provided offsets), we reset the start index to 0 to maintain a valid span range
	// and avoid runtime panics. This is a temporary fix until the root cause is identified.
	if startIdx >= endIdx {
		startIdx = 0
	}

	return matchSpan{startOffset: startIdx, endOffset: endIdx}
}

// CoreOption is a functional option type for configuring an AhoCorasickCore instance.
type CoreOption func(*Core)

// WithSpanCalculator sets the span calculator for AhoCorasickCore.
func WithSpanCalculator(spanCalculator spanCalculator) CoreOption {
	return func(ac *Core) { ac.spanCalculator = spanCalculator }
}

// Core encapsulates the operations and data structures used for keyword matching via the
// Aho-Corasick algorithm. It is responsible for constructing and managing the trie for efficient
// substring searches, as well as mapping keywords to their associated detectors for rapid lookups.
type Core struct {
	// prefilter is a ahocorasick struct used for doing efficient string
	// matching given a set of words. (keywords from the rules in the config)
	prefilter ahocorasick.Trie
	// Maps for efficient lookups during detection.
	// (This implementation maps in two layers: from keywords to detector
	// type and then again from detector type to detector. We could
	// go straight from keywords to detectors but doing it this way makes
	// some consuming code a little cleaner.)
	keywordsToDetectors map[string][]DetectorKey
	detectorsByKey      map[DetectorKey]detectors.Detector
	spanCalculator      spanCalculator // Strategy for calculating match spans
}

// NewAhoCorasickCore allocates and initializes a new instance of AhoCorasickCore. It uses the
// provided detector slice to create a map from keywords to detectors and build the Aho-Corasick
// prefilter trie.
func NewAhoCorasickCore(allDetectors []detectors.Detector, opts ...CoreOption) *Core {
	keywordsToDetectors := make(map[string][]DetectorKey)
	detectorsByKey := make(map[DetectorKey]detectors.Detector, len(allDetectors))
	var keywords []string
	for _, d := range allDetectors {
		key := CreateDetectorKey(d)
		detectorsByKey[key] = d
		for _, kw := range d.Keywords() {
			kwLower := strings.ToLower(kw)
			keywords = append(keywords, kwLower)
			keywordsToDetectors[kwLower] = append(keywordsToDetectors[kwLower], key)
		}
	}

	const defaultOffsetRadius int64 = 512
	core := &Core{
		keywordsToDetectors: keywordsToDetectors,
		detectorsByKey:      detectorsByKey,
		prefilter:           *ahocorasick.NewTrieBuilder().AddStrings(keywords).Build(),
		spanCalculator:      newAdjustableSpanCalculator(defaultOffsetRadius), // Default span calculator
	}

	for _, opt := range opts {
		opt(core)
	}

	return core
}

// DetectorMatch represents a detected pattern's metadata in a data chunk.
// It encapsulates the key identifying a specific detector, the detector instance itself,
// the start and end offsets of the matched keyword in the chunk, and the matched portions of the chunk data.
type DetectorMatch struct {
	Key DetectorKey
	detectors.Detector
	matchSpans []matchSpan

	// matches is a slice of byte slices, each representing a matched portion of the chunk data.
	matches [][]byte
}

// MatchSpan represents a single occurrence of a matched keyword in the chunk.
// It contains the start and end byte offsets of the matched keyword within the chunk.
type matchSpan struct {
	startOffset int64
	endOffset   int64
}

// addMatchSpan adds a match span to the DetectorMatch instance.
func (d *DetectorMatch) addMatchSpan(spans ...matchSpan) {
	d.matchSpans = append(d.matchSpans, spans...)
}

// mergeMatches merges overlapping or adjacent matchSpans into a single matchSpan.
// It updates the matchSpans field with the merged spans.
func (d *DetectorMatch) mergeMatches() {
	if len(d.matchSpans) <= 1 {
		return
	}

	merged := make([]matchSpan, 0, len(d.matchSpans))
	current := d.matchSpans[0]

	for i := 1; i < len(d.matchSpans); i++ {
		if d.matchSpans[i].startOffset <= current.endOffset {
			if d.matchSpans[i].endOffset > current.endOffset {
				current.endOffset = d.matchSpans[i].endOffset
			}
			continue
		}
		merged = append(merged, current)
		current = d.matchSpans[i]
	}

	merged = append(merged, current)
	d.matchSpans = merged
}

// extractMatches extracts the matched portions from the chunk data and stores them in the matches field.
func (d *DetectorMatch) extractMatches(chunkData []byte) {
	d.matches = make([][]byte, len(d.matchSpans))
	for i, m := range d.matchSpans {
		d.matches[i] = chunkData[m.startOffset:m.endOffset]
	}
}

// Matches returns a slice of byte slices, each representing a matched portion of the chunk data.
func (d *DetectorMatch) Matches() [][]byte { return d.matches }

// FindDetectorMatches finds the matching detectors for a given chunk of data using the Aho-Corasick algorithm.
// It returns a slice of DetectorMatch instances, each containing the detector key, detector,
// a slice of matchSpans, and the corresponding matched portions of the chunk data.
//
// Each matchSpan represents a position in the chunk data where a keyword was found,
// along with the corresponding span (start and end positions).
// The span is determined based on the configured spanCalculator strategy.
// Adjacent or overlapping matches are merged to avoid duplicating or overlapping the matched
// portions of the chunk data.
//
// The matches field contains the actual byte slices of the matched portions from the chunk data.
func (ac *Core) FindDetectorMatches(chunkData []byte) []*DetectorMatch {
	matches := ac.prefilter.Match(bytes.ToLower(chunkData))

	matchCount := len(matches)
	if matchCount == 0 {
		return nil
	}

	detectorMatches := make(map[DetectorKey]*DetectorMatch)

	for _, m := range matches {
		for _, k := range ac.keywordsToDetectors[m.MatchString()] {
			if _, exists := detectorMatches[k]; !exists {
				detector := ac.detectorsByKey[k]
				detectorMatches[k] = &DetectorMatch{
					Key:        k,
					Detector:   detector,
					matchSpans: make([]matchSpan, 0),
				}
			}

			detectorMatch := detectorMatches[k]
			startIdx := m.Pos()
			span := ac.spanCalculator.calculateSpan(
				spanCalculationParams{
					keywordIdx: startIdx,
					chunkData:  chunkData,
					detector:   detectorMatch.Detector,
				},
			)
			detectorMatch.addMatchSpan(span)
		}
	}

	uniqueDetectors := make([]*DetectorMatch, 0, len(detectorMatches))
	for _, detectorMatch := range detectorMatches {
		// Merge overlapping or adjacent match spans.
		detectorMatch.mergeMatches()
		detectorMatch.extractMatches(chunkData)

		uniqueDetectors = append(uniqueDetectors, detectorMatch)
	}

	return uniqueDetectors
}

// CreateDetectorKey creates a unique key for each detector from its type, version, and, for
// custom regex detectors, its name.
func CreateDetectorKey(d detectors.Detector) DetectorKey {
	detectorType := d.Type()
	var version int
	if v, ok := d.(detectors.Versioner); ok {
		version = v.Version()
	}
	var customDetectorName string
	if r, ok := d.(*custom_detectors.CustomRegexWebhook); ok {
		customDetectorName = r.GetName()
	}
	return DetectorKey{detectorType: detectorType, version: version, customDetectorName: customDetectorName}
}

func (ac *Core) KeywordsToDetectors() map[string][]DetectorKey {
	return ac.keywordsToDetectors
}
