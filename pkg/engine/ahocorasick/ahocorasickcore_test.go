package ahocorasick

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/trufflesecurity/trufflehog/v3/pkg/custom_detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/custom_detectorspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

const TestDetectorType = -1

type testDetectorV1 struct {
}

func (testDetectorV1) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	return make([]detectors.Result, 0), nil
}

func (testDetectorV1) Keywords() []string { return []string{"a", "b"} }

func (testDetectorV1) Type() detectorspb.DetectorType {
	return TestDetectorType
}

func (testDetectorV1) Version() int { return 1 }

func (testDetectorV1) Description() string { return "" }

type testDetectorV2 struct {
}

func (testDetectorV2) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	return make([]detectors.Result, 0), nil
}

func (testDetectorV2) Keywords() []string {
	return []string{"a"}
}

func (testDetectorV2) Type() detectorspb.DetectorType {
	return TestDetectorType
}

func (testDetectorV2) Version() int { return 2 }

func (testDetectorV2) Description() string { return "" }

type testDetectorV3 struct {
}

func (testDetectorV3) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	return make([]detectors.Result, 0), nil
}

func (testDetectorV3) Keywords() []string {
	return []string{"truffle"}
}

func (testDetectorV3) Type() detectorspb.DetectorType {
	return TestDetectorType
}

func (testDetectorV3) Version() int { return 1 }

func (testDetectorV3) Description() string { return "" }

var _ detectors.Detector = (*testDetectorV4)(nil)
var _ detectors.MultiPartCredentialProvider = (*testDetectorV4)(nil)
var _ detectors.StartOffsetProvider = (*testDetectorV4)(nil)

type testDetectorV4 struct{}

func (testDetectorV4) FromData(context.Context, bool, []byte) ([]detectors.Result, error) {
	return make([]detectors.Result, 0), nil
}

func (testDetectorV4) Keywords() []string { return []string{"password"} }

func (testDetectorV4) Type() detectorspb.DetectorType { return TestDetectorType }

func (testDetectorV4) Version() int { return 1 }

func (testDetectorV4) Description() string { return "" }

func (testDetectorV4) MaxCredentialSpan() int64 { return 15 }

func (testDetectorV4) StartOffset() int64 { return 5 }

var _ detectors.Detector = (*testDetectorV5)(nil)
var _ detectors.MaxSecretSizeProvider = (*testDetectorV5)(nil)
var _ detectors.StartOffsetProvider = (*testDetectorV5)(nil)

type testDetectorV5 struct{}

func (testDetectorV5) FromData(context.Context, bool, []byte) ([]detectors.Result, error) {
	return make([]detectors.Result, 0), nil
}

func (testDetectorV5) Keywords() []string { return []string{"password"} }

func (testDetectorV5) Type() detectorspb.DetectorType { return TestDetectorType }

func (testDetectorV5) Version() int { return 1 }

func (testDetectorV5) Description() string { return "" }

func (testDetectorV5) MaxSecretSize() int64 { return 10 }

func (testDetectorV5) StartOffset() int64 { return 3 }

var _ detectors.Detector = (*testDetectorV6)(nil)
var _ detectors.Detector = (*testDetectorV6)(nil)
var _ detectors.StartOffsetProvider = (*testDetectorV6)(nil)

type testDetectorV6 struct{}

func (testDetectorV6) FromData(context.Context, bool, []byte) ([]detectors.Result, error) {
	return make([]detectors.Result, 0), nil
}

func (testDetectorV6) Keywords() []string { return []string{"password"} }

func (testDetectorV6) Type() detectorspb.DetectorType { return TestDetectorType }

func (testDetectorV6) Version() int { return 1 }

func (testDetectorV6) Description() string { return "" }

func (testDetectorV6) StartOffset() int64 { return 1 }

var _ detectors.Detector = (*testDetectorV1)(nil)
var _ detectors.Detector = (*testDetectorV2)(nil)
var _ detectors.Versioner = (*testDetectorV1)(nil)
var _ detectors.Versioner = (*testDetectorV2)(nil)
var _ detectors.Versioner = (*testDetectorV3)(nil)

func TestAhoCorasickCore_MultipleCustomDetectorsMatchable(t *testing.T) {
	customDetector1, err := custom_detectors.NewWebhookCustomRegex(&custom_detectorspb.CustomRegex{
		Name:     "custom detector 1",
		Keywords: []string{"a"},
		Regex:    map[string]string{"": ""},
	})
	assert.Nil(t, err)

	customDetector2, err := custom_detectors.NewWebhookCustomRegex(&custom_detectorspb.CustomRegex{
		Name:     "custom detector 2",
		Keywords: []string{"a"},
		Regex:    map[string]string{"": ""},
	})
	assert.Nil(t, err)

	allDetectors := []detectors.Detector{customDetector1, customDetector2}

	ac := NewAhoCorasickCore(allDetectors)

	dts := ac.FindDetectorMatches([]byte("a"))
	matchingDetectors := make([]detectors.Detector, 0, 2)
	for _, d := range dts {
		matchingDetectors = append(matchingDetectors, d.Detector)
	}
	assert.ElementsMatch(t, allDetectors, matchingDetectors)
}

func TestAhoCorasickCore_MultipleDetectorVersionsMatchable(t *testing.T) {
	v1 := testDetectorV1{}
	v2 := testDetectorV2{}
	allDetectors := []detectors.Detector{v1, v2}

	ac := NewAhoCorasickCore(allDetectors)

	dts := ac.FindDetectorMatches([]byte("a"))
	matchingDetectors := make([]detectors.Detector, 0, 2)
	for _, d := range dts {
		matchingDetectors = append(matchingDetectors, d.Detector)
	}
	assert.ElementsMatch(t, allDetectors, matchingDetectors)
}

func TestAhoCorasickCore_NoDuplicateDetectorsMatched(t *testing.T) {
	d := testDetectorV1{}
	allDetectors := []detectors.Detector{d}

	ac := NewAhoCorasickCore(allDetectors)

	dts := ac.FindDetectorMatches([]byte("a a b b"))
	matchingDetectors := make([]detectors.Detector, 0, 2)
	for _, d := range dts {
		matchingDetectors = append(matchingDetectors, d.Detector)
	}
	assert.ElementsMatch(t, allDetectors, matchingDetectors)
}

func TestFindDetectorMatches(t *testing.T) {
	testCases := []struct {
		name           string
		opts           []CoreOption
		detectors      []detectors.Detector
		sampleData     string
		expectedResult map[DetectorKey][][]int64
	}{

		{
			name: "single matchSpan",
			detectors: []detectors.Detector{
				testDetectorV3{},
			},
			sampleData: "This is a sample data containing keyword truffle",
			expectedResult: map[DetectorKey][][]int64{
				CreateDetectorKey(testDetectorV3{}): {{0, 48}},
			},
		},
		{
			name: "Multiple matches overlapping",
			detectors: []detectors.Detector{
				testDetectorV1{},
			},
			sampleData: "This is a sample data containing keyword a",
			expectedResult: map[DetectorKey][][]int64{
				CreateDetectorKey(testDetectorV1{}): {{0, 42}},
			},
		},
		{
			name: "Multiple matches",
			detectors: []detectors.Detector{
				testDetectorV2{},
			},
			sampleData: `This is the first occurrence of the letter a.
                 Lorem ipsum dolor sit met, consectetur dipiscing elit. Sed uctor,
                 mgn bibendum bibendum, ugue ugue tincidunt ugue,
                 eget ultricies ugue ugue id ugue. Meens liquet libero
                 c libero molestie, nec mlesud ugue ugue eget. Donec
                 sed ugue. Sed euismod, ugue sit met liqum lcini,
                 ugue ugue tincidunt ugue, eget ultricies ugue ugue id
                 ugue. Meens liquet libero c libero molestie, nec
                 mlesud ugue ugue eget. Donec sed ugue. Sed euismod,
                 ugue sit met liqum lcini, ugue ugue tincidunt ugue,
                 eget ultricies ugue ugue id ugue. Meens liquet libero
                 c libero molestie, nec mlesud ugue ugue eget. This is the second occurrence of the letter a.`,
			expectedResult: map[DetectorKey][][]int64{
				CreateDetectorKey(testDetectorV2{}): {{0, 856}},
			},
		},
		{
			name: "single matchSpan; entireSpanChunkCalculator",
			opts: []CoreOption{WithSpanCalculator(&EntireChunkSpanCalculator{})},
			detectors: []detectors.Detector{
				testDetectorV3{},
			},
			sampleData: "This is a sample data containing keyword truffle",
			expectedResult: map[DetectorKey][][]int64{
				CreateDetectorKey(testDetectorV3{}): {{0, 48}},
			},
		},
		{
			name: "Multiple matches overlapping; entireSpanChunkCalculator",
			opts: []CoreOption{WithSpanCalculator(&EntireChunkSpanCalculator{})},
			detectors: []detectors.Detector{
				testDetectorV1{},
			},
			sampleData: "This is a sample data containing keyword a",
			expectedResult: map[DetectorKey][][]int64{
				CreateDetectorKey(testDetectorV1{}): {{0, 42}},
			},
		},
		{
			name: "Multiple matches; entireSpanChunkCalculator",
			opts: []CoreOption{WithSpanCalculator(&EntireChunkSpanCalculator{})},
			detectors: []detectors.Detector{
				testDetectorV2{},
			},
			sampleData: `This is the first occurrence of the letter a.
                 Lorem ipsum dolor sit met, consectetur dipiscing elit. Sed uctor,
                 mgn bibendum bibendum, ugue ugue tincidunt ugue,
                 eget ultricies ugue ugue id ugue. Meens liquet libero
                 c libero molestie, nec mlesud ugue ugue eget. Donec
                 sed ugue. Sed euismod, ugue sit met liqum lcini,
                 ugue ugue tincidunt ugue, eget ultricies ugue ugue id
                 ugue. Meens liquet libero c libero molestie, nec
                 mlesud ugue ugue eget. Donec sed ugue. Sed euismod,
                 ugue sit met liqum lcini, ugue ugue tincidunt ugue,
                 eget ultricies ugue ugue id ugue. Meens liquet libero
                 c libero molestie, nec mlesud ugue ugue eget. This is the second occurrence of the letter a.`,
			expectedResult: map[DetectorKey][][]int64{
				CreateDetectorKey(testDetectorV2{}): {{0, 856}},
			},
		},
		{
			name: "keyword in the middle of the credential; MultiPartCredentialProvider, StartOffsetProvider",
			detectors: []detectors.Detector{
				testDetectorV4{},
			},
			sampleData: "This is a password in the middle of some data",
			expectedResult: map[DetectorKey][][]int64{
				CreateDetectorKey(testDetectorV4{}): {{5, 25}},
			},
		},
		{
			name: "keyword at the end of the credential; MultiPartCredentialProvider, StartOffsetProvider",
			detectors: []detectors.Detector{
				testDetectorV4{},
			},
			sampleData: "This data ends with a password",
			expectedResult: map[DetectorKey][][]int64{
				CreateDetectorKey(testDetectorV4{}): {{17, 30}},
			},
		},
		{
			name: "keyword near the start of the data; MultiPartCredentialProvider, StartOffsetProvider",
			detectors: []detectors.Detector{
				testDetectorV4{},
			},
			sampleData: "a password at the start",
			expectedResult: map[DetectorKey][][]int64{
				CreateDetectorKey(testDetectorV4{}): {{0, 17}},
			},
		},
		{
			name: "keyword in the middle of the credential; MaxSecretSizeProvider, StartOffsetProvider",
			detectors: []detectors.Detector{
				testDetectorV5{},
			},
			sampleData: "This is a password in the middle of some data",
			expectedResult: map[DetectorKey][][]int64{
				CreateDetectorKey(testDetectorV5{}): {{7, 20}},
			},
		},
		{
			name: "keyword at the end of the credential; MaxSecretSizeProvider, StartOffsetProvider",
			detectors: []detectors.Detector{
				testDetectorV5{},
			},
			sampleData: "This data ends with a password",
			expectedResult: map[DetectorKey][][]int64{
				CreateDetectorKey(testDetectorV5{}): {{19, 30}},
			},
		},
		{
			name: "keyword near the start of the data; MaxSecretSizeProvider, StartOffsetProvider",
			detectors: []detectors.Detector{
				testDetectorV5{},
			},
			sampleData: "a password at the start",
			expectedResult: map[DetectorKey][][]int64{
				CreateDetectorKey(testDetectorV5{}): {{0, 12}},
			},
		},
		{
			name: "keyword in the middle of the credential; StartOffsetProvider",
			detectors: []detectors.Detector{
				testDetectorV6{},
			},
			sampleData: "This is a password in the middle of some data",
			expectedResult: map[DetectorKey][][]int64{
				CreateDetectorKey(testDetectorV6{}): {{9, 45}},
			},
		},
		{
			name: "keyword at the end of the credential; StartOffsetProvider",
			detectors: []detectors.Detector{
				testDetectorV6{},
			},
			sampleData: "This data ends with a password",
			expectedResult: map[DetectorKey][][]int64{
				CreateDetectorKey(testDetectorV6{}): {{21, 30}},
			},
		},
		{
			name: "keyword near the start of the data; StartOffsetProvider",
			detectors: []detectors.Detector{
				testDetectorV6{},
			},
			sampleData: "a password at the start",
			expectedResult: map[DetectorKey][][]int64{
				CreateDetectorKey(testDetectorV6{}): {{1, 23}},
			},
		},
		{
			name: "multiple keyword in the middle of the credential; StartOffsetProvider",
			detectors: []detectors.Detector{
				testDetectorV6{},
			},
			sampleData: "This is a password in the middle of some data, and another password at the end!",
			expectedResult: map[DetectorKey][][]int64{
				CreateDetectorKey(testDetectorV6{}): {{9, 79}},
			},
		},
		{
			name: "No matches",
			detectors: []detectors.Detector{
				testDetectorV1{},
				testDetectorV2{},
			},
			sampleData:     "xxy yzz lnnope",
			expectedResult: map[DetectorKey][][]int64{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ac := NewAhoCorasickCore(tc.detectors, tc.opts...)
			detectorMatches := ac.FindDetectorMatches([]byte(tc.sampleData))

			// Verify that all matching detectors and their matches are returned.
			for _, detectorMatch := range detectorMatches {
				assert.Contains(t, tc.expectedResult, detectorMatch.Key, "Expected detector key to be present")

				expectedMatches := tc.expectedResult[detectorMatch.Key]
				actualMatches := make([][]int64, len(detectorMatch.matchSpans))
				for i, match := range detectorMatch.matchSpans {
					actualMatches[i] = []int64{match.startOffset, match.endOffset}
				}

				assert.ElementsMatch(t, expectedMatches, actualMatches, "Expected matches to be returned for the detector")
			}

			// Verify that all expected matches are returned for each detector.
			for key, expectedMatches := range tc.expectedResult {
				var actualMatches [][]int64
				for _, detectorMatch := range detectorMatches {
					if detectorMatch.Key == key {
						for _, match := range detectorMatch.matchSpans {
							actualMatches = append(actualMatches, []int64{match.startOffset, match.endOffset})
						}
					}
				}
				assert.ElementsMatch(t, expectedMatches, actualMatches, "Expected all matches to be returned for the detector")
			}
		})
	}
}
