package custom_detectors

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/custom_detectorspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/protoyaml"
)

func TestCustomRegexTemplateParsing(t *testing.T) {
	testCustomRegexTemplateYaml := `name: Internal bi tool
keywords:
- secret_v1_
- pat_v2_
regex:
  id_pat_example: ([a-zA-Z0-9]{32})
  secret_pat_example: ([a-zA-Z0-9]{32})
verify:
- endpoint: http://localhost:8000/{id_pat_example}
  unsafe: true
  headers:
  - 'Authorization: Bearer {secret_pat_example.0}'
  successRanges:
  - 200-250
  - '288'`

	var got custom_detectorspb.CustomRegex
	assert.NoError(t, protoyaml.UnmarshalStrict([]byte(testCustomRegexTemplateYaml), &got))
	assert.Equal(t, "Internal bi tool", got.Name)
	assert.Equal(t, []string{"secret_v1_", "pat_v2_"}, got.Keywords)
	assert.Equal(t, map[string]string{
		"id_pat_example":     "([a-zA-Z0-9]{32})",
		"secret_pat_example": "([a-zA-Z0-9]{32})",
	}, got.Regex)
	assert.Equal(t, 1, len(got.Verify))
	assert.Equal(t, "http://localhost:8000/{id_pat_example}", got.Verify[0].Endpoint)
	assert.Equal(t, true, got.Verify[0].Unsafe)
	assert.Equal(t, []string{"Authorization: Bearer {secret_pat_example.0}"}, got.Verify[0].Headers)
	assert.Equal(t, []string{"200-250", "288"}, got.Verify[0].SuccessRanges)
}

func TestCustomRegexWebhookParsing(t *testing.T) {
	testCustomRegexWebhookYaml := `name: Internal bi tool
keywords:
- secret_v1_
- pat_v2_
regex:
  id_pat_example: ([a-zA-Z0-9]{32})
  secret_pat_example: ([a-zA-Z0-9]{32})
verify:
- endpoint: http://localhost:8000/
  unsafe: true
  headers:
  - 'Authorization: Bearer token'`

	var got custom_detectorspb.CustomRegex
	assert.NoError(t, protoyaml.UnmarshalStrict([]byte(testCustomRegexWebhookYaml), &got))
	assert.Equal(t, "Internal bi tool", got.Name)
	assert.Equal(t, []string{"secret_v1_", "pat_v2_"}, got.Keywords)
	assert.Equal(t, map[string]string{
		"id_pat_example":     "([a-zA-Z0-9]{32})",
		"secret_pat_example": "([a-zA-Z0-9]{32})",
	}, got.Regex)
	assert.Equal(t, 1, len(got.Verify))
	assert.Equal(t, "http://localhost:8000/", got.Verify[0].Endpoint)
	assert.Equal(t, true, got.Verify[0].Unsafe)
	assert.Equal(t, []string{"Authorization: Bearer token"}, got.Verify[0].Headers)
}

// TestCustomDetectorsParsing tests the full `detectors` configuration.
func TestCustomDetectorsParsing(t *testing.T) {
	// TODO: Support both template and webhook.
	testYamlConfig := `detectors:
- name: Internal bi tool
  keywords:
  - secret_v1_
  - pat_v2_
  regex:
    id_pat_example: ([a-zA-Z0-9]{32})
    secret_pat_example: ([a-zA-Z0-9]{32})
  verify:
  - endpoint: http://localhost:8000/
    unsafe: true
    headers:
    - 'Authorization: Bearer token'`

	var messages custom_detectorspb.CustomDetectors
	assert.NoError(t, protoyaml.UnmarshalStrict([]byte(testYamlConfig), &messages))
	assert.Equal(t, 1, len(messages.Detectors))

	got := messages.Detectors[0]
	assert.Equal(t, "Internal bi tool", got.Name)
	assert.Equal(t, []string{"secret_v1_", "pat_v2_"}, got.Keywords)
	assert.Equal(t, map[string]string{
		"id_pat_example":     "([a-zA-Z0-9]{32})",
		"secret_pat_example": "([a-zA-Z0-9]{32})",
	}, got.Regex)
	assert.Equal(t, 1, len(got.Verify))
	assert.Equal(t, "http://localhost:8000/", got.Verify[0].Endpoint)
	assert.Equal(t, true, got.Verify[0].Unsafe)
	assert.Equal(t, []string{"Authorization: Bearer token"}, got.Verify[0].Headers)
}

func TestFromData_InvalidRegEx(t *testing.T) {
	c := &CustomRegexWebhook{
		&custom_detectorspb.CustomRegex{
			Name:     "Internal bi tool",
			Keywords: []string{"secret_v1_", "pat_v2_"},
			Regex: map[string]string{
				"test": "!!?(?:?)[a-zA-Z0-9]{32}", // invalid regex
			},
		}, make(map[string]bool),
	}

	_, err := c.FromData(context.Background(), false, []byte("test"))
	assert.Error(t, err)
}

func TestProductIndices(t *testing.T) {
	tests := []struct {
		name  string
		input []int
		want  [][]int
	}{
		{
			name:  "zero",
			input: []int{3, 0},
			want:  nil,
		},
		{
			name:  "one input",
			input: []int{3},
			want:  [][]int{{0}, {1}, {2}},
		},
		{
			name:  "two inputs",
			input: []int{3, 2},
			want: [][]int{
				{0, 0}, {1, 0}, {2, 0},
				{0, 1}, {1, 1}, {2, 1},
			},
		},
		{
			name:  "three inputs",
			input: []int{3, 2, 3},
			want: [][]int{
				{0, 0, 0}, {1, 0, 0}, {2, 0, 0},
				{0, 1, 0}, {1, 1, 0}, {2, 1, 0},
				{0, 0, 1}, {1, 0, 1}, {2, 0, 1},
				{0, 1, 1}, {1, 1, 1}, {2, 1, 1},
				{0, 0, 2}, {1, 0, 2}, {2, 0, 2},
				{0, 1, 2}, {1, 1, 2}, {2, 1, 2},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := productIndices(tt.input...)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestProductIndicesMax(t *testing.T) {
	got := productIndices(2, 3, 4, 5, 6)
	assert.GreaterOrEqual(t, 2*3*4*5*6, maxTotalMatches)
	assert.Equal(t, maxTotalMatches, len(got))
}

func TestPermutateMatches(t *testing.T) {
	tests := []struct {
		name  string
		input map[string][][]string
		want  []map[string][]string
	}{
		{
			name:  "two matches",
			input: map[string][][]string{"foo": {{"matchA"}, {"matchB"}}, "bar": {{"matchC"}}},
			want: []map[string][]string{
				{"foo": {"matchA"}, "bar": {"matchC"}},
				{"foo": {"matchB"}, "bar": {"matchC"}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := permutateMatches(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestDetector(t *testing.T) {
	detector, err := NewWebhookCustomRegex(&custom_detectorspb.CustomRegex{
		Name: "test",
		// "password" is normally flagged as a false positive, but CustomRegex
		// should allow the user to decide and report it as a result.
		Keywords: []string{"password"},
		Regex:    map[string]string{"regex": "password=.*"},
	})
	assert.NoError(t, err)
	results, err := detector.FromData(context.Background(), false, []byte(`password="123456"`))
	assert.NoError(t, err)
	assert.Equal(t, 1, len(results))
	assert.Equal(t, results[0].Raw, []byte(`password="123456"`))
}

func BenchmarkProductIndices(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = productIndices(3, 2, 6)
	}
}
