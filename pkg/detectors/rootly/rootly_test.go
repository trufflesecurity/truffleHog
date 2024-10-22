package rootly

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestRootly_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern",
			input: "rootly_7f1e8738d7d6b540bc52e1bc24c6e2c109dc44642f9e5d583be7e5d04f8bd282",
			want:  []string{"rootly_7f1e8738d7d6b540bc52e1bc24c6e2c109dc44642f9e5d583be7e5d04f8bd282"},
		},
		{
			name:  "valid pattern - key out of prefix range",
			input: "rootly keyword is not close to the real key in the data ='rootly_7f1e8738d7d6b540bc52e1bc24c6e2c109dc44642f9e5d583be7e5d04f8bd282'",
			want:  []string{"rootly_7f1e8738d7d6b540bc52e1bc24c6e2c109dc44642f9e5d583be7e5d04f8bd282"},
		},
		{
			name:  "invalid pattern",
			input: "rootly_A$3b9f8c1e2d4f5b6c7d8e9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d",
			want:  nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
				t.Errorf("keywords '%v' not matched by: %s", d.Keywords(), test.input)
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			if err != nil {
				t.Errorf("error = %v", err)
				return
			}

			if len(results) != len(test.want) {
				if len(results) == 0 {
					t.Errorf("did not receive result")
				} else {
					t.Errorf("expected %d results, only received %d", len(test.want), len(results))
				}
				return
			}

			actual := make(map[string]struct{}, len(results))
			for _, r := range results {
				if len(r.RawV2) > 0 {
					actual[string(r.RawV2)] = struct{}{}
				} else {
					actual[string(r.Raw)] = struct{}{}
				}
			}
			expected := make(map[string]struct{}, len(test.want))
			for _, v := range test.want {
				expected[v] = struct{}{}
			}

			if diff := cmp.Diff(expected, actual); diff != "" {
				t.Errorf("%s diff: (-want +got)\n%s", test.name, diff)
			}
		})
	}
}
