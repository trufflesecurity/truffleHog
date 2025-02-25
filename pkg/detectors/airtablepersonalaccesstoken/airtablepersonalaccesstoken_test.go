package airtablepersonalaccesstoken

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validPattern1  = "patfqpIZBPU6EAt5x.458546d9c77b21f8a98141f2a4039d5626010f19efc16c20d57c4f41d44c8c85"
	validPattern2  = "pat0VXr5I2HcapZE8.da2606afb7d97e936719ec952a4a18b44045e385d4ddf4f38dcc246fb63f0165"
	invalidPattern = "tokfqpIZBPU6EAt5x.458546d9c77b21f8a98141f2a403-d5626010f19efc16c20d57c4f41d44c8c85"
)

func TestAirtablepersonalaccesstoken_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "typical pattern",
			input: fmt.Sprintf("airtable token = '%s'", validPattern1),
			want:  []string{validPattern1},
		},
		{
			name: "finds all matches",
			input: fmt.Sprintf(`airtable token 1 = '%s'
			airtable token 2 = '%s'`, validPattern1, validPattern2),
			want: []string{validPattern1, validPattern2},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("airtable token = '%s'", invalidPattern),
			want:  []string{},
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
