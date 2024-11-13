package airtableapikey

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validPattern   = "app_pOcv67-Yuztyq / key_Yuztyq-pOcv67"
	invalidPattern = "app_pOcv67%Yuztyq/key_Yuztyq*pOcv67"
)

func TestAirTableApiKey_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - with key",
			input: fmt.Sprintf("airtable secrets: %s", validPattern),
			want:  []string{"app_pOcv67-Yuztyq:key_Yuztyq-pOcv67"},
		},
		{
			name: "valid pattern - with personal key",
			input: `document.addEventListener('DOMContentLoaded', function () {
    base = new Airtable({ apiKey: 'patHSL6ZkPWx8Rkva.f0b2c1970c1cd8b5126d04eaf59d9fd500a39736c73bbb3a471fsf7eb3561ec0' }).base('appiiuioD2lBj2DaJ');

   reloadData();`,
			want: []string{"appiiuioD2lBj2DaJ:patHSL6ZkPWx8Rkva.f0b2c1970c1cd8b5126d04eaf59d9fd500a39736c73bbb3a471fsf7eb3561ec0"},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("airtable secrets: '%s'", invalidPattern),
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
