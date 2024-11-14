package faceplusplus

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validPattern = `[{
		"_id": "1a8d0cca-e1a9-4318-bc2f-f5658ab2dcb5",
		"name": "FacePlusPlus",
		"type": "Detector",
		"api": true,
		"authentication_type": "",
		"verification_url": "https://api.example.com/example",
		"test_secrets": {
			"faceplusplus_id": "ipScAHzUxOS2CQ3JwTdIDG1ClxZl_iVH",
			"faceplusplus_secret": "Qomsw0IQtp3iz1jlxAqQJO5afpbeEeAh"
		},
		"expected_response": "200",
		"method": "POST",
		"deprecated": false
	}]`
	secrets = []string{
		// TODO: Add logic to avoid verification when key and id is same because the regex is same for both
		"Qomsw0IQtp3iz1jlxAqQJO5afpbeEeAhQomsw0IQtp3iz1jlxAqQJO5afpbeEeAh",
		"ipScAHzUxOS2CQ3JwTdIDG1ClxZl_iVHQomsw0IQtp3iz1jlxAqQJO5afpbeEeAh",
		"Qomsw0IQtp3iz1jlxAqQJO5afpbeEeAhipScAHzUxOS2CQ3JwTdIDG1ClxZl_iVH",
		"ipScAHzUxOS2CQ3JwTdIDG1ClxZl_iVHipScAHzUxOS2CQ3JwTdIDG1ClxZl_iVH",
	}
)

func TestFacePlusPlus_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern",
			input: validPattern,
			want:  secrets,
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
