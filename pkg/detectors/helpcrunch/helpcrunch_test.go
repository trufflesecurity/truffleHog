package helpcrunch

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
		"name": "HelpCrunch",
		"type": "Detector",
		"api": true,
		"authentication_type": "",
		"verification_url": "https://api.example.com/example",
		"test_secrets": {
			"helpcrunch_secret": "TDV4P0BqcSgI8ZX-GK0o5GbC0-N12GG1thviz6TLRjQxGQSQha+WO78Qz9lMcNvVQ1doHalcElenPD4QoVnZgfEMk2=OOL5-bit2wxH+ykI97mG3jAMhxd5yBm+xMdE8FCdFXQfDPblQ3CjKJBDCfQQNxE+6LkQqS7CoiX2RnlJV8a0ztpe54hHgfirH8oyz=YOvBu9p+FPAj3zv9Ph4W/rV63yPoJsE0l9SLbcCF8uQz/ot1epzk5aqXb-UtZ7WEKApQJO+gEptNV=ylZKceF2KN7irbtmsmKeW0Mf12quDqqj+Yd4zMP3C1wEodnOm9RSofIEX"
		},
		"expected_response": "200",
		"method": "GET",
		"deprecated": false
	}]`
	secret = "TDV4P0BqcSgI8ZX-GK0o5GbC0-N12GG1thviz6TLRjQxGQSQha+WO78Qz9lMcNvVQ1doHalcElenPD4QoVnZgfEMk2=OOL5-bit2wxH+ykI97mG3jAMhxd5yBm+xMdE8FCdFXQfDPblQ3CjKJBDCfQQNxE+6LkQqS7CoiX2RnlJV8a0ztpe54hHgfirH8oyz=YOvBu9p+FPAj3zv9Ph4W/rV63yPoJsE0l9SLbcCF8uQz/ot1epzk5aqXb-UtZ7WEKApQJO+gEptNV=ylZKceF2KN7irbtmsmKeW0Mf12quDqqj+Yd4zMP3C1wEodnOm9RSofIEX"
)

func TestHelpCrunch_Pattern(t *testing.T) {
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
			want:  []string{secret},
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
