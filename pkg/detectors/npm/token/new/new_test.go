package new

import (
	"context"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

type npmPatternTestCase struct {
	input    string
	expected string
}

func TestNpmTokenNew_Pattern(t *testing.T) {
	cases := map[string]npmPatternTestCase{
		"no_context": {
			input:    `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`,
			expected: "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",
		},
		".npmrc": {
			input:    `//registry.npmjs.org/:_authToken=npm_ZAQB7VuVmml1pMGorDFwyeEpuQrA8I4ypgPF`,
			expected: "npm_ZAQB7VuVmml1pMGorDFwyeEpuQrA8I4ypgPF",
		},
		"yaml_spec": {
			input: `    - env:
        NPM_TOKEN: npm_tCEMceczuiTXKQaBjGIaAezYQ63PqI972ANG`,
			expected: "npm_tCEMceczuiTXKQaBjGIaAezYQ63PqI972ANG",
		},
		"bashrc": {
			input:    `export NPM_TOKEN=npm_ySTLJHpS9DCwByClZBMyqRWptr2kB40hEjiS`,
			expected: "npm_ySTLJHpS9DCwByClZBMyqRWptr2kB40hEjiS",
		},

		// Invalid
		"invalid/placeholder_0": {
			input: `   //registry.npmjs.org/:_authToken=npm_000000000000000000000000000000000000`,
		},
		"invalid/placeholder_x": {
			input: `//registry.npmjs.org/:_authToken=npm_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX`,
		},
		"invalid/word_boundary": {
			input: `    "image_small_url": "https://c10.patreonusercontent.com/3/eyJoIjo2NDAsInYiOiIzIiwidyI6NjQwfQ%3D%3D/patreon-media/campaign/1493621/91a5dc5347a741af89aaed35d2a82b5c?token-time=2145916800\u0026token-hash=Qznpm_uHiQAba4K3HTRZjrhQei4dU0tmZbaavLrM2FY%3D",`,
		},
		"invalid/uppercase": {
			input: `"operationId": "Npm_GetScopedPackageVersionFromRecycleBin",`,
		},
	}

	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
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

			if len(results) == 0 {
				if test.expected != "" {
					t.Error("did not receive result")
				}
				return
			}

			actual := string(results[0].Raw)
			if test.expected != actual {
				t.Errorf("expected '%s' != actual '%s'", test.expected, actual)
			}
		})
	}
}
