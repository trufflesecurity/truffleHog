package azuresearchadminkey

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestAzureSearchAdminKey_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "valid pattern",
			input: `
	azure:
		azureKey: wRRPyhjv8m6JGRujUUrPKa8d3rJ0mrGAxhmqf3A68OgZmlWUJyma
		azureService: testingservice01.search.windows.net
	`,
			want: []string{`{"service":"testingservice01","key":"wRRPyhjv8m6JGRujUUrPKa8d3rJ0mrGAxhmqf3A68OgZmlWUJyma"}`},
		},
		{
			name: "jupyter notebook",
			input: `
    {
      "cell_type": "code",
      "execution_count": 7,
      "id": "b188568f",
      "metadata": {},
      "outputs": [
        {
          "name": "stdout",
          "output_type": "stream",
          "text": [
            "https://news-search.search.windows.net azureblob-index 2021-04-30-Preview iOExxhJ2A2wjdAGTjsMxASsJj3y3zUR54kjNTNpW9hAzSeD8PE3k\n"
          ]
        }
      ],
      "source": [
        "print(os.getenv(\"AZURE_COGNITIVE_SEARCH_ENDPOINT\"), os.getenv('AZURE_COGNITIVE_SEARCH_INDEX_NAME'), os.getenv('AZURE_COGNITIVE_SEARCH_API_VERSION'), os.getenv(\"AZURE_COGNITIVE_SEARCH_KEY\"))"
      ]`,
			want: []string{`{"service":"news-search","key":"iOExxhJ2A2wjdAGTjsMxASsJj3y3zUR54kjNTNpW9hAzSeD8PE3k"}`},
		},
		{
			name: "invalid pattern",
			input: `
	azure:
		Key: wRRPyhjv8m6JGRujUUr-PK#a8d3rJ0mrGAxhmqf3A68OgZmlWUJyma
		Service: TS01.search.windows.net
	`,
			want: nil,
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
