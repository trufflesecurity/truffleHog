package onepassword

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestOnePassword_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "typical pattern",
			input: "ops_eyJlbWFpbCI6ImVqd2U2NHFtbHhocmlAMXBhc3N3b3Jkc2VydmljZWFjY291bnRzLmxjbCIsIm11ayI6eyJhbGciOiJBMjU2R0NNIiwiZXh0Ijp0cnVlLCJrIjoiTThWUGZJYzhWRWZUaGNNWExhS0NLRjhzTWg1Sk1ac1BBdHU5MmZRTmItbyIsImtleV9vcHMiOlsiZW5jcnlwdCIsImRlY3J5cHQiXSwia3R5Ijoib2N0Iiwia2lkIjoibXAifSwic2VjcmV0S2V5IjoiQTMtQzRaSk1OLVBRVFpUTC1IR0w4NC1HNjRNNy1LVlpSTi00WlZQNiIsInNycFgiOiI4NzBkNjdhOWU2MjY2MjVkOWUzNjg1MDc4MDRjOWMzMmU2NjFjNTdlN2U1NTg3NzgyOTFiZjI5ZDVhMjc5YWUxIiwic2lnbkluQWRkcmVzcyI6ImdvdGhhbS5iNWxvY2FsLmNvbTo0MDAwIiwidXNlckF1dGgiOnsibWV0aG9kIjoiU1JQZy00MDk2IiwiYWxnIjoiUEJFUzJnLUhTMjU2IiwiaXRlcmF0aW9ucyI6MTAwMDAwLCJzYWx0IjoiRk1SVVBpeXJONFhmXzhIb2g2WVJYUSJ9fQ",
			want:  []string{"ops_eyJlbWFpbCI6ImVqd2U2NHFtbHhocmlAMXBhc3N3b3Jkc2VydmljZWFjY291bnRzLmxjbCIsIm11ayI6eyJhbGciOiJBMjU2R0NNIiwiZXh0Ijp0cnVlLCJrIjoiTThWUGZJYzhWRWZUaGNNWExhS0NLRjhzTWg1Sk1ac1BBdHU5MmZRTmItbyIsImtleV9vcHMiOlsiZW5jcnlwdCIsImRlY3J5cHQiXSwia3R5Ijoib2N0Iiwia2lkIjoibXAifSwic2VjcmV0S2V5IjoiQTMtQzRaSk1OLVBRVFpUTC1IR0w4NC1HNjRNNy1LVlpSTi00WlZQNiIsInNycFgiOiI4NzBkNjdhOWU2MjY2MjVkOWUzNjg1MDc4MDRjOWMzMmU2NjFjNTdlN2U1NTg3NzgyOTFiZjI5ZDVhMjc5YWUxIiwic2lnbkluQWRkcmVzcyI6ImdvdGhhbS5iNWxvY2FsLmNvbTo0MDAwIiwidXNlckF1dGgiOnsibWV0aG9kIjoiU1JQZy00MDk2IiwiYWxnIjoiUEJFUzJnLUhTMjU2IiwiaXRlcmF0aW9ucyI6MTAwMDAwLCJzYWx0IjoiRk1SVVBpeXJONFhmXzhIb2g2WVJYUSJ9fQ"},
		},
		{
			name: "finds all matches",
			input: `ops_eyJlbWFpbCI6ImVqd2U2NHFtbHhocmlAMXBhc3N3b3Jkc2VydmljZWFjY291bnRzLmxjbCIsIm11ayI6eyJhbGciOiJBMjU2R0NNIiwiZXh0Ijp0cnVlLCJrIjoiTThWUGZJYzhWRWZUaGNNWExhS0NLRjhzTWg1Sk1ac1BBdHU5MmZRTmItbyIsImtleV9vcHMiOlsiZW5jcnlwdCIsImRlY3J5cHQiXSwia3R5Ijoib2N0Iiwia2lkIjoibXAifSwic2VjcmV0S2V5IjoiQTMtQzRaSk1OLVBRVFpUTC1IR0w4NC1HNjRNNy1LVlpSTi00WlZQNiIsInNycFgiOiI4NzBkNjdhOWU2MjY2MjVkOWUzNjg1MDc4MDRjOWMzMmU2NjFjNTdlN2U1NTg3NzgyOTFiZjI5ZDVhMjc5YWUxIiwic2lnbkluQWRkcmVzcyI6ImdvdGhhbS5iNWxvY2FsLmNvbTo0MDAwIiwidXNlckF1dGgiOnsibWV0aG9kIjoiU1JQZy00MDk2IiwiYWxnIjoiUEJFUzJnLUhTMjU2IiwiaXRlcmF0aW9ucyI6MTAwMDAwLCJzYWx0IjoiRk1SVsBpeXJONFhmXzhIb2g2WVJYUSJ9fQ
ops_eyJlbWFpbCI6ImVqd2U2NHFtbHhocmlAMXBhc3N3b3Jkc2VydmljZWFjY291bnRzLmxjbCIsIm11ayI6eyJhbGciOiJBMjU2R0NNIiwiZXh0Ijp0cnVlLCJrIjoiTThWUGZJYzhWRWZUaGNNWExhS0NLRjhzTWg1Sk1ac1BBdHU5MmZRTmItbyIsImtleV9vcHMiOlsiZW5jcnlwdCIsImRlY3J5cHQiXSwia3R5Ijoib2N0Iiwia2lkIjoibXAifSwic2VjcmV0S2V5IjoiQTMtQzRaSk1OLVBRVFpUTC1IR0w4NC1HNjRNNy1LVlpSTi00WlZQNiIsInNycFgiOiI4NzBkNjdhOWU2MjY2MjVkOWUzNjg1MDc4MDRjOWMzMmU2NjFjNTdlN2U1NTg3NzgyOTFiZjI5ZDVhMjc5YWUxIiwic2lnbkluQWRkcmVzcyI6ImdvdGhhbS5iNWxvY2FsLmNvbTo0MDAwIiwidXNlckF1dGgiOnsibWV0aG9kIjoiU1JQZy00MDk2IiwiYWxnIjoiUEJFUzJnLUhTMjU2IiwiaXRlcmF0aW9ucyI6MTAwMDAwLCJzYWx0IjoiRk1SVVBpeXJONFhmXzhIb2g2WVJYUSJ9fQ`,
			want: []string{
				`ops_eyJlbWFpbCI6ImVqd2U2NHFtbHhocmlAMXBhc3N3b3Jkc2VydmljZWFjY291bnRzLmxjbCIsIm11ayI6eyJhbGciOiJBMjU2R0NNIiwiZXh0Ijp0cnVlLCJrIjoiTThWUGZJYzhWRWZUaGNNWExhS0NLRjhzTWg1Sk1ac1BBdHU5MmZRTmItbyIsImtleV9vcHMiOlsiZW5jcnlwdCIsImRlY3J5cHQiXSwia3R5Ijoib2N0Iiwia2lkIjoibXAifSwic2VjcmV0S2V5IjoiQTMtQzRaSk1OLVBRVFpUTC1IR0w4NC1HNjRNNy1LVlpSTi00WlZQNiIsInNycFgiOiI4NzBkNjdhOWU2MjY2MjVkOWUzNjg1MDc4MDRjOWMzMmU2NjFjNTdlN2U1NTg3NzgyOTFiZjI5ZDVhMjc5YWUxIiwic2lnbkluQWRkcmVzcyI6ImdvdGhhbS5iNWxvY2FsLmNvbTo0MDAwIiwidXNlckF1dGgiOnsibWV0aG9kIjoiU1JQZy00MDk2IiwiYWxnIjoiUEJFUzJnLUhTMjU2IiwiaXRlcmF0aW9ucyI6MTAwMDAwLCJzYWx0IjoiRk1SVsBpeXJONFhmXzhIb2g2WVJYUSJ9fQ`,
				`ops_eyJlbWFpbCI6ImVqd2U2NHFtbHhocmlAMXBhc3N3b3Jkc2VydmljZWFjY291bnRzLmxjbCIsIm11ayI6eyJhbGciOiJBMjU2R0NNIiwiZXh0Ijp0cnVlLCJrIjoiTThWUGZJYzhWRWZUaGNNWExhS0NLRjhzTWg1Sk1ac1BBdHU5MmZRTmItbyIsImtleV9vcHMiOlsiZW5jcnlwdCIsImRlY3J5cHQiXSwia3R5Ijoib2N0Iiwia2lkIjoibXAifSwic2VjcmV0S2V5IjoiQTMtQzRaSk1OLVBRVFpUTC1IR0w4NC1HNjRNNy1LVlpSTi00WlZQNiIsInNycFgiOiI4NzBkNjdhOWU2MjY2MjVkOWUzNjg1MDc4MDRjOWMzMmU2NjFjNTdlN2U1NTg3NzgyOTFiZjI5ZDVhMjc5YWUxIiwic2lnbkluQWRkcmVzcyI6ImdvdGhhbS5iNWxvY2FsLmNvbTo0MDAwIiwidXNlckF1dGgiOnsibWV0aG9kIjoiU1JQZy00MDk2IiwiYWxnIjoiUEJFUzJnLUhTMjU2IiwiaXRlcmF0aW9ucyI6MTAwMDAwLCJzYWx0IjoiRk1SVVBpeXJONFhmXzhIb2g2WVJYUSJ9fQ`,
			},
		},
		{
			name:  "invalid pattern",
			input: "onepassword_token = 'ops_1a2b3c4d'",
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
