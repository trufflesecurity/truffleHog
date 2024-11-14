package gcpapplicationdefaultcredentials

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestGcpapplicationdefaultcredentials_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "typical pattern",
			input: `{
					"client_id": "191375729402-oiuj2498ry3497gjveoierj8294jfj41.apps.googleusercontent.com",
					"client_secret": "z-OIFJWEOIJGWER91834325R",
					"refresh_token": "1//0_joijgor3i4ut98579862709342j3kjJOIE02834jijfewoifjowiejfhghyzznfoiwejfwnvuhewiufnwinciwu_-o2i3jjfcc",
					"type": "authorized_user"
				}`,
			want: []string{
				"191375729402-oiuj2498ry3497gjveoierj8294jfj411//0_joijgor3i4ut98579862709342j3kjJOIE02834jijfewoifjowiejfhghyzznfoiwejfwnvuhewiufnwinciwu_-o2i3jjfcc",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			detectorMatches := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(detectorMatches) == 0 {
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
