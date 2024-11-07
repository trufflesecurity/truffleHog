//go:build detectors
// +build detectors

package dropbox

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestDropbox_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "typical pattern; API Explorer Token",
			input: "dropbox_access_token = 'sl.u.AFTdsdpAiWY_giz5n5am9X7M01K4MeXwxOxhJAJGilJ4bj4uFlUxrA4XV96JOnBXf92I_rjBbpmM6kNELLAfe1Mte1IHkYYIPOyqbciOJECMUoyFOBl9GxjJN9_FjTjjBIBQR_lPskThzIfI0IXSIKSLc7fH9hP-2jwbxYdyZTBOwPJ9y3cuClJbbR-A3rejwAL3on0RSTxoSYcDezHlW0SvR7TAwEcuqqIqpJA6_cxyhG-jfMAh4kr4AS_kghKHrzDR_WeyoC5Ju8ev4o6Y9I_rcj787hS_JuBGZcEZ9yI9mYb4l0jwU84tb3HF7aza4XqhSTEhgfBNrTvPJ-YNhrS59KZKG7vVkTOqpyQBiaGHXrA4SFUA_PhbLA9y9r8f1XRR-VLwYavzMb6TtZjSRh5TdPO1g70u7SEzoAz5uWwXX6y-L5HocLCprsbzGypmSYT0lO3N4r2aqsjCuzxsEODOXBex2qofkk5fOSuu5XewElxQxacYZYyB3xBKC_TJ-EWhm44xDsmE1u-Ymeo3CQVJZFbqD_csb5SaUpuRv1-Jn2lkiNirq9jyTZyfnJbruMpdsVzfDxh84ArR-prFtOKR04GV_R6izGdkXZM47WVKJn8TaCJlmfLwc68NW6VgiR_EVxBTQ5Mou0OLo61KTj3PqoObhrRIz5C4-GDbWY4AFW3Ht_RlEtuinyDFNu1i_0dxWW_DMt9u0iwNeRXD5YPBOAD9uia90G-ohlbwtzPSsvnFcebE_6tEIuTosoKtMd8F88ZVwViAPkaV_hVAohOWbAvgCAoS_kfWWqY4kLRojor2DRDLgR3JcuRsapgyqNuT7hbbxFMYPYCnb9GHz3teyolFL0bIfHPgHA_y7AEQknXJskl2farR_waPI3i3l2Xsn7Pm7sPplSrBbuiRj6ZFWGk3heZ05InkgfXoRDal018XWGlUMV6tf7GYbGXccRhqMbsRUZmDcJfffRPZI0Vxxohcl6LHF3ydGGEOb-wsdyAU1IgKt6t1Fq3PUljJg0c0sFIiztffjuOQY5igJC1ts6S5_W34v4u95ydRMnCj08MCviUQUYAXp4ykVoiHydJVOq2LkOcjcTxgPuLyghGLoBYYA9Yb4XpgWyfB0XhCbeDHuoQhaaHToHTBzvsm1cXwZFQDKb69Xdq3yIHyFI6GUyoEZXEok0clHbM1TCS9cacoM4Go2Pw9cWpUgTSq3q_7-9bClx9ky8m-74Vi_dzUhu9c_MIuETCy4SQEffYxvFNVAdbuCeGVYngOQ5DyXCJq1V-SB8v52eNG1KLIfHtn'",
			want:  []string{"sl.u.AFTdsdpAiWY_giz5n5am9X7M01K4MeXwxOxhJAJGilJ4bj4uFlUxrA4XV96JOnBXf92I_rjBbpmM6kNELLAfe1Mte1IHkYYIPOyqbciOJECMUoyFOBl9GxjJN9_FjTjjBIBQR_lPskThzIfI0IXSIKSLc7fH9hP-2jwbxYdyZTBOwPJ9y3cuClJbbR-A3rejwAL3on0RSTxoSYcDezHlW0SvR7TAwEcuqqIqpJA6_cxyhG-jfMAh4kr4AS_kghKHrzDR_WeyoC5Ju8ev4o6Y9I_rcj787hS_JuBGZcEZ9yI9mYb4l0jwU84tb3HF7aza4XqhSTEhgfBNrTvPJ-YNhrS59KZKG7vVkTOqpyQBiaGHXrA4SFUA_PhbLA9y9r8f1XRR-VLwYavzMb6TtZjSRh5TdPO1g70u7SEzoAz5uWwXX6y-L5HocLCprsbzGypmSYT0lO3N4r2aqsjCuzxsEODOXBex2qofkk5fOSuu5XewElxQxacYZYyB3xBKC_TJ-EWhm44xDsmE1u-Ymeo3CQVJZFbqD_csb5SaUpuRv1-Jn2lkiNirq9jyTZyfnJbruMpdsVzfDxh84ArR-prFtOKR04GV_R6izGdkXZM47WVKJn8TaCJlmfLwc68NW6VgiR_EVxBTQ5Mou0OLo61KTj3PqoObhrRIz5C4-GDbWY4AFW3Ht_RlEtuinyDFNu1i_0dxWW_DMt9u0iwNeRXD5YPBOAD9uia90G-ohlbwtzPSsvnFcebE_6tEIuTosoKtMd8F88ZVwViAPkaV_hVAohOWbAvgCAoS_kfWWqY4kLRojor2DRDLgR3JcuRsapgyqNuT7hbbxFMYPYCnb9GHz3teyolFL0bIfHPgHA_y7AEQknXJskl2farR_waPI3i3l2Xsn7Pm7sPplSrBbuiRj6ZFWGk3heZ05InkgfXoRDal018XWGlUMV6tf7GYbGXccRhqMbsRUZmDcJfffRPZI0Vxxohcl6LHF3ydGGEOb-wsdyAU1IgKt6t1Fq3PUljJg0c0sFIiztffjuOQY5igJC1ts6S5_W34v4u95ydRMnCj08MCviUQUYAXp4ykVoiHydJVOq2LkOcjcTxgPuLyghGLoBYYA9Yb4XpgWyfB0XhCbeDHuoQhaaHToHTBzvsm1cXwZFQDKb69Xdq3yIHyFI6GUyoEZXEok0clHbM1TCS9cacoM4Go2Pw9cWpUgTSq3q_7-9bClx9ky8m-74Vi_dzUhu9c_MIuETCy4SQEffYxvFNVAdbuCeGVYngOQ5DyXCJq1V-SB8v52eNG1KLIfHtn"},
		},
		{
			name:  "typical pattern; Access Token",
			input: "sl.B-0SI0a3GFk2Ew81yf9HsWC6_yMSZ41-IBEscOQ_8aDwLevZMCSAvTouU2JyhWUME7-6p8omVz1-5DZ8B_150DTi7MwdtEk5sZWbPHT71STR6Y-0A_vfUNm9VOB5zN1PiLrJneoVliNL",
			want:  []string{"sl.B-0SI0a3GFk2Ew81yf9HsWC6_yMSZ41-IBEscOQ_8aDwLevZMCSAvTouU2JyhWUME7-6p8omVz1-5DZ8B_150DTi7MwdtEk5sZWbPHT71STR6Y-0A_vfUNm9VOB5zN1PiLrJneoVliNL"},
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
