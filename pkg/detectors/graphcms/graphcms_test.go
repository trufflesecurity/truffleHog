package graphcms

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
		"name": "GraphCMS",
		"type": "Detector",
		"api": true,
		"authentication_type": "",
		"verification_url": "https://api.example.com/example",
		"test_secrets": {
			"secret": "eyQLdHMLjpK5snSPYf6ZCiXXxQRlie2wMITSkTjuzywCiga696mNUt2k2nEL4mv70CKQD9STxcN@eyr4kx6eWKut5zTR6Ei9o94jSCNWjkjQgYoD1pihdbTrr0sHys5uSHOUtiICAtcgsXjewxjyHvro9JYMClVEiGMQoxRC8d1NKfChOjrSO2unumWMsSMSgoA1KQLlHXd0efLuN94KiA3tjLN2Om8SsvLrk29LTPhaQYMvyx02x4IPjLlcHLqSt7cSVUqOe0uGxyIGyzsT7wx9PT56zbieLhRmO697zwyuiN4LpCccP7PuJB9qjz9AofCvgP8TJNsUZdwqcLFiyYTmZQ66Tn9Vpa1IJIdp2oq6izYegl49PDQtuP60A5O7xS7wV5QnFrkqmQkj7WeDUAtRECfTSgfFuXYLPwfYD7cYkfBRC7I1sdnH5tV1R4YEizugtQR5FhVeXHJJkfa-eNjLX9rUsnUNEJTvHOkiyjPvJkUfYzbJMUEVAjIhzny9V04DfnCh7l1mrVM0s_dpUP4fEmAe5fJjDHOMpvtZar0AByzBRpac9Rih0eWpbrMv7sNXh3d9pRPf-AtzCyKqzQ25_FJ6J6wN2evxXnqV4KhSmRTkaaNra4jsF3Sh8cMVYN-jAV6UBeKdSSLcFpjhlnVD6y59PnxFxbL7lj4UxVql3GpqnuKdd3MjN9OOQW2oqI8fd7_I8-vNwowWIuh4K5J0MbBIHCCgvqvdfPEHv4tBKFaj71zcEiDwOQJNxtL-kU_xTpcij9Rq5gnSRufQo1D932wSEe4NrHjZJhJu5qjtR1VC1dujLotyZvYhlyFJ22Lr2Tj5btj-VNjZeCJuv3QcQwR7mSI23O1e1_ESHnYkq4EMd17EIVWucgGZ1jZxGURTAU2bNJMDYUuramusFKAPtaL9i2uVDMQNukiWQI3fIrkOFguGnsCksOSWx80pu2C7CdvhH2SpF0kVnggTcz5W2AR4HPKu4645wBAY_IoirLUcCeKCjWTRJBH2kanqUCweHHU1qRSHncvYdkm0TRGkjpewoZs6JNpxc0WzClIatcVKOAbak3SKLULu28y5b-eIY_x2vqgYmjVZKsjqiQpJblkrRpJsnj3w0-B",
			"graphcms_id": "trevo1rp5egljk1vwk83enlti"
		},
		"expected_response": "200",
		"method": "GET",
		"deprecated": false
	}]`
	secret = "eyQLdHMLjpK5snSPYf6ZCiXXxQRlie2wMITSkTjuzywCiga696mNUt2k2nEL4mv70CKQD9STxcN@eyr4kx6eWKut5zTR6Ei9o94jSCNWjkjQgYoD1pihdbTrr0sHys5uSHOUtiICAtcgsXjewxjyHvro9JYMClVEiGMQoxRC8d1NKfChOjrSO2unumWMsSMSgoA1KQLlHXd0efLuN94KiA3tjLN2Om8SsvLrk29LTPhaQYMvyx02x4IPjLlcHLqSt7cSVUqOe0uGxyIGyzsT7wx9PT56zbieLhRmO697zwyuiN4LpCccP7PuJB9qjz9AofCvgP8TJNsUZdwqcLFiyYTmZQ66Tn9Vpa1IJIdp2oq6izYegl49PDQtuP60A5O7xS7wV5QnFrkqmQkj7WeDUAtRECfTSgfFuXYLPwfYD7cYkfBRC7I1sdnH5tV1R4YEizugtQR5FhVeXHJJkfa-eNjLX9rUsnUNEJTvHOkiyjPvJkUfYzbJMUEVAjIhzny9V04DfnCh7l1mrVM0s_dpUP4fEmAe5fJjDHOMpvtZar0AByzBRpac9Rih0eWpbrMv7sNXh3d9pRPf-AtzCyKqzQ25_FJ6J6wN2evxXnqV4KhSmRTkaaNra4jsF3Sh8cMVYN-jAV6UBeKdSSLcFpjhlnVD6y59PnxFxbL7lj4UxVql3GpqnuKdd3MjN9OOQW2oqI8fd7_I8-vNwowWIuh4K5J0MbBIHCCgvqvdfPEHv4tBKFaj71zcEiDwOQJNxtL-kU_xTpcij9Rq5gnSRufQo1D932wSEe4NrHjZJhJu5qjtR1VC1dujLotyZvYhlyFJ22Lr2Tj5btj-VNjZeCJuv3QcQwR7mSI23O1e1_ESHnYkq4EMd17EIVWucgGZ1jZxGURTAU2bNJMDYUuramusFKAPtaL9i2uVDMQNukiWQI3fIrkOFguGnsCksOSWx80pu2C7CdvhH2SpF0kVnggTcz5W2AR4HPKu4645wBAY_IoirLUcCeKCjWTRJBH2kanqUCweHHU1qRSHncvYdkm0TRGkjpewoZs6JNpxc0WzClIatcVKOAbak3SKLULu28y5b-eIY_x2vqgYmjVZKsjqiQpJblkrRpJsnj3w0-B"
)

func TestGraphCMS_Pattern(t *testing.T) {
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
