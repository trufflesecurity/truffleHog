package v2

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestAzure_Pattern(t *testing.T) {
	t.Parallel()
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		// Valid
		{
			name: "valid - single secret, client, tenant",
			input: `ClientID - 9794fe8b-1ff6-4cf6-b28c-72c8fb124942
Client Secret- nfu7Q~XRIzdfTQS4QN_ABnmQKg4dPA10~5lbocIl
Tenant ID - d4a48591-844d-44a2-8a84-9c94028bdfab`,
			want: []string{`{"clientSecret":"nfu7Q~XRIzdfTQS4QN_ABnmQKg4dPA10~5lbocIl","clientId":"9794fe8b-1ff6-4cf6-b28c-72c8fb124942","tenantId":"d4a48591-844d-44a2-8a84-9c94028bdfab"}`},
		},
		{
			name: "valid - single secret, multiple client/tenant",
			input: `
cas.authn.azure-active-directory.client-id=5b82d177-f2ee-461b-a1f6-0624fff3caf0,
#cas.authn.azure-active-directory.client-id=51b65b04-5658-49e0-9955-f1705935bf0a,
cas.authn.azure-active-directory.login-url=https://login.microsoftonline.com/common/,
cas.authn.azure-active-directory.tenant=19653e91-7a9a-4bd6-8752-3070fc17e9e7,
#cas.authn.azure-active-directory.tenant=9b5eb0ce-7b2c-4f8d-8542-6248ee2c6525,
cas.authn.azure-active-directory.client-secret=pe48Q~~WtAjXI8HronCfgvzgHPfMGWjn4Hy4vcgC,
`,
			want: []string{"pe48Q~~WtAjXI8HronCfgvzgHPfMGWjn4Hy4vcgC"},
		},

		// Invalid
		{
			name: "invalid - low entropy",
			input: `
tenant_id         = "1821c750-3a5f-4255-88ad-e24b7a1564c1"
client_id         = "4e14d6ff-c99b-4d10-8491-00f731747898"
client_secret	  = "bP88Q~xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"`,
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

type testCase struct {
	Input    string
	Expected map[string]struct{}
}

func Test_FindClientSecretMatches(t *testing.T) {
	t.Parallel()
	cases := map[string]testCase{
		// Valid
		"secret": {
			Input: `servicePrincipal:
  tenantId: "608e4ac4-2ca8-40dd-a046-4064540a1cde"
  clientId: "1474bfe8-663c-486e-9daf-f1f580302218"
  clientSecret: "R028Q~ZOKzgCYyhr1ZJNNKhP8gUcD3Dpy2jMqaXf"
agentImage: "karbar.azurecr.io/kar-agent"`,
			Expected: map[string]struct{}{
				"R028Q~ZOKzgCYyhr1ZJNNKhP8gUcD3Dpy2jMqaXf": {},
			},
		},
		"secret_start_with_dash": {
			Input: `azure:
      active-directory:
        enabled: true
        profile:
          tenant-id: 11111111-1111-1111-1111-111111111111
        credential:
          client-id: 00000000-0000-0000-0000-000000000000
          client-secret: -bs8Q~F9mPSWiDihY0NIpcQjAWoUoQ.c-seM-c0_`,
			Expected: map[string]struct{}{
				"-bs8Q~F9mPSWiDihY0NIpcQjAWoUoQ.c-seM-c0_": {},
			},
		},
		"secret_end_with_dash": {
			Input: `OPENID_CLIENT_ID=8595f61a-109a-497d-8c8f-566b733e95fe
OPENID_CLIENT_SECRET=aZ78Q~C~--E4dgsHZklBWtAw0mdajUHAaXXG5cq-
OPENID_GRANT_TYPE=client_credentials`,
			Expected: map[string]struct{}{
				"aZ78Q~C~--E4dgsHZklBWtAw0mdajUHAaXXG5cq-": {},
			},
		},
		"client_secret": {
			Input: `      "RequestBody": "client_id=4cb7565b-9ff0-49ed-b317-4dace4a70396\u0026grant_type=client_credentials\u0026client_info=1\u0026client_secret=-6s8Q~.Q9CKMOXHGs_BA3ig2wUzyDRyulhWEOc3u\u0026claims=%7B%22access_token%22%3A\u002B%7B%22xms_cc%22%3A\u002B%7B%22values%22%3A\u002B%5B%22CP1%22%5D%7D%7D%7D\u0026scope=https%3A%2F%2Fmanagement.azure.com%2F.default",`,
			Expected: map[string]struct{}{
				"-6s8Q~.Q9CKMOXHGs_BA3ig2wUzyDRyulhWEOc3u": {},
			},
		},

		// Invalid
		"invalid - low entropy": {
			Input:    `CLIENT_SECRET = 'USe8Q~xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'`,
			Expected: nil,
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			matches := findSecretMatches(test.Input)
			if len(matches) == 0 {
				if len(test.Expected) != 0 {
					t.Fatalf("no matches found, expected: %v", test.Expected)
					return
				} else {
					return
				}
			}

			if diff := cmp.Diff(test.Expected, matches); diff != "" {
				t.Errorf("%s diff: (-want +got)\n%s", name, diff)
			}
		})
	}
}
