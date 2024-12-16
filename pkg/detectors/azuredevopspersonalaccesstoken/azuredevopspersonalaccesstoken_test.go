package azure_devops

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestAzureDevopsPersonalAccessToken_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		// old
		{
			name: "valid - old token",
			input: `
provider "azuredevops" {
  # Configuration options
  org_service_url       = "https://dev.azure.com/housemd"
  personal_access_token = "qkfon5cdjdekin4qnkgfr2nf367h6yjnnqm5upwqepd3rekl4l5a"
}`,
			want: []string{"qkfon5cdjdekin4qnkgfr2nf367h6yjnnqm5upwqepd3rekl4l5a:housemd"},
		},

		// new
		{
			name: "valid - az devops CLI",
			input: `        echo "Tests failed. Creating a bug in Azure DevOps..."
        az devops login --organization https://dev.azure.com/TechServicesCorp --token A0us9bS1c6qe5blb6CT4FGRR4JcmPDg7uadVFmw4D65bvtdPcdVdJQQJ99AKACAAAAAPnX9AAAASAhDO4GFB
        az boards work-item create --title "Automated Bug: Test Failure" --type $(bugType) --description "Tests failed. See results.log for details." --project "Test"`,
			want: []string{"A0us9bS1c6qe5blb6CT4FGRR4JcmPDg7uadVFmw4D65bvtdPcdVdJQQJ99AKACAAAAAPnX9AAAASAhDO4GFB:TechServicesCorp"},
		},
		{
			name: "valid - environment variables",
			input: `# Base image: Azure CLI with a lightweight Ubuntu distribution-mcr.microsoft.com/azure-cli:2.52.0
FROM ubuntu:20.04

# Set environment variables for Azure DevOps agent
ENV AZP_URL=https://dev.azure.com/EBOrg21
ENV AZP_TOKEN=2ZGS1XLyxTU2wXlrXy71ldl1tBKceXM9kl6mVAeQchvWIErzkwtBJQjJ99AKACAAAAAAAAAAAAASAZDO5BA2
ENV AZP_POOL=TestParty
`,
			want: []string{"2ZGS1XLyxTU2wXlrXy71ldl1tBKceXM9kl6mVAeQchvWIErzkwtBJQjJ99AKACAAAAAAAAAAAAASAZDO5BA2:EBOrg21"},
		},
		{
			name: "valid - jupyter notebook",
			input: `       "4  https://dev.azure.com/SSGL-SMT/10_BG_AU5...  "
      ]
     },
     "execution_count": 3,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "df.head()"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 4,
   "metadata": {},
   "outputs": [],
   "source": [
    "token = r\"49QzGd2ZOLTWdoMc0S3M0cZkVVsBMTua01tlMYOkTUnEwxebgYdheQQJ99AKACAAAAAHsyrdAAASAZDOULjm\""
   ]`,
			want: []string{"49QzGd2ZOLTWdoMc0S3M0cZkVVsBMTua01tlMYOkTUnEwxebgYdheQQJ99AKACAAAAAHsyrdAAASAZDOULjm:SSGL-SMT"},
		},

		// Invalid
		{
			name:  "invalid",
			input: `ssh.dev.azure.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7Hr1oTWqNqOlzGJOfGJ4NakVyIzf1rXYd4d7wo6jBlkLvCA4odBlL0mDUyZ0/QUfTTqeu+tm22gOsv+VrVTMk6vwRU75gY/y9ut5Mb3bR5BV58dKXyq9A9UeB5Cakehn5Zgm6x1mKoVyf+FFn26iYqXJRgzIZZcZ5V6hrE0Qg39kZm4az48o0AUbf6Sp4SLdvnuMa2sVNwHBboS7EJkm57XQPVU3/QpyNLHbWDdzwtrlS+ez30S3AdYhLKEOxAG8weOnyrtLJAUen9mTkol8oII1edf7mWWbWVf0nBmly21+nZcmCTISQBtdcyPaEno7fFQMDD26/s0lfKob4Kw8H`,
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
