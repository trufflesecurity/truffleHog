package uuid

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

func TestNpmTokenUuid_Pattern(t *testing.T) {
	cases := map[string]npmPatternTestCase{
		"npmrc/_authToken/top_level": {
			input: `registry=https://nexus.company.com/repository/npm-group/
_authToken=NpmToken.3e9adc26-5c1b-3fdf-901f-6df392a48616`,
			expected: "3e9adc26-5c1b-3fdf-901f-6df392a48616",
		},
		"npmrc/_authToken/scoped/npm": {
			input: `loglevel=silent
registry=https://registry.npmjs.org/
//registry.npmjs.org/:_authToken=fcb3b15d-4d4a-44dc-b92d-13ee9d25582d`,
			expected: "fcb3b15d-4d4a-44dc-b92d-13ee9d25582d",
		},
		"npmrc/_authToken/scoped/nexus": {
			input: `  echo email=jdoe@company.com > .npmrc
  echo always-auth=true >> .npmrc
  echo registry=https://nexus.company.com:8443/repository/npm-registry/ >> .npmrc
  echo //nexus.company.com:8443/repository/npm-registry/:_authToken=NpmToken.de093289-9551-3238-a766-9d2c694f2600 >> .npmrc`,
			expected: "de093289-9551-3238-a766-9d2c694f2600",
		},
		"npmrc/_authToken/scopegd/other(1)": {
			input: `@fontawesome:registry=https://npm.fontawesome.com/
//npm.fontawesome.com/:_authToken=E8EC7793-A630-49AA-3351-6887EE647296`,
			expected: "E8EC7793-A630-49AA-3351-6887EE647296",
		},
		"yarn/npmAuthToken/scoped": {
			input: `npmScopes:
  fortawesome:
    npmAlwaysAuth: true
    npmRegistryServer: "https://npm.fontawesome.com/"
    npmAuthToken: "${20FCC725-C7FF-4BBF-3DE8-632C89A16C87}"`,
			expected: "20FCC725-C7FF-4BBF-3DE8-632C89A16C87",
		},
		"misc(1)": {
			input: `CI: "true"
            NPM_PUBLISH_URL: "http://nexus3.company.net:8081/repository/npm-releases/"
            NPM_PUBLISH_TOKEN: "b5505337-ffb2-3fac-8b3a-fcd81b8bb8fb"`,
			expected: "b5505337-ffb2-3fac-8b3a-fcd81b8bb8fb",
		},
		"misc(2)": {
			input: `- name: NPM_PUBLISH_TOKEN
  description: "Npm user used when upload artifacts"
  required: true
  value: "NpmToken.b5505337-ffb2-3fac-8b3a-fcd81b8ab8fb"`,
			expected: "b5505337-ffb2-3fac-8b3a-fcd81b8ab8fb",
		},
		"misc(3)": {
			input: `root@4f5ec7bfe603:/<span class="token comment"># cd &amp;&amp; cat .npmrc </span>
//192.168.1.253:8081/repository/npm-group-local/:_authToken<span class="token operator">=</span>NpmToken.7385beb7-2f92-3295-8ccf-8020132d6232`,
			expected: "7385beb7-2f92-3295-8ccf-8020132d6232",
		},
		"misc(4)": {
			input:    `ENV NPM_TOKEN "16b46f03-f1fb-4dce-9a98-c7e685751e67"`,
			expected: "16b46f03-f1fb-4dce-9a98-c7e685751e67",
		},
		"misc(5)": {
			input: // https://github.com/arnaud-deprez/jenkins-docker-openshift/blob/60bb4dbe4d5484ff3f81697c26892dda4cd33930/charts/jenkins-openshift/values.yaml#L209
			`            CI: "true"
            NPM_MIRROR_URL: "http://nexus3:8081/repository/npm-public/"
            NPM_PUBLISH_URL: "http://nexus3:8081/repository/npm-releases/"
            NPM_PUBLISH_TOKEN: "b5505337-ffb2-3fac-8b3a-fcd81b8bb8fb"`,
			expected: "b5505337-ffb2-3fac-8b3a-fcd81b8bb8fb",
		},

		// Invalid
		"invalid/_authToken/variable": {
			input: `//npm.pkg.github.com/:_authToken=${GITHUB_PACKAGES_AUTH_TOKEN}`,
		},
		"invalid/default": {
			input: `assert(registry, 'registry not set, example: "https://nexus.foo.com/repository/mynpm/"')
const tokenErrorMsg =  'npm token invalid, example: "NpmToken.00000000-0000-0000-0000-000000000000" before base64 encoded'`,
		},
		"invalid/not_uuid": {
			input: `# .npmrc
# @ngiq:registry=https://registry.corp.net/repository/npm-group
# //registry.corp.net/repository/:_authToken=NpmToken.xxxx`,
		},
		"invalid/wrong_case": {
			input: `{\"name\":\"NPmLslOudNeTLpfg\",\"correlationId\":\"9cdc2447-3eaa-4191-b6ed-43e9b6b1b3c3\"}`,
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
