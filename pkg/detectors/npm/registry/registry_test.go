package registry

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

func TestNpm_FindTokenRegistry(t *testing.T) {
	cases := map[string]struct {
		data     string
		token    string
		expected *Info
	}{
		".npmrc / _auth / top-level / no registry": {
			data:     "_auth = \"cGFzc3dvcmQ=\"\nemail = john.doe@example.com",
			token:    "cGFzc3dvcmQ=",
			expected: nil,
		},
		// TODO: Associate top-level auth with top-level registry.
		// ".npmrc / _auth / top-level / registry": {
		//	input: "_auth = \"cGFzc3dvcmQ=\"\nalways-auth = true\nregistry=https://nexus.company.com/repository/npm-group/",
		//	token: "cGFzc3dvcmQ=",
		//	expected: &Info{
		//		Type: nexusRepo3,
		//		Scheme:       httpsScheme,
		//		Uri:          "nexus.company.com/repository/npm-group",
		//	},
		// },
		".npmrc / _auth / scoped / registry": {
			data:  "\"//artifactory.company.com/artifactory/api/npm/npm/:_auth\"=cGFzc3dvcmQ=\n",
			token: "cGFzc3dvcmQ=",
			expected: &Info{
				Type:   artifactoryHosted,
				Scheme: UnknownScheme,
				Uri:    "artifactory.company.com/artifactory/api/npm/npm",
			},
		},
		".npmrc / _authToken / no trailing slash": {
			data:  `"//artifactory.company.com/artifactory/api/npm/npm:_authToken" "=cGFzc3dvcmQ="`,
			token: "cGFzc3dvcmQ=",
			expected: &Info{
				Type:   artifactoryHosted,
				Scheme: UnknownScheme,
				Uri:    "artifactory.company.com/artifactory/api/npm/npm",
			},
		},
		".npmrc / _authToken / registry": {
			data:  `"//artifactory.company.com/artifactory/api/npm/npm/:_authToken" "=cGFzc3dvcmQ="`,
			token: "cGFzc3dvcmQ=",
			expected: &Info{
				Type:   artifactoryHosted,
				Scheme: UnknownScheme,
				Uri:    "artifactory.company.com/artifactory/api/npm/npm",
			},
		},
		"cli / _authToken / registry": {
			data:  "npm config set @company:registry=https://npm.pkg.github.com/\nnpm config set //npm.pkg.github.com/:_authToken=ghp_sS3gaQUHaXSdwojeksTlaIAgJ7jWsn4D7gPO\n",
			token: "ghp_sS3gaQUHaXSdwojeksTlaIAgJ7jWsn4D7gPO",
			expected: &Info{
				Type:   githubCloud,
				Scheme: HttpsScheme,
				Uri:    "npm.pkg.github.com",
			},
		},
		"cli / _authToken / multiple registries": {
			data:  "npm config set @other:registry=https://npm.pkg.github.com/\nnpm config set //npm.pkg.github.com/:_authToken=ghp_sS3gaQUHaXSdwojeksTlaIAgJ7jWsn4D7gPO\nnpm config set \"@fortawesome:registry\" https://npm.fontawesome.com/\nnpm config set \"//npm.fontawesome.com/:_authToken\" cGFzc3dvcmQ=",
			token: "cGFzc3dvcmQ=",
			expected: &Info{
				Type:   other,
				Scheme: HttpsScheme,
				Uri:    "npm.fontawesome.com",
			},
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			actual := FindTokenURL(test.data, test.token)

			ignoreOpts := cmpopts.IgnoreFields(Info{})
			if diff := cmp.Diff(test.expected, actual, ignoreOpts); diff != "" {
				t.Errorf("diff: (-expected +actual)\n%s", diff)
			}
		})
	}
}

type registryTestCase struct {
	input    string
	expected *Info
}

func TestNpm_FindAllRegistryURLs_Known(t *testing.T) {
	cases := map[string]registryTestCase{
		"npm - default": {
			input: `NpmToken.35ea93c4-8c57-4a7c-8526-115b9eeeab8a`,
		},
		"npm": {
			input: "//registry.npmjs.org/:_authToken=cGFzc3dvcmQ=",
			expected: &Info{
				Type:   npm,
				Scheme: HttpsScheme,
				Uri:    "registry.npmjs.org",
			},
		},
		"artifactoryHosted": {
			input: `//repo.company.com/artifactory/api/npm/npm-repo/:_password=cGFzc3dvcmQ=`,
			expected: &Info{
				Type: artifactoryHosted,
				Uri:  "repo.company.com/artifactory/api/npm/npm-repo",
			},
		},
		"artifactoryCloud": {
			input: `//company.jfrog.io/company/api/npm/npm/:_authToken=cGFzc3dvcmQ=`,
			expected: &Info{
				Type:   artifactoryCloud,
				Scheme: HttpsScheme,
				Uri:    "company.jfrog.io/company/api/npm/npm",
			},
		},
		"nexusRepo2 - repository": {
			input: `//nexus.company.org:8081/nexus/content/repositories/npm`,
			expected: &Info{
				Type: nexusRepo2,
				Uri:  "nexus.company.org:8081/nexus/content/repositories/npm",
			},
		},
		"nexusRepo2 - group": {
			input: `//nexus.company.org:8081/nexus/content/groups/npm`,
			expected: &Info{
				Type: nexusRepo2,
				Uri:  "nexus.company.org:8081/nexus/content/groups/npm",
			},
		},
		"nexusRepo3": {
			input: `//nexus.company.com/repository/npm-proxy`,
			expected: &Info{
				Type: nexusRepo3,
				Uri:  "nexus.company.com/repository/npm-proxy",
			},
		},
		"gitlab - project": {
			input: `//gitlab.matrix.org/api/v4/projects/27/packages/npm/`,
			expected: &Info{
				Type: gitlab,
				Uri:  "gitlab.matrix.org/api/v4/projects/27/packages/npm",
			},
		},
		"gitlab - group": {
			input: `//gitlab.com/api/v4/groups/1234/-/packages/npm/`,
			expected: &Info{
				Type: gitlab,
				Uri:  "gitlab.com/api/v4/groups/1234/-/packages/npm",
			},
		},
		// This is apparently a thing? No idea, found it in the wild though.
		"gitlab - top-level": {
			input: `"//code.company.com/api/v4/packages/npm/:_authToken" "ZENNP-123456789"`,
			expected: &Info{
				Type: gitlab,
				Uri:  "code.company.com/api/v4/packages/npm",
			},
		},
		"gitlab - .yarnrc.yml - npmRegistries (2)": {
			input: `  npmRegistries:
    //npm.company.com/api/v4/packages/npm:
      npmAlwaysAuth: true
      npmAuthToken: "<your_token>"`,
			expected: &Info{
				Type:   gitlab,
				Scheme: UnknownScheme,
				Uri:    "npm.company.com/api/v4/packages/npm",
			},
		},
		"github": {
			input: `//npm.pkg.github.com/`,
			expected: &Info{
				Type:   githubCloud,
				Scheme: HttpsScheme,
				Uri:    "npm.pkg.github.com",
			},
		},
		"azure - org": {
			input: `//pkgs.dev.azure.com/company/_packaging/feed/npm/registry/`,
			expected: &Info{
				Type:   azure,
				Scheme: HttpsScheme,
				Uri:    "pkgs.dev.azure.com/company/_packaging/feed/npm/registry",
			},
		},
		"azure - repo": {
			input: `//pkgs.dev.azure.com/company/project/_packaging/feed/npm/`,
			expected: &Info{
				Type:   azure,
				Scheme: HttpsScheme,
				Uri:    "pkgs.dev.azure.com/company/project/_packaging/feed/npm/registry",
			},
		},
		"azure - visualstudio": {
			input: `//company.pkgs.visualstudio.com/05337347-30ac-46d4-b46f-5f5cb80c6818/_packaging/feed/npm/registry/`,
			expected: &Info{
				Type:   azure,
				Scheme: HttpsScheme,
				Uri:    "company.pkgs.visualstudio.com/05337347-30ac-46d4-b46f-5f5cb80c6818/_packaging/feed/npm/registry",
			},
		},
		"google artifact registry": {
			input: `@rbl:registry=https://us-central1-npm.pkg.dev/company/project/
//us-central1-npm.pkg.dev/company/project/:_authToken="ya29.A0ARrdaM9VpQcc5egcSN7zzEGQLzvz5jZiXEkIDmnsV2RW3KBbhbq8qkRHMUcC6gxknE9LuDW3mt4Dz3teWYXfI-4WGr6_mTQqj60BhAg4sPA7wov7PM-E3QonNwTN9De41ARPJUyvfc8Mi2GVoYzle3MJ_8KNYo4"
//us-central1-npm.pkg.dev/company/project/:always-auth=true`,
			expected: &Info{
				Type:   googleArtifactRegistry,
				Scheme: HttpsScheme,
				Uri:    "us-central1-npm.pkg.dev/company/project",
			},
		},
		"jetbrains": {
			input: `//npm.pkg.jetbrains.space/company/p/project/repo/`,
			expected: &Info{
				Type:   jetbrains,
				Scheme: HttpsScheme,
				Uri:    "npm.pkg.jetbrains.space/company/p/project/repo",
			},
		},
		"gemfury": {
			input: `//npm.fury.io/user/`,
			expected: &Info{
				Type:   gemfury,
				Scheme: HttpsScheme,
				Uri:    "npm.fury.io/user",
			},
		},
		"aws - npmRegistries": {
			input: `npmRegistries:
  "https://compstak-prod-278693104475.d.codeartifact.us-east-1.amazonaws.com/npm/frontend/":
    npmAlwaysAuth: true
    npmAuthToken: "${CODEARTIFACT_AUTH_TOKEN}"`,
			expected: &Info{
				Type:   awsCodeArtifact,
				Scheme: HttpsScheme,
				Uri:    "compstak-prod-278693104475.d.codeartifact.us-east-1.amazonaws.com/npm/frontend",
			},
		},
		"aws - npmScopes": {
			input: `npmScopes:
  compstak:
    npmAlwaysAuth: true
    npmAuthToken: "${CODEARTIFACT_AUTH_TOKEN}"
    npmRegistryServer: https://compstak-prod-278696104475.d.codeartifact.us-east-1.amazonaws.com/npm/frontend`,
			expected: &Info{
				Type:   awsCodeArtifact,
				Scheme: HttpsScheme,
				Uri:    "compstak-prod-278696104475.d.codeartifact.us-east-1.amazonaws.com/npm/frontend",
			},
		},
	}

	for name, tCase := range cases {
		var expected Info
		if tCase.expected != nil {
			expected = *tCase.expected
		} else {
			expected = Info{}
		}

		schemes := [...]Scheme{UnknownScheme, HttpScheme, HttpsScheme}
		for _, scheme := range schemes {
			var (
				expected = expected
				uri      = expected.Uri
				input    string
			)

			if expected.Scheme == UnknownScheme {
				expected.Scheme = scheme
			}

			if scheme == UnknownScheme {
				input = tCase.input
			} else if scheme == HttpScheme {
				input = fmt.Sprintf("registry=http://%s/\n%s", uri, tCase.input)
			} else {
				input = fmt.Sprintf("registry=https://%s/\n%s", uri, tCase.input)
			}

			t.Run(fmt.Sprintf("%s - %s", name, scheme.String()), func(t *testing.T) {
				urls := FindAllURLs(context.Background(), input, false)
				if len(urls) == 0 && expected.Uri == "" {
					return
				} else if len(urls) != 1 && expected.Uri != "" {
					t.Errorf("expected 1 result, got %d (%v)", len(urls), urls)
					return
				}

				var actual Info
				for _, i := range urls {
					actual = *i
				}

				if diff := cmp.Diff(expected, actual); diff != "" {
					t.Errorf("diff: (-expected +actual)\n%s", diff)
				}
			})
		}
	}
}

func TestNpm_FindAllRegistryURLs_Unknown(t *testing.T) {
	cases := map[string]registryTestCase{
		"nothing": {
			input:    `NpmToken.35ea93c4-8c57-4a7c-8526-115b9eeeab8a`,
			expected: nil,
		},
		"package.json - publishConfig": {
			input: `"\"publishConfig\": {\n    \"registry\": \"http://repository.dsv.myhost/npmjs\"\n  },`,
			expected: &Info{
				Type:   other,
				Scheme: HttpScheme,
				Uri:    "repository.dsv.myhost/npmjs",
			},
		},
		"cli - publish registry flag": {
			input: `//npm publish --registry http://ec2-18-223-132-112.us-east-2.compute.amazonaws.com:8081/npm/`,
			expected: &Info{
				Type:   other,
				Scheme: HttpScheme,
				Uri:    "ec2-18-223-132-112.us-east-2.compute.amazonaws.com:8081/npm",
			},
		},
		"cli - publish scoped registry flag": {
			input: `//npm publish --@myscope:registry=http://internal.company.com/packages/npmjs-registry/`,
			expected: &Info{
				Type:   other,
				Scheme: HttpScheme,
				Uri:    "internal.company.com/packages/npmjs-registry",
			},
		},
		"cli - config registry": {
			input: `npm config set registry "https://npm.company.com/"`,
			expected: &Info{
				Type:   other,
				Scheme: HttpsScheme,
				Uri:    "npm.company.com",
			},
		},
		"cli - config scope registry": {
			input: `npm config set "@company:registry" "https://npm.company.com/"`,
			expected: &Info{
				Type:   other,
				Scheme: HttpsScheme,
				Uri:    "npm.company.com",
			},
		},
		"cli - config authToken": {
			input: `npm config set "//npm.company.com/:_authToken" token123`,
			expected: &Info{
				Type:   other,
				Scheme: UnknownScheme,
				Uri:    "npm.company.com",
			},
		},
		".npmrc - registry": {
			input: `"registry=https://npm.company.com/`,
			expected: &Info{
				Type:   other,
				Scheme: HttpsScheme,
				Uri:    "npm.company.com",
			},
		},
		".npmrc - scope registry": {
			input: `@company:registry = https://repo.company.com:8443/`,
			expected: &Info{
				Type:   other,
				Scheme: HttpsScheme,
				Uri:    "repo.company.com:8443",
			},
		},
		".npmrc - scope registry, no equals": {
			input: `"@company:registry" "https://artifacts.company.com/npm/"`,
			expected: &Info{
				Type:   other,
				Scheme: HttpsScheme,
				Uri:    "artifacts.company.com/npm",
			},
		},
		".npmrc - scope": {
			input: `@company = "https://repo.company.com/"`,
			expected: &Info{
				Type:   other,
				Scheme: HttpsScheme,
				Uri:    "repo.company.com",
			},
		},
		".npmrc - _auth": {
			input: `"//npm.company.com/:_auth" = "cGFzc3dvcmQ="`,
			expected: &Info{
				Type:   other,
				Scheme: UnknownScheme,
				Uri:    "npm.company.com",
			},
		},
		".npmrc - _auth with https context": {
			input: `"//npm.company.com/:_auth" = "cGFzc3dvcmQ="
registry=https://npm.company.com/`,
			expected: &Info{
				Type:   other,
				Scheme: HttpsScheme,
				Uri:    "npm.company.com",
			},
		},
		".npmrc - _auth with http context": {
			input: `"//npm.company.com/:_auth" = "cGFzc3dvcmQ="
registry=http://npm.company.com/`,
			expected: &Info{
				Type:   other,
				Scheme: HttpScheme,
				Uri:    "npm.company.com",
			},
		},
		".npmrc - _password": {
			input: `//npm.company.com/:_password=cGFzc3dvcmQ=`,
			expected: &Info{
				Type:   other,
				Scheme: UnknownScheme,
				Uri:    "npm.company.com",
			},
		},
		".npmrc - ip": {
			input: `@eventdex:registry=http://4.89.41.88:4873/
//4.89.41.88:4873/:_authToken="DgcjMOa2QyMunSLr9YDzUA=="`,
			expected: &Info{
				Type:   other,
				Scheme: HttpScheme,
				Uri:    "4.89.41.88:4873",
			},
		},
		// https://docs.unity3d.com/Manual/upm-config-scoped.html
		".upmconfig.toml": {
			input: `[npmAuth."https://api.bintray.example/npm/mycompany/myregistry"]`,
			expected: &Info{
				Type:   other,
				Scheme: HttpsScheme,
				Uri:    "api.bintray.example/npm/mycompany/myregistry",
			},
		},
		".yarnrc.yml - npmScopes (1)": {
			input: `npmScopes:
  fortawesome:
    npmAlwaysAuth: true
    npmRegistryServer: "https://npm.fontawesome.com/"
    npmAuthToken: "${20FCC725-C7FF-4BBF-3DE8-632C89A16C87}"`,
			expected: &Info{
				Type:   other,
				Scheme: HttpsScheme,
				Uri:    "npm.fontawesome.com",
			},
		},
		".yarnrc.yml - npmRegistries (2)": {
			input: `run: |
          echo "npmRegistries:" >> ~/.yarnrc.yml
          echo "  //registry.company.com:" >> ~/.yarnrc.yml
          echo "    npmAuthToken: $NPM_TOKEN" >> ~/.yarnrc.yml`,
			expected: &Info{
				Type:   other,
				Scheme: UnknownScheme,
				Uri:    "registry.company.com",
			},
		},
		// TODO: https://github.com/renovatebot/renovate/blob/075a96c00aa53ede32576e924fe81b040789fc14/docs/usage/getting-started/private-packages.md
		// "renovatebot": {
		//	input: `      matchHost: 'https://packages.my-company.com/myregistry/',`,
		//	expected: &Info{
		//		Type: other,
		//		Scheme:       HttpsScheme,
		//		Uri:          "packages.my-company.com/myregistry",
		//	},
		// },
		// https://github.com/renovatebot/renovate/blob/b8d06fd3e007027064cfb5e93d0f14dcb7fead4d/lib/modules/manager/npm/post-update/rules.spec.ts#L39
		// additionalYarnRcYml: {
		//	npmRegistries: {
		//		'//registry.company.com/': {
		//			npmAuthIdent: 'user123:pass123',
		//		},
		//	},
		// },

		// Invalid
		"invalid/readme": {
			input: `# token-substitute

[![Build Status](https://travis-ci.org/trustpilot/node-token-substitute.svg?branch=master)](https://travis-ci.org/trustpilot/node-token-substitute) [![npm](https://img.shields.io/npm/v/token-substitute.svg)](https://www.npmjs.com/package/token-substitute)`,
		},
	}

	for name, tCase := range cases {
		t.Run(name, func(t *testing.T) {
			urls := FindAllURLs(context.Background(), tCase.input, false)
			if len(urls) != 1 && tCase.expected != nil {
				t.Errorf("expected 1 result for %s, got %d (%v)", tCase.input, len(urls), urls)
				return
			} else if len(urls) > 0 && tCase.expected == nil {
				t.Errorf("expected no result for %s, got %d (%v)", tCase.input, len(urls), urls)
				return
			}

			var actualInfo *Info
			for _, i := range urls {
				actualInfo = i
			}

			if diff := cmp.Diff(tCase.expected, actualInfo); diff != "" {
				t.Errorf("diff: (-expected +actual)\n%s", diff)
			}
		})
	}
}
