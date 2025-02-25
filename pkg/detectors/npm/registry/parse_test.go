package registry

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	regexp "github.com/wasilibs/go-re2"
)

func TestHostPat(t *testing.T) {
	tests := map[string]struct {
		input    string
		expected string
	}{
		// Valid - Domain
		"domain - default registry": {
			input:    `registry.npmjs.org`,
			expected: "registry.npmjs.org",
		},
		"domain - dashes": {
			input:    `nexus.pas-mini.io`,
			expected: "nexus.pas-mini.io",
		},
		"domain - with port": {
			input:    `nexus3.my-company.tk:8081`,
			expected: "nexus3.my-company.tk:8081",
		},
		// Valid - IPv4
		"": {
			input:    `30.125.69.246`,
			expected: "30.125.69.246",
		},
		"ip - with port": {
			input:    `10.10.69.203:8081`,
			expected: "10.10.69.203:8081",
		},

		// Invalid
		"invalid - localhost with port": {
			input: "localhost:8080",
		},
	}

	p := regexp.MustCompile(hostPat)
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			actual := p.FindString(test.input)
			if actual == "" {
				if test.expected != "" {
					t.Errorf("expecting %s but got nothing", test.expected)
					return
				}
				return
			}

			assert.Equal(t, test.expected, actual)
		})
	}
}

func TestNpm_KnownRegistryPat(t *testing.T) {
	cases := map[Type]map[string][]string{
		npm: {
			"//registry.npmjs.org/":       {"//", "registry.npmjs.org"},
			"https://registry.npmjs.org/": {"https://", "registry.npmjs.org"},
			`  resolved "https://registry.yarnpkg.com/abstract-logging/-/abstract-logging-2.0.1.tgz#6b0c371df212db7129b57d2e7fcf282b8bf1c839"`: {"https://", "registry.yarnpkg.com"},
		},
		artifactoryHosted: {
			"https://artifactory.prd.cds.internal.unity3d.com/artifactory/api/npm/upm-npm/": {"https://", "artifactory.prd.cds.internal.unity3d.com/artifactory/api/npm/upm-npm"},
			"registry=http://10.85.59.116/artifactory/v1.0/artifacts/npm/":                  {"http://", "10.85.59.116/artifactory/v1.0/artifacts/npm"},
		},
		artifactoryCloud: {
			"//voomp.jfrog.io/artifactory/api/npm/vk-common-bk/:_authToken=e7da2cb5-b625-4aa1-8baf-291a8dfd037d": {"//", "voomp.jfrog.io/artifactory/api/npm/vk-common-bk"},
			"//trfhog.jfrog.io/trfhog/api/npm/npm/:_authToken=e7da2cb5-b625-4aa1-8baf-291a8dfd037d":              {"//", "trfhog.jfrog.io/geckorobotics/api/npm/npm"},
		},
		nexusRepo2: {
			"http://nexus.zenoss.eng:8081/nexus/content/repositories/npm/":     {"http://", "nexus.zenoss.eng:8081/nexus/content/repositories/npm"},
			"http://nexus.pas-mini.io/nexus/content/repositories/npm-private/": {"http://", "nexus.pas-mini.io/nexus/content/repositories/npm-private"},
		},
		nexusRepo3: {
			"registry=http://30.125.69.246/repository/npm-group/":                                    {"http://", "30.125.69.246/repository/npm-group"},
			"https://repo.huaweicloud.com/repository/npm/":                                           {"https://", "repo.huaweicloud.com/repository/npm"},
			"http://artifacts.lan.tribe56.com:8081/repository/npm-proxy/@babel/":                     {"http://", "artifacts.lan.tribe56.com:8081/repository/npm-proxy"},
			"http://10.10.69.203:8081/repository/npm-group/":                                         {"http://", "10.10.69.203:8081/repository/npm-group"},
			"//nexus.public.prd.int.corp-devops.co.uk/repository/moon/":                              {"//", "nexus.public.prd.int.corp-devops.co.uk/repository/moon"},
			"//ec2-18-225-132-112.us-east-2.compute.amazonaws.com:8081/repository/postboard-server/": {"//", "ec2-18-225-132-112.us-east-2.compute.amazonaws.com:8081/repository/postboard-server"},
			`- name: NPM_PUBLISH_URL
  description: "Maven repository url to where jenkins will upload releases artifacts"
  required: true
  value: "http://nexus3.my-company.tk:8081/repository/npm-releases/"
- name: NPM_PUBLISH_TOKEN
  description: "Npm user used when upload artifacts"
  required: true
  value: "NpmToken.b5505337-ffb2-3fac-8b3a-fcd81b8bb8fb"`: {"http://", "nexus3.my-company.tk:8081/repository/npm-releases"},
			`<figure class="highlight shell"><table><tr><td class="gutter"><pre><span class="line">1</span><br><span class="line">2</span><br><span class="line">3</span><br></pre></td><td class="code"><pre><span class="line">[root@nexus3 ~]# cat ~/.npmrc</span><br><span class="line">registry=http://registry.blog.co/repository/npm-group/</span><br><span class="line">//registry.blog.co/repository/npm-group/:_authToken=NpmToken.72b83be3-4b24-3dd1-850f-056cd78bb513</span><br></pre></td></tr></table></figure>`: {"http://", "registry.blog.co/repository/npm-group"},
		},
		gitlab: {
			`"https://gitlab.matrix.org/api/v4/projects/27/packages/npm/@matrix-org/olm/-/@matrix-org/olm-3.2.3.tgz",`: {"https://", "gitlab.matrix.org/api/v4/projects/27/packages/npm"},
			"https://gitlab.com/api/v4/groups/123456/-/packages/npm/":                                                  {"https://", "gitlab.com/api/v4/groups/123456/-/packages/npm"}, // couldn't find a real example of this
		},
		githubCloud: {
			"https://npm.pkg.github.com/":        {"https://", "npm.pkg.github.com"},
			"https://npm.pkg.github.com/company": {"https://", "npm.pkg.github.com"},
		},
		azure: {
			"//pkgs.dev.azure.com/company/_packaging/feed/npm/":                                                 {"//", "pkgs.dev.azure.com/company/_packaging/feed/npm"},
			"https://pkgs.dev.azure.com/company/project/_packaging/feed/npm/registry/":                          {"https://", "pkgs.dev.azure.com/company/project/_packaging/feed/npm/registry"},
			"https://pkgs.dev.azure.com/company/project/_packaging/feed/npm/registry":                           {"https://", "pkgs.dev.azure.com/company/project/_packaging/feed/npm/registry"},
			"//pkgs.dev.azure.com/company/b675ba30-3f64-41c8-b35d-79c162dc3fd7/_packaging/feed/npm/":            {"//", "pkgs.dev.azure.com/company/b675ba30-3f64-41c8-b35d-79c162dc3fd7/_packaging/feed/npm"},
			"//tso-na.pkgs.visualstudio.com/7bc545d8-bf9c-477e-bb91-17a982c30c2e/_packaging/feed/npm/registry/": {"//", "ftso-na.pkgs.visualstudio.com/7bc545d8-bf9c-477e-bb91-17a982c30c2e/_packaging/feed/npm/registry"},
			"//company.pkgs.visualstudio.com/project/_packaging/feed/npm/registry/":                             {"//", "company.pkgs.visualstudio.com/project/_packaging/feed/npm/registry"},
			"//company.pkgs.visualstudio.com/_packaging/feed/npm/registry/:username=bart":                       {"//", "company.pkgs.visualstudio.com/_packaging/feed/npm/registry"},
		},
		jetbrains: {
			"//npm.pkg.jetbrains.space/multiplier/p/multiplier/npm/":                        {"//", "npm.pkg.jetbrains.space/multiplier/p/multiplier/npm"},
			"https://npm.pkg.jetbrains.space/dwan/p/main/npmempty/":                         {"https://", "npm.pkg.jetbrains.space/dwan/p/main/npmempty"},
			"https://npm.pkg.jetbrains.space/public/p/jetbrains-gamedev/jetbrains-gamedev/": {"https://", "npm.pkg.jetbrains.space/public/p/jetbrains-gamedev/jetbrains-gamedev"},
		},
		googleArtifactRegistry: {
			"https://us-west1-npm.pkg.dev/company/project":                                  {"https://", "us-west1-npm.pkg.dev/company/project"},
			"https://npm.pkg.dev/company/project":                                           {"https://", "npm.pkg.dev/company/project"},
			"//europe-west4-npm.pkg.dev/corp-staging/corp-libs/:username=oauth2accesstoken": {"//", "europe-west4-npm.pkg.dev/corp-staging/corp-libs"},
		},
		gemfury: {
			"//npm.fury.io/dependabot/": {"//", "npm.fury.io/dependabot"},
		},
	}
	for group, inputs := range cases {
		t.Run(group.String(), func(t *testing.T) {
			for input, expected := range inputs {
				matches := knownRegistryPat.FindStringSubmatch(input)
				if len(matches) == 0 {
					t.Errorf("no result for %s", input)
					return
				}

				index, uri := firstNonEmptyMatch(matches, 2)
				rType := Type(index - 1)
				if rType != group {
					t.Errorf("expected type %s, got %s (%s)", group.String(), rType.String(), input)
				}
				if matches[1] != expected[0] {
					t.Errorf("expected prefix %s, got %s (%s)", expected[0], matches[1], input)
				}
				if uri != expected[1] {
					t.Errorf("expected uri %s, got %s (%s)", expected[1], uri, input)
				}
			}
		})
	}
}

func TestNpm_GenericRegistryPat(t *testing.T) {
	cases := map[string]string{
		// .npmrc
		"registry = https://npm.company.de:4873/":                                               "https://npm.company.de:4873",
		"registry=https://registry.npm.taobao.org/":                                             "https://registry.npm.taobao.org",
		`"registry" "https://registry.npmmirror.com/"`:                                          "https://registry.npmmirror.com",
		`@company:registry="https://npm.company.io"`:                                            "https://npm.company.io",
		"@marketwall:registry=http://10.0.0.13:4873":                                            "http://10.0.0.13:4873",
		`"@fortawesome:registry" "https://npm.fontawesome.com/"`:                                "https://npm.fontawesome.com",
		"@example=https://api.bintray.example/npm/mycompany/myregistry":                         "https://api.bintray.example/npm/mycompany/myregistry",
		`"@example" "https://api.bintray.example/npm/mycompany/myregistry"`:                     "https://api.bintray.example/npm/mycompany/myregistry",
		"//npm.company.com/:_authToken='fake123'":                                               "//npm.company.com",
		"//registry-node.company.com/org/1123600651823311/registry/supermap/:_password=123fake": "//registry-node.company.com/org/1123600651823311/registry/supermap",
		`"//npm.fontawesome.com/:_authToken" "XXXXXXX-my-token"`:                                "//npm.fontawesome.com",
		`"//npm.fontawesome.com:_authToken" "XXXXXXX-my-token"`:                                 "//npm.fontawesome.com",
		`registry=http://55825a54e4454.registry.net:8443/`:                                      "http://55825a54e4454.registry.net:8443",
		// yarnrc.yml
		`npmScopes:
  "my-company":
    npmAlwaysAuth: true
    npmAuthToken: xxx-xxx
    npmRegistryServer: "https://repo.company.org/npm"`: "https://repo.company.org/npm",
		`  await fixture.exec("yarn config set npmRegistryServer http://npm.corp.xyz:8080");`:                          "http://npm.corp.xyz:8080",
		`yarn config set npmScopes --json '{ "storybook": { "npmRegistryServer": "http://repo.company.org:6001/" } }'`: "http://repo.company.org:6001",
		`yarn config set npmScopes.my-org.npmRegistryServer "https://repo.company.org/npm/nested"`:                     "https://repo.company.org/npm/nested",
		`  npmScopes:
    company:
      npmRegistryServer: '${METAMASK_NPM_REGISTRY:-https://your.company.com/private/registry}'`: "https://your.company.com/private/registry",
		// upmconfig.toml
		`[npmAuth."https://api.bintray.com/npm/joe-company/my-registry"]`:                    "https://api.bintray.com/npm/joe-company/my-registry",
		`echo "[npmAuth.'https://your.company.com/private/registry/']" >> ~/.upmconfig.toml`: "https://your.company.com/private/registry",

		// Invalid
		`# token-substitute

[![Build Status](https://travis-ci.org/trustpilot/node-token-substitute.svg?branch=master)](https://travis-ci.org/trustpilot/node-token-substitute) [![npm](https://img.shields.io/npm/v/token-substitute.svg)](https://www.npmjs.com/package/token-substitute)`: "",
	}
	for input, expected := range cases {
		if knownRegistryPat.MatchString(input) {
			t.Errorf("matches |knownRegistryPat|: %s", input)
			continue
		}

		matches := genericRegistryPat.FindStringSubmatch(input)
		if len(matches) == 0 && expected != "" {
			t.Errorf("received no matches for '%s'\n", input)
			continue
		} else if len(matches) > 0 && expected == "" {
			t.Errorf("match not expected for '%s'\n", input)
			continue
		}

		_, match := firstNonEmptyMatch(matches, 1)
		if match != expected {
			t.Errorf("expected '%s', got '%s'\n\t(%s)", expected, match, input)
		}
	}
}

func TestNpm_InvalidRegistryPat(t *testing.T) {
	cases := []string{
		// npm
		// https://github.com/npm/arborist/blob/6bc6c76b4ff156979509bc26a3c50020f69c8c0f/README.md?plain=1#L25
		"  '@foo:registry': 'https://registry.foo.com/',",
		// short-links
		"This library can be installed from the\n[npm registry](https://npm.im/express-rate-limit), or from",
		"(https://www.npmjs.com/package/token-substitute",
		"www.npmjs.com",

		// NpmMirror.com (read-only mirror)
		// "registry=https://registry.npmmirror.com",
		// "registry=http://r.cnpmjs.org/",
		// " npm i --registry=https://registry.npm.taobao.org",

		// Bun
		// https://github.com/oven-sh/bun/blob/693a00dc5b99ad3eefd1d50bfbe3a11ee625a291/docs/install/registries.md?plain=1#L22
		"\"@myorg3\" = { token = \"$npm_token\", url = \"https://registry.myorg.com/\" }",

		// Lerna
		// https://github.com/lerna/lerna/blob/3d747a176f632d6e1186e24c216527031c1744e6/e2e/create/src/create.spec.ts#L1047C13-L1049C15
		"\"publishConfig\": {\n              \"registry\": \"my-registry.com\"\n            },",

		// Renovate
		// https://github.com/renovatebot/renovate/blob/b8d06fd3e007027064cfb5e93d0f14dcb7fead4d/lib/modules/datasource/npm/index.spec.ts#L255
		"    const npmrc = 'registry=https://npm.mycustomregistry.com/';",

		// Terraform
		"registry.terraform.io/providers/hashicorp/google/4.69.1/docs/resources/monitoring_notification_channel",
		"www.terraform.io/docs/providers/google-beta/r/google_monitoring_notification_channel",

		// Test values from a common npm dependency.
		// https://github.com/rexxars/registry-auth-token/blob/main/test/auth-token.test.js
		// "registry=http://registry.npmjs.eu/",
		"registry=http://registry.foobar.cc/",
		"//registry.foobar.com/:username=foobar",
		"registry=http://registry.foobar.eu",
		"registry=http://registry.foo.bar",
		"registry=http://some.host/registry/deep/path",
		"//registry.blah.foo:_authToken=whatev",
		"//registry.last.thing:_authToken=yep",
		"//registry.blah.com/foo:_authToken=whatev",
		"//registry.blah.org/foo/bar:_authToken=recurseExactlyOneLevel",
		"//registry.blah.edu/foo/bar/baz:_authToken=recurseNoLevel",
		"//registry.blah.eu:_authToken=yep",
		"//contoso.pkgs.visualstudio.com/_packaging/MyFeed/npm/:_authToken=heider",
		// "registry=http://localhost:8770/",
		"travis-ci.org/rexxars/registry-auth-token",

		// other common examples
		"  npm config set registry http://npm.example.com/",
		"npm install express --registry http://my.registry.com/ --verbose",
		"'//some.other.registry/:_authToken",
		"'//some.registry/:_authToken",
		"//acme.example.org/:_authToken=TOKEN_FOR_ACME",
		"browsenpm.org/package/registry-auth-token",
		"https://developer.github.com/v3/media",
		"https://api.github.com/orgs/octocat/hooks/1/deliveries",
		"https://help.github.com/en/articles/virtual-environments-for-github-actions",
	}
	for _, input := range cases {
		if !invalidRegistryPat.MatchString(input) {
			t.Errorf("received match for '%s'\n", input)
		}
	}
}

func TestNpm_ParseKnownRegistryUri(t *testing.T) {
	cases := map[Type]struct {
		data     string
		uri      string
		expected *Info
	}{
		other: {
			data:     `//npm.fontawesome.com/:_authToken=e7da2cb5-b625-4aa1-8baf-291a8dfd037d`,
			uri:      "npm.fontawesome.com",
			expected: nil,
		},
		npm: {
			data: `//registry.yarnpk.org/:_authToken=e7da2cb5-b625-4aa1-8baf-291a8dfd037d`,
			uri:  "//registry.yarnpk.org",
			expected: &Info{
				Scheme: HttpsScheme,
				Uri:    "registry.npmjs.org",
			},
		},
		artifactoryCloud: {
			data: `//company.jfrog.io/company/api/npm/npm/:_authToken=e7da2cb5-b625-4aa1-8baf-291a8dfd037d`,
			uri:  "//company.jfrog.io/company/api/npm/npm",
			expected: &Info{
				Scheme: HttpsScheme,
				Uri:    "company.jfrog.io/company/api/npm/npm",
			},
		},
		artifactoryHosted: {
			data: "registry=http://artifactory.internal-dev.company.net/artifactory/api/npm/npm/\n//artifactory.internal-dev.company.net/artifactory/api/npm/npm/:_authToken=e7da2cb5-b625-4aa1-8baf-291a8dfd037d",
			uri:  "//artifactory.internal-dev.company.net/artifactory/api/npm/npm",
			expected: &Info{
				Scheme: HttpScheme,
				Uri:    "artifactory.internal-dev.company.net/artifactory/api/npm/npm",
			},
		},
		nexusRepo2: {
			data: "registry=http://nexus.corp.org/nexus/content/repositories/npm-group/\n//nexus.corp.org/nexus/content/repositories/npm-group/:_authToken=e7da2cb5-b625-4aa1-8baf-291a8dfd037d",
			uri:  "//nexus.corp.org/nexus/content/repositories/npm-group",
			expected: &Info{
				Scheme: HttpScheme,
				Uri:    "nexus.corp.org/nexus/content/repositories/npm-group",
			},
		},
		nexusRepo3: {
			data: "registry=https://nexus.corp.org/repository/npm-hosted/\n//nexus.corp.org/repository/npm-hosted/:_authToken=e7da2cb5-b625-4aa1-8baf-291a8dfd037d",
			uri:  "//nexus.corp.org/repository/npm-hosted",
			expected: &Info{
				Scheme: HttpsScheme,
				Uri:    "nexus.corp.org/repository/npm-hosted",
			},
		},
		gitlab: {
			data: "@company:registry=https://gitlab.com/api/v4/projects/12354452/packages/npm/\n//gitlab.com/api/v4/projects/12354452/packages/npm/:_authToken=e7da2cb5-b625-4aa1-8baf-291a8dfd037d",
			uri:  "//gitlab.com/api/v4/projects/12354452/packages/npm",
			expected: &Info{
				Scheme: HttpsScheme,
				Uri:    "gitlab.com/api/v4/projects/12354452/packages/npm",
			},
		},
		githubCloud: {
			data: `//npm.pkg.github.com/:_authToken=e7da2cb5-b625-4aa1-8baf-291a8dfd037d`,
			uri:  "//npm.pkg.github.com",
			expected: &Info{
				Scheme: HttpsScheme,
				Uri:    "npm.pkg.github.com",
			},
		},
		azure: {
			data: `//pkgs.dev.azure.com/company/project/_packaging/feed/npm/:_authToken=e7da2cb5-b625-4aa1-8baf-291a8dfd037d`,
			uri:  "//pkgs.dev.azure.com/company/project/_packaging/feed/npm",
			expected: &Info{
				Scheme: HttpsScheme,
				Uri:    "pkgs.dev.azure.com/company/project/_packaging/feed/npm/registry",
			},
		},
		jetbrains: {
			data: `//npm.pkg.jetbrains.space/public/p/jetbrains-gamedev/jetbrains-gamedev/:_authToken=e7da2cb5-b625-4aa1-8baf-291a8dfd037d`,
			uri:  "//npm.pkg.jetbrains.space/public/p/jetbrains-gamedev/jetbrains-gamedev",
			expected: &Info{
				Scheme: HttpsScheme,
				Uri:    "npm.pkg.jetbrains.space/public/p/jetbrains-gamedev/jetbrains-gamedev",
			},
		},
		googleArtifactRegistry: {
			data: `//us-east1-npm.pkg.dev/company-dev-167118/project/:_authToken=e7da2cb5-b625-4aa1-8baf-291a8dfd037d`,
			uri:  "//us-east1-npm.pkg.dev/company-dev-167118/project",
			expected: &Info{
				Scheme: HttpsScheme,
				Uri:    "us-east1-npm.pkg.dev/company-dev-167118/project",
			},
		},
		gemfury: {
			data: `//npm-proxy.fury.io/user/:_authToken=e7da2cb5-b625-4aa1-8baf-291a8dfd037d`,
			uri:  "//npm-proxy.fury.io/user",
			expected: &Info{
				Scheme: HttpsScheme,
				Uri:    "npm-proxy.fury.io/user",
			},
		},
	}

	for group, c := range cases {
		t.Run(group.String(), func(t *testing.T) {
			actual := parseKnownRegistryURI(c.data, c.uri)
			if actual == nil {
				if c.expected != nil {
					t.Errorf("no result for %s", c.data)
				}
				return
			}

			c.expected.Type = group
			if diff := cmp.Diff(c.expected, actual); diff != "" {
				t.Errorf("diff: (-expected +actual)\n%s", diff)
			}
		})
	}
}

func TestNpm_ParseUnknownRegistryUri(t *testing.T) {
	// Not exhaustive, parseUnknownRegistryURI doesn't do much.
	cases := []struct {
		data     string
		uri      string
		expected *Info
	}{
		{
			data: `//npm.fontawesome.com/:_authToken=e7da2cb5-b625-4aa1-8baf-291a8dfd037d`,
			uri:  "npm.fontawesome.com",
			expected: &Info{
				Type:   other,
				Scheme: UnknownScheme,
				Uri:    "npm.fontawesome.com",
			},
		},
		{
			data: "@fortawesome:registry=https://npm.fontawesome.com\n//npm.fontawesome.com/:_authToken=e7da2cb5-b625-4aa1-8baf-291a8dfd037d",
			uri:  "npm.fontawesome.com",
			expected: &Info{
				Type:   other,
				Scheme: HttpsScheme,
				Uri:    "npm.fontawesome.com",
			},
		},
	}

	for _, c := range cases {
		actual := parseUnknownRegistryURI(c.data, c.uri)
		if actual == nil {
			t.Errorf("no result for %s", c.data)
			continue
		}

		if diff := cmp.Diff(c.expected, actual); diff != "" {
			t.Errorf("diff: (-expected +actual)\n%s", diff)
		}
	}
}

func TestNpm_ParseRegistryURLScheme(t *testing.T) {
	cases := []struct {
		data           string
		uri            string
		expectedScheme Scheme
		expectedUri    string
	}{
		{
			data:           `registry=HTTPS://NPM.EXAMPLE.COM`,
			uri:            "HTTPS://NPM.EXAMPLE.COM",
			expectedScheme: HttpsScheme,
			expectedUri:    "NPM.EXAMPLE.COM",
		},
		{
			data:           `registry=http://npm.example.com/`,
			uri:            "http://npm.example.com",
			expectedScheme: HttpScheme,
			expectedUri:    "npm.example.com",
		},
		{
			data:           `//repo.example.com/project/npm/:_authToken=abc123`,
			uri:            "repo.example.com/project/npm",
			expectedScheme: UnknownScheme,
			expectedUri:    "repo.example.com/project/npm",
		},
		{
			data:           `repo.example.com/project/npm`,
			uri:            "repo.example.com/project/npm",
			expectedScheme: UnknownScheme,
			expectedUri:    "repo.example.com/project/npm",
		},
		{
			data:           "registry=httpS://repo.example.com/project/npm\n//repo.example.com/project/npm/:_authToken=abc123",
			uri:            "repo.example.com/project/npm",
			expectedScheme: HttpsScheme,
			expectedUri:    "repo.example.com/project/npm",
		},
		{
			data:           "registry=htTp://repo.example.com/project/npm\n//repo.example.com/project/npm/:_authToken=abc123",
			uri:            "repo.example.com/project/npm",
			expectedScheme: HttpScheme,
			expectedUri:    "repo.example.com/project/npm",
		},
	}

	for _, c := range cases {
		actualScheme, actualUri := parseRegistryURLScheme(c.data, c.uri)
		if actualScheme != c.expectedScheme {
			t.Errorf("Scheme: expected=%s, actual=%s", c.expectedScheme, actualScheme)
		}
		if actualUri != c.expectedUri {
			t.Errorf("uri: expected=%s, actual=%s", c.expectedUri, actualUri)
		}
	}
}
