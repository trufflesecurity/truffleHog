package generic

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

func TestNpmTokenGeneric_Pattern(t *testing.T) {
	cases := map[string]npmPatternTestCase{
		".npmrc/_authToken/top_level": {
			input: `_authToken = dL4dfTOJSL8pijHrBFPKqp2bUwLGkVotezEn8dfTPe-Qa1cP
registry = https://npm.company.com/
always-auth = true`,
			expected: "dL4dfTOJSL8pijHrBFPKqp2bUwLGkVotezEn8dfTPe-Qa1cP",
		},
		".npmrc/_authToken/json": {
			input:    `"_authToken": "VVEvgoi7lSkBaCd4s0Gb0A==",`,
			expected: "VVEvgoi7lSkBaCd4s0Gb0A==",
		},
		".npmrc/_authToken/top_level/quoted": {
			input:    `# _authToken=VVEvgoi7lSkBaCd4s0Gb0A==`,
			expected: "VVEvgoi7lSkBaCd4s0Gb0A==",
		},
		".npmrc/_authToken/top_level/backtick": {
			input:    "`_authToken=VVEvgoi7lSkBaCd4s0Gb0A==`,",
			expected: "VVEvgoi7lSkBaCd4s0Gb0A==",
		},
		".npmrc/_authToken/scoped/artifactory": {
			input: `registry=https://artifactory.example.com/artifactory/api/npm/npm/
//artifactory.example.com/artifactory/api/npm/npm/:_authToken=eyJ2ZXIiOiIyIiwidHlwIjoiSldUIiwiYWxnIjoiUlMyNTYiLCJraWQiOiJSZ25DcnBEVXlKOV9yNElVRnNSU2hqU0E0aGpibEpjZ0M2bnJhN3ZqcTNNIn0.eyJzdWIiOiJqZnJ0QDAxY2pwdDc0N3ZyNHo0MTU4MHNiN3MxYW14XC91c2Vyc1wvYXJ0dXJvLmNhbXBvcyIsInNjcCI6ImFwcGxpZWQtcGVybWlzc2lvbnNcL2dyb3VwczpyZWFkZXJzLGRlcGxveS1kZXYtbnBtLGRlcGxveS1sb2NhbCIsImF1ZCI6ImpmcnRAMDFjanB0NzQ3dnI0ejQxNTgwc2I3czFhbXgiLCJpc3MiOiJqZnJ0QDAxY2pwdDc0N3ZyNHo0MTU4MHNiN3MxYW14XC91c2Vyc1wvYXJ0dXJvLmNhbXBvcyIsImV4cCI6MTY1NjAwNDUxOSwiaWF0IjoxNjU2MDAwOTE5LCJqdGkiOiJjOWZhM2VhNS01MzE0LTQwMzUtYjNiYy03OGNjMDJmYmM1NWMifQ.EIEPLzz9H2oQ3rKLKI_t1qtxi-G9ym6P6J5z7xWLsq79aHK3XV_E8_yuUK8giaOOdl_CaITOjl8Bt2aUVXTZKFKIOiQMLscBM4B6qGj_n4Qq8jiMwcKjnD_iWx8Wo-aNHHxgjvrRdWf-2UPIm6lSc77oZbUNAjhA5Q-W3uQRG7d50FGZpq_EEZsfbOcD7EMU2ZnvfYNTgTtmhZWfLefzB6xUF8WHgiDAVHJKQ2fKLX45Z9trc2SkKQmPBxaS-pBtKBhK15kQZ3x625KtLRr2ZwgOaJKHcg4SwuGOpyTF48nTk53SDorSj6fqlypTavVQRi-5cuSGTPrqLObk6lwpRg`,
			expected: "eyJ2ZXIiOiIyIiwidHlwIjoiSldUIiwiYWxnIjoiUlMyNTYiLCJraWQiOiJSZ25DcnBEVXlKOV9yNElVRnNSU2hqU0E0aGpibEpjZ0M2bnJhN3ZqcTNNIn0.eyJzdWIiOiJqZnJ0QDAxY2pwdDc0N3ZyNHo0MTU4MHNiN3MxYW14XC91c2Vyc1wvYXJ0dXJvLmNhbXBvcyIsInNjcCI6ImFwcGxpZWQtcGVybWlzc2lvbnNcL2dyb3VwczpyZWFkZXJzLGRlcGxveS1kZXYtbnBtLGRlcGxveS1sb2NhbCIsImF1ZCI6ImpmcnRAMDFjanB0NzQ3dnI0ejQxNTgwc2I3czFhbXgiLCJpc3MiOiJqZnJ0QDAxY2pwdDc0N3ZyNHo0MTU4MHNiN3MxYW14XC91c2Vyc1wvYXJ0dXJvLmNhbXBvcyIsImV4cCI6MTY1NjAwNDUxOSwiaWF0IjoxNjU2MDAwOTE5LCJqdGkiOiJjOWZhM2VhNS01MzE0LTQwMzUtYjNiYy03OGNjMDJmYmM1NWMifQ.EIEPLzz9H2oQ3rKLKI_t1qtxi-G9ym6P6J5z7xWLsq79aHK3XV_E8_yuUK8giaOOdl_CaITOjl8Bt2aUVXTZKFKIOiQMLscBM4B6qGj_n4Qq8jiMwcKjnD_iWx8Wo-aNHHxgjvrRdWf-2UPIm6lSc77oZbUNAjhA5Q-W3uQRG7d50FGZpq_EEZsfbOcD7EMU2ZnvfYNTgTtmhZWfLefzB6xUF8WHgiDAVHJKQ2fKLX45Z9trc2SkKQmPBxaS-pBtKBhK15kQZ3x625KtLRr2ZwgOaJKHcg4SwuGOpyTF48nTk53SDorSj6fqlypTavVQRi-5cuSGTPrqLObk6lwpRg",
		},
		".npmrc/_authToken/scoped/gitlab_old": {
			input:    `RUN npm config set "//gitlab.com/api/v4/packages/npm/:_authToken" "aB3_-9R2sPqLxY0ZwCc8D"`,
			expected: "aB3_-9R2sPqLxY0ZwCc8D",
		},
		".npmrc/_authToken/scoped/gitlab_new": {
			input: `@company:registry=https://gitlab.com/api/v4/projects/12356452/packages/npm/
//gitlab.com/api/v4/projects/12356452/packages/npm/:_authToken=glpat-ijTwXA7JxJAEx7uzmVfH`,
			expected: "glpat-ijTwXA7JxJAEx7uzmVfH",
		},
		".npmrc/_authToken/scoped/github": {
			input: `npm config set @company:registry=https://npm.pkg.github.com/
    npm config set //npm.pkg.github.com/:_authToken=ghp_sS4gaQUHsXSdwojekGTlaIAgJ77Wsn4D7gPO
    npm install -g @company/internal-package@1.2.3`,
			expected: "ghp_sS4gaQUHsXSdwojekGTlaIAgJ77Wsn4D7gPO",
		},
		".npmrc/_authToken/scoped/google": {
			input: `//us-east1-npm.pkg.dev/company-dev-167118/project/:_authToken=ya29.c.b0Aaekm1IkdX0VHcPkEnYB8dmgL5IHi3jXTffM9hwjaNInirTSOv3hsCsJuCyswioQpO1UGkvVqReYpSW7V6sxmTv7fSPpZJeKzRQcKb6LLjApF7gFGyZMg9lUf7YBFixyGDZxaq0T-FnksK8O7KC4MSxalTe4dnl_jWXcs7FKi-FQOwsAuR1-zwRS63F1YG9fpCq2WykPhjwcbYPVlb3jpTOmIJhGpaWq7Sd5_uunWTHadgI3sCCazp_rT8xa8MS8YtyTJl716Taix4nmD-2Rertq9uS8P9AkFHMHaRvXl3W2PbNHxQtJ3fI3RRmBaVSe5WQlA1MofCol-lUN344KqfknpMfIjuXhB4h5fRB5zZ0Z2te_f0SVS1ZZ1Ox-sWVbh-2keFJ9Um0OS7O46rIOg_z7X-817qf_rIWmhQZgmk6ubI4hVR-7_lUl8lzi0ypo6Ve2wVZd6n9q8ws_RWt5k1Q_YkI0ukMe-U3a7s8F16w7r0OSFqVmhy0psYQ4-8jp79IhUbdm10l32tQhZ22UcIuBk8S4FX4c7nUIWk1Xd9xeu0JJ8Xrwd6nW24i1j-vbnMZxk0t1_5ZljUXVncxo5xjucr4WyYOmvuaS_iSaz89jUdYfxiOxWieiUVbuzZSXWvZFFZrkQFggeq3Vq2hmj6Zls_W8Bm9o8-8020S6692rB5pf8h6b-RI4zig928xufkWtVfMXU3fth24eVWqYIIy_qQh6UcJ1_VZF8uvMYoowUu3aQShisof8eoi8qQixO4YIJ2VSSctnFvthQUJ_0p5Vt9YQSyx_XqS8_1VeaMpnwWMkXXSVZrflo9Ieb_s-V9RlYB23attr3oR0_5Q95rzgJXivy1-UmhIO3iSn4QWZceeJynjv1MB01tyJd35icywcmc5j5onQl5F3x0_rdZSZyhVduujy6gFk1yBnWidRFg38QU4Y2_ZwS68e66SjYXddORq9-xaw6fjO4qkb1n6i6zb00eX1mY2rq8UpqQ6v4t1n4n4h9M3
@fortawesome:registry=https://npm.fontawesome.com/`,
			expected: "ya29.c.b0Aaekm1IkdX0VHcPkEnYB8dmgL5IHi3jXTffM9hwjaNInirTSOv3hsCsJuCyswioQpO1UGkvVqReYpSW7V6sxmTv7fSPpZJeKzRQcKb6LLjApF7gFGyZMg9lUf7YBFixyGDZxaq0T-FnksK8O7KC4MSxalTe4dnl_jWXcs7FKi-FQOwsAuR1-zwRS63F1YG9fpCq2WykPhjwcbYPVlb3jpTOmIJhGpaWq7Sd5_uunWTHadgI3sCCazp_rT8xa8MS8YtyTJl716Taix4nmD-2Rertq9uS8P9AkFHMHaRvXl3W2PbNHxQtJ3fI3RRmBaVSe5WQlA1MofCol-lUN344KqfknpMfIjuXhB4h5fRB5zZ0Z2te_f0SVS1ZZ1Ox-sWVbh-2keFJ9Um0OS7O46rIOg_z7X-817qf_rIWmhQZgmk6ubI4hVR-7_lUl8lzi0ypo6Ve2wVZd6n9q8ws_RWt5k1Q_YkI0ukMe-U3a7s8F16w7r0OSFqVmhy0psYQ4-8jp79IhUbdm10l32tQhZ22UcIuBk8S4FX4c7nUIWk1Xd9xeu0JJ8Xrwd6nW24i1j-vbnMZxk0t1_5ZljUXVncxo5xjucr4WyYOmvuaS_iSaz89jUdYfxiOxWieiUVbuzZSXWvZFFZrkQFggeq3Vq2hmj6Zls_W8Bm9o8-8020S6692rB5pf8h6b-RI4zig928xufkWtVfMXU3fth24eVWqYIIy_qQh6UcJ1_VZF8uvMYoowUu3aQShisof8eoi8qQixO4YIJ2VSSctnFvthQUJ_0p5Vt9YQSyx_XqS8_1VeaMpnwWMkXXSVZrflo9Ieb_s-V9RlYB23attr3oR0_5Q95rzgJXivy1-UmhIO3iSn4QWZceeJynjv1MB01tyJd35icywcmc5j5onQl5F3x0_rdZSZyhVduujy6gFk1yBnWidRFg38QU4Y2_ZwS68e66SjYXddORq9-xaw6fjO4qkb1n6i6zb00eX1mY2rq8UpqQ6v4t1n4n4h9M3",
		},
		".npmrc/_authToken/scoped/gemfury": {
			input: `# always-auth=true
# registry=https://npm.fury.io/company/
# //npm.fury.io/company/:_authToken=Du4CPz7SsRom1Mz8hbSR`,
			expected: "Du4CPz7SsRom1Mz8hbSR",
		},
		".npmrc/_authToken/scoped/ip": {
			input:    `//104.16.27.34:8080/:_authToken="VVEvgoi7lSkBaCd4s0Gb0A=="`,
			expected: "VVEvgoi7lSkBaCd4s0Gb0A==",
		},
		".npmrc/_authToken/scoped/ip(2)": {
			input: `@eventdex:registry=http://4.89.41.88:4873/
//4.89.41.88:4873/:_authToken="DgcjMOa2QyMunSLr9YDzUA=="`,
			expected: "DgcjMOa2QyMunSLr9YDzUA==",
		},
		".npmrc/_authToken/scoped/other(1)": {
			input: `//npm.company.com/:_authToken="VVEvgoi7lSkBaCd4s0Gb0A=="
always_auth=true
registry=https://npm.company.com/
user=jdoe`,
			expected: "VVEvgoi7lSkBaCd4s0Gb0A==",
		},
		".npmrc/_authToken/scoped/other(2)": {
			input: `loglevel=silent
registry=https://npm.company.de:4873/
@babel:registry=https://registry.npmjs.org
//npm.company.de:4873/:_authToken="zZcZwiAWuyyspOAGrzAlE/LBH55oyfzsIOQvPsQ/5n0="`,
			expected: "zZcZwiAWuyyspOAGrzAlE/LBH55oyfzsIOQvPsQ/5n0=",
		},
		".npmrc/_authToken/scoped/other(3)": {
			input: `strict-ssl=true
//r.privjs.com/:_authToken=JWT_eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyVVVJRCI6ImI1NjM1NDdmLTQ5NTQtNGVkOS04ZDI4LTkzZjFlYjE2YjgwYyIsInVzZXJuYW1lIjoiZGFya28iLCJpYXQiOjE2NzAzMzQwMTV9.itmCA6WviKLcGwahuV-K2cvDtDkM_j7o_NjZrdzWu0M
@module-federation:registry=https://r.privjs.com`,
			expected: "JWT_eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyVVVJRCI6ImI1NjM1NDdmLTQ5NTQtNGVkOS04ZDI4LTkzZjFlYjE2YjgwYyIsInVzZXJuYW1lIjoiZGFya28iLCJpYXQiOjE2NzAzMzQwMTV9.itmCA6WviKLcGwahuV-K2cvDtDkM_j7o_NjZrdzWu0M",
		},
		".npmrc/_authToken/scoped/other(4)": {
			input: `registry=http://registry-tls01.company-group.fr:4873/
strict-ssl=false
always-auth=true
email=mimi@mail.fr
//registry-tls01.company-group.fr:4873/:_authToken="re/bd4eJ9u2x4bL3Nboteg=="`,
			expected: "re/bd4eJ9u2x4bL3Nboteg==",
		},
		".npmrc/_authToken/scoped/other(5)": {
			input: `registry = "http://cpny-npm:4873/"
//cpny-npm:4873/:_authToken="csNoanwPNA0SGF/V/Q+CRJWzHc/lRymCeBWSRGDZ+kY="`,
			expected: "csNoanwPNA0SGF/V/Q+CRJWzHc/lRymCeBWSRGDZ+kY=",
		},
		".npmrc/_authToken/scoped/other(6)": {
			input:    `//registry.npmjs.org/:_authToken=k959+pC+k3Mzfx+skChHuseaS8Z4McpY5iJ6n9SywyuQL4/Gr9IQPqDtl3MhQuNX`,
			expected: "k959+pC+k3Mzfx+skChHuseaS8Z4McpY5iJ6n9SywyuQL4/Gr9IQPqDtl3MhQuNX",
		},
		// Generic variable
		"NPM_TOKEN/buildkite": {
			input: `steps:
  - label: 'Install'
    command: NODE_ENV=development yarn install --frozen-lockfile
    plugins:
      - ssh://git@github.com/foo/bar-plugin#v0.0.18:
        secrets:
          NPM_TOKEN: "x3jAqghGq90/oN3mM3rWxQ8KaD4nw9g6bw/dL4dfTOJSL8pijHrBFPK6p7bUwLGkVotezEn8dfTPe-Qa1cP"`,
			expected: "x3jAqghGq90/oN3mM3rWxQ8KaD4nw9g6bw/dL4dfTOJSL8pijHrBFPK6p7bUwLGkVotezEn8dfTPe-Qa1cP",
		},
		"NPM_TOKEN/cloudbuild": {
			input: `secrets:
- kmsKeyName: projects/myproject/locations/global/keyRings/cloud-build/cryptoKeys/cloud-build
  secretEnv:
    NPM_TOKEN: CiQAwtE8WoPa1sNqAQJZ1WMODuJooVmO6zihz2hAZOfUmDsgogUSTQCq8yp8qgltY+8jWpAR9GuS1JaVhd+fTVRilqLtdi2yXSdiDPTzLhZ+30bMlAOcoc0PxhCBn3JOpn8H1xshX+mG8yK7xog2Uq+CLVx/

timeout: 60s`,
			expected: "CiQAwtE8WoPa1sNqAQJZ1WMODuJooVmO6zihz2hAZOfUmDsgogUSTQCq8yp8qgltY+8jWpAR9GuS1JaVhd+fTVRilqLtdi2yXSdiDPTzLhZ+30bMlAOcoc0PxhCBn3JOpn8H1xshX+mG8yK7xog2Uq+CLVx/",
		},
		"NPM_TOKEN/github_actions": {
			input: `        run: |
          utils/prepare_puppeteer_core.js
          npm config set '//wombat-dressing-room.appspot.com/:_authToken' 'abc123tokentest'
          npm publish`,
			expected: "abc123tokentest",
		},

		// Invalid
		// TODO: re-enable this.
		// "invalid/_authToken/top_level": {
		//	input: `_authToken = ${NPM_TOKEN}
		// registry = https://npm.company.com/`,
		//		},
		"invalid/_authToken/v1_pattern": {
			input: `echo //nexus.company.com/repository/npm-registry/:_authToken=NpmToken.fe093789-9551-3238-a766-9d2b694f2600 >> .npmrc`,
		},
		"invalid/_authToken/v2_pattern": {
			input: `  //registry.npmjs.org/:_authToken=npm_ArCHsOJAC3gMXmzaVwUts00QfWWUrW4UuewA`,
		},
		"invalid/npm": {
			input: `"name": "npm-token-substitute",`,
		},
		"invalid/yarn_lock": {
			input: `convert-source-map@~1.1.0:
  version "1.1.3"
  resolved "http://registry.npmjs.org/convert-source-map/-/convert-source-map-1.1.3.tgz#4829c877e9fe49b3161f3bf3673888e204699860"

css-selector-tokenizer@^0.7.0:
  version "0.7.1"
  resolved "https://registry.yarnpkg.com/css-selector-tokenizer/-/css-selector-tokenizer-0.7.1.tgz#a177271a8bca5019172f4f891fc6eed9cbf68d5d"`,
		},
		"invalid/npm/registry-auth-token": {
			input: `"registry-auth-token": {
      "version": "3.4.0",
      "resolved": "https://registry.npmjs.org/registry-auth-token/-/registry-auth-token-3.4.0.tgz",
      "integrity": "sha512-4LM6Fw8eBQdwMYcES4yTnn2TqIasbXuwDx3um+QRs7S55aMKCBKBxvPXl2RiUjHwuJLTyYfxSpmfSAjQpcuP+A==",
      "requires": {
        "rc": "^1.1.6",
        "safe-buffer": "^5.0.1"
      }
    },`,
		},
		"invalid/npm-shrinkwrap.json": {
			input: `"esprima-harmony-jscs": {
              "version": "1.1.0-regex-token-fix",
              "from": "https://registry.npmjs.org/esprima-harmony-jscs/-/esprima-harmony-jscs-1.1.0-regex-token-fix.tgz",
              "resolved": "https://registry.npmjs.org/esprima-harmony-jscs/-/esprima-harmony-jscs-1.1.0-regex-token-fix.tgz"`,
		},
		// https://github.com/pnpm/pnpm/commit/5ab3a9e#diff-b02f9e32edb01aed8f7e33f169666aba1c8c06d16acb9cf1cf24176855df7d5bR1086
		"invalid/npm-shrinkwrap.yml": {
			input: `registry.npmjs.org/package-json/2.4.0:
    dependencies:
      got: registry.npmjs.org/got/5.7.1
      registry-auth-token: registry.npmjs.org/registry-auth-token/3.1.0
      registry-url: registry.npmjs.org/registry-url/3.1.0`,
		},
		// https://github.com/UrbanCompass/pnpm/commit/bc34aba#diff-8668a637b544f80ebbb2ca3331adc637eef630ec5d2ed31f2f3db86136171128R31
		"invalid/_authToken/pnpm_placeholder": {
			input: `  'let rawNpmConfig = {
//localhost:4873/:_authToken': data.token,
    'registry': 'http://localhost:4873/',`,
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
