package registry

import (
	"fmt"
	"strings"

	regexp "github.com/wasilibs/go-re2"
)

var (
	domainPat = `(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}` // this doesn't match single segment hosts (e.g., localhost)
	ipV4Pat   = `(?:[0-9]{1,3}\.){3}[0-9]{1,3}`                        // overly permissive but should be fine in context
	hostPat   = fmt.Sprintf(`(?:%s|%s)(?::\d{1,5})?`, domainPat, ipV4Pat)

	knownRegistryPat = func() *regexp.Regexp {
		var sb strings.Builder
		sb.WriteString(`(?i)((?:https?:)?//)(?:`)
		// `registry.yarnpkg.com` is a reverse-proxy (https://github.com/yarnpkg/yarn/issues/889)
		// `registry.npmmirror.com` and `registry.npm.taobao.org` are mirrors (https://stackoverflow.com/a/73147820)
		sb.WriteString(`(registry\.(?:npmjs\.(?:com|eu|org(?:\.au)?)|npmmirror\.com|npm\.taobao\.org|yarnpkg\.com))`)
		artifactoryPath := `/(?:artifactory|[a-z0-9._-]+)/api/npm/[a-z][a-z0-9._-]+`
		artifactoryOldPath := `/(?:artifactory|[a-z0-9._-]+)/v\d\.\d/artifacts/[a-z][a-z0-9._-]+`   // appears to be a path from older versions.
		sb.WriteString(`|([a-z0-9]+(?:[a-z0-9-]+[a-z0-9])?\.jfrog\.io` + artifactoryPath + `)`)     // cloud
		sb.WriteString(fmt.Sprintf(`|(%s(?:%s|%s))`, hostPat, artifactoryPath, artifactoryOldPath)) // hosted
		// https://help.sonatype.com/repomanager2/node-packaged-modules-and-npm-registries
		sb.WriteString(`|(` + hostPat + `/nexus/content/(?:groups|repositories)/[a-z0-9-][a-z0-9._-]+)`)
		// https://help.sonatype.com/repomanager3/nexus-repository-administration/formats/npm-registry/configuring-npm
		// TODO: Handle non-standard subdirectories like `example.com/artifacts/repository/npm-public`
		sb.WriteString(`|(` + hostPat + `/(?:nexus/)?repository/[a-z0-9-][a-z0-9._-]+)`)
		// https://docs.gitlab.com/ee/user/packages/npm_registry/
		sb.WriteString(`|(` + hostPat + `/api/v4/(?:groups/\d+/-/|projects/\d+/)?packages/npm)`)
		// https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-npm-registry
		sb.WriteString(`|(npm\.pkg\.github\.com)`)
		// https://learn.microsoft.com/en-us/azure/devops/artifacts/get-started-npm?view=azure-devops&tabs=Windows
		// https://stackoverflow.com/a/73495381
		azurePat := `pkgs\.dev\.azure\.com/[a-z0-9._-]+(?:/[a-z0-9._-]+)?`
		vsPat := `[a-z0-9-]+\.pkgs\.visualstudio\.com(?:/[a-z0-9._-]+)?`
		sb.WriteString(fmt.Sprintf(`|((?:%s|%s)/_packaging/[a-z0-9._-]+/npm(?:/registry)?)`, azurePat, vsPat))
		// https://www.jetbrains.com/help/space/using-an-npm-registry-with-npmjs-com.html
		sb.WriteString(`|(npm\.pkg\.jetbrains\.space/[a-z0-9][a-z0-9-]{0,61}[a-z0-9]/p/[a-z0-9][a-z0-9-]*[a-z0-9]/[a-z0-9][a-z0-9-]+[a-z0-9])`)
		// Only contain letters, numbers, and hypthens.
		// Must begin and end with letter or number
		sb.WriteString(`|((?:[a-z0-9][a-z0-9-]*[a-z0-9]-)?npm\.pkg\.dev/[a-z0-9-]+/[a-z0-9._-]+)`)
		sb.WriteString(`|(npm(?:-proxy)?\.fury\.io/[a-z0-9._-]+)`)
		sb.WriteString(`|([a-z0-9-]+\.d\.codeartifact\.[a-z-]+[^-]-\d\.amazonaws\.com/npm/[a-z0-9_-]+)`)
		sb.WriteString(`)`)

		return regexp.MustCompile(sb.String())
	}()

	genericRegistryPat = func() *regexp.Regexp {
		urlPat := fmt.Sprintf(`%s(?:/[a-z0-9._-]+)*`, hostPat)

		var sb strings.Builder
		sb.WriteString(`(?i)`)
		// .npmrc
		// //(npm.example.com)/:_authToken=...
		// TODO: match based on prefix or suffix?
		// sb.WriteString(fmt.Sprintf(`(?:^|['"\x60 \t;#-])(//%s)(?:/?:_auth|_password|user)?`, urlPat))
		sb.WriteString(fmt.Sprintf(`(?:^|['"\x60 \t;#-])(//%s)(?:/?:_auth|_password|user)?`, urlPat))
		// registry=https://npm.example.com/ or @scope:registry=https://npm.example.com/
		sb.WriteString(fmt.Sprintf(`|registry.{1,50}?['"]?(https?://%s)/?['"]?`, urlPat))
		// @scope=https://npm.example.com/ (rare)
		sb.WriteString(fmt.Sprintf(`|@[a-z0-9\-_]{1,50}['"]?[ \t]*(?:=[ \t]*)?['"]?(https?://%s)/?['"]?`, urlPat))
		// .yarnrc.toml
		sb.WriteString(fmt.Sprintf(`|npmRegistryServer['"]?[ \t]*:[ \t]*['"]?(https?://%s)/?(?:['"]|\s)`, urlPat))
		sb.WriteString(fmt.Sprintf(`|npmRegistries['"]?[ \t]*:(?:.|\s){0,50}((?:https?:)?//%s)/?['"]?:`, urlPat))
		// .upmconfig.toml
		sb.WriteString(fmt.Sprintf(`|\[npmAuth\.['"](https?://%s)/?['"]\]`, urlPat))

		pat := regexp.MustCompile(sb.String())
		// fmt.Println(pat.String())
		// Sanity check to make sure the pattern doesn't contain a mistake.
		if pat.NumSubexp() != 6 {
			panic(fmt.Sprintf("Pattern |genericRegistryPat| should have 6 capture groups but has %d", pat.NumSubexp()))
		}
		return pat
	}()

	// Common false-positives that can be safely ignored.
	invalidRegistryPat = func() *regexp.Regexp {
		var sb strings.Builder
		sb.WriteString("(?i)(")
		sb.WriteString(`contoso\.pkgs\.visualstudio\.com/?`)
		sb.WriteString(`|registry\.(blah\.(com|edu|eu|foo|org)|foo(bar)?\.(bar|cc|com|eu)|last\.thing|myorg\.com)/?`)
		// sb.WriteString(`|r(egistry\.(npmmirror\.com|npm\.taobao\.org)|\.cnpmjs\.org)/?`)
		sb.WriteString(`|\.terraform\.io/?`)
		sb.WriteString(`|\.?lvh.me/?`)
		sb.WriteString(`|\.?example\.(com|org)/?`)
		sb.WriteString(`|my[.-]registry\.com/?`)
		sb.WriteString(`|some\.(host|(other\.)?registry)/?`)
		sb.WriteString(`|npm\.im/?`)
		sb.WriteString(`|npm\.mycustomregistry\.com/?`)
		sb.WriteString(`|(www\.npmjs\.com|browsenpm\.org)/?`)
		sb.WriteString(`|travis-ci\.org/`)
		sb.WriteString(`|(api|developer|help|www)\.github\.com/`)
		sb.WriteString(")")
		return regexp.MustCompile(sb.String())
	}()
)

// parseKnownRegistryURI
func parseKnownRegistryURI(data string, registryUri string) *Info {
	matches := knownRegistryPat.FindStringSubmatch(registryUri)
	if len(matches) == 0 {
		return nil
	}

	// Skip the first two indices: 1 is the entire string, 2 is the protocol.
	index, uri := firstNonEmptyMatch(matches, 2)
	info := &Info{
		Type: Type(index - 1),
	}
	info.Scheme, info.Uri = parseRegistryURLScheme(data, uri)

	// Ensure that things like "registry.yarnpkg.org" get substituted with the proper npm URL.
	if info.Type == npm && info.Uri != defaultInfo.Uri {
		info.Uri = defaultInfo.Uri
	}

	if info.Uri == "" {
		fmt.Printf("[k] input: '%s', parsed='%s', info='%s'\n", registryUri, uri, info.Uri)
	}

	// Normalize the URI.
	if info.Type == npm && info.Scheme != HttpsScheme {
		info.Scheme = HttpsScheme
	} else if info.Type == artifactoryCloud && info.Scheme != HttpsScheme {
		info.Scheme = HttpsScheme
	} else if info.Type == githubCloud && info.Scheme != HttpsScheme {
		info.Scheme = HttpsScheme
	} else if info.Type == azure {
		if info.Scheme != HttpsScheme {
			info.Scheme = HttpsScheme
		}
		if !strings.HasSuffix(strings.ToLower(info.Uri), "/registry") {
			info.Uri = info.Uri + "/registry"
		}
	} else if info.Type == jetbrains && info.Scheme != HttpsScheme {
		info.Scheme = HttpsScheme
	} else if info.Type == googleArtifactRegistry && info.Scheme != HttpsScheme {
		info.Scheme = HttpsScheme
	} else if info.Type == gemfury && info.Scheme != HttpsScheme {
		info.Scheme = HttpsScheme
	} else if info.Type == awsCodeArtifact && info.Scheme != HttpsScheme {
		info.Scheme = HttpsScheme
	}

	// Ignore known false-positives.
	if invalidRegistryPat.MatchString(uri) {
		return nil
	}

	return info
}

// parseUnknownRegistryURI
func parseUnknownRegistryURI(data string, registryUri string) *Info {
	scheme, uri := parseRegistryURLScheme(data, registryUri)
	info := &Info{
		Type:   other,
		Scheme: scheme,
		Uri:    uri,
	}

	if info.Uri == "" {
		fmt.Printf("[uk] input: '%s', parsed='%s'\n", registryUri, uri)
	}
	// Ignore known false-positives.
	if invalidRegistryPat.MatchString(uri) {
		return nil
	}

	return info
}

// parseRegistryURLScheme attempts to find the Scheme of the provided |uri|.
// If |uri| does not have a scheme, it looks for context in the |data| chunk.
func parseRegistryURLScheme(data string, uri string) (Scheme, string) {
	var (
		scheme           = UnknownScheme
		uriWithoutScheme string
	)
	// If the match starts with "http" or "https", we can be confident about the scheme.
	// Otherwise, it is UnknownScheme.
	u := strings.ToLower(uri) // for case-insensitive comparison. Might not be the best way.
	if strings.HasPrefix(u, "https://") {
		scheme = HttpsScheme
		uriWithoutScheme = uri[8:]
	} else if strings.HasPrefix(u, "http://") {
		scheme = HttpScheme
		uriWithoutScheme = uri[7:]
	} else if strings.HasPrefix(u, "//") {
		uriWithoutScheme = uri[2:]
	} else {
		uriWithoutScheme = uri
	}

	// If the Scheme is UnknownScheme, look for other instances of the Uri that might have the scheme.
	//
	// scheme    -> registry=https://example.com/repository/npm-proxy/
	// no scheme -> //example.com/repository/npm-proxy/:_authToken=123456
	if scheme == UnknownScheme {
		var (
			uriPat  = regexp.MustCompile(`(?i)(https?)://` + uriWithoutScheme)
			schemes = make(map[string]struct{})
		)
		for _, m := range uriPat.FindAllStringSubmatch(data, -1) {
			schemes[strings.ToLower(m[1])] = struct{}{}
		}
		// Decisively HTTP or HTTPS; nothing or both is equally useless.
		if len(schemes) == 1 {
			if _, ok := schemes["https"]; ok {
				scheme = HttpsScheme
			} else {
				scheme = HttpScheme
			}
		}
	}
	return scheme, uriWithoutScheme
}

// firstNonEmptyMatch returns the index and value of the first non-empty match.
// If no non-empty match is found, it will return: 0, "".
func firstNonEmptyMatch(matches []string, skip int) (int, string) {
	if len(matches) < skip {
		return 0, ""
	}
	// The first index is the entire matched string.
	for i, val := range matches[skip:] {
		if val != "" {
			return i + skip, val
		}
	}
	return 0, ""
}
