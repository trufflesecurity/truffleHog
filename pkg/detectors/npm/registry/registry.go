package registry

import (
	"fmt"
	"regexp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

type Info struct {
	Type   Type
	Scheme Scheme
	Uri    string
}

// The Scheme of the registry URL.
type Scheme int

const (
	UnknownScheme Scheme = iota
	HttpScheme
	HttpsScheme
)

// String returns the HTTP prefix that corresponds to the enum: "", "http://", and "https://" respectively.
func (scheme Scheme) String() string {
	return [...]string{
		"",
		"http://",
		"https://",
	}[scheme]
}

var defaultInfo = &Info{
	Type:   npm,
	Scheme: HttpsScheme,
	Uri:    "registry.npmjs.org",
}

// FindTokenURL returns the specific registry associated with the |token| if a high confidence match is found in |data|.
//
// Common configurations:
// - npm: https://docs.npmjs.com/using-private-packages-in-a-ci-cd-workflow#create-and-check-in-a-project-specific-npmrc-file
// - Yarn (TODO)
// - Unity Package Manager (TODO)
func FindTokenURL(data string, token string) *Info {
	// .npmrc stores auth as `//registry.com/path/:authToken=$TOKEN
	// Therefore, we should be able to correlate a token to a registry with a high degree of confidence.
	// TODO: handle other formats, such as Yarn.
	registryAuthPat := regexp.MustCompile(fmt.Sprintf(
		// language=regexp
		`(?i)(//%s(?:/[a-z0-9._-]+)*)/?:(?:_auth(?:Token)?|_password).{1,20}%s`, hostPat, regexp.QuoteMeta(token)))
	matches := registryAuthPat.FindStringSubmatch(data)
	if len(matches) == 0 {
		return nil
	}

	// A match was found, attempt to parse it into `Info`.
	uri := matches[1]
	info := parseKnownRegistryURI(data, uri)
	if info == nil {
		info = parseUnknownRegistryURI(data, uri)
	}
	return info
}

// FindAllURLs returns all instances of URLs that *look like* placeholderList.
// These are not associated with a specific token.
func FindAllURLs(ctx context.Context, data string, includeDefault bool) map[string]*Info {
	registries := make(map[string]*Info)

	// Look for known high-confidence matches.
	for _, matches := range knownRegistryPat.FindAllStringSubmatch(data, -1) {
		var (
			scheme = matches[1]
			_, uri = firstNonEmptyMatch(matches, 2) // first two matches are the entire string and protocol/prefix
			info   = parseKnownRegistryURI(data, scheme+uri)
		)
		if info == nil || info.Uri == "" {
			continue
		} else if _, ok := registries[info.Uri]; ok {
			continue
		}

		logger(ctx).V(3).Info("Found KNOWN registry URL", "registry", info.Scheme.String()+info.Uri)
		registries[info.Uri] = info
	}

	// Attempt to parse any other low confidence matches.
	for _, matches := range genericRegistryPat.FindAllStringSubmatch(data, -1) {
		// Skip known registry patterns, those should have already been handled above.
		if knownRegistryPat.MatchString(matches[0]) {
			continue
		}

		var (
			_, uri = firstNonEmptyMatch(matches, 1) // first match is the entire string
			info   = parseUnknownRegistryURI(data, uri)
		)
		if info == nil || info.Uri == "" {
			continue
		} else if _, ok := registries[info.Uri]; ok {
			continue
		}

		logger(ctx).V(3).Info("Found UNKNOWN registry URL", "registry", info.Scheme.String()+info.Uri)
		registries[info.Uri] = info
	}

	if len(registries) == 0 && includeDefault {
		registries[defaultInfo.Uri] = defaultInfo
	}
	return registries
}
