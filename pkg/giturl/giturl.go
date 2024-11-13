package giturl

import (
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/pkg/errors"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

type provider string

const (
	providerGithub    provider = "Github"
	providerGitlab    provider = "Gitlab"
	providerBitbucket provider = "Bitbucket"
	providerAzure     provider = "Azure"

	urlGithub    = "github.com/"
	urlGitlab    = "gitlab.com/"
	urlBitbucket = "bitbucket.org/"
	urlAzure     = "dev.azure.com/"
)

func determineProvider(repo string) provider {
	switch {
	case strings.Contains(repo, urlGithub):
		return providerGithub
	case strings.Contains(repo, urlGitlab):
		return providerGitlab
	case strings.Contains(repo, urlBitbucket):
		return providerBitbucket
	case strings.Contains(repo, urlAzure):
		return providerAzure
	default:
		return ""
	}
}

func NormalizeBitbucketRepo(repoURL string) (string, error) {
	if !strings.HasPrefix(repoURL, "https") {
		return "", errors.New("Bitbucket requires https repo urls: e.g. https://bitbucket.org/org/repo.git")
	}

	return NormalizeOrgRepoURL(providerBitbucket, repoURL)
}

func NormalizeGerritProject(project string) (string, error) {
	return "", errors.Errorf("Not yet implemented")
}

func NormalizeGithubRepo(repoURL string) (string, error) {
	return NormalizeOrgRepoURL(providerGithub, repoURL)
}

func NormalizeGitlabRepo(repoURL string) (string, error) {
	if !strings.HasPrefix(repoURL, "http:") && !strings.HasPrefix(repoURL, "https:") {
		return "", errors.New("Gitlab requires http/https repo urls: e.g. https://gitlab.com/org/repo.git")
	}

	return NormalizeOrgRepoURL(providerGitlab, repoURL)
}

// NormalizeOrgRepoURL attempts to normalize repos for any provider using the example.com/org/repo style.
// e.g. %s, Gitlab and Bitbucket
func NormalizeOrgRepoURL(provider provider, repoURL string) (string, error) {
	if strings.HasSuffix(repoURL, ".git") {
		return repoURL, nil
	}

	parsed, err := url.Parse(repoURL)
	if err != nil {
		return "", errors.Wrapf(err, "Unable to parse %s Repo URL", provider)
	}

	// The provider repo url should have a path length of 3
	//               0 / 1 / 2     (3 total)
	// e.g. example.com/org/repo
	// If it is 1, or the 2nd section is empty, it's likely just the org.
	// If it is 3, there's something at the end that shouldn't be there.
	// Let the user know in any case.
	switch parts := strings.Split(parsed.Path, "/"); {
	case len(parts) <= 1:
		return "", errors.Errorf("%s repo appears to be missing the path. Repo url: %q", provider, repoURL)

	case len(parts) == 2:
		org := parts[1]

		if len(org) == 0 {
			return "", errors.Errorf("%s repo appears to be missing the org name. Repo url: %q", provider, repoURL)
		} else {
			return "", errors.Errorf("%s repo appears to be missing the repo name. Org: %q Repo url: %q", provider, org, repoURL)
		}

	case len(parts) == 3:
		org, repo := parts[1], parts[2]

		if len(org) == 0 {
			return "", errors.Errorf("%s repo appears to be missing the org name. Repo url: %q", provider, repoURL)
		}
		if len(repo) == 0 {
			return "", errors.Errorf("%s repo appears to be missing the repo name. Org: %q Repo url: %q", provider, org, repoURL)
		}

	case len(parts) > 3 && strings.HasSuffix(parsed.Path, "/"):
		return "", errors.Errorf("%s repo contains a trailing slash. Repo url: %q", provider, repoURL)
	}

	// If we're here it's probably a provider repo without ".git" at the end, so add it and return
	parsed.Path += ".git"
	return parsed.String(), nil
}

// GenerateLink crafts a link to the specific file from a commit.
// Supports GitHub, GitLab, Bitbucket, and Azure Repos.
// If the provider supports hyperlinks to specific lines, the line number will be included.
func GenerateLink(repo, commit, file string, line int64) string {
	// Some paths contain '%' which breaks |url.Parse| if not encoded.
	// https://developer.mozilla.org/en-US/docs/Glossary/Percent-encoding
	file = strings.ReplaceAll(file, "%", "%25")

	switch determineProvider(repo) {
	case providerBitbucket:
		return repo[:len(repo)-4] + "/commits/" + commit

	case providerAzure:
		baseLink := repo + "/commit/" + commit + "/" + file
		if line > 0 {
			baseLink += "?line=" + strconv.FormatInt(line, 10)
		}
		return baseLink

	case providerGithub, providerGitlab:
		// If the provider name isn't one of the cloud defaults, it is probably an on-prem github or gitlab.
		// So do the same thing.
		fallthrough
	default:
		var baseLink string

		// Gist links are formatted differently
		if strings.HasPrefix(repo, "https://gist.github.com") {
			baseLink = repo[:len(repo)-4] + "/"
			if commit != "" {
				baseLink += commit + "/"
			}
			if file != "" {
				cleanedFileName := strings.ReplaceAll(file, ".", "-")
				baseLink += "#file-" + cleanedFileName
			}
			if line > 0 {
				if strings.Contains(baseLink, "#") {
					baseLink += "-L" + strconv.FormatInt(line, 10)
				} else {
					baseLink += "#L" + strconv.FormatInt(line, 10)
				}
			}
		} else if file == "" {
			baseLink = repo[:len(repo)-4] + "/commit/" + commit
		} else {
			baseLink = repo[:len(repo)-4] + "/blob/" + commit + "/" + file
			if line > 0 {
				baseLink += "#L" + strconv.FormatInt(line, 10)
			}
		}
		return baseLink
	}
}

var linePattern = regexp.MustCompile(`L\d+`)

// UpdateLinkLineNumber updates the line number in a repository link.
// Used post-link generation to refine reported issue locations within large scanned blocks.
func UpdateLinkLineNumber(ctx context.Context, link string, newLine int64) string {
	link = strings.Replace(link, "%", "%25", -1)
	parsedURL, err := url.Parse(link)
	if err != nil {
		ctx.Logger().Error(err, "unable to parse link to update line number", "link", link)
		return link
	}

	if newLine <= 0 {
		// Don't change the link if the line number is 0.
		return link
	}

	switch determineProvider(link) {
	case providerBitbucket:
		// For Bitbucket, it doesn't support line links (based on the GenerateLink function).
		// So we don't need to change anything.
		return link

	case providerAzure:
		// For Azure, line numbers are appended as ?line=<number>.
		query := parsedURL.Query()
		query.Set("line", strconv.FormatInt(newLine, 10))
		parsedURL.RawQuery = query.Encode()

	case providerGithub, providerGitlab:
		// If the provider name isn't one of the cloud defaults, it is probably an on-prem github or gitlab.
		// So do the same thing.
		fallthrough
	default:
		// Assumed format: .../blob/<commit>/file.go#L<number>
		fragment := "L" + strconv.FormatInt(newLine, 10)
		if linePattern.MatchString(parsedURL.Fragment) {
			parsedURL.Fragment = linePattern.ReplaceAllString(parsedURL.Fragment, fragment)
		} else {
			parsedURL.Fragment += fragment
		}
	}

	return parsedURL.String()
}
