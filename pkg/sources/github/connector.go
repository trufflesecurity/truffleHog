package github

import (
	"fmt"

	gogit "github.com/go-git/go-git/v5"
	"github.com/google/go-github/v67/github"
	"github.com/trufflesecurity/trufflehog/v3/pkg/log"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
)

const cloudEndpoint = "https://api.github.com"

type Connector interface {
	// APIClient returns a configured GitHub client that can be used for GitHub API operations.
	APIClient() *github.Client
	// Clone clones a repository using the configured authentication information.
	Clone(ctx context.Context, repoURL string) (string, *gogit.Repository, error)
}

func NewConnector(
	cred any,
	apiEndpoint string,
	handleRateLimit func(ctx context.Context, errIn error, reporters ...errorReporter) bool,
) (Connector, error) {

	switch cred := cred.(type) {
	case *sourcespb.GitHub_GithubApp:
		log.RedactGlobally(cred.GithubApp.GetPrivateKey())
		return newAppConnector(apiEndpoint, cred.GithubApp)
	case *sourcespb.GitHub_BasicAuth:
		log.RedactGlobally(cred.BasicAuth.GetPassword())
		return newBasicAuthConnector(apiEndpoint, cred.BasicAuth)
	case *sourcespb.GitHub_Token:
		log.RedactGlobally(cred.Token)
		return newTokenConnector(apiEndpoint, cred.Token, handleRateLimit)
	case *sourcespb.GitHub_Unauthenticated:
		return newUnauthenticatedConnector(apiEndpoint)
	default:
		return nil, fmt.Errorf("unknown GitHub credential type %T", cred)
	}
}
