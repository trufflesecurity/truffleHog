package github

import (
	gogit "github.com/go-git/go-git/v5"
	"github.com/google/go-github/v67/github"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

const cloudEndpoint = "https://api.github.com"

// Connector abstracts over the authenticated ways to interact with GitHub: cloning and API operations.
type Connector interface {
	// APIClient returns a configured GitHub client that can be used for GitHub API operations.
	APIClient() *github.Client
	// Clone clones a repository using the configured authentication information.
	Clone(ctx context.Context, repoURL string, args ...string) (string, *gogit.Repository, error)
}
