package github

import (
	"fmt"

	gogit "github.com/go-git/go-git/v5"
	"github.com/google/go-github/v67/github"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/git"
)

type unauthenticatedConnector struct {
	apiClient *github.Client
}

var _ Connector = (*unauthenticatedConnector)(nil)

func NewUnauthenticatedConnector(apiEndpoint string) (Connector, error) {
	const httpTimeoutSeconds = 60
	httpClient := common.RetryableHTTPClientTimeout(int64(httpTimeoutSeconds))
	apiClient, err := createGitHubClient(httpClient, apiEndpoint)
	if err != nil {
		return nil, fmt.Errorf("could not create API client: %w", err)
	}
	return &unauthenticatedConnector{
		apiClient: apiClient,
	}, nil
}

func (c *unauthenticatedConnector) APIClient() *github.Client {
	return c.apiClient
}

func (c *unauthenticatedConnector) Clone(ctx context.Context, repoURL string, args ...string) (string, *gogit.Repository, error) {
	return git.CloneRepoUsingUnauthenticated(ctx, repoURL, args...)
}
