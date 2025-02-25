package github

import (
	"fmt"

	gogit "github.com/go-git/go-git/v5"
	"github.com/google/go-github/v67/github"
	"github.com/shurcooL/githubv4"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/git"
)

type unauthenticatedConnector struct {
	apiClient     *github.Client
	graphqlClient *githubv4.Client
}

var _ connector = (*unauthenticatedConnector)(nil)

func newUnauthenticatedConnector(ctx context.Context, apiEndpoint string) (*unauthenticatedConnector, error) {
	const httpTimeoutSeconds = 60
	httpClient := common.RetryableHTTPClientTimeout(int64(httpTimeoutSeconds))
	apiClient, err := createAPIClient(ctx, httpClient, apiEndpoint)
	if err != nil {
		return nil, fmt.Errorf("could not create API client: %w", err)
	}

	graphqlClient, err := createGraphqlClient(ctx, httpClient, apiEndpoint)
	if err != nil {
		return nil, err
	}

	return &unauthenticatedConnector{
		apiClient:     apiClient,
		graphqlClient: graphqlClient,
	}, nil
}

func (c *unauthenticatedConnector) APIClient() *github.Client {
	return c.apiClient
}

func (c *unauthenticatedConnector) GraphQLClient() *githubv4.Client {
	return c.graphqlClient
}

func (c *unauthenticatedConnector) Clone(ctx context.Context, repoURL string) (string, *gogit.Repository, error) {
	return git.CloneRepoUsingUnauthenticated(ctx, repoURL)
}
