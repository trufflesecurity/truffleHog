package github

import (
	"fmt"
	"strings"
	"sync"

	gogit "github.com/go-git/go-git/v5"
	"github.com/google/go-github/v67/github"
	"github.com/shurcooL/githubv4"
	"golang.org/x/oauth2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/git"
)

type tokenConnector struct {
	token         string
	apiClient     *github.Client
	graphqlClient *githubv4.Client

	isGitHubEnterprise bool
	handleRateLimit    func(context.Context, error, ...errorReporter) bool
	user               string
	userMu             sync.Mutex
}

var _ connector = (*tokenConnector)(nil)

func newTokenConnector(ctx context.Context, apiEndpoint string, token string, handleRateLimit func(context.Context, error, ...errorReporter) bool) (*tokenConnector, error) {
	const httpTimeoutSeconds = 60
	httpClient := common.RetryableHTTPClientTimeout(int64(httpTimeoutSeconds))
	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	httpClient.Transport = &oauth2.Transport{
		Base:   httpClient.Transport,
		Source: tokenSource,
	}

	apiClient, err := createAPIClient(ctx, httpClient, apiEndpoint)
	if err != nil {
		return nil, fmt.Errorf("could not create API client: %w", err)
	}

	graphqlClient, err := createGraphqlClient(ctx, httpClient, apiEndpoint)
	if err != nil {
		return nil, err
	}

	return &tokenConnector{
		apiClient:          apiClient,
		graphqlClient:      graphqlClient,
		token:              token,
		isGitHubEnterprise: !strings.EqualFold(apiEndpoint, cloudV3Endpoint),
		handleRateLimit:    handleRateLimit,
	}, nil
}

func (c *tokenConnector) APIClient() *github.Client {
	return c.apiClient
}

func (c *tokenConnector) GraphQLClient() *githubv4.Client {
	return c.graphqlClient
}

func (c *tokenConnector) Clone(ctx context.Context, repoURL string) (string, *gogit.Repository, error) {
	if err := c.setUserIfUnset(ctx); err != nil {
		return "", nil, err
	}
	return git.CloneRepoUsingToken(ctx, c.token, repoURL, c.user)
}

func (c *tokenConnector) IsGithubEnterprise() bool {
	return c.isGitHubEnterprise
}

func (c *tokenConnector) getUser(ctx context.Context) (string, error) {
	var (
		user *github.User
		err  error
	)
	for {
		user, _, err = c.apiClient.Users.Get(ctx, "")
		if c.handleRateLimit(ctx, err) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("could not get GitHub user: %w", err)
		}
		break
	}
	return user.GetLogin(), nil
}

func (c *tokenConnector) setUserIfUnset(ctx context.Context) error {
	c.userMu.Lock()
	defer c.userMu.Unlock()

	if c.user != "" {
		return nil
	}

	user, err := c.getUser(ctx)
	if err != nil {
		return err
	}

	c.user = user
	return nil
}
