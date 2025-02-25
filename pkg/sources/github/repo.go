package github

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	gogit "github.com/go-git/go-git/v5"
	"github.com/google/go-github/v67/github"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/giturl"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

type repoInfoCache struct {
	mu    sync.RWMutex
	cache map[string]repoInfo
}

func newRepoInfoCache() repoInfoCache {
	return repoInfoCache{
		cache: make(map[string]repoInfo),
	}
}

func (r *repoInfoCache) put(repoURL string, info repoInfo) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache[repoURL] = info
}

func (r *repoInfoCache) get(repoURL string) (repoInfo, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	info, ok := r.cache[repoURL]
	return info, ok
}

type repoInfo struct {
	owner      string
	name       string
	fullName   string
	hasWiki    bool // the repo is _likely_ to have a wiki (see the comment on wikiIsReachable func).
	size       int
	visibility source_metadatapb.Visibility
}

func (s *Source) cloneRepo(ctx context.Context, repoURL string) (string, *gogit.Repository, error) {
	return s.connector.Clone(ctx, repoURL)
}

type repoListOptions interface {
	getListOptions() *github.ListOptions
}

type repoLister func(ctx context.Context, target string, opts repoListOptions) ([]*github.Repository, *github.Response, error)

type appListOptions struct {
	github.ListOptions
}

func (a *appListOptions) getListOptions() *github.ListOptions {
	return &a.ListOptions
}

func (s *Source) appListReposWrapper(ctx context.Context, _ string, opts repoListOptions) ([]*github.Repository, *github.Response, error) {
	someRepos, res, err := s.connector.APIClient().Apps.ListRepos(ctx, opts.getListOptions())
	if someRepos != nil {
		return someRepos.Repositories, res, err
	}
	return nil, res, err
}

func (s *Source) getReposByApp(ctx context.Context, reporter sources.UnitReporter) error {
	return s.processRepos(ctx, "", reporter, s.appListReposWrapper, &appListOptions{
		ListOptions: github.ListOptions{
			PerPage: defaultPagination,
		},
	})
}

type userListOptions struct {
	github.RepositoryListByUserOptions
}

func (u *userListOptions) getListOptions() *github.ListOptions {
	return &u.ListOptions
}

func (s *Source) userListReposWrapper(ctx context.Context, user string, opts repoListOptions) ([]*github.Repository, *github.Response, error) {
	return s.connector.APIClient().Repositories.ListByUser(ctx, user, &opts.(*userListOptions).RepositoryListByUserOptions)
}

func (s *Source) getReposByUser(ctx context.Context, user string, reporter sources.UnitReporter) error {
	return s.processRepos(ctx, user, reporter, s.userListReposWrapper, &userListOptions{
		RepositoryListByUserOptions: github.RepositoryListByUserOptions{
			ListOptions: github.ListOptions{
				PerPage: defaultPagination,
			},
		},
	})
}

type orgListOptions struct {
	github.RepositoryListByOrgOptions
}

func (o *orgListOptions) getListOptions() *github.ListOptions {
	return &o.ListOptions
}

func (s *Source) orgListReposWrapper(ctx context.Context, org string, opts repoListOptions) ([]*github.Repository, *github.Response, error) {
	// TODO: It's possible to exclude forks when making the API request rather than doing post-request filtering
	return s.connector.APIClient().Repositories.ListByOrg(ctx, org, &opts.(*orgListOptions).RepositoryListByOrgOptions)
}

func (s *Source) getReposByOrg(ctx context.Context, org string, reporter sources.UnitReporter) error {
	return s.processRepos(ctx, org, reporter, s.orgListReposWrapper, &orgListOptions{
		RepositoryListByOrgOptions: github.RepositoryListByOrgOptions{
			ListOptions: github.ListOptions{
				PerPage: defaultPagination,
			},
		},
	})
}

// userType indicates whether an account belongs to a person or organization.
//
// See:
// - https://docs.github.com/en/get-started/learning-about-github/types-of-github-accounts
// - https://docs.github.com/en/rest/users/users?apiVersion=2022-11-28#get-a-user
type userType int

const (
	// Default invalid state.
	unknown userType = iota
	// The account is a person (https://docs.github.com/en/rest/users/users).
	user
	// The account is an organization (https://docs.github.com/en/rest/orgs/orgs).
	organization
)

func (s *Source) getReposByOrgOrUser(ctx context.Context, name string, reporter sources.UnitReporter) (userType, error) {
	var err error

	// List repositories for the organization |name|.
	err = s.getReposByOrg(ctx, name, reporter)
	if err == nil {
		return organization, nil
	} else if !isGitHub404Error(err) {
		reporter.UnitErr(ctx, fmt.Errorf("error getting repos by org: %w", err))
		return unknown, err
	}

	// List repositories for the user |name|.
	err = s.getReposByUser(ctx, name, reporter)
	if err == nil {
		if err := s.addUserGistsToCache(ctx, name, reporter); err != nil {
			ctx.Logger().Error(err, "Unable to add user to cache")
		}
		return user, nil
	} else if !isGitHub404Error(err) {
		return unknown, err
	}

	return unknown, fmt.Errorf("account '%s' not found", name)
}

// isGitHub404Error returns true if |err| is a `github.ErrorResponse` and has the status code `404`.
func isGitHub404Error(err error) bool {
	var ghErr *github.ErrorResponse
	if !errors.As(err, &ghErr) {
		return false
	}

	return ghErr.Response.StatusCode == http.StatusNotFound
}

// processRepos is the main function for getting repositories from a source.
func (s *Source) processRepos(ctx context.Context, target string, reporter sources.UnitReporter, listRepos repoLister, listOpts repoListOptions) error {
	logger := ctx.Logger().WithValues("target", target)
	opts := listOpts.getListOptions()

	var (
		numRepos, numForks int
		uniqueOrgs         = map[string]struct{}{}
	)

	for {
		someRepos, res, err := listRepos(ctx, target, listOpts)
		if s.handleRateLimitWithUnitReporter(ctx, reporter, err) {
			continue
		}
		if err != nil {
			return err
		}

		ctx.Logger().V(2).Info("Listed repos", "page", opts.Page, "last_page", res.LastPage)
		for _, r := range someRepos {
			if r.GetFork() {
				if !s.conn.IncludeForks {
					continue
				}
				numForks++
			}
			numRepos++

			if r.GetOwner().GetType() == "Organization" {
				uniqueOrgs[r.GetOwner().GetLogin()] = struct{}{}
			}

			repoName, repoURL := r.GetFullName(), r.GetCloneURL()
			s.totalRepoSize += r.GetSize()
			s.filteredRepoCache.Set(repoName, repoURL)
			s.cacheRepoInfo(r)
			reporter.UnitOk(ctx, RepoUnit{Name: repoName, URL: repoURL})
			logger.V(3).Info("repo attributes", "name", repoName, "kb_size", r.GetSize(), "repo_url", repoURL)
		}

		if res.NextPage == 0 {
			break
		}
		opts.Page = res.NextPage
	}

	logger.V(2).Info("found repos", "total", numRepos, "num_forks", numForks, "num_orgs", len(uniqueOrgs))
	githubOrgsEnumerated.WithLabelValues(s.name).Add(float64(len(uniqueOrgs)))

	return nil
}

func (s *Source) cacheRepoInfo(r *github.Repository) {
	info := repoInfo{
		owner:    r.GetOwner().GetLogin(),
		name:     r.GetName(),
		fullName: r.GetFullName(),
		hasWiki:  r.GetHasWiki(),
		size:     r.GetSize(),
	}
	if r.GetPrivate() {
		info.visibility = source_metadatapb.Visibility_private
	} else {
		info.visibility = source_metadatapb.Visibility_public
	}
	s.repoInfoCache.put(r.GetCloneURL(), info)
}

func (s *Source) cacheGistInfo(g *github.Gist) {
	info := repoInfo{
		owner: g.GetOwner().GetLogin(),
	}
	if g.GetPublic() {
		info.visibility = source_metadatapb.Visibility_public
	} else {
		info.visibility = source_metadatapb.Visibility_private
	}
	s.repoInfoCache.put(g.GetGitPullURL(), info)
}

// wikiIsReachable returns true if https://github.com/$org/$repo/wiki is not redirected.
// Unfortunately, this isn't 100% accurate. Some repositories have `has_wiki: true` and don't redirect their wiki page,
// but still don't have a cloneable wiki.
func (s *Source) wikiIsReachable(ctx context.Context, repoURL string) bool {
	wikiURL := strings.TrimSuffix(repoURL, ".git") + "/wiki"
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, wikiURL, nil)
	if err != nil {
		return false
	}

	res, err := s.connector.APIClient().Client().Do(req)
	if err != nil {
		return false
	}
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()

	// If the wiki is disabled, or is enabled but has no content, the request should be redirected.
	return wikiURL == res.Request.URL.String()
}

func (s *Source) normalizeRepo(repo string) (string, error) {
	// If there's a '/', assume it's a URL and try to normalize it.
	if strings.ContainsRune(repo, '/') {
		return giturl.NormalizeGithubRepo(repo)
	}

	return "", fmt.Errorf("no repositories found for %s", repo)
}
