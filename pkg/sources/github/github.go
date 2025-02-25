package github

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gobwas/glob"
	"github.com/google/go-github/v67/github"
	"github.com/trufflesecurity/trufflehog/v3/pkg/log"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/cache"
	"github.com/trufflesecurity/trufflehog/v3/pkg/cache/simple"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/giturl"
	"github.com/trufflesecurity/trufflehog/v3/pkg/handlers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sanitizer"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/git"
)

const (
	SourceType = sourcespb.SourceType_SOURCE_TYPE_GITHUB

	unauthGithubOrgRateLimt = 30
	defaultPagination       = 100
	membersAppPagination    = 500
)

type Source struct {
	name string

	sourceID          sources.SourceID
	jobID             sources.JobID
	verify            bool
	orgsCache         cache.Cache[string]
	memberCache       map[string]struct{}
	repos             []string
	filteredRepoCache *filteredRepoCache
	repoInfoCache     repoInfoCache
	totalRepoSize     int // total size of all repos in kb

	useCustomContentWriter bool
	git                    *git.Git

	scanOptMu   sync.Mutex // protects the scanOptions
	scanOptions *git.ScanOptions

	conn            *sourcespb.GitHub
	jobPool         *errgroup.Group
	resumeInfoMutex sync.Mutex
	resumeInfoSlice []string
	connector       Connector

	includePRComments     bool
	includeIssueComments  bool
	includeGistComments   bool
	commentsTimeframeDays uint32

	sources.Progress
	sources.CommonSourceUnitUnmarshaller
}

// --------------------------------------------------------------------------------
// RepoUnit and GistUnit are implementations of SourceUnit used during
// enumeration. The different types aren't strictly necessary, but are a bit
// more explicit and allow type checking/safety.

var _ sources.SourceUnit = (*RepoUnit)(nil)
var _ sources.SourceUnit = (*GistUnit)(nil)

type RepoUnit struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

func (r RepoUnit) SourceUnitID() (string, sources.SourceUnitKind) { return r.URL, "repo" }
func (r RepoUnit) Display() string                                { return r.Name }

type GistUnit struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

func (g GistUnit) SourceUnitID() (string, sources.SourceUnitKind) { return g.URL, "gist" }
func (g GistUnit) Display() string                                { return g.Name }

// --------------------------------------------------------------------------------

// WithCustomContentWriter sets the useCustomContentWriter flag on the source.
func (s *Source) WithCustomContentWriter() { s.useCustomContentWriter = true }

func (s *Source) WithScanOptions(scanOptions *git.ScanOptions) {
	s.scanOptions = scanOptions
}

func (s *Source) setScanOptions(base, head string) {
	s.scanOptMu.Lock()
	defer s.scanOptMu.Unlock()
	s.scanOptions.BaseHash = base
	s.scanOptions.HeadHash = head
}

// Ensure the Source satisfies the interfaces at compile time
var _ sources.Source = (*Source)(nil)
var _ sources.SourceUnitUnmarshaller = (*Source)(nil)
var _ sources.SourceUnitEnumChunker = (*Source)(nil)

var endsWithGithub = regexp.MustCompile(`github\.com/?$`)

// Type returns the type of source.
// It is used for matching source types in configuration and job input.
func (s *Source) Type() sourcespb.SourceType {
	return SourceType
}

func (s *Source) SourceID() sources.SourceID {
	return s.sourceID
}

func (s *Source) JobID() sources.JobID {
	return s.jobID
}

// filteredRepoCache is a wrapper around cache.Cache that filters out repos
// based on include and exclude globs.
type filteredRepoCache struct {
	cache.Cache[string]
	include, exclude []glob.Glob
}

func (s *Source) newFilteredRepoCache(ctx context.Context, c cache.Cache[string], include, exclude []string) *filteredRepoCache {
	includeGlobs := make([]glob.Glob, 0, len(include))
	excludeGlobs := make([]glob.Glob, 0, len(exclude))
	for _, ig := range include {
		g, err := glob.Compile(ig)
		if err != nil {
			ctx.Logger().V(1).Info("invalid include glob", "include_value", ig, "err", err)
			continue
		}
		includeGlobs = append(includeGlobs, g)
	}
	for _, eg := range exclude {
		g, err := glob.Compile(eg)
		if err != nil {
			ctx.Logger().V(1).Info("invalid exclude glob", "exclude_value", eg, "err", err)
			continue
		}
		excludeGlobs = append(excludeGlobs, g)
	}
	return &filteredRepoCache{Cache: c, include: includeGlobs, exclude: excludeGlobs}
}

// Set overrides the cache.Cache Set method to filter out repos based on
// include and exclude globs.
func (c *filteredRepoCache) Set(key, val string) {
	if c.ignoreRepo(key) {
		return
	}
	if !c.includeRepo(key) {
		return
	}
	c.Cache.Set(key, val)
}

func (c *filteredRepoCache) ignoreRepo(s string) bool {
	for _, g := range c.exclude {
		if g.Match(s) {
			return true
		}
	}
	return false
}

func (c *filteredRepoCache) includeRepo(s string) bool {
	if len(c.include) == 0 {
		return true
	}

	for _, g := range c.include {
		if g.Match(s) {
			return true
		}
	}
	return false
}

// Init returns an initialized GitHub source.
func (s *Source) Init(aCtx context.Context, name string, jobID sources.JobID, sourceID sources.SourceID, verify bool, connection *anypb.Any, concurrency int) error {
	err := git.CmdCheck()
	if err != nil {
		return err
	}

	s.name = name
	s.sourceID = sourceID
	s.jobID = jobID
	s.verify = verify
	s.jobPool = &errgroup.Group{}
	s.jobPool.SetLimit(concurrency)

	// Setup scan options if it wasn't provided.
	if s.scanOptions == nil {
		s.scanOptions = &git.ScanOptions{}
	}

	var conn sourcespb.GitHub
	err = anypb.UnmarshalTo(connection, &conn, proto.UnmarshalOptions{})
	if err != nil {
		return fmt.Errorf("error unmarshalling connection: %w", err)
	}
	s.conn = &conn

	connector, err := newConnector(s)
	if err != nil {
		return fmt.Errorf("could not create connector: %w", err)
	}
	s.connector = connector

	s.orgsCache = simple.NewCache[string]()
	for _, org := range s.conn.Organizations {
		s.orgsCache.Set(org, org)
	}
	s.memberCache = make(map[string]struct{})

	s.filteredRepoCache = s.newFilteredRepoCache(aCtx,
		simple.NewCache[string](),
		append(s.conn.GetRepositories(), s.conn.GetIncludeRepos()...),
		s.conn.GetIgnoreRepos(),
	)
	s.repos = s.conn.Repositories
	for _, repo := range s.repos {
		r, err := s.normalizeRepo(repo)
		if err != nil {
			aCtx.Logger().Error(err, "invalid repository", "repo", repo)
			continue
		}
		s.filteredRepoCache.Set(repo, r)
	}
	s.repoInfoCache = newRepoInfoCache()

	s.includeIssueComments = s.conn.IncludeIssueComments
	s.includePRComments = s.conn.IncludePullRequestComments
	s.includeGistComments = s.conn.IncludeGistComments
	s.commentsTimeframeDays = s.conn.CommentsTimeframeDays

	// Head or base should only be used with incoming webhooks
	if (len(s.conn.Head) > 0 || len(s.conn.Base) > 0) && len(s.repos) != 1 {
		return fmt.Errorf("cannot specify head or base with multiple repositories")
	}

	cfg := &git.Config{
		SourceName:   s.name,
		JobID:        s.jobID,
		SourceID:     s.sourceID,
		SourceType:   s.Type(),
		Verify:       s.verify,
		SkipBinaries: conn.GetSkipBinaries(),
		SkipArchives: conn.GetSkipArchives(),
		Concurrency:  concurrency,
		SourceMetadataFunc: func(file, email, commit, timestamp, repository string, line int64) *source_metadatapb.MetaData {
			return &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_Github{
					Github: &source_metadatapb.Github{
						Commit:     sanitizer.UTF8(commit),
						File:       sanitizer.UTF8(file),
						Email:      sanitizer.UTF8(email),
						Repository: sanitizer.UTF8(repository),
						Link:       giturl.GenerateLink(repository, commit, file, line),
						Timestamp:  sanitizer.UTF8(timestamp),
						Line:       line,
						Visibility: s.visibilityOf(aCtx, repository),
					},
				},
			}
		},
		UseCustomContentWriter: s.useCustomContentWriter,
	}
	s.git = git.NewGit(cfg)

	return nil
}

// Validate is used by enterprise CLI to validate the GitHub config file.
func (s *Source) Validate(ctx context.Context) []error {
	if _, _, err := s.connector.APIClient().Users.Get(ctx, ""); err != nil {
		return []error{err}
	}

	return nil
}

func (s *Source) visibilityOf(ctx context.Context, repoURL string) source_metadatapb.Visibility {
	// It isn't possible to get the visibility of a wiki.
	// We must use the visibility of the corresponding repository.
	if strings.HasSuffix(repoURL, ".wiki.git") {
		repoURL = strings.TrimSuffix(repoURL, ".wiki.git") + ".git"
	}

	repoInfo, ok := s.repoInfoCache.get(repoURL)
	if !ok {
		// This should never happen.
		err := fmt.Errorf("no repoInfo for URL: %s", repoURL)
		ctx.Logger().Error(err, "failed to get repository visibility")
		return source_metadatapb.Visibility_unknown
	}

	return repoInfo.visibility
}

// Chunks emits chunks of bytes over a channel.
func (s *Source) Chunks(ctx context.Context, chunksChan chan *sources.Chunk, targets ...sources.ChunkingTarget) error {
	chunksReporter := sources.ChanReporter{Ch: chunksChan}
	// If targets are provided, we're only scanning the data in those targets.
	// Otherwise, we're scanning all data.
	// This allows us to only scan the commit where a vulnerability was found.
	if len(targets) > 0 {
		errs := s.scanTargets(ctx, targets, chunksReporter)
		return errors.Join(errs...)
	}

	// Reset consumption and rate limit metrics on each run.
	githubNumRateLimitEncountered.WithLabelValues(s.name).Set(0)
	githubSecondsSpentRateLimited.WithLabelValues(s.name).Set(0)
	githubReposScanned.WithLabelValues(s.name).Set(0)

	// We don't care about handling enumerated values as they happen during
	// the normal Chunks flow because we enumerate and scan in two steps.
	noopReporter := sources.VisitorReporter{
		VisitUnit: func(context.Context, sources.SourceUnit) error {
			return nil
		},
	}
	err := s.Enumerate(ctx, noopReporter)
	if err != nil {
		return fmt.Errorf("error enumerating: %w", err)
	}

	return s.scan(ctx, chunksReporter)
}

// Enumerate enumerates the GitHub source based on authentication method and
// user configuration. It populates s.filteredRepoCache, s.repoInfoCache,
// s.memberCache, s.totalRepoSize, s.orgsCache, and s.repos. Additionally,
// repositories and gists are reported to the provided UnitReporter.
func (s *Source) Enumerate(ctx context.Context, reporter sources.UnitReporter) error {
	seenUnits := make(map[sources.SourceUnit]struct{})
	// Wrapper reporter to deduplicate and filter found units.
	dedupeReporter := sources.VisitorReporter{
		VisitUnit: func(ctx context.Context, su sources.SourceUnit) error {
			// Only report units that passed the user configured filter.
			name := su.Display()
			if !s.filteredRepoCache.Exists(name) {
				return ctx.Err()
			}
			// Only report a unit once.
			if _, ok := seenUnits[su]; ok {
				return ctx.Err()
			}
			seenUnits[su] = struct{}{}
			return reporter.UnitOk(ctx, su)
		},
		VisitErr: reporter.UnitErr,
	}
	// Report any values that were already configured.
	// This compensates for differences in enumeration logic between `--org` and `--repo`.
	// See: https://github.com/trufflesecurity/trufflehog/pull/2379#discussion_r1487454788
	for _, name := range s.filteredRepoCache.Keys() {
		url, _ := s.filteredRepoCache.Get(name)
		url, err := s.ensureRepoInfoCache(ctx, url, &unitErrorReporter{reporter})
		if err != nil {
			if err := dedupeReporter.UnitErr(ctx, err); err != nil {
				return err
			}
		}
		if err := dedupeReporter.UnitOk(ctx, RepoUnit{Name: name, URL: url}); err != nil {
			return err
		}
	}

	// I'm not wild about switching on the connector type here (as opposed to dispatching to the connector itself) but
	// this felt like a compromise that allowed me to isolate connection logic without rewriting the entire source.
	switch c := s.connector.(type) {
	case *appConnector:
		if err := s.enumerateWithApp(ctx, c.InstallationClient(), dedupeReporter); err != nil {
			return err
		}
	case *basicAuthConnector:
		if err := s.enumerateBasicAuth(ctx, dedupeReporter); err != nil {
			return err
		}
	case *tokenConnector:
		if err := s.enumerateWithToken(ctx, c.IsGithubEnterprise(), dedupeReporter); err != nil {
			return err
		}
	case *unauthenticatedConnector:
		s.enumerateUnauthenticated(ctx, dedupeReporter)
	}
	s.repos = make([]string, 0, s.filteredRepoCache.Count())

	// Double make sure that all enumerated repositories in the
	// filteredRepoCache have an entry in the repoInfoCache.
	for _, repo := range s.filteredRepoCache.Values() {
		ctx := context.WithValue(ctx, "repo", repo)

		repo, err := s.ensureRepoInfoCache(ctx, repo, &unitErrorReporter{reporter})
		if err != nil {
			ctx.Logger().Error(err, "error caching repo info")
			_ = dedupeReporter.UnitErr(ctx, fmt.Errorf("error caching repo info: %w", err))
		}
		s.repos = append(s.repos, repo)
	}
	githubReposEnumerated.WithLabelValues(s.name).Set(float64(len(s.repos)))
	ctx.Logger().Info("Completed enumeration", "num_repos", len(s.repos), "num_orgs", s.orgsCache.Count(), "num_members", len(s.memberCache))
	// We must sort the repos so we can resume later if necessary.
	sort.Strings(s.repos)
	return nil
}

// ensureRepoInfoCache checks that s.repoInfoCache has an entry for the
// provided repository URL. If not, it fetches and stores the metadata for the
// repository. In some cases, the gist URL needs to be normalized, which is
// returned by this function.
func (s *Source) ensureRepoInfoCache(ctx context.Context, repo string, reporter errorReporter) (string, error) {
	if _, ok := s.repoInfoCache.get(repo); ok {
		return repo, nil
	}
	ctx.Logger().V(2).Info("Caching repository info")

	_, urlParts, err := getRepoURLParts(repo)
	if err != nil {
		return repo, fmt.Errorf("failed to parse repository URL: %w", err)
	}

	if isGistUrl(urlParts) {
		// Cache gist info.
		for {
			gistID := extractGistID(urlParts)
			gist, _, err := s.connector.APIClient().Gists.Get(ctx, gistID)
			// Normalize the URL to the Gist's pull URL.
			// See https://github.com/trufflesecurity/trufflehog/pull/2625#issuecomment-2025507937
			repo = gist.GetGitPullURL()

			if s.handleRateLimit(ctx, err, reporter) {
				continue
			}

			if err != nil {
				return repo, fmt.Errorf("failed to fetch gist")
			}

			s.cacheGistInfo(gist)
			break
		}
	} else {
		// Cache repository info.
		for {
			ghRepo, _, err := s.connector.APIClient().Repositories.Get(ctx, urlParts[1], urlParts[2])
			if s.handleRateLimit(ctx, err, reporter) {
				continue
			}
			if err != nil {
				return repo, fmt.Errorf("failed to fetch repository")
			}
			s.cacheRepoInfo(ghRepo)
			break
		}
	}
	return repo, nil
}

func (s *Source) enumerateBasicAuth(ctx context.Context, reporter sources.UnitReporter) error {
	for _, org := range s.orgsCache.Keys() {
		orgCtx := context.WithValue(ctx, "account", org)
		userType, err := s.getReposByOrgOrUser(ctx, org, reporter)
		if err != nil {
			orgCtx.Logger().Error(err, "error fetching repos for org or user")
			continue
		}

		// TODO: This modifies s.memberCache but it doesn't look like
		// we do anything with it.
		if userType == organization && s.conn.ScanUsers {
			if err := s.addMembersByOrg(ctx, org, reporter); err != nil {
				orgCtx.Logger().Error(err, "Unable to add members by org")
			}
		}
	}

	return nil
}

func (s *Source) enumerateUnauthenticated(ctx context.Context, reporter sources.UnitReporter) {
	if s.orgsCache.Count() > unauthGithubOrgRateLimt {
		ctx.Logger().Info("You may experience rate limiting when using the unauthenticated GitHub api. Consider using an authenticated scan instead.")
	}

	for _, org := range s.orgsCache.Keys() {
		orgCtx := context.WithValue(ctx, "account", org)
		userType, err := s.getReposByOrgOrUser(ctx, org, reporter)
		if err != nil {
			orgCtx.Logger().Error(err, "error fetching repos for org or user")
			continue
		}

		if userType == organization && s.conn.ScanUsers {
			orgCtx.Logger().Info("WARNING: Enumerating unauthenticated does not support scanning organization members (--include-members)")
		}
	}
}

func (s *Source) enumerateWithToken(ctx context.Context, isGithubEnterprise bool, reporter sources.UnitReporter) error {
	ctx.Logger().V(1).Info("Enumerating with token")

	var ghUser *github.User
	var err error
	for {
		ghUser, _, err = s.connector.APIClient().Users.Get(ctx, "")
		if s.handleRateLimitWithUnitReporter(ctx, reporter, err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("error getting user: %w", err)
		}
		break
	}

	specificScope := len(s.repos) > 0 || s.orgsCache.Count() > 0
	if !specificScope {
		// Enumerate the user's orgs and repos if none were specified.
		if err := s.getReposByUser(ctx, ghUser.GetLogin(), reporter); err != nil {
			ctx.Logger().Error(err, "Unable to fetch repos for the current user", "user", ghUser.GetLogin())
		}
		if err := s.addUserGistsToCache(ctx, ghUser.GetLogin(), reporter); err != nil {
			ctx.Logger().Error(err, "Unable to fetch gists for the current user", "user", ghUser.GetLogin())
		}

		if isGithubEnterprise {
			s.addAllVisibleOrgs(ctx, reporter)
		} else {
			// Scan for orgs is default with a token.
			// GitHub App enumerates the repos that were assigned to it in GitHub App settings.
			s.addOrgsByUser(ctx, ghUser.GetLogin(), reporter)
		}
	}

	if len(s.orgsCache.Keys()) > 0 {
		for _, org := range s.orgsCache.Keys() {
			orgCtx := context.WithValue(ctx, "account", org)
			userType, err := s.getReposByOrgOrUser(ctx, org, reporter)
			if err != nil {
				orgCtx.Logger().Error(err, "Unable to fetch repos for org or user")
				continue
			}

			if userType == organization && s.conn.ScanUsers {
				if err := s.addMembersByOrg(ctx, org, reporter); err != nil {
					orgCtx.Logger().Error(err, "Unable to add members for org")
				}
			}
		}

		if s.conn.ScanUsers && len(s.memberCache) > 0 {
			ctx.Logger().Info("Fetching repos for org members", "org_count", s.orgsCache.Count(), "member_count", len(s.memberCache))
			s.addReposForMembers(ctx, reporter)
		}
	}

	return nil
}

func (s *Source) enumerateWithApp(ctx context.Context, installationClient *github.Client, reporter sources.UnitReporter) error {
	// If no repos were provided, enumerate them.
	if len(s.repos) == 0 {
		if err := s.getReposByApp(ctx, reporter); err != nil {
			return err
		}

		// Check if we need to find user repos.
		if s.conn.ScanUsers {
			err := s.addMembersByApp(ctx, installationClient, reporter)
			if err != nil {
				return err
			}
			ctx.Logger().Info("Scanning repos", "org_members", len(s.memberCache))
			// TODO: Replace loop below with a call to s.addReposForMembers(ctx, reporter)
			for member := range s.memberCache {
				logger := ctx.Logger().WithValues("member", member)
				if err := s.addUserGistsToCache(ctx, member, reporter); err != nil {
					logger.Error(err, "error fetching gists by user")
				}
				if err := s.getReposByUser(ctx, member, reporter); err != nil {
					logger.Error(err, "error fetching repos by user")
				}
			}
		}
	}

	return nil
}

func createGitHubClient(httpClient *http.Client, apiEndpoint string) (*github.Client, error) {
	// If we're using public GitHub, make a regular client.
	// Otherwise, make an enterprise client.
	if strings.EqualFold(apiEndpoint, cloudEndpoint) {
		return github.NewClient(httpClient), nil
	}

	return github.NewClient(httpClient).WithEnterpriseURLs(apiEndpoint, apiEndpoint)
}

func (s *Source) scan(ctx context.Context, reporter sources.ChunkReporter) error {
	var scannedCount uint64 = 1

	ctx.Logger().V(2).Info("Found repos to scan", "count", len(s.repos))

	// If there is resume information available, limit this scan to only the repos that still need scanning.
	reposToScan, progressIndexOffset := sources.FilterReposToResume(s.repos, s.GetProgress().EncodedResumeInfo)
	s.repos = reposToScan

	for i, repoURL := range s.repos {
		s.jobPool.Go(func() error {
			if common.IsDone(ctx) {
				return nil
			}
			ctx := context.WithValue(ctx, "repo", repoURL)

			// TODO: set progress complete is being called concurrently with i
			s.setProgressCompleteWithRepo(i, progressIndexOffset, repoURL)
			// Ensure the repo is removed from the resume info after being scanned.
			defer func(s *Source, repoURL string) {
				s.resumeInfoMutex.Lock()
				defer s.resumeInfoMutex.Unlock()
				s.resumeInfoSlice = sources.RemoveRepoFromResumeInfo(s.resumeInfoSlice, repoURL)
			}(s, repoURL)

			if err := s.scanRepo(ctx, repoURL, reporter); err != nil {
				ctx.Logger().Error(err, "error scanning repo")
				return nil
			}

			atomic.AddUint64(&scannedCount, 1)
			return nil
		})
	}

	_ = s.jobPool.Wait()
	s.SetProgressComplete(len(s.repos), len(s.repos), "Completed GitHub scan", "")

	return nil
}

// scanRepo attempts to scan the provided URL and any associated wiki and
// comments if configured. An error is returned if we could not find necessary
// repository metadata or clone the repo, otherwise all errors are reported to
// the ChunkReporter.
func (s *Source) scanRepo(ctx context.Context, repoURL string, reporter sources.ChunkReporter) error {
	if !strings.HasSuffix(repoURL, ".git") {
		return fmt.Errorf("repo does not end in .git")
	}
	// Scan the repository
	repoInfo, ok := s.repoInfoCache.get(repoURL)
	if !ok {
		// This should never happen.
		return fmt.Errorf("no repoInfo for URL: %s", repoURL)
	}
	duration, err := s.cloneAndScanRepo(ctx, repoURL, repoInfo, reporter)
	if err != nil {
		return err
	}

	// Scan the wiki, if enabled, and the repo has one.
	if s.conn.IncludeWikis && repoInfo.hasWiki && s.wikiIsReachable(ctx, repoURL) {
		wikiURL := strings.TrimSuffix(repoURL, ".git") + ".wiki.git"
		wikiCtx := context.WithValue(ctx, "repo", wikiURL)

		_, err := s.cloneAndScanRepo(wikiCtx, wikiURL, repoInfo, reporter)
		if err != nil {
			// Ignore "Repository not found" errors.
			// It's common for GitHub's API to say a repo has a wiki when it doesn't.
			if !strings.Contains(err.Error(), "not found") {
				if err := reporter.ChunkErr(ctx, fmt.Errorf("error scanning wiki: %w", err)); err != nil {
					return err
				}
			}

			// Don't return, it still might be possible to scan comments.
		}
	}

	// Scan comments, if enabled.
	if s.includeGistComments || s.includeIssueComments || s.includePRComments {
		if err := s.scanComments(ctx, repoURL, repoInfo, reporter); err != nil {
			err := fmt.Errorf("error scanning comments: %w", err)
			if err := reporter.ChunkErr(ctx, err); err != nil {
				return err
			}
		}
	}

	ctx.Logger().V(2).Info("finished scanning repo", "duration_seconds", duration)
	githubReposScanned.WithLabelValues(s.name).Inc()
	return nil
}

func (s *Source) cloneAndScanRepo(ctx context.Context, repoURL string, repoInfo repoInfo, reporter sources.ChunkReporter) (time.Duration, error) {
	var duration time.Duration

	ctx.Logger().V(2).Info("attempting to clone repo")
	path, repo, err := s.cloneRepo(ctx, repoURL)
	if err != nil {
		return duration, err
	}
	defer os.RemoveAll(path)

	// TODO: Can this be set once or does it need to be set on every iteration? Is |s.scanOptions| set every clone?
	s.setScanOptions(s.conn.Base, s.conn.Head)

	start := time.Now()
	if err = s.git.ScanRepo(ctx, repo, path, s.scanOptions, reporter); err != nil {
		return duration, fmt.Errorf("error scanning repo %s: %w", repoURL, err)
	}
	duration = time.Since(start)
	return duration, nil
}

var (
	rateLimitMu         sync.RWMutex
	rateLimitResumeTime time.Time
)

// errorReporter is an interface that captures just the error reporting functionality
type errorReporter interface {
	Err(ctx context.Context, err error) error
}

// wrapper to adapt UnitReporter to errorReporter
type unitErrorReporter struct {
	reporter sources.UnitReporter
}

func (u unitErrorReporter) Err(ctx context.Context, err error) error {
	return u.reporter.UnitErr(ctx, err)
}

// wrapper to adapt ChunkReporter to errorReporter
type chunkErrorReporter struct {
	reporter sources.ChunkReporter
}

func (c chunkErrorReporter) Err(ctx context.Context, err error) error {
	return c.reporter.ChunkErr(ctx, err)
}

// handleRateLimit handles GitHub API rate limiting with an optional error reporter.
// Returns true if a rate limit was handled.
//
// Unauthenticated users have a rate limit of 60 requests per hour.
// Authenticated users have a rate limit of 5,000 requests per hour,
// however, certain actions are subject to a stricter "secondary" limit.
// https://docs.github.com/en/rest/overview/rate-limits-for-the-rest-api
func (s *Source) handleRateLimit(ctx context.Context, errIn error, reporters ...errorReporter) bool {
	if errIn == nil {
		return false
	}

	rateLimitMu.RLock()
	resumeTime := rateLimitResumeTime
	rateLimitMu.RUnlock()

	var retryAfter time.Duration
	if resumeTime.IsZero() || time.Now().After(resumeTime) {
		rateLimitMu.Lock()
		var (
			now = time.Now()

			// GitHub has both primary (RateLimit) and secondary (AbuseRateLimit) errors.
			limitType  string
			rateLimit  *github.RateLimitError
			abuseLimit *github.AbuseRateLimitError
		)
		if errors.As(errIn, &rateLimit) {
			limitType = "primary"
			rate := rateLimit.Rate
			if rate.Remaining == 0 { // TODO: Will we ever receive a |RateLimitError| when remaining > 0?
				retryAfter = rate.Reset.Sub(now)
			}
		} else if errors.As(errIn, &abuseLimit) {
			limitType = "secondary"
			retryAfter = abuseLimit.GetRetryAfter()
		} else {
			rateLimitMu.Unlock()
			return false
		}

		jitter := time.Duration(rand.IntN(10)+1) * time.Second
		if retryAfter > 0 {
			retryAfter = retryAfter + jitter
			rateLimitResumeTime = now.Add(retryAfter)
			ctx.Logger().Info(fmt.Sprintf("exceeded %s rate limit", limitType), "retry_after", retryAfter.String(), "resume_time", rateLimitResumeTime.Format(time.RFC3339))
			// Only report the error if a reporter was provided
			for _, reporter := range reporters {
				_ = reporter.Err(ctx, fmt.Errorf("exceeded %s rate limit", limitType))
			}
		} else {
			retryAfter = (5 * time.Minute) + jitter
			rateLimitResumeTime = now.Add(retryAfter)
			// TODO: Use exponential backoff instead of static retry time.
			ctx.Logger().Error(errIn, "unexpected rate limit error", "retry_after", retryAfter.String(), "resume_time", rateLimitResumeTime.Format(time.RFC3339))
		}

		rateLimitMu.Unlock()
	} else {
		retryAfter = time.Until(resumeTime)
	}

	githubNumRateLimitEncountered.WithLabelValues(s.name).Inc()
	time.Sleep(retryAfter)
	githubSecondsSpentRateLimited.WithLabelValues(s.name).Add(retryAfter.Seconds())
	return true
}

// handleRateLimitWithUnitReporter is a wrapper around handleRateLimit that includes unit reporting
func (s *Source) handleRateLimitWithUnitReporter(ctx context.Context, reporter sources.UnitReporter, errIn error) bool {
	return s.handleRateLimit(ctx, errIn, &unitErrorReporter{reporter: reporter})
}

// handleRateLimitWithChunkReporter is a wrapper around handleRateLimit that includes chunk reporting
func (s *Source) handleRateLimitWithChunkReporter(ctx context.Context, reporter sources.ChunkReporter, errIn error) bool {
	return s.handleRateLimit(ctx, errIn, &chunkErrorReporter{reporter: reporter})
}

func (s *Source) addReposForMembers(ctx context.Context, reporter sources.UnitReporter) {
	ctx.Logger().Info("Fetching repos from members", "members", len(s.memberCache))
	for member := range s.memberCache {
		if err := s.addUserGistsToCache(ctx, member, reporter); err != nil {
			ctx.Logger().Info("Unable to fetch gists by user", "user", member, "error", err)
		}
		if err := s.getReposByUser(ctx, member, reporter); err != nil {
			ctx.Logger().Info("Unable to fetch repos by user", "user", member, "error", err)
		}
	}
}

// addUserGistsToCache collects all the gist urls for a given user,
// and adds them to the filteredRepoCache.
func (s *Source) addUserGistsToCache(ctx context.Context, user string, reporter sources.UnitReporter) error {
	gistOpts := &github.GistListOptions{}
	logger := ctx.Logger().WithValues("user", user)

	for {
		gists, res, err := s.connector.APIClient().Gists.List(ctx, user, gistOpts)
		if s.handleRateLimitWithUnitReporter(ctx, reporter, err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("could not list gists for user %s: %w", user, err)
		}

		for _, gist := range gists {
			s.filteredRepoCache.Set(gist.GetID(), gist.GetGitPullURL())
			s.cacheGistInfo(gist)
			if err := reporter.UnitOk(ctx, GistUnit{Name: gist.GetID(), URL: gist.GetGitPullURL()}); err != nil {
				return err
			}
		}

		if res == nil || res.NextPage == 0 {
			break
		}
		logger.V(2).Info("Listed gists", "page", gistOpts.Page, "last_page", res.LastPage)
		gistOpts.Page = res.NextPage
	}
	return nil
}

func (s *Source) addMembersByApp(ctx context.Context, installationClient *github.Client, reporter sources.UnitReporter) error {
	opts := &github.ListOptions{
		PerPage: membersAppPagination,
	}

	// TODO: Check rate limit for this call.
	installs, _, err := installationClient.Apps.ListInstallations(ctx, opts)
	if err != nil {
		return fmt.Errorf("could not enumerate installed orgs: %w", err)
	}

	for _, org := range installs {
		if org.Account.GetType() != "Organization" {
			continue
		}
		if err := s.addMembersByOrg(ctx, *org.Account.Login, reporter); err != nil {
			return err
		}
	}

	return nil
}

func (s *Source) addAllVisibleOrgs(ctx context.Context, reporter sources.UnitReporter) {
	ctx.Logger().V(2).Info("enumerating all visible organizations on GHE")
	// Enumeration on this endpoint does not use pages it uses a since ID.
	// The endpoint will return organizations with an ID greater than the given since ID.
	// Empty org response is our cue to break the enumeration loop.
	orgOpts := &github.OrganizationsListOptions{
		Since: 0,
		ListOptions: github.ListOptions{
			PerPage: defaultPagination,
		},
	}
	for {
		orgs, _, err := s.connector.APIClient().Organizations.ListAll(ctx, orgOpts)
		if s.handleRateLimitWithUnitReporter(ctx, reporter, err) {
			continue
		}
		if err != nil {
			ctx.Logger().Error(err, "could not list all organizations")
			return
		}

		if len(orgs) == 0 {
			break
		}

		lastOrgID := *orgs[len(orgs)-1].ID
		ctx.Logger().V(2).Info(fmt.Sprintf("listed organization IDs %d through %d", orgOpts.Since, lastOrgID))
		orgOpts.Since = lastOrgID

		for _, org := range orgs {
			var name string
			switch {
			case org.Name != nil:
				name = *org.Name
			case org.Login != nil:
				name = *org.Login
			default:
				continue
			}
			s.orgsCache.Set(name, name)
			ctx.Logger().V(2).Info("adding organization for repository enumeration", "id", org.ID, "name", name)
		}
	}
}

func (s *Source) addOrgsByUser(ctx context.Context, user string, reporter sources.UnitReporter) {
	orgOpts := &github.ListOptions{
		PerPage: defaultPagination,
	}
	logger := ctx.Logger().WithValues("user", user)
	for {
		orgs, resp, err := s.connector.APIClient().Organizations.List(ctx, "", orgOpts)
		if s.handleRateLimitWithUnitReporter(ctx, reporter, err) {
			continue
		}
		if err != nil {
			logger.Error(err, "Could not list organizations")
			return
		}

		logger.V(2).Info("Listed orgs", "page", orgOpts.Page, "last_page", resp.LastPage)
		for _, org := range orgs {
			if org.Login == nil {
				continue
			}
			s.orgsCache.Set(*org.Login, *org.Login)
		}
		if resp.NextPage == 0 {
			break
		}
		orgOpts.Page = resp.NextPage
	}
}

func (s *Source) addMembersByOrg(ctx context.Context, org string, reporter sources.UnitReporter) error {
	opts := &github.ListMembersOptions{
		PublicOnly: false,
		ListOptions: github.ListOptions{
			PerPage: membersAppPagination,
		},
	}

	logger := ctx.Logger().WithValues("org", org)
	for {
		members, res, err := s.connector.APIClient().Organizations.ListMembers(ctx, org, opts)
		if s.handleRateLimitWithUnitReporter(ctx, reporter, err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("could not list organization (%q) members: account may not have access to list organization members: %w", org, err)
		}
		if len(members) == 0 {
			return fmt.Errorf("organization (%q) had 0 members: account may not have access to list organization members", org)
		}

		logger.V(2).Info("Listed members", "page", opts.Page, "last_page", res.LastPage)
		for _, m := range members {
			usr := m.Login
			if usr == nil || *usr == "" {
				continue
			}
			if _, ok := s.memberCache[*usr]; !ok {
				s.memberCache[*usr] = struct{}{}
			}
		}
		if res.NextPage == 0 {
			break
		}
		opts.Page = res.NextPage
	}

	return nil
}

// setProgressCompleteWithRepo calls the s.SetProgressComplete after safely setting up the encoded resume info string.
func (s *Source) setProgressCompleteWithRepo(index int, offset int, repoURL string) {
	s.resumeInfoMutex.Lock()
	defer s.resumeInfoMutex.Unlock()

	// Add the repoURL to the resume info slice.
	s.resumeInfoSlice = append(s.resumeInfoSlice, repoURL)
	sort.Strings(s.resumeInfoSlice)

	// Make the resume info string from the slice.
	encodedResumeInfo := sources.EncodeResumeInfo(s.resumeInfoSlice)

	s.SetProgressComplete(index+offset, len(s.repos)+offset, fmt.Sprintf("Repo: %s", repoURL), encodedResumeInfo)
}

func (s *Source) scanComments(ctx context.Context, repoPath string, repoInfo repoInfo, reporter sources.ChunkReporter) error {
	urlString, urlParts, err := getRepoURLParts(repoPath)
	if err != nil {
		return err
	}

	var cutoffTime *time.Time
	if s.commentsTimeframeDays > 0 {
		daysToFilter := int(s.commentsTimeframeDays)
		t := time.Now().AddDate(0, 0, -daysToFilter)
		cutoffTime = &t
	}

	if s.includeGistComments && isGistUrl(urlParts) {
		return s.processGistComments(ctx, urlString, urlParts, repoInfo, reporter, cutoffTime)
	} else if s.includeIssueComments || s.includePRComments {
		return s.processRepoComments(ctx, repoInfo, reporter, cutoffTime)
	}
	return nil
}

// trimURLAndSplit removes extraneous information from the |url| and splits it into segments.
// This is typically 3 segments: host, owner, and name/ID; however, Gists have some edge cases.
//
// Examples:
// - "https://github.com/trufflesecurity/trufflehog" => ["github.com", "trufflesecurity", "trufflehog"]
// - "https://gist.github.com/nat/5fdbb7f945d121f197fb074578e53948" => ["gist.github.com", "nat", "5fdbb7f945d121f197fb074578e53948"]
// - "https://gist.github.com/ff0e5e8dc8ec22f7a25ddfc3492d3451.git" => ["gist.github.com", "ff0e5e8dc8ec22f7a25ddfc3492d3451"]
// - "https://github.company.org/gist/nat/5fdbb7f945d121f197fb074578e53948.git" => ["github.company.org", "gist", "nat", "5fdbb7f945d121f197fb074578e53948"]
func getRepoURLParts(repoURLString string) (string, []string, error) {
	// Support ssh and https URLs.
	repoURL, err := git.GitURLParse(repoURLString)
	if err != nil {
		return "", nil, err
	}

	// Remove the user information.
	// e.g., `git@github.com` -> `github.com`
	if repoURL.User != nil {
		repoURL.User = nil
	}

	urlString := repoURL.String()
	trimmedURL := strings.TrimPrefix(urlString, repoURL.Scheme+"://")
	trimmedURL = strings.TrimSuffix(trimmedURL, ".git")
	urlParts := strings.Split(trimmedURL, "/")

	// Validate
	switch len(urlParts) {
	case 2:
		// gist.github.com/<gist_id>
		if !strings.EqualFold(urlParts[0], "gist.github.com") {
			err = fmt.Errorf("failed to parse repository or gist URL (%s): 2 path segments are only expected if the host is 'gist.github.com' ('gist.github.com', '<gist_id>')", urlString)
		}
	case 3:
		// github.com/<user>/repo>
		// gist.github.com/<user>/<gist_id>
		// github.company.org/<user>/repo>
		// github.company.org/gist/<gist_id>
	case 4:
		// github.company.org/gist/<user/<id>
		if !strings.EqualFold(urlParts[1], "gist") || (strings.EqualFold(urlParts[0], "github.com") && strings.EqualFold(urlParts[1], "gist")) {
			err = fmt.Errorf("failed to parse repository or gist URL (%s): 4 path segments are only expected if the host isn't 'github.com' and the path starts with 'gist' ('github.example.com', 'gist', '<owner>', '<gist_id>')", urlString)
		}
	default:
		err = fmt.Errorf("invalid repository or gist URL (%s): length of URL segments should be between 2 and 4, not %d (%v)", urlString, len(urlParts), urlParts)
	}

	if err != nil {
		return "", nil, err
	}
	return urlString, urlParts, nil
}

const initialPage = 1 // page to start listing from

func (s *Source) processGistComments(ctx context.Context, gistURL string, urlParts []string, repoInfo repoInfo, reporter sources.ChunkReporter, cutoffTime *time.Time) error {
	ctx.Logger().V(2).Info("Scanning GitHub Gist comments")

	// GitHub Gist URL.
	gistID := extractGistID(urlParts)

	options := &github.ListOptions{
		PerPage: defaultPagination,
		Page:    initialPage,
	}
	for {
		comments, _, err := s.connector.APIClient().Gists.ListComments(ctx, gistID, options)
		if s.handleRateLimitWithChunkReporter(ctx, reporter, err) {
			continue
		}
		if err != nil {
			return err
		}

		if err = s.chunkGistComments(ctx, gistURL, repoInfo, comments, reporter, cutoffTime); err != nil {
			return err
		}

		options.Page++
		if len(comments) < options.PerPage {
			break
		}
	}
	return nil
}

func extractGistID(urlParts []string) string {
	return urlParts[len(urlParts)-1]
}

func isGistUrl(urlParts []string) bool {
	return strings.EqualFold(urlParts[0], "gist.github.com") || (len(urlParts) == 4 && strings.EqualFold(urlParts[1], "gist"))
}

func (s *Source) chunkGistComments(ctx context.Context, gistURL string, gistInfo repoInfo, comments []*github.GistComment, reporter sources.ChunkReporter, cutoffTime *time.Time) error {
	for _, comment := range comments {
		// Stop processing comments as soon as one created before the cutoff time is detected, as these are sorted
		if cutoffTime != nil && comment.GetCreatedAt().Before(*cutoffTime) {
			break
		}

		// Create chunk and send it to the channel.
		chunk := sources.Chunk{
			SourceName: s.name,
			SourceID:   s.SourceID(),
			SourceType: s.Type(),
			JobID:      s.JobID(),
			SourceMetadata: &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_Github{
					Github: &source_metadatapb.Github{
						Link:       sanitizer.UTF8(comment.GetURL()),
						Username:   sanitizer.UTF8(comment.GetUser().GetLogin()),
						Email:      sanitizer.UTF8(comment.GetUser().GetEmail()),
						Repository: sanitizer.UTF8(gistURL),
						Timestamp:  sanitizer.UTF8(comment.GetCreatedAt().String()),
						Visibility: gistInfo.visibility,
					},
				},
			},
			Data:   []byte(sanitizer.UTF8(comment.GetBody())),
			Verify: s.verify,
		}

		if err := reporter.ChunkOk(ctx, chunk); err != nil {
			return err
		}
	}
	return nil
}

// Note: these can't be consts because the address is needed when using with the GitHub library.
var (
	// sortType defines the criteria for sorting comments.
	// By setting this to "updated" we can use this to reliably manage the comment timeframe filtering below
	sortType = "updated"
	// directionType defines the direction of sorting.
	// "desc" means comments will be sorted in descending order, showing the latest comments first, which is critical for managing the comment timeframe filtering
	directionType = "desc"
	// allComments is a placeholder for specifying the comment ID to start listing from.
	// A value of 0 means that all comments will be listed.
	allComments = 0
	// state of "all" for the ListByRepo captures both open and closed issues.
	state = "all"
)

func (s *Source) processRepoComments(ctx context.Context, repoInfo repoInfo, reporter sources.ChunkReporter, cutoffTime *time.Time) error {
	if s.includeIssueComments {
		ctx.Logger().V(2).Info("Scanning issues")
		if err := s.processIssues(ctx, repoInfo, reporter); err != nil {
			return err
		}
		if err := s.processIssueComments(ctx, repoInfo, reporter, cutoffTime); err != nil {
			return err
		}
	}

	if s.includePRComments {
		ctx.Logger().V(2).Info("Scanning pull requests")
		if err := s.processPRs(ctx, repoInfo, reporter); err != nil {
			return err
		}
		if err := s.processPRComments(ctx, repoInfo, reporter, cutoffTime); err != nil {
			return err
		}
	}

	return nil
}

func (s *Source) processIssues(ctx context.Context, repoInfo repoInfo, reporter sources.ChunkReporter) error {
	bodyTextsOpts := &github.IssueListByRepoOptions{
		Sort:      sortType,
		Direction: directionType,
		State:     state,
		ListOptions: github.ListOptions{
			PerPage: defaultPagination,
			Page:    initialPage,
		},
	}

	for {
		issues, _, err := s.connector.APIClient().Issues.ListByRepo(ctx, repoInfo.owner, repoInfo.name, bodyTextsOpts)
		if s.handleRateLimitWithChunkReporter(ctx, reporter, err) {
			continue
		}

		if err != nil {
			return err
		}

		if err = s.chunkIssues(ctx, repoInfo, issues, reporter); err != nil {
			return err
		}

		bodyTextsOpts.ListOptions.Page++

		if len(issues) < defaultPagination {
			break
		}
	}
	return nil
}

func (s *Source) chunkIssues(ctx context.Context, repoInfo repoInfo, issues []*github.Issue, reporter sources.ChunkReporter) error {
	for _, issue := range issues {
		// Skip pull requests since covered by processPRs.
		if issue.IsPullRequest() {
			continue
		}

		// Create chunk and send it to the channel.
		chunk := sources.Chunk{
			SourceName: s.name,
			SourceID:   s.SourceID(),
			JobID:      s.JobID(),
			SourceType: s.Type(),
			SourceMetadata: &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_Github{
					Github: &source_metadatapb.Github{
						Link:       sanitizer.UTF8(issue.GetHTMLURL()),
						Username:   sanitizer.UTF8(issue.GetUser().GetLogin()),
						Email:      sanitizer.UTF8(issue.GetUser().GetEmail()),
						Repository: sanitizer.UTF8(repoInfo.fullName),
						Timestamp:  sanitizer.UTF8(issue.GetCreatedAt().String()),
						Visibility: repoInfo.visibility,
					},
				},
			},
			Data:   []byte(sanitizer.UTF8(issue.GetTitle() + "\n" + issue.GetBody())),
			Verify: s.verify,
		}

		if err := reporter.ChunkOk(ctx, chunk); err != nil {
			return err
		}
	}
	return nil
}

func (s *Source) processIssueComments(ctx context.Context, repoInfo repoInfo, reporter sources.ChunkReporter, cutoffTime *time.Time) error {
	issueOpts := &github.IssueListCommentsOptions{
		Sort:      &sortType,
		Direction: &directionType,
		ListOptions: github.ListOptions{
			PerPage: defaultPagination,
			Page:    initialPage,
		},
	}

	for {
		issueComments, _, err := s.connector.APIClient().Issues.ListComments(ctx, repoInfo.owner, repoInfo.name, allComments, issueOpts)
		if s.handleRateLimitWithChunkReporter(ctx, reporter, err) {
			continue
		}
		if err != nil {
			return err
		}

		if err = s.chunkIssueComments(ctx, repoInfo, issueComments, reporter, cutoffTime); err != nil {
			return err
		}

		issueOpts.ListOptions.Page++
		if len(issueComments) < defaultPagination {
			break
		}
	}
	return nil
}

func (s *Source) chunkIssueComments(ctx context.Context, repoInfo repoInfo, comments []*github.IssueComment, reporter sources.ChunkReporter, cutoffTime *time.Time) error {
	for _, comment := range comments {
		// Stop processing comments as soon as one created before the cutoff time is detected, as these are sorted
		if cutoffTime != nil && comment.GetUpdatedAt().Before(*cutoffTime) {
			continue
		}

		// Create chunk and send it to the channel.
		chunk := sources.Chunk{
			SourceName: s.name,
			SourceID:   s.SourceID(),
			JobID:      s.JobID(),
			SourceType: s.Type(),
			SourceMetadata: &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_Github{
					Github: &source_metadatapb.Github{
						Link:       sanitizer.UTF8(comment.GetHTMLURL()),
						Username:   sanitizer.UTF8(comment.GetUser().GetLogin()),
						Email:      sanitizer.UTF8(comment.GetUser().GetEmail()),
						Repository: sanitizer.UTF8(repoInfo.fullName),
						Timestamp:  sanitizer.UTF8(comment.GetCreatedAt().String()),
						Visibility: repoInfo.visibility,
					},
				},
			},
			Data:   []byte(sanitizer.UTF8(comment.GetBody())),
			Verify: s.verify,
		}

		if err := reporter.ChunkOk(ctx, chunk); err != nil {
			return err
		}
	}
	return nil
}

func (s *Source) processPRs(ctx context.Context, repoInfo repoInfo, reporter sources.ChunkReporter) error {
	prOpts := &github.PullRequestListOptions{
		Sort:      sortType,
		Direction: directionType,
		State:     state,
		ListOptions: github.ListOptions{
			PerPage: defaultPagination,
			Page:    initialPage,
		},
	}

	for {
		prs, _, err := s.connector.APIClient().PullRequests.List(ctx, repoInfo.owner, repoInfo.name, prOpts)
		if s.handleRateLimitWithChunkReporter(ctx, reporter, err) {
			continue
		}
		if err != nil {
			return err
		}

		if err = s.chunkPullRequests(ctx, repoInfo, prs, reporter); err != nil {
			return err
		}

		prOpts.ListOptions.Page++

		if len(prs) < defaultPagination {
			break
		}
	}
	return nil
}

func (s *Source) processPRComments(ctx context.Context, repoInfo repoInfo, reporter sources.ChunkReporter, cutoffTime *time.Time) error {
	prOpts := &github.PullRequestListCommentsOptions{
		Sort:      sortType,
		Direction: directionType,
		ListOptions: github.ListOptions{
			PerPage: defaultPagination,
			Page:    initialPage,
		},
	}

	for {
		prComments, _, err := s.connector.APIClient().PullRequests.ListComments(ctx, repoInfo.owner, repoInfo.name, allComments, prOpts)
		if s.handleRateLimitWithChunkReporter(ctx, reporter, err) {
			continue
		}
		if err != nil {
			return err
		}

		if err = s.chunkPullRequestComments(ctx, repoInfo, prComments, reporter, cutoffTime); err != nil {
			return err
		}

		prOpts.ListOptions.Page++

		if len(prComments) < defaultPagination {
			break
		}
	}
	return nil
}

func (s *Source) chunkPullRequests(ctx context.Context, repoInfo repoInfo, prs []*github.PullRequest, reporter sources.ChunkReporter) error {
	for _, pr := range prs {
		// Create chunk and send it to the channel.
		chunk := sources.Chunk{
			SourceName: s.name,
			SourceID:   s.SourceID(),
			SourceType: s.Type(),
			JobID:      s.JobID(),
			SourceMetadata: &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_Github{
					Github: &source_metadatapb.Github{
						Link:       sanitizer.UTF8(pr.GetHTMLURL()),
						Username:   sanitizer.UTF8(pr.GetUser().GetLogin()),
						Email:      sanitizer.UTF8(pr.GetUser().GetEmail()),
						Repository: sanitizer.UTF8(repoInfo.fullName),
						Timestamp:  sanitizer.UTF8(pr.GetCreatedAt().String()),
						Visibility: repoInfo.visibility,
					},
				},
			},
			Data:   []byte(sanitizer.UTF8(pr.GetTitle() + "\n" + pr.GetBody())),
			Verify: s.verify,
		}

		if err := reporter.ChunkOk(ctx, chunk); err != nil {
			return err
		}
	}
	return nil
}

func (s *Source) chunkPullRequestComments(ctx context.Context, repoInfo repoInfo, comments []*github.PullRequestComment, reporter sources.ChunkReporter, cutoffTime *time.Time) error {
	for _, comment := range comments {
		// Stop processing comments as soon as one created before the cutoff time is detected, as these are sorted
		if cutoffTime != nil && comment.GetUpdatedAt().Before(*cutoffTime) {
			continue
		}

		// Create chunk and send it to the channel.
		chunk := sources.Chunk{
			SourceName: s.name,
			SourceID:   s.SourceID(),
			JobID:      s.JobID(),
			SourceType: s.Type(),
			SourceMetadata: &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_Github{
					Github: &source_metadatapb.Github{
						Link:       sanitizer.UTF8(comment.GetHTMLURL()),
						Username:   sanitizer.UTF8(comment.GetUser().GetLogin()),
						Email:      sanitizer.UTF8(comment.GetUser().GetEmail()),
						Repository: sanitizer.UTF8(repoInfo.fullName),
						Timestamp:  sanitizer.UTF8(comment.GetCreatedAt().String()),
						Visibility: repoInfo.visibility,
					},
				},
			},
			Data:   []byte(sanitizer.UTF8(comment.GetBody())),
			Verify: s.verify,
		}

		if err := reporter.ChunkOk(ctx, chunk); err != nil {
			return err
		}
	}
	return nil
}

func (s *Source) scanTargets(ctx context.Context, targets []sources.ChunkingTarget, reporter sources.ChunkReporter) []error {
	var errs []error
	for _, tgt := range targets {
		if err := s.scanTarget(ctx, tgt, reporter); err != nil {
			ctx.Logger().Error(err, "error scanning target")
			errs = append(errs, &sources.TargetedScanError{Err: err, SecretID: tgt.SecretID})
		}
	}

	return errs
}

func (s *Source) scanTarget(ctx context.Context, target sources.ChunkingTarget, reporter sources.ChunkReporter) error {
	metaType, ok := target.QueryCriteria.GetData().(*source_metadatapb.MetaData_Github)
	if !ok {
		return fmt.Errorf("unable to cast metadata type for targeted scan")
	}
	meta := metaType.Github

	u, err := url.Parse(meta.GetLink())
	if err != nil {
		return fmt.Errorf("unable to parse GitHub URL: %w", err)
	}

	// The owner is the second segment and the repo is the third segment of the path.
	// Ex: https://github.com/owner/repo/.....
	segments := strings.Split(u.Path, "/")
	if len(segments) < 3 {
		return fmt.Errorf("invalid GitHub URL")
	}

	readCloser, resp, err := s.connector.APIClient().Repositories.DownloadContents(
		ctx,
		segments[1],
		segments[2],
		meta.GetFile(),
		&github.RepositoryContentGetOptions{Ref: meta.GetCommit()})
	// As of this writing, if the returned readCloser is not nil, it's just the Body of the returned github.Response, so
	// there's no need to independently close it.
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return fmt.Errorf("could not download file for scan: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected HTTP response status when trying to download file for scan: %v", resp.Status)
	}

	chunkSkel := sources.Chunk{
		SourceType: s.Type(),
		SourceName: s.name,
		SourceID:   s.SourceID(),
		JobID:      s.JobID(),
		SecretID:   target.SecretID,
		SourceMetadata: &source_metadatapb.MetaData{
			Data: &source_metadatapb.MetaData_Github{Github: meta},
		},
		Verify: s.verify,
	}
	fileCtx := context.WithValues(ctx, "path", meta.GetFile())
	return handlers.HandleFile(fileCtx, readCloser, &chunkSkel, reporter)
}

func (s *Source) ChunkUnit(ctx context.Context, unit sources.SourceUnit, reporter sources.ChunkReporter) error {
	repoURL, _ := unit.SourceUnitID()
	ctx = context.WithValue(ctx, "repo", repoURL)
	// ChunkUnit is not guaranteed to be called from Enumerate, so we must
	// check and fetch the repoInfoCache for this repo.
	repoURL, err := s.ensureRepoInfoCache(ctx, repoURL, &chunkErrorReporter{reporter: reporter})
	if err != nil {
		return err
	}
	return s.scanRepo(ctx, repoURL, reporter)
}

func newConnector(source *Source) (Connector, error) {
	apiEndpoint := source.conn.Endpoint
	if apiEndpoint == "" || endsWithGithub.MatchString(apiEndpoint) {
		apiEndpoint = cloudEndpoint
	}

	switch cred := source.conn.GetCredential().(type) {
	case *sourcespb.GitHub_GithubApp:
		log.RedactGlobally(cred.GithubApp.GetPrivateKey())
		return NewAppConnector(apiEndpoint, cred.GithubApp)
	case *sourcespb.GitHub_BasicAuth:
		log.RedactGlobally(cred.BasicAuth.GetPassword())
		return NewBasicAuthConnector(apiEndpoint, cred.BasicAuth)
	case *sourcespb.GitHub_Token:
		log.RedactGlobally(cred.Token)
		return NewTokenConnector(apiEndpoint, cred.Token, func(c context.Context, err error) bool {
			return source.handleRateLimit(c, err)
		})
	case *sourcespb.GitHub_Unauthenticated:
		return NewUnauthenticatedConnector(apiEndpoint)
	default:
		return nil, fmt.Errorf("unknown connection type %T", source.conn.GetCredential())
	}
}
