package gitlab

import (
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/trufflesecurity/trufflehog/v3/pkg/log"
	"golang.org/x/sync/errgroup"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/giturl"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sanitizer"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/git"

	gogit "github.com/go-git/go-git/v5"
	"github.com/gobwas/glob"
	"github.com/xanzy/go-gitlab"
	"golang.org/x/exp/slices"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

const SourceType = sourcespb.SourceType_SOURCE_TYPE_GITLAB

// This is the URL for gitlab hosted at gitlab.com
const gitlabBaseURL = "https://gitlab.com/"

type Source struct {
	name     string
	sourceID sources.SourceID
	jobID    sources.JobID
	verify   bool

	authMethod   string
	user         string
	password     string
	token        string
	url          string
	repos        []string
	ignoreRepos  []string
	includeRepos []string

	// This is an experimental flag used to investigate some suspicious behavior we've seen with very large GitLab
	// organizations that have lots of group sharing.
	enumerateSharedProjects bool

	useCustomContentWriter bool
	git                    *git.Git
	scanOptions            *git.ScanOptions

	resumeInfoSlice []string
	resumeInfoMutex sync.Mutex
	sources.Progress

	jobPool *errgroup.Group
	sources.CommonSourceUnitUnmarshaller
}

// WithCustomContentWriter sets the useCustomContentWriter flag on the source.
func (s *Source) WithCustomContentWriter() { s.useCustomContentWriter = true }

// Ensure the Source satisfies the interfaces at compile time.
var _ sources.Source = (*Source)(nil)
var _ sources.SourceUnitUnmarshaller = (*Source)(nil)
var _ sources.Validator = (*Source)(nil)
var _ sources.SourceUnitEnumChunker = (*Source)(nil)

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

// globRepoFilter is a wrapper around cache.Cache that filters out repos
// based on include and exclude globs.
type globRepoFilter struct {
	include, exclude []glob.Glob
}

func newGlobRepoFilter(include, exclude []string, onCompileErr func(err error, pattern string)) *globRepoFilter {
	includeGlobs := make([]glob.Glob, 0, len(include))
	excludeGlobs := make([]glob.Glob, 0, len(exclude))
	for _, ig := range include {
		g, err := glob.Compile(ig)
		if err != nil {
			onCompileErr(err, ig)
			continue
		}
		includeGlobs = append(includeGlobs, g)
	}
	for _, eg := range exclude {
		g, err := glob.Compile(eg)
		if err != nil {
			onCompileErr(err, eg)
			continue
		}
		excludeGlobs = append(excludeGlobs, g)
	}
	return &globRepoFilter{include: includeGlobs, exclude: excludeGlobs}
}

func (c *globRepoFilter) ignoreRepo(s string) bool {
	for _, g := range c.exclude {
		if g.Match(s) {
			return true
		}
	}
	return false
}

func (c *globRepoFilter) includeRepo(s string) bool {
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

// Init returns an initialized Gitlab source.
func (s *Source) Init(ctx context.Context, name string, jobId sources.JobID, sourceId sources.SourceID, verify bool, connection *anypb.Any, concurrency int) error {
	s.name = name
	s.sourceID = sourceId
	s.jobID = jobId
	s.verify = verify
	s.jobPool = &errgroup.Group{}
	s.jobPool.SetLimit(concurrency)

	if err := git.CmdCheck(); err != nil {
		return err
	}

	var conn sourcespb.GitLab
	err := anypb.UnmarshalTo(connection, &conn, proto.UnmarshalOptions{})
	if err != nil {
		return fmt.Errorf("error unmarshalling connection: %w", err)
	}

	s.repos = conn.GetRepositories()
	s.ignoreRepos = conn.GetIgnoreRepos()
	s.includeRepos = conn.GetIncludeRepos()
	s.enumerateSharedProjects = !conn.ExcludeProjectsSharedIntoGroups

	ctx.Logger().V(3).Info("setting ignore repos patterns", "patterns", s.ignoreRepos)
	ctx.Logger().V(3).Info("setting include repos patterns", "patterns", s.includeRepos)

	switch cred := conn.GetCredential().(type) {
	case *sourcespb.GitLab_Token:
		s.authMethod = "TOKEN"
		s.token = cred.Token
		log.RedactGlobally(s.token)
	case *sourcespb.GitLab_Oauth:
		s.authMethod = "OAUTH"
		s.token = cred.Oauth.RefreshToken
		log.RedactGlobally(s.token)
		// TODO: is it okay if there is no client id and secret? Might be an issue when marshalling config to proto
	case *sourcespb.GitLab_BasicAuth:
		s.authMethod = "BASIC_AUTH"
		s.user = cred.BasicAuth.Username
		s.password = cred.BasicAuth.Password
		// We may need the password as a token if the user is using an access_token with basic auth.
		s.token = cred.BasicAuth.Password
		log.RedactGlobally(cred.BasicAuth.Password)
	default:
		return fmt.Errorf("invalid configuration given for source %q (%s)", name, s.Type().String())
	}

	s.url, err = normalizeGitlabEndpoint(conn.Endpoint)
	if err != nil {
		return err
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
		SourceMetadataFunc: func(repository, commit, commitSource, email, timestamp, file string, line int64) *source_metadatapb.MetaData {
			return &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_Gitlab{
					Gitlab: &source_metadatapb.Gitlab{
						Repository:   sanitizer.UTF8(repository),
						Commit:       sanitizer.UTF8(commit),
						CommitSource: sanitizer.UTF8(commitSource),
						Email:        sanitizer.UTF8(email),
						Timestamp:    sanitizer.UTF8(timestamp),
						File:         sanitizer.UTF8(file),
						Line:         line,
						Link:         giturl.GenerateLink(repository, commit, file, line),
					},
				},
			}
		},
		UseCustomContentWriter: s.useCustomContentWriter,
	}
	s.git = git.NewGit(cfg)

	return nil
}

// Chunks emits chunks of bytes over a channel.
func (s *Source) Chunks(ctx context.Context, chunksChan chan *sources.Chunk, targets ...sources.ChunkingTarget) error {
	// Start client.
	apiClient, err := s.newClient()
	if err != nil {
		return err
	}

	// If targets are provided, we're only scanning the data in those targets.
	// Otherwise, we're scanning all data.
	// This allows us to only scan the commit where a vulnerability was found.
	if len(targets) > 0 {
		return s.scanTargets(ctx, apiClient, targets, chunksChan)
	}

	gitlabReposScanned.WithLabelValues(s.name).Set(0)
	// Get repo within target.
	repos, errs := normalizeRepos(s.repos)
	for _, repoErr := range errs {
		ctx.Logger().Info("error normalizing repo", "error", repoErr)
	}

	// End early if we had errors getting specified repos but none were validated.
	if len(errs) > 0 && len(repos) == 0 {
		return fmt.Errorf("all specified repos had validation issues, ending scan")
	}

	// Get all repos if not specified.
	if len(repos) == 0 {
		ctx.Logger().Info("no repositories configured, enumerating")
		ignoreRepo := buildIgnorer(s.includeRepos, s.ignoreRepos, func(err error, pattern string) {
			ctx.Logger().Error(err, "could not compile include/exclude repo glob", "glob", pattern)
		})
		reporter := sources.VisitorReporter{
			VisitUnit: func(ctx context.Context, unit sources.SourceUnit) error {
				id, _ := unit.SourceUnitID()
				repos = append(repos, id)
				return ctx.Err()
			},
		}
		if err := s.getAllProjectRepos(ctx, apiClient, ignoreRepo, reporter); err != nil {
			return err
		}
	} else {
		gitlabReposEnumerated.WithLabelValues(s.name).Set(float64(len(repos)))
	}

	s.repos = repos
	// We must sort the repos so we can resume later if necessary.
	slices.Sort(s.repos)

	return s.scanRepos(ctx, chunksChan)
}

func (s *Source) scanTargets(ctx context.Context, client *gitlab.Client, targets []sources.ChunkingTarget, chunksChan chan *sources.Chunk) error {
	ctx = context.WithValues(ctx, "scan_type", "targeted")
	for _, tgt := range targets {
		if err := s.scanTarget(ctx, client, tgt, chunksChan); err != nil {
			ctx.Logger().Error(err, "error scanning target")
		}
	}

	return nil
}

func (s *Source) scanTarget(ctx context.Context, client *gitlab.Client, target sources.ChunkingTarget, chunksChan chan *sources.Chunk) error {
	metaType, ok := target.QueryCriteria.GetData().(*source_metadatapb.MetaData_Gitlab)
	if !ok {
		return fmt.Errorf("unable to cast metadata type for targeted scan")
	}
	meta := metaType.Gitlab
	projID, sha := int(meta.GetProjectId()), meta.GetCommit()
	if projID == 0 || sha == "" {
		return fmt.Errorf("project ID and commit SHA must be provided for targeted scan")
	}

	aCtx := context.WithValues(ctx, "project_id", projID, "commit", sha)

	diffs, _, err := client.Commits.GetCommitDiff(projID, sha, new(gitlab.GetCommitDiffOptions), gitlab.WithContext(ctx))
	if err != nil {
		return fmt.Errorf("error fetching diffs for commit %s: %w", sha, err)
	}

	for _, diff := range diffs {
		if diff.Diff == "" {
			aCtx.Logger().V(4).Info("skipping empty diff", "file", diff.NewPath)
			continue
		}

		chunk := &sources.Chunk{
			SourceType: s.Type(),
			SourceName: s.name,
			SourceID:   s.SourceID(),
			JobID:      s.JobID(),
			SecretID:   target.SecretID,
			Data:       []byte(diff.Diff),
			SourceMetadata: &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_Gitlab{Gitlab: meta},
			},
			Verify: s.verify,
		}

		if err := common.CancellableWrite(ctx, chunksChan, chunk); err != nil {
			return err
		}
	}

	return nil
}

func (s *Source) Validate(ctx context.Context) []error {
	// The client is only used to query Gitlab for a repo list - it's not used to actually clone anything. Thus, we
	// don't use it if there is a list of explicitly configured repos. However, constructing it validates that the
	// configured authentication method is sensible, so we'll do it here.
	apiClient, err := s.newClient()
	if err != nil {
		return []error{err}
	}

	_, _, err = apiClient.Users.CurrentUser()
	if err != nil {
		return []error{fmt.Errorf("gitlab authentication failed using method %v: %w", s.authMethod, err)}
	}

	explicitlyConfiguredRepos, errs := normalizeRepos(s.repos)

	if len(explicitlyConfiguredRepos) > 0 {
		user := s.user
		if user == "" {
			user = "placeholder"
		}

		// We only check reachability for explicitly configured repositories. The purpose of source validation is to
		// help users validate their configuration files, and Gitlab telling us about repositories that it won't let us
		// access isn't a local configuration issue.
		for _, r := range explicitlyConfiguredRepos {
			if err := git.PingRepoUsingToken(ctx, s.token, r, user); err != nil {
				err = fmt.Errorf("could not reach git repository %q: %w", r, err)
				errs = append(errs, err)
			}
		}

		if len(s.ignoreRepos) > 0 {
			errs = append(
				errs,
				fmt.Errorf("both repositories and ignore patterns were explicitly configured; ignore patterns will not be used"),
			)
		}
	}

	if len(explicitlyConfiguredRepos) > 0 || len(errs) > 0 {
		return errs
	}

	ignoreProject := buildIgnorer(s.includeRepos, s.ignoreRepos, func(err error, pattern string) {
		errs = append(errs, fmt.Errorf("could not compile include/exclude repo pattern %q: %w", pattern, err))
	})

	// Query GitLab for the list of configured repos.
	var repos []string
	visitor := sources.VisitorReporter{
		VisitUnit: func(ctx context.Context, unit sources.SourceUnit) error {
			id, _ := unit.SourceUnitID()
			repos = append(repos, id)
			return nil
		},
	}
	if err := s.getAllProjectRepos(ctx, apiClient, ignoreProject, visitor); err != nil {
		errs = append(errs, err)
		return errs
	}

	if len(repos) == 0 {
		errs = append(errs, fmt.Errorf("ignore patterns excluded all projects"))
	}

	return errs
}

func (s *Source) newClient() (*gitlab.Client, error) {
	// Initialize a new api instance.
	switch s.authMethod {
	case "OAUTH":
		apiClient, err := gitlab.NewOAuthClient(s.token, gitlab.WithBaseURL(s.url))
		if err != nil {
			return nil, fmt.Errorf("could not create Gitlab OAUTH client for %q: %w", s.url, err)
		}
		return apiClient, nil

	case "BASIC_AUTH":
		apiClient, err := gitlab.NewBasicAuthClient(s.user, s.password, gitlab.WithBaseURL(s.url))
		if err != nil {
			return nil, fmt.Errorf("could not create Gitlab BASICAUTH client for %q: %w", s.url, err)
		}
		// If the user is using an access_token rather than a username/password, then basic auth
		// will not work. In this case, we test to see if basic auth would work, and if it does not,
		// we proceed with an OAuth client using the access_token (s.password) as the token.
		// At this point, s.token is already set to s.password
		if s.basicAuthSuccessful(apiClient) {
			return apiClient, nil
		}
		fallthrough
	case "TOKEN":
		apiClient, err := gitlab.NewOAuthClient(s.token, gitlab.WithBaseURL(s.url))
		if err != nil {
			return nil, fmt.Errorf("could not create Gitlab TOKEN client for %q: %w", s.url, err)
		}
		return apiClient, nil

	default:
		return nil, fmt.Errorf("invalid auth method %q", s.authMethod)
	}
}

func (s *Source) basicAuthSuccessful(apiClient *gitlab.Client) bool {
	user, resp, err := apiClient.Users.CurrentUser()
	if err != nil {
		return false
	}
	if resp.StatusCode != 200 {
		return false
	}
	if user != nil {
		return true
	}
	return false
}

// getAllProjectRepos enumerates all GitLab projects using the provided API
// client. The reporter is used to report the valid repository found for
// projects that are not ignored.
func (s *Source) getAllProjectRepos(
	ctx context.Context,
	apiClient *gitlab.Client,
	ignoreRepo func(string) bool,
	reporter sources.UnitReporter,
) error {
	gitlabReposEnumerated.WithLabelValues(s.name).Set(0)

	// Projects without repo will get user projects, groups projects, and subgroup projects.
	user, _, err := apiClient.Users.CurrentUser()
	if err != nil {
		return fmt.Errorf("unable to authenticate using %s: %w", s.authMethod, err)
	}

	uniqueProjects := make(map[int]*gitlab.Project)
	// Record the projectsWithNamespace for logging.
	var projectsWithNamespace []string

	// Used to filter out duplicate projects.
	processProjects := func(ctx context.Context, projList []*gitlab.Project) error {
		for _, proj := range projList {
			ctx := context.WithValues(ctx,
				"project_id", proj.ID,
				"project_name", proj.NameWithNamespace)
			// Skip projects we've already seen.
			if _, exists := uniqueProjects[proj.ID]; exists {
				ctx.Logger().V(3).Info("skipping project", "reason", "ID already seen")
				continue
			}
			// Skip projects configured to be ignored.
			if ignoreRepo(proj.PathWithNamespace) {
				ctx.Logger().V(3).Info("skipping project", "reason", "ignored in config")
				continue
			}
			// Record that we've seen this project.
			uniqueProjects[proj.ID] = proj
			// Report an error if we could not convert the project into a URL.
			if _, err := url.Parse(proj.HTTPURLToRepo); err != nil {
				ctx.Logger().V(3).Info("skipping project",
					"reason", "URL parse failure",
					"url", proj.HTTPURLToRepo,
					"parse_error", err)

				err = fmt.Errorf("could not parse url %q given by project: %w", proj.HTTPURLToRepo, err)
				if err := reporter.UnitErr(ctx, err); err != nil {
					return err
				}
				continue
			}
			// Report the unit.
			ctx.Logger().V(3).Info("accepting project")
			unit := git.SourceUnit{Kind: git.UnitRepo, ID: proj.HTTPURLToRepo}
			gitlabReposEnumerated.WithLabelValues(s.name).Inc()
			projectsWithNamespace = append(projectsWithNamespace, proj.NameWithNamespace)
			if err := reporter.UnitOk(ctx, unit); err != nil {
				return err
			}
		}
		return nil
	}

	const (
		orderBy         = "id" // TODO: Use keyset pagination (https://docs.gitlab.com/ee/api/rest/index.html#keyset-based-pagination)
		paginationLimit = 100  // Default is 20, max is 100.
	)
	listOpts := gitlab.ListOptions{PerPage: paginationLimit}

	projectQueryOptions := &gitlab.ListProjectsOptions{OrderBy: gitlab.Ptr(orderBy), ListOptions: listOpts}
	for {
		userProjects, res, err := apiClient.Projects.ListUserProjects(user.ID, projectQueryOptions)
		if err != nil {
			err = fmt.Errorf("received error on listing user projects: %w", err)
			if err := reporter.UnitErr(ctx, err); err != nil {
				return err
			}
			break
		}
		ctx.Logger().V(3).Info("listed user projects", "count", len(userProjects))
		if err := processProjects(ctx, userProjects); err != nil {
			return err
		}
		projectQueryOptions.Page = res.NextPage
		if res.NextPage == 0 {
			break
		}
	}

	listGroupsOptions := gitlab.ListGroupsOptions{
		ListOptions:  listOpts,
		AllAvailable: gitlab.Ptr(false), // This actually grabs public groups on public GitLab if set to true.
		TopLevelOnly: gitlab.Ptr(false),
		Owned:        gitlab.Ptr(false),
	}

	if s.url != gitlabBaseURL {
		listGroupsOptions.AllAvailable = gitlab.Ptr(true)
	}

	ctx.Logger().Info("beginning group enumeration",
		"list_options", listOpts,
		"all_available", *listGroupsOptions.AllAvailable)
	gitlabGroupsEnumerated.WithLabelValues(s.name).Set(0)

	var groups []*gitlab.Group
	for {
		groupList, res, err := apiClient.Groups.ListGroups(&listGroupsOptions)
		if err != nil {
			err = fmt.Errorf("received error on listing groups, you probably don't have permissions to do that: %w", err)
			if err := reporter.UnitErr(ctx, err); err != nil {
				return err
			}
			break
		}
		ctx.Logger().V(3).Info("listed groups", "count", len(groupList))
		groups = append(groups, groupList...)
		gitlabGroupsEnumerated.WithLabelValues(s.name).Add(float64(len(groupList)))
		listGroupsOptions.Page = res.NextPage
		if res.NextPage == 0 {
			break
		}
	}

	ctx.Logger().Info("got groups", "group_count", len(groups))

	for _, group := range groups {
		ctx := context.WithValue(ctx, "group_id", group.ID)
		listGroupProjectOptions := &gitlab.ListGroupProjectsOptions{
			ListOptions:      listOpts,
			OrderBy:          gitlab.Ptr(orderBy),
			IncludeSubGroups: gitlab.Ptr(true),
			WithShared:       gitlab.Ptr(s.enumerateSharedProjects),
		}
		for {
			grpPrjs, res, err := apiClient.Groups.ListGroupProjects(group.ID, listGroupProjectOptions)
			if err != nil {
				err = fmt.Errorf(
					"received error on listing group projects for %q, you probably don't have permissions to do that: %w",
					group.FullPath, err,
				)
				if err := reporter.UnitErr(ctx, err); err != nil {
					return err
				}
				break
			}
			ctx.Logger().V(3).Info("listed group projects", "count", len(grpPrjs))
			if err := processProjects(ctx, grpPrjs); err != nil {
				return err
			}
			listGroupProjectOptions.Page = res.NextPage
			if res.NextPage == 0 {
				break
			}
		}
	}

	ctx.Logger().Info("Enumerated GitLab projects", "count", len(projectsWithNamespace))

	return nil
}

func (s *Source) scanRepos(ctx context.Context, chunksChan chan *sources.Chunk) error {
	// If there is resume information available, limit this scan to only the repos that still need scanning.
	reposToScan, progressIndexOffset := sources.FilterReposToResume(s.repos, s.GetProgress().EncodedResumeInfo)
	ctx.Logger().V(2).Info("filtered repos to resume", "before", len(s.repos), "after", len(reposToScan))
	s.repos = reposToScan
	scanErrs := sources.NewScanErrors()

	for i, repo := range s.repos {
		repoURL := repo
		s.jobPool.Go(func() error {
			logger := ctx.Logger().WithValues("repo", repoURL)
			if common.IsDone(ctx) {
				// We are returning nil instead of the scanErrors slice here because
				// we don't want to mark this scan as errored if we cancelled it.
				logger.V(2).Info("Skipping repo because context was cancelled")
				return nil
			}

			if len(repoURL) == 0 {
				logger.V(2).Info("Skipping empty repo")
				return nil
			}

			s.setProgressCompleteWithRepo(i, progressIndexOffset, repoURL)
			// Ensure the repo is removed from the resume info after being scanned.
			defer func(s *Source) {
				s.resumeInfoMutex.Lock()
				defer s.resumeInfoMutex.Unlock()
				s.resumeInfoSlice = sources.RemoveRepoFromResumeInfo(s.resumeInfoSlice, repoURL)
			}(s)

			var path string
			var repo *gogit.Repository
			var err error
			if s.authMethod == "UNAUTHENTICATED" {
				path, repo, err = git.CloneRepoUsingUnauthenticated(ctx, repoURL)
			} else {
				// If a username is not provided we need to use a default one in order to clone a private repo.
				// Not setting "placeholder" as s.user on purpose in case any downstream services rely on a "" value for s.user.
				user := s.user
				if user == "" {
					user = "placeholder"
				}
				path, repo, err = git.CloneRepoUsingToken(ctx, s.token, repoURL, user)
			}
			if err != nil {
				scanErrs.Add(err)
				return nil
			}
			defer os.RemoveAll(path)

			logger.V(2).Info("starting scan", "num", i+1, "total", len(s.repos))
			if err = s.git.ScanRepo(ctx, repo, path, s.scanOptions, sources.ChanReporter{Ch: chunksChan}); err != nil {
				scanErrs.Add(err)
				return nil
			}
			gitlabReposScanned.WithLabelValues(s.name).Inc()

			logger.V(2).Info("completed scan", "num", i+1, "total", len(s.repos))
			return nil
		})
	}

	_ = s.jobPool.Wait()
	if scanErrs.Count() > 0 {
		ctx.Logger().V(2).Info("encountered errors while scanning", "count", scanErrs.Count(), "errors", scanErrs)
	}
	s.SetProgressComplete(len(s.repos), len(s.repos), "Completed Gitlab scan", "")

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

	// Add the offset to both the index and the repos to give the proper place and proper repo count.
	s.SetProgressComplete(index+offset, len(s.repos)+offset, fmt.Sprintf("Repo: %s", repoURL), encodedResumeInfo)
}

func (s *Source) WithScanOptions(scanOptions *git.ScanOptions) {
	s.scanOptions = scanOptions
}

func buildIgnorer(include, exclude []string, onCompile func(err error, pattern string)) func(repo string) bool {

	// compile and load globRepoFilter
	globRepoFilter := newGlobRepoFilter(include, exclude, onCompile)

	f := func(repo string) bool {
		if !globRepoFilter.includeRepo(repo) || globRepoFilter.ignoreRepo(repo) {
			return true
		}
		return false
	}

	return f
}

func normalizeRepos(repos []string) ([]string, []error) {
	// Optimistically allocate space for all valid repositories.
	validRepos := make([]string, 0, len(repos))
	var errs []error
	for _, prj := range repos {
		repo, err := giturl.NormalizeGitlabRepo(prj)
		if err != nil {
			errs = append(errs, fmt.Errorf("unable to normalize gitlab repo url %q: %w", prj, err))
			continue
		}

		validRepos = append(validRepos, repo)
	}
	return validRepos, errs
}

// normalizeGitlabEndpoint ensures that if an endpoint is going to gitlab.com, we use https://gitlab.com/ as the endpoint.
// If we see the protocol is http, we error, because this shouldn't be used.
// Otherwise, it ensures we are using https as our protocol, if none was provided.
func normalizeGitlabEndpoint(gitlabEndpoint string) (string, error) {
	if gitlabEndpoint == "" {
		return gitlabBaseURL, nil
	}

	gitlabURL, err := url.Parse(gitlabEndpoint)
	if err != nil {
		return "", err
	}

	// We probably didn't receive a URL with a scheme, which messed up the parsing.
	if gitlabURL.Host == "" {
		gitlabURL, err = url.Parse("https://" + gitlabEndpoint)
		if err != nil {
			return "", err
		}
	}

	// If the host is gitlab.com, this is the cloud version, which has only one valid endpoint.
	if gitlabURL.Host == "gitlab.com" {
		return gitlabBaseURL, nil
	}

	// Beyond here, on-prem gitlab is being used, so we have to mostly leave things as-is.

	if gitlabURL.Scheme != "https" {
		return "", fmt.Errorf("https was not used as URL scheme, but is required. Please use https")
	}

	// The gitlab library wants trailing slashes.
	if !strings.HasSuffix(gitlabURL.Path, "/") {
		gitlabURL.Path = gitlabURL.Path + "/"
	}

	return gitlabURL.String(), nil
}

// Enumerate reports all GitLab repositories to be scanned to the reporter. If
// none are configured, it will find all repositories within all projects that
// the configured user has access to, while respecting the configured ignore
// rules.
func (s *Source) Enumerate(ctx context.Context, reporter sources.UnitReporter) error {
	// Start client.
	apiClient, err := s.newClient()
	if err != nil {
		return err
	}

	// Get repos within target.
	repos, errs := normalizeRepos(s.repos)
	for _, repoErr := range errs {
		ctx.Logger().Info("error normalizing repo", "error", repoErr)
		if err := reporter.UnitErr(ctx, repoErr); err != nil {
			return err
		}
	}

	// End early if we had errors getting specified repos but none were validated.
	if len(errs) > 0 && len(repos) == 0 {
		return fmt.Errorf("all configured repos had validation issues")
	}

	// Report all repos if specified.
	if len(repos) > 0 {
		gitlabReposEnumerated.WithLabelValues(s.name).Set(0)
		for _, repo := range repos {
			unit := git.SourceUnit{Kind: git.UnitRepo, ID: repo}
			if err := reporter.UnitOk(ctx, unit); err != nil {
				return err
			}
			gitlabReposEnumerated.WithLabelValues(s.name).Inc()
		}
		return nil
	}

	// Otherwise, enumerate all repos.
	ignoreRepo := buildIgnorer(s.includeRepos, s.ignoreRepos, func(err error, pattern string) {
		ctx.Logger().Error(err, "could not compile include/exclude repo glob", "glob", pattern)
		// TODO: Handle error returned from UnitErr.
		_ = reporter.UnitErr(ctx, fmt.Errorf("could not compile include/exclude repo glob: %w", err))
	})
	return s.getAllProjectRepos(ctx, apiClient, ignoreRepo, reporter)
}

// ChunkUnit downloads and reports chunks for the given GitLab repository unit.
func (s *Source) ChunkUnit(ctx context.Context, unit sources.SourceUnit, reporter sources.ChunkReporter) error {
	repoURL, _ := unit.SourceUnitID()

	var path string
	var repo *gogit.Repository
	var err error
	if s.authMethod == "UNAUTHENTICATED" {
		path, repo, err = git.CloneRepoUsingUnauthenticated(ctx, repoURL)
	} else {
		// If a username is not provided we need to use a default one in order to clone a private repo.
		// Not setting "placeholder" as s.user on purpose in case any downstream services rely on a "" value for s.user.
		user := s.user
		if user == "" {
			user = "placeholder"
		}
		path, repo, err = git.CloneRepoUsingToken(ctx, s.token, repoURL, user)
	}
	if err != nil {
		return err
	}
	defer os.RemoveAll(path)

	return s.git.ScanRepo(ctx, repo, path, s.scanOptions, reporter)
}
