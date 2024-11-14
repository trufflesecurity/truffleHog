package huggingface

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-logr/logr"
	"github.com/gobwas/glob"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/cache"
	"github.com/trufflesecurity/trufflehog/v3/pkg/cache/simple"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/giturl"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sanitizer"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/git"
)

const (
	SourceType        = sourcespb.SourceType_SOURCE_TYPE_HUGGINGFACE
	DatasetsRoute     = "datasets"
	SpacesRoute       = "spaces"
	ModelsAPIRoute    = "models"
	DiscussionsRoute  = "discussions"
	APIRoute          = "api"
	DATASET           = "dataset"
	MODEL             = "model"
	SPACE             = "space"
	defaultPagination = 100
)

type resourceType string

type Source struct {
	name             string
	huggingfaceToken string

	sourceID               sources.SourceID
	jobID                  sources.JobID
	verify                 bool
	useCustomContentWriter bool
	orgsCache              cache.Cache[string]
	usersCache             cache.Cache[string]

	models   []string
	spaces   []string
	datasets []string

	filteredModelsCache   *filteredRepoCache
	filteredSpacesCache   *filteredRepoCache
	filteredDatasetsCache *filteredRepoCache

	repoInfoCache repoInfoCache

	git *git.Git

	scanOptions *git.ScanOptions

	apiClient       *HFClient
	log             logr.Logger
	conn            *sourcespb.Huggingface
	jobPool         *errgroup.Group
	resumeInfoMutex sync.Mutex
	resumeInfoSlice []string

	skipAllModels      bool
	skipAllSpaces      bool
	skipAllDatasets    bool
	includeDiscussions bool
	includePrs         bool

	sources.Progress
	sources.CommonSourceUnitUnmarshaller
}

// Ensure the Source satisfies the interfaces at compile time
var _ sources.Source = (*Source)(nil)
var _ sources.SourceUnitUnmarshaller = (*Source)(nil)

// WithCustomContentWriter sets the useCustomContentWriter flag on the source.
func (s *Source) WithCustomContentWriter() { s.useCustomContentWriter = true }

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

func (s *Source) newFilteredRepoCache(c cache.Cache[string], include, exclude []string) *filteredRepoCache {
	includeGlobs := make([]glob.Glob, 0, len(include))
	excludeGlobs := make([]glob.Glob, 0, len(exclude))
	for _, ig := range include {
		g, err := glob.Compile(ig)
		if err != nil {
			s.log.V(1).Info("invalid include glob", "include_value", ig, "err", err)
			continue
		}
		includeGlobs = append(includeGlobs, g)
	}
	for _, eg := range exclude {
		g, err := glob.Compile(eg)
		if err != nil {
			s.log.V(1).Info("invalid exclude glob", "exclude_value", eg, "err", err)
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

// Init returns an initialized HuggingFace source.
func (s *Source) Init(aCtx context.Context, name string, jobID sources.JobID, sourceID sources.SourceID, verify bool, connection *anypb.Any, concurrency int) error {
	err := git.CmdCheck()
	if err != nil {
		return err
	}

	s.log = aCtx.Logger()

	s.name = name
	s.sourceID = sourceID
	s.jobID = jobID
	s.verify = verify
	s.jobPool = &errgroup.Group{}
	s.jobPool.SetLimit(concurrency)

	var conn sourcespb.Huggingface
	err = anypb.UnmarshalTo(connection, &conn, proto.UnmarshalOptions{})
	if err != nil {
		return fmt.Errorf("error unmarshalling connection: %w", err)
	}
	s.conn = &conn

	s.orgsCache = simple.NewCache[string]()
	for _, org := range s.conn.Organizations {
		s.orgsCache.Set(org, org)
	}

	s.usersCache = simple.NewCache[string]()
	for _, user := range s.conn.Users {
		s.usersCache.Set(user, user)
	}

	// Verify ignore and include models, spaces, and datasets are valid
	// this ensures that calling --org <org> --ignore-model <org/model> contains the proper
	// repo format of org/model. Otherwise, we would scan the entire org.
	if err := s.validateIgnoreIncludeRepos(); err != nil {
		return err
	}

	s.filteredModelsCache = s.newFilteredRepoCache(simple.NewCache[string](),
		append(s.conn.GetModels(), s.conn.GetIncludeModels()...),
		s.conn.GetIgnoreModels(),
	)

	s.filteredSpacesCache = s.newFilteredRepoCache(simple.NewCache[string](),
		append(s.conn.GetSpaces(), s.conn.GetIncludeSpaces()...),
		s.conn.GetIgnoreSpaces(),
	)

	s.filteredDatasetsCache = s.newFilteredRepoCache(simple.NewCache[string](),
		append(s.conn.GetDatasets(), s.conn.GetIncludeDatasets()...),
		s.conn.GetIgnoreDatasets(),
	)

	s.models = initializeRepos(s.filteredModelsCache, s.conn.Models, fmt.Sprintf("%s/%s.git", s.conn.Endpoint, "%s"))
	s.spaces = initializeRepos(s.filteredSpacesCache, s.conn.Spaces, fmt.Sprintf("%s/%s/%s.git", s.conn.Endpoint, SpacesRoute, "%s"))
	s.datasets = initializeRepos(s.filteredDatasetsCache, s.conn.Datasets, fmt.Sprintf("%s/%s/%s.git", s.conn.Endpoint, DatasetsRoute, "%s"))
	s.repoInfoCache = newRepoInfoCache()

	s.includeDiscussions = s.conn.IncludeDiscussions
	s.includePrs = s.conn.IncludePrs

	cfg := &git.Config{
		SourceName:  s.name,
		JobID:       s.jobID,
		SourceID:    s.sourceID,
		SourceType:  s.Type(),
		Verify:      s.verify,
		Concurrency: concurrency,
		SourceMetadataFunc: func(file, email, commit, timestamp, repository string, line int64) *source_metadatapb.MetaData {
			return &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_Huggingface{
					Huggingface: &source_metadatapb.Huggingface{
						Commit:       sanitizer.UTF8(commit),
						File:         sanitizer.UTF8(file),
						Email:        sanitizer.UTF8(email),
						Repository:   sanitizer.UTF8(repository),
						Link:         giturl.GenerateLink(repository, commit, file, line),
						Timestamp:    sanitizer.UTF8(timestamp),
						Line:         line,
						Visibility:   s.visibilityOf(aCtx, repository),
						ResourceType: s.getResourceType(aCtx, repository),
					},
				},
			}
		},
		UseCustomContentWriter: s.useCustomContentWriter,
	}
	s.git = git.NewGit(cfg)

	s.huggingfaceToken = s.conn.GetToken()
	s.apiClient = NewHFClient(s.conn.Endpoint, s.huggingfaceToken, 10*time.Second)

	s.skipAllModels = s.conn.SkipAllModels
	s.skipAllSpaces = s.conn.SkipAllSpaces
	s.skipAllDatasets = s.conn.SkipAllDatasets

	return nil
}

func (s *Source) validateIgnoreIncludeRepos() error {
	if err := verifySlashSeparatedStrings(s.conn.IgnoreModels); err != nil {
		return err
	}
	if err := verifySlashSeparatedStrings(s.conn.IncludeModels); err != nil {
		return err
	}
	if err := verifySlashSeparatedStrings(s.conn.IgnoreSpaces); err != nil {
		return err
	}
	if err := verifySlashSeparatedStrings(s.conn.IncludeSpaces); err != nil {
		return err
	}
	if err := verifySlashSeparatedStrings(s.conn.IgnoreDatasets); err != nil {
		return err
	}
	if err := verifySlashSeparatedStrings(s.conn.IncludeDatasets); err != nil {
		return err
	}
	return nil
}

func verifySlashSeparatedStrings(s []string) error {
	for _, str := range s {
		if !strings.Contains(str, "/") {
			return fmt.Errorf("invalid owner/repo: %s", str)
		}
	}
	return nil
}

func initializeRepos(cache *filteredRepoCache, repos []string, urlPattern string) []string {
	returnRepos := make([]string, 0)
	for _, repo := range repos {
		if !cache.ignoreRepo(repo) {
			url := fmt.Sprintf(urlPattern, repo)
			cache.Set(repo, url)
			returnRepos = append(returnRepos, repo)
		}
	}
	return returnRepos
}

func (s *Source) getResourceType(ctx context.Context, repoURL string) string {
	repoInfo, ok := s.repoInfoCache.get(repoURL)
	if !ok {
		// This should never happen.
		err := fmt.Errorf("no repoInfo for URL: %s", repoURL)
		ctx.Logger().Error(err, "failed to get repository resource type")
		return ""
	}

	return string(repoInfo.resourceType)
}

func (s *Source) visibilityOf(ctx context.Context, repoURL string) source_metadatapb.Visibility {
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
	err := s.enumerate(ctx)
	if err != nil {
		return err
	}
	return s.scan(ctx, chunksChan)
}

func (s *Source) enumerate(ctx context.Context) error {
	s.enumerateAuthors(ctx)

	s.models = make([]string, 0, s.filteredModelsCache.Count())
	for _, repo := range s.filteredModelsCache.Keys() {
		if err := s.cacheRepoInfo(ctx, repo, MODEL, s.filteredModelsCache); err != nil {
			continue
		}
	}

	s.spaces = make([]string, 0, s.filteredSpacesCache.Count())
	for _, repo := range s.filteredSpacesCache.Keys() {
		if err := s.cacheRepoInfo(ctx, repo, SPACE, s.filteredSpacesCache); err != nil {
			continue
		}
	}

	s.datasets = make([]string, 0, s.filteredDatasetsCache.Count())
	for _, repo := range s.filteredDatasetsCache.Keys() {
		if err := s.cacheRepoInfo(ctx, repo, DATASET, s.filteredDatasetsCache); err != nil {
			continue
		}
	}

	s.log.Info("Completed enumeration", "num_models", len(s.models), "num_spaces", len(s.spaces), "num_datasets", len(s.datasets))

	// We must sort the repos so we can resume later if necessary.
	sort.Strings(s.models)
	sort.Strings(s.datasets)
	sort.Strings(s.spaces)
	return nil
}

func (s *Source) cacheRepoInfo(ctx context.Context, repo string, repoType string, repoCache *filteredRepoCache) error {
	repoURL, _ := repoCache.Get(repo)
	repoCtx := context.WithValue(ctx, repoType, repoURL)

	if _, ok := s.repoInfoCache.get(repoURL); !ok {
		repoCtx.Logger().V(2).Info("Caching " + repoType + " info")
		repo, err := s.apiClient.GetRepo(repoCtx, repo, repoType)
		if err != nil {
			repoCtx.Logger().Error(err, "failed to fetch "+repoType)
			return err
		}
		// check if repo empty
		if repo.RepoID == "" {
			repoCtx.Logger().Error(fmt.Errorf("no repo found for repo"), repoURL)
			return nil
		}
		s.repoInfoCache.put(repoURL, repoInfo{
			owner:        repo.Owner,
			name:         strings.Split(repo.RepoID, "/")[1],
			fullName:     repo.RepoID,
			visibility:   getVisibility(repo.IsPrivate),
			resourceType: resourceType(repoType),
		})
	}
	s.updateRepoLists(repoURL, repoType)
	return nil
}

func getVisibility(isPrivate bool) source_metadatapb.Visibility {
	if isPrivate {
		return source_metadatapb.Visibility_private
	}
	return source_metadatapb.Visibility_public
}

func (s *Source) updateRepoLists(repoURL string, repoType string) {
	switch repoType {
	case MODEL:
		s.models = append(s.models, repoURL)
	case SPACE:
		s.spaces = append(s.spaces, repoURL)
	case DATASET:
		s.datasets = append(s.datasets, repoURL)
	}
}

func (s *Source) fetchAndCacheRepos(ctx context.Context, resourceType string, org string) error {
	var repos []Repo
	var err error
	var url string
	var filteredCache *filteredRepoCache
	switch resourceType {
	case MODEL:
		filteredCache = s.filteredModelsCache
		url = fmt.Sprintf("%s/%s.git", s.conn.Endpoint, "%s")
		repos, err = s.apiClient.ListReposByAuthor(ctx, MODEL, org)
	case SPACE:
		filteredCache = s.filteredSpacesCache
		url = fmt.Sprintf("%s/%s/%s.git", s.conn.Endpoint, SpacesRoute, "%s")
		repos, err = s.apiClient.ListReposByAuthor(ctx, SPACE, org)
	case DATASET:
		filteredCache = s.filteredDatasetsCache
		url = fmt.Sprintf("%s/%s/%s.git", s.conn.Endpoint, DatasetsRoute, "%s")
		repos, err = s.apiClient.ListReposByAuthor(ctx, DATASET, org)
	}
	if err != nil {
		return err
	}

	for _, repo := range repos {
		repoURL := fmt.Sprintf(url, repo.RepoID)
		filteredCache.Set(repo.RepoID, repoURL)
		if err := s.cacheRepoInfo(ctx, repo.RepoID, resourceType, filteredCache); err != nil {
			continue
		}
	}
	return nil
}

func (s *Source) enumerateAuthors(ctx context.Context) {
	for _, org := range s.orgsCache.Keys() {
		orgCtx := context.WithValue(ctx, "organization", org)
		if !s.skipAllModels {
			if err := s.fetchAndCacheRepos(orgCtx, MODEL, org); err != nil {
				orgCtx.Logger().Error(err, "Failed to fetch models for organization")
				continue
			}
		}
		if !s.skipAllSpaces {
			if err := s.fetchAndCacheRepos(orgCtx, SPACE, org); err != nil {
				orgCtx.Logger().Error(err, "Failed to fetch spaces for organization")
				continue
			}
		}
		if !s.skipAllDatasets {
			if err := s.fetchAndCacheRepos(orgCtx, DATASET, org); err != nil {
				orgCtx.Logger().Error(err, "Failed to fetch datasets for organization")
				continue
			}
		}
	}
	for _, user := range s.usersCache.Keys() {
		userCtx := context.WithValue(ctx, "user", user)
		if !s.skipAllModels {
			if err := s.fetchAndCacheRepos(userCtx, MODEL, user); err != nil {
				userCtx.Logger().Error(err, "Failed to fetch models for user")
				continue
			}
		}
		if !s.skipAllSpaces {
			if err := s.fetchAndCacheRepos(userCtx, SPACE, user); err != nil {
				userCtx.Logger().Error(err, "Failed to fetch spaces for user")
				continue
			}
		}
		if !s.skipAllDatasets {
			if err := s.fetchAndCacheRepos(userCtx, DATASET, user); err != nil {
				userCtx.Logger().Error(err, "Failed to fetch datasets for user")
				continue
			}
		}
	}
}

func (s *Source) scanRepos(ctx context.Context, chunksChan chan *sources.Chunk, resourceType string) error {
	var scannedCount uint64 = 1

	repos := s.getReposListByType(resourceType)

	s.log.V(2).Info("Found "+resourceType+" to scan", "count", len(repos))

	// If there is resume information available, limit this scan to only the repos that still need scanning.
	reposToScan, progressIndexOffset := sources.FilterReposToResume(repos, s.GetProgress().EncodedResumeInfo)
	repos = reposToScan

	scanErrs := sources.NewScanErrors()

	if s.scanOptions == nil {
		s.scanOptions = &git.ScanOptions{}
	}

	for i, repoURL := range repos {
		s.jobPool.Go(func() error {
			if common.IsDone(ctx) {
				return nil
			}

			// TODO: set progress complete is being called concurrently with i
			s.setProgressCompleteWithRepo(i, progressIndexOffset, repoURL, resourceType, repos)
			// Ensure the repo is removed from the resume info after being scanned.
			defer func(s *Source, repoURL string) {
				s.resumeInfoMutex.Lock()
				defer s.resumeInfoMutex.Unlock()
				s.resumeInfoSlice = sources.RemoveRepoFromResumeInfo(s.resumeInfoSlice, repoURL)
			}(s, repoURL)

			// Scan the repository
			repoInfo, ok := s.repoInfoCache.get(repoURL)
			if !ok {
				// This should never happen.
				err := fmt.Errorf("no repoInfo for URL: %s", repoURL)
				s.log.Error(err, "failed to scan "+resourceType)
				return nil
			}
			repoCtx := context.WithValues(ctx, resourceType, repoURL)
			duration, err := s.cloneAndScanRepo(repoCtx, repoURL, repoInfo, chunksChan)
			if err != nil {
				scanErrs.Add(err)
				return nil
			}

			// Scan discussions and PRs, if enabled.
			if s.includeDiscussions || s.includePrs {
				if err = s.scanDiscussions(repoCtx, repoInfo, chunksChan); err != nil {
					scanErrs.Add(fmt.Errorf("error scanning discussions/PRs in repo %s: %w", repoURL, err))
					return nil
				}
			}

			repoCtx.Logger().V(2).Info(fmt.Sprintf("scanned %d/%d "+resourceType+"s", scannedCount, len(s.models)), "duration_seconds", duration)
			atomic.AddUint64(&scannedCount, 1)
			return nil
		})
	}

	_ = s.jobPool.Wait()
	if scanErrs.Count() > 0 {
		s.log.V(0).Info("failed to scan some repositories", "error_count", scanErrs.Count(), "errors", scanErrs.String())
	}
	s.SetProgressComplete(len(repos), len(repos), "Completed HuggingFace "+resourceType+" scan", "")
	return nil
}

func (s *Source) getReposListByType(resourceType string) []string {
	switch resourceType {
	case MODEL:
		return s.models
	case SPACE:
		return s.spaces
	case DATASET:
		return s.datasets
	}
	return nil
}

func (s *Source) scan(ctx context.Context, chunksChan chan *sources.Chunk) error {
	if err := s.scanRepos(ctx, chunksChan, MODEL); err != nil {
		return err
	}
	if err := s.scanRepos(ctx, chunksChan, SPACE); err != nil {
		return err
	}
	if err := s.scanRepos(ctx, chunksChan, DATASET); err != nil {
		return err
	}
	return nil
}

func (s *Source) cloneAndScanRepo(ctx context.Context, repoURL string, repoInfo repoInfo, chunksChan chan *sources.Chunk) (time.Duration, error) {
	ctx.Logger().V(2).Info("attempting to clone %s", repoInfo.resourceType)
	path, repo, err := s.cloneRepo(ctx, repoURL)
	if err != nil {
		return 0, err
	}
	defer os.RemoveAll(path)

	var logger logr.Logger
	logger.V(2).Info("scanning %s", repoInfo.resourceType)

	start := time.Now()
	if err = s.git.ScanRepo(ctx, repo, path, s.scanOptions, sources.ChanReporter{Ch: chunksChan}); err != nil {
		return 0, fmt.Errorf("error scanning repo %s: %w", repoURL, err)
	}
	return time.Since(start), nil
}

// setProgressCompleteWithRepo calls the s.SetProgressComplete after safely setting up the encoded resume info string.
func (s *Source) setProgressCompleteWithRepo(index int, offset int, repoURL string, resourceType string, repos []string) {
	s.resumeInfoMutex.Lock()
	defer s.resumeInfoMutex.Unlock()

	// Add the repoURL to the resume info slice.
	s.resumeInfoSlice = append(s.resumeInfoSlice, repoURL)
	sort.Strings(s.resumeInfoSlice)

	// Make the resume info string from the slice.
	encodedResumeInfo := sources.EncodeResumeInfo(s.resumeInfoSlice)
	s.SetProgressComplete(index+offset, len(repos)+offset, fmt.Sprintf("%ss: %s", resourceType, repoURL), encodedResumeInfo)
}

func (s *Source) scanDiscussions(ctx context.Context, repoInfo repoInfo, chunksChan chan *sources.Chunk) error {
	discussions, err := s.apiClient.ListDiscussions(ctx, repoInfo)
	if err != nil {
		return err
	}
	for _, discussion := range discussions.Discussions {
		if (discussion.IsPR && s.includePrs) || (!discussion.IsPR && s.includeDiscussions) {
			d, err := s.apiClient.GetDiscussionByID(ctx, repoInfo, discussion.GetID())
			if err != nil {
				return err
			}
			// Note: there is no discussion "description" or similar to chunk, only comments
			if err = s.chunkDiscussionComments(ctx, repoInfo, d, chunksChan); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Source) chunkDiscussionComments(ctx context.Context, repoInfo repoInfo, discussion Discussion, chunksChan chan *sources.Chunk) error {
	for _, comment := range discussion.Events {
		chunk := &sources.Chunk{
			SourceName: s.name,
			SourceID:   s.SourceID(),
			JobID:      s.JobID(),
			SourceType: s.Type(),
			SourceMetadata: &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_Huggingface{
					Huggingface: &source_metadatapb.Huggingface{
						Link:       sanitizer.UTF8(fmt.Sprintf("%s/%s#%s", s.conn.Endpoint, discussion.GetDiscussionPath(), comment.GetID())),
						Username:   sanitizer.UTF8(comment.GetAuthor()),
						Repository: sanitizer.UTF8(fmt.Sprintf("%s/%s", s.conn.Endpoint, discussion.GetGitPath())),
						Timestamp:  sanitizer.UTF8(comment.GetCreatedAt()),
						Visibility: repoInfo.visibility,
					},
				},
			},
			Data:   []byte(comment.Data.Latest.Raw),
			Verify: s.verify,
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case chunksChan <- chunk:
		}
	}
	return nil
}
