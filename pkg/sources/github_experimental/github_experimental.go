package github_experimental

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/go-logr/logr"
	"github.com/google/go-github/v67/github"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

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
	SourceType = sourcespb.SourceType_SOURCE_TYPE_GITHUB_EXPERIMENTAL
)

type Source struct {
	name                   string
	sourceID               sources.SourceID
	jobID                  sources.JobID
	verify                 bool
	repoInfoCache          repoInfoCache
	useCustomContentWriter bool
	git                    *git.Git
	scanOptions            *git.ScanOptions
	httpClient             *http.Client
	log                    logr.Logger
	conn                   *sourcespb.GitHubExperimental
	apiClient              *github.Client

	sources.Progress
	sources.CommonSourceUnitUnmarshaller
}

// WithCustomContentWriter sets the useCustomContentWriter flag on the source.
func (s *Source) WithCustomContentWriter() { s.useCustomContentWriter = true }

func (s *Source) WithScanOptions(scanOptions *git.ScanOptions) {
	s.scanOptions = scanOptions
}

// Ensure the Source satisfies the interfaces at compile time
var _ sources.Source = (*Source)(nil)
var _ sources.SourceUnitUnmarshaller = (*Source)(nil)

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

// Init returns an initialized GitHubExperimental source.
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

	s.httpClient = common.RetryableHTTPClientTimeout(60)
	s.apiClient = github.NewClient(s.httpClient)

	var conn sourcespb.GitHubExperimental
	err = anypb.UnmarshalTo(connection, &conn, proto.UnmarshalOptions{})
	if err != nil {
		return fmt.Errorf("error unmarshalling connection: %w", err)
	}
	s.conn = &conn
	s.conn.Repository, err = s.normalizeRepo(s.conn.Repository)
	if err != nil {
		return fmt.Errorf("error normalizing repo: %w", err)
	}

	s.repoInfoCache = newRepoInfoCache()

	cfg := &git.Config{
		SourceName:   s.name,
		JobID:        s.jobID,
		SourceID:     s.sourceID,
		SourceType:   s.Type(),
		Verify:       s.verify,
		SkipBinaries: false,
		SkipArchives: false,
		Concurrency:  concurrency,
		SourceMetadataFunc: func(repository, commit, ref, email, timestamp, file string, line int64) *source_metadatapb.MetaData {
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
	if s.conn.ObjectDiscovery {
		err := s.EnumerateAndScanAllObjects(ctx, chunksChan)
		return err
	}
	return nil
}

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
