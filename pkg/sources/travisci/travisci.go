package travisci

import (
	"fmt"
	"strconv"

	"github.com/go-errors/errors"
	"github.com/shuheiktgw/go-travis"
	"github.com/trufflesecurity/trufflehog/v3/pkg/log"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

const (
	SourceType = sourcespb.SourceType_SOURCE_TYPE_TRAVISCI

	baseURL = "https://api.travis-ci.com/"

	pageSize = 100
)

type Source struct {
	name     string
	sourceId sources.SourceID
	jobId    sources.JobID
	verify   bool
	jobPool  *errgroup.Group
	sources.Progress
	client *travis.Client
	sources.CommonSourceUnitUnmarshaller
	returnAfterFirstChunk bool
}

// Ensure the Source satisfies the interfaces at compile time.
var _ sources.Source = (*Source)(nil)
var _ sources.SourceUnitUnmarshaller = (*Source)(nil)

// Type returns the type of source.
// It is used for matching source types in configuration and job input.
func (s *Source) Type() sourcespb.SourceType {
	return SourceType
}

func (s *Source) SourceID() sources.SourceID {
	return s.sourceId
}

func (s *Source) JobID() sources.JobID {
	return s.jobId
}

// Init returns an initialized TravisCI source.
func (s *Source) Init(ctx context.Context, name string, jobId sources.JobID, sourceId sources.SourceID, verify bool, connection *anypb.Any, concurrency int) error {
	s.name = name
	s.sourceId = sourceId
	s.jobId = jobId
	s.verify = verify
	s.jobPool = &errgroup.Group{}
	s.jobPool.SetLimit(concurrency)

	var conn sourcespb.TravisCI
	if err := anypb.UnmarshalTo(connection, &conn, proto.UnmarshalOptions{}); err != nil {
		return errors.WrapPrefix(err, "error unmarshalling connection", 0)
	}

	switch conn.Credential.(type) {
	case *sourcespb.TravisCI_Token:
		if conn.GetToken() == "" {
			return errors.New("token is empty")
		}
		s.client = travis.NewClient(baseURL, conn.GetToken())
		s.client.HTTPClient = common.RetryableHTTPClientTimeout(3)
		log.RedactGlobally(conn.GetToken())

		user, _, err := s.client.User.Current(ctx, nil)
		if err != nil {
			return errors.WrapPrefix(err, "error getting testing travis client", 0)
		}
		ctx.Logger().V(2).Info("authenticated to Travis CI with user", "username", user.Login)
	default:
		return errors.New("credential type not implemented for Travis CI")
	}

	return nil
}

func (s *Source) Enumerate(ctx context.Context, reporter sources.UnitReporter) error {
	for repoPage := 0; ; repoPage++ {
		repositories, _, err := s.client.Repositories.List(ctx, &travis.RepositoriesOption{
			Limit:  pageSize,
			Offset: repoPage * pageSize,
		})
		if err != nil {
			if repoPage == 0 {
				return fmt.Errorf("error listing repositories: %w", err)
			}
			reporter.UnitErr(ctx, err)
		}

		if len(repositories) == 0 {
			break
		}

		for _, repo := range repositories {
			reporter.UnitOk(ctx, sources.CommonSourceUnit{
				ID:   strconv.Itoa(int(*repo.Id)),
				Kind: "repo",
			})
			ctx.Logger().V(2).Info("enumerated repository", "id", repo.Id, "name", repo.Name)
		}
	}

	return nil
}

// ChunkUnit implements SourceUnitChunker interface.
func (s *Source) ChunkUnit(ctx context.Context, unit sources.SourceUnit, reporter sources.ChunkReporter) error {
	repoURL, _ := unit.SourceUnitID()
	repo, _, err := s.client.Repositories.Find(ctx, repoURL, nil)
	if err != nil {
		return fmt.Errorf("error finding repository: %w", err)
	}
	logger := ctx.Logger().WithValues("repo", *repo.Name)
	logger.V(2).Info("scanning repository")

	// Counts continuous errors from ListByRepoSlug. Used to quit early in
	// case the API always returns an error.
	var buildPageErrs int
	for buildPage := 0; ; buildPage++ {
		builds, _, err := s.client.Builds.ListByRepoSlug(ctx, *repo.Slug, &travis.BuildsByRepoOption{
			Limit:  pageSize,
			Offset: buildPage * pageSize,
		})
		if err != nil {
			reporter.ChunkErr(ctx, err)
			buildPageErrs++
			if buildPageErrs >= 5 {
				return fmt.Errorf("encountered too many errors listing builds, aborting")
			}
			continue
		}
		// Reset the page error counter.
		buildPageErrs = 0

		if len(builds) == 0 {
			break
		}

		for _, build := range builds {
			jobs, _, err := s.client.Jobs.ListByBuild(ctx, *build.Id)
			if err != nil {
				reporter.ChunkErr(ctx, err)
				continue
			}

			if len(jobs) == 0 {
				break
			}

			for _, job := range jobs {
				log, _, err := s.client.Logs.FindByJobId(ctx, *job.Id)
				if err != nil {
					reporter.ChunkErr(ctx, err)
					continue
				}

				logger.V(3).Info("scanning job", "id", *job.Id, "number", *job.Number)

				chunk := sources.Chunk{
					SourceType: s.Type(),
					SourceName: s.name,
					SourceID:   s.SourceID(),
					JobID:      s.JobID(),
					Data:       []byte(*log.Content),
					SourceMetadata: &source_metadatapb.MetaData{
						Data: &source_metadatapb.MetaData_TravisCI{
							TravisCI: &source_metadatapb.TravisCI{
								Username:    *job.Owner.Login,
								Repository:  *repo.Name,
								BuildNumber: *build.Number,
								JobNumber:   *job.Number,
								Link:        fmt.Sprintf("https://app.travis-ci.com/github/%s/%s/jobs/%d", *job.Owner.Login, *repo.Name, *job.Id),
								Public:      !*repo.Private,
							},
						},
					},
					Verify: s.verify,
				}

				reporter.ChunkOk(ctx, chunk)

				if s.returnAfterFirstChunk {
					return nil
				}
			}
		}
	}

	return nil
}

// Chunks emits chunks of bytes over a channel.
// It's a no-op because we've implemented the SourceUnitChunker interface instead.
func (s *Source) Chunks(ctx context.Context, chunksChan chan *sources.Chunk, _ ...sources.ChunkingTarget) error {
	return nil
}
