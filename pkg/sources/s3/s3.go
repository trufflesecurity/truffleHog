package s3

import (
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/go-errors/errors"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/handlers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/log"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sanitizer"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

const (
	SourceType = sourcespb.SourceType_SOURCE_TYPE_S3

	defaultAWSRegion     = "us-east-1"
	defaultMaxObjectSize = 250 * 1024 * 1024 // 250 MiB
	maxObjectSizeLimit   = 250 * 1024 * 1024 // 250 MiB
)

type Source struct {
	name        string
	sourceID    sources.SourceID
	jobID       sources.JobID
	verify      bool
	concurrency int
	conn        *sourcespb.S3

	progressTracker *ProgressTracker
	sources.Progress

	errorCount    *sync.Map
	jobPool       *errgroup.Group
	maxObjectSize int64

	sources.CommonSourceUnitUnmarshaller
}

// Ensure the Source satisfies the interfaces at compile time
var _ sources.Source = (*Source)(nil)
var _ sources.SourceUnitUnmarshaller = (*Source)(nil)
var _ sources.Validator = (*Source)(nil)

// Type returns the type of source
func (s *Source) Type() sourcespb.SourceType { return SourceType }

func (s *Source) SourceID() sources.SourceID { return s.sourceID }

func (s *Source) JobID() sources.JobID { return s.jobID }

// Init returns an initialized AWS source
func (s *Source) Init(
	ctx context.Context,
	name string,
	jobID sources.JobID,
	sourceID sources.SourceID,
	verify bool,
	connection *anypb.Any,
	concurrency int,
) error {
	s.name = name
	s.sourceID = sourceID
	s.jobID = jobID
	s.verify = verify
	s.concurrency = concurrency
	s.errorCount = &sync.Map{}
	s.jobPool = &errgroup.Group{}
	s.jobPool.SetLimit(concurrency)

	var conn sourcespb.S3
	if err := anypb.UnmarshalTo(connection, &conn, proto.UnmarshalOptions{}); err != nil {
		return fmt.Errorf("error unmarshalling connection: %w", err)
	}
	s.conn = &conn

	s.progressTracker = NewProgressTracker(ctx, conn.GetEnableResumption(), &s.Progress)

	s.setMaxObjectSize(conn.GetMaxObjectSize())

	if len(conn.GetBuckets()) > 0 && len(conn.GetIgnoreBuckets()) > 0 {
		return errors.New("either a bucket include list or a bucket ignore list can be specified, but not both")
	}

	return nil
}

func (s *Source) Validate(ctx context.Context) []error {
	var errs []error
	visitor := func(c context.Context, defaultRegionClient *s3.S3, roleArn string, buckets []string) error {
		roleErrs := s.validateBucketAccess(c, defaultRegionClient, roleArn, buckets)
		if len(roleErrs) > 0 {
			errs = append(errs, roleErrs...)
		}
		return nil
	}

	if err := s.visitRoles(ctx, visitor); err != nil {
		errs = append(errs, err)
	}

	return errs
}

// setMaxObjectSize sets the maximum size of objects that will be scanned. If
// not set, set to a negative number, or set larger than the
// maxObjectSizeLimit, the defaultMaxObjectSizeLimit will be used.
func (s *Source) setMaxObjectSize(maxObjectSize int64) {
	if maxObjectSize <= 0 || maxObjectSize > maxObjectSizeLimit {
		s.maxObjectSize = defaultMaxObjectSize
	} else {
		s.maxObjectSize = maxObjectSize
	}
}

func (s *Source) newClient(region, roleArn string) (*s3.S3, error) {
	cfg := aws.NewConfig()
	cfg.CredentialsChainVerboseErrors = aws.Bool(true)
	cfg.Region = aws.String(region)

	switch cred := s.conn.GetCredential().(type) {
	case *sourcespb.S3_SessionToken:
		cfg.Credentials = credentials.NewStaticCredentials(
			cred.SessionToken.GetKey(),
			cred.SessionToken.GetSecret(),
			cred.SessionToken.GetSessionToken(),
		)
		log.RedactGlobally(cred.SessionToken.GetSecret())
		log.RedactGlobally(cred.SessionToken.GetSessionToken())
	case *sourcespb.S3_AccessKey:
		cfg.Credentials = credentials.NewStaticCredentials(cred.AccessKey.GetKey(), cred.AccessKey.GetSecret(), "")
		log.RedactGlobally(cred.AccessKey.GetSecret())
	case *sourcespb.S3_Unauthenticated:
		cfg.Credentials = credentials.AnonymousCredentials
	default:
		// In all other cases, the AWS SDK will follow its normal waterfall logic to pick up credentials (i.e. they can
		// come from the environment or the credentials file or whatever else AWS gets up to).
	}

	if roleArn != "" {
		sess, err := session.NewSession(cfg)
		if err != nil {
			return nil, err
		}

		stsClient := sts.New(sess)
		cfg.Credentials = stscreds.NewCredentialsWithClient(stsClient, roleArn, func(p *stscreds.AssumeRoleProvider) {
			p.RoleSessionName = "trufflehog"
		})
	}

	sess, err := session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
		Config:            *cfg,
	})
	if err != nil {
		return nil, err
	}

	return s3.New(sess), nil
}

// getBucketsToScan returns a list of S3 buckets to scan.
// If the connection has a list of buckets specified, those are returned.
// Otherwise, it lists all buckets the client has access to and filters out the ignored ones.
// The list of buckets is sorted lexicographically to ensure consistent ordering,
// which allows resuming scanning from the same place if the scan is interrupted.
//
// Note: The IAM identity needs the s3:ListBuckets permission.
func (s *Source) getBucketsToScan(client *s3.S3) ([]string, error) {
	if buckets := s.conn.GetBuckets(); len(buckets) > 0 {
		slices.Sort(buckets)
		return buckets, nil
	}

	ignore := make(map[string]struct{}, len(s.conn.GetIgnoreBuckets()))
	for _, bucket := range s.conn.GetIgnoreBuckets() {
		ignore[bucket] = struct{}{}
	}

	res, err := client.ListBuckets(&s3.ListBucketsInput{})
	if err != nil {
		return nil, err
	}

	var bucketsToScan []string
	for _, bucket := range res.Buckets {
		name := *bucket.Name
		if _, ignored := ignore[name]; !ignored {
			bucketsToScan = append(bucketsToScan, name)
		}
	}
	slices.Sort(bucketsToScan)

	return bucketsToScan, nil
}

// workerSignal provides thread-safe tracking of cancellation state across multiple
// goroutines processing S3 bucket pages. It ensures graceful shutdown when the context
// is cancelled during bucket scanning operations.
//
// This type serves several key purposes:
//  1. AWS ListObjectsV2PagesWithContext requires a callback that can only return bool,
//     not error. workerSignal bridges this gap by providing a way to communicate
//     cancellation back to the caller.
//  2. The pageChunker spawns multiple concurrent workers to process objects within
//     each page. workerSignal enables these workers to detect and respond to
//     cancellation signals.
//  3. Ensures proper progress tracking by allowing the main scanning loop to detect
//     when workers have been cancelled and handle cleanup appropriately.
type workerSignal struct{ cancelled atomic.Bool }

// newWorkerSignal creates a new workerSignal
func newWorkerSignal() *workerSignal { return new(workerSignal) }

// MarkCancelled marks that a context cancellation was detected.
func (ws *workerSignal) MarkCancelled() { ws.cancelled.Store(true) }

// WasCancelled returns true if context cancellation was detected.
func (ws *workerSignal) WasCancelled() bool { return ws.cancelled.Load() }

// pageMetadata contains metadata about a single page of S3 objects being scanned.
type pageMetadata struct {
	bucket     string                  // The name of the S3 bucket being scanned
	pageNumber int                     // Current page number in the pagination sequence
	client     *s3.S3                  // AWS S3 client configured for the appropriate region
	page       *s3.ListObjectsV2Output // Contains the list of S3 objects in this page
}

// processingState tracks the state of concurrent S3 object processing.
type processingState struct {
	errorCount   *sync.Map     // Thread-safe map tracking errors per prefix
	objectCount  *uint64       // Total number of objects processed
	workerSignal *workerSignal // Coordinates cancellation across worker goroutines
}

func (s *Source) scanBuckets(
	ctx context.Context,
	client *s3.S3,
	role string,
	bucketsToScan []string,
	chunksChan chan *sources.Chunk,
) error {
	if role != "" {
		ctx = context.WithValue(ctx, "role", role)
	}
	var objectCount uint64

	// Determine starting point for resuming scan.
	resumePoint, err := s.progressTracker.GetResumePoint(ctx)
	if err != nil {
		return fmt.Errorf("failed to get resume point :%w", err)
	}

	startIdx, _ := slices.BinarySearch(bucketsToScan, resumePoint.CurrentBucket)

	// Create worker signal to track cancellation across page processing.
	workerSignal := newWorkerSignal()

	bucketsToScanCount := len(bucketsToScan)
	for i := startIdx; i < bucketsToScanCount; i++ {
		bucket := bucketsToScan[i]
		ctx := context.WithValue(ctx, "bucket", bucket)

		if common.IsDone(ctx) {
			return ctx.Err()
		}

		ctx.Logger().V(3).Info("Scanning bucket")

		s.SetProgressComplete(
			i,
			len(bucketsToScan),
			fmt.Sprintf("Bucket: %s", bucket),
			s.Progress.EncodedResumeInfo, // Do not set, resume handled by progressTracker
		)

		regionalClient, err := s.getRegionalClientForBucket(ctx, client, role, bucket)
		if err != nil {
			ctx.Logger().Error(err, "could not get regional client for bucket")
			continue
		}

		errorCount := sync.Map{}

		input := &s3.ListObjectsV2Input{Bucket: &bucket}
		if bucket == resumePoint.CurrentBucket && resumePoint.StartAfter != "" {
			input.StartAfter = &resumePoint.StartAfter
			ctx.Logger().V(3).Info(
				"Resuming bucket scan",
				"start_after", resumePoint.StartAfter,
			)
		}

		pageNumber := 1
		err = regionalClient.ListObjectsV2PagesWithContext(
			ctx,
			input,
			func(page *s3.ListObjectsV2Output, _ bool) bool {
				pageMetadata := pageMetadata{
					bucket:     bucket,
					pageNumber: pageNumber,
					client:     regionalClient,
					page:       page,
				}
				processingState := processingState{
					errorCount:   &errorCount,
					objectCount:  &objectCount,
					workerSignal: workerSignal,
				}
				s.pageChunker(ctx, pageMetadata, processingState, chunksChan)

				if workerSignal.WasCancelled() {
					return false // Stop pagination
				}

				pageNumber++
				return true
			})

		// Check if we stopped due to cancellation.
		if workerSignal.WasCancelled() {
			return ctx.Err()
		}

		if err != nil {
			if role == "" {
				ctx.Logger().Error(err, "could not list objects in bucket")
			} else {
				// Our documentation blesses specifying a role to assume without specifying buckets to scan, which will
				// often cause this to happen a lot (because in that case the scanner tries to scan every bucket in the
				// account, but the role probably doesn't have access to all of them). This makes it expected behavior
				// and therefore not an error.
				ctx.Logger().V(3).Info("could not list objects in bucket", "err", err)
			}
		}
	}

	s.SetProgressComplete(
		len(bucketsToScan),
		len(bucketsToScan),
		fmt.Sprintf("Completed scanning source %s. %d objects scanned.", s.name, objectCount),
		"",
	)

	return nil
}

// Chunks emits chunks of bytes over a channel.
func (s *Source) Chunks(ctx context.Context, chunksChan chan *sources.Chunk, _ ...sources.ChunkingTarget) error {
	visitor := func(c context.Context, defaultRegionClient *s3.S3, roleArn string, buckets []string) error {
		return s.scanBuckets(c, defaultRegionClient, roleArn, buckets, chunksChan)
	}

	return s.visitRoles(ctx, visitor)
}

func (s *Source) getRegionalClientForBucket(
	ctx context.Context,
	defaultRegionClient *s3.S3,
	role string,
	bucket string,
) (*s3.S3, error) {
	region, err := s3manager.GetBucketRegionWithClient(ctx, defaultRegionClient, bucket)
	if err != nil {
		return nil, fmt.Errorf("could not get s3 region for bucket: %s", bucket)
	}

	if region == defaultAWSRegion {
		return defaultRegionClient, nil
	}

	regionalClient, err := s.newClient(region, role)
	if err != nil {
		return nil, fmt.Errorf("could not create regional s3 client for bucket %s: %w", bucket, err)
	}

	return regionalClient, nil
}

// pageChunker emits chunks onto the given channel from a page.
func (s *Source) pageChunker(
	ctx context.Context,
	metadata pageMetadata,
	state processingState,
	chunksChan chan *sources.Chunk,
) {
	s.progressTracker.Reset()
	ctx = context.WithValues(ctx, "bucket", metadata.bucket, "page_number", metadata.pageNumber)

	for objIdx, obj := range metadata.page.Contents {
		if obj == nil {
			if err := s.progressTracker.UpdateObjectProgress(ctx, objIdx, metadata.bucket, metadata.page.Contents); err != nil {
				ctx.Logger().Error(err, "could not update progress for nil object")
			}
			continue
		}

		ctx = context.WithValues(ctx, "key", *obj.Key, "size", *obj.Size)

		if common.IsDone(ctx) {
			state.workerSignal.MarkCancelled()
			return
		}

		// Skip GLACIER and GLACIER_IR objects.
		if obj.StorageClass == nil || strings.Contains(*obj.StorageClass, "GLACIER") {
			ctx.Logger().V(5).Info("Skipping object in storage class", "storage_class", *obj.StorageClass)
			if err := s.progressTracker.UpdateObjectProgress(ctx, objIdx, metadata.bucket, metadata.page.Contents); err != nil {
				ctx.Logger().Error(err, "could not update progress for glacier object")
			}
			continue
		}

		// Ignore large files.
		if *obj.Size > s.maxObjectSize {
			ctx.Logger().V(5).Info("Skipping %d byte file (over maxObjectSize limit)")
			if err := s.progressTracker.UpdateObjectProgress(ctx, objIdx, metadata.bucket, metadata.page.Contents); err != nil {
				ctx.Logger().Error(err, "could not update progress for large file")
			}
			continue
		}

		// File empty file.
		if *obj.Size == 0 {
			ctx.Logger().V(5).Info("Skipping empty file")
			if err := s.progressTracker.UpdateObjectProgress(ctx, objIdx, metadata.bucket, metadata.page.Contents); err != nil {
				ctx.Logger().Error(err, "could not update progress for empty file")
			}
			continue
		}

		// Skip incompatible extensions.
		if common.SkipFile(*obj.Key) {
			ctx.Logger().V(5).Info("Skipping file with incompatible extension")
			if err := s.progressTracker.UpdateObjectProgress(ctx, objIdx, metadata.bucket, metadata.page.Contents); err != nil {
				ctx.Logger().Error(err, "could not update progress for incompatible file")
			}
			continue
		}

		s.jobPool.Go(func() error {
			defer common.RecoverWithExit(ctx)
			if common.IsDone(ctx) {
				state.workerSignal.MarkCancelled()
				return ctx.Err()
			}

			if strings.HasSuffix(*obj.Key, "/") {
				ctx.Logger().V(5).Info("Skipping directory")
				return nil
			}

			path := strings.Split(*obj.Key, "/")
			prefix := strings.Join(path[:len(path)-1], "/")

			nErr, ok := state.errorCount.Load(prefix)
			if !ok {
				nErr = 0
			}
			if nErr.(int) > 3 {
				ctx.Logger().V(2).Info("Skipped due to excessive errors")
				return nil
			}
			// Make sure we use a separate context for the GetObjectWithContext call.
			// This ensures that the timeout is isolated and does not affect any downstream operations. (e.g. HandleFile)
			const getObjectTimeout = 30 * time.Second
			objCtx, cancel := context.WithTimeout(ctx, getObjectTimeout)
			defer cancel()

			res, err := metadata.client.GetObjectWithContext(objCtx, &s3.GetObjectInput{
				Bucket: &metadata.bucket,
				Key:    obj.Key,
			})
			if err != nil {
				if !strings.Contains(err.Error(), "AccessDenied") {
					ctx.Logger().Error(err, "could not get S3 object")
				}
				// According to the documentation for GetObjectWithContext,
				// the response can be non-nil even if there was an error.
				// It's uncertain if the body will be nil in such cases,
				// but we'll close it if it's not.
				if res != nil && res.Body != nil {
					res.Body.Close()
				}

				nErr, ok := state.errorCount.Load(prefix)
				if !ok {
					nErr = 0
				}
				if nErr.(int) > 3 {
					ctx.Logger().V(3).Info("Skipped due to excessive errors")
					return nil
				}
				nErr = nErr.(int) + 1
				state.errorCount.Store(prefix, nErr)
				// too many consecutive errors on this page
				if nErr.(int) > 3 {
					ctx.Logger().V(2).Info("Too many consecutive errors, excluding prefix", "prefix", prefix)
				}
				return nil
			}
			defer res.Body.Close()

			email := "Unknown"
			if obj.Owner != nil {
				email = *obj.Owner.DisplayName
			}
			modified := obj.LastModified.String()
			chunkSkel := &sources.Chunk{
				SourceType: s.Type(),
				SourceName: s.name,
				SourceID:   s.SourceID(),
				JobID:      s.JobID(),
				SourceMetadata: &source_metadatapb.MetaData{
					Data: &source_metadatapb.MetaData_S3{
						S3: &source_metadatapb.S3{
							Bucket:    metadata.bucket,
							File:      sanitizer.UTF8(*obj.Key),
							Link:      sanitizer.UTF8(makeS3Link(metadata.bucket, *metadata.client.Config.Region, *obj.Key)),
							Email:     sanitizer.UTF8(email),
							Timestamp: sanitizer.UTF8(modified),
						},
					},
				},
				Verify: s.verify,
			}

			if err := handlers.HandleFile(ctx, res.Body, chunkSkel, sources.ChanReporter{Ch: chunksChan}); err != nil {
				ctx.Logger().Error(err, "error handling file")
				return nil
			}

			atomic.AddUint64(state.objectCount, 1)
			ctx.Logger().V(5).Info("S3 object scanned.", "object_count", state.objectCount)
			nErr, ok = state.errorCount.Load(prefix)
			if !ok {
				nErr = 0
			}
			if nErr.(int) > 0 {
				state.errorCount.Store(prefix, 0)
			}

			// Update progress after successful processing.
			if err := s.progressTracker.UpdateObjectProgress(ctx, objIdx, metadata.bucket, metadata.page.Contents); err != nil {
				ctx.Logger().Error(err, "could not update progress for scanned object")
			}

			return nil
		})
	}

	_ = s.jobPool.Wait()
}

func (s *Source) validateBucketAccess(ctx context.Context, client *s3.S3, roleArn string, buckets []string) []error {
	shouldHaveAccessToAllBuckets := roleArn == ""
	wasAbleToListAnyBucket := false
	var errs []error

	for _, bucket := range buckets {
		if common.IsDone(ctx) {
			return append(errs, ctx.Err())
		}

		regionalClient, err := s.getRegionalClientForBucket(ctx, client, roleArn, bucket)
		if err != nil {
			errs = append(errs, fmt.Errorf("could not get regional client for bucket %q: %w", bucket, err))
			continue
		}

		_, err = regionalClient.ListObjectsV2(&s3.ListObjectsV2Input{Bucket: &bucket})
		if err == nil {
			wasAbleToListAnyBucket = true
		} else if shouldHaveAccessToAllBuckets {
			errs = append(errs, fmt.Errorf("could not list objects in bucket %q: %w", bucket, err))
		}
	}

	if !wasAbleToListAnyBucket {
		if roleArn == "" {
			errs = append(errs, errors.New("could not list objects in any bucket"))
		} else {
			errs = append(errs, fmt.Errorf("role %q could not list objects in any bucket", roleArn))
		}
	}

	return errs
}

// visitRoles iterates over the configured AWS roles and calls the provided function
// for each role, passing in the default S3 client, the role ARN, and the list of
// buckets to scan.
//
// The provided function parameter typically implements the core scanning logic
// and must handle context cancellation appropriately.
//
// If no roles are configured, it will call the function with an empty role ARN.
func (s *Source) visitRoles(
	ctx context.Context,
	f func(c context.Context, defaultRegionClient *s3.S3, roleArn string, buckets []string) error,
) error {
	roles := s.conn.GetRoles()
	if len(roles) == 0 {
		roles = []string{""}
	}

	for _, role := range roles {
		client, err := s.newClient(defaultAWSRegion, role)
		if err != nil {
			return fmt.Errorf("could not create s3 client: %w", err)
		}

		bucketsToScan, err := s.getBucketsToScan(client)
		if err != nil {
			return fmt.Errorf("role %q could not list any s3 buckets for scanning: %w", role, err)
		}

		if err := f(ctx, client, role, bucketsToScan); err != nil {
			return err
		}
	}

	return nil
}

// S3 links currently have the general format of:
// https://[bucket].s3[.region unless us-east-1].amazonaws.com/[key]
func makeS3Link(bucket, region, key string) string {
	if region == defaultAWSRegion {
		region = ""
	} else {
		region = "." + region
	}
	return fmt.Sprintf("https://%s.s3%s.amazonaws.com/%s", bucket, region, key)
}
