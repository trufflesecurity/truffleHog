package sources

import (
	"sync"

	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
)

// Chunk contains data to be decoded and scanned along with context on where it came from.
type Chunk struct {
	// SourceName is the name of the Source that produced the chunk.
	SourceName string
	// SourceID is the ID of the source that the Chunk originated from.
	SourceID int64
	// SourceType is the type of Source that produced the chunk.
	SourceType sourcespb.SourceType
	// SourceMetadata holds the context of where the Chunk was found.
	SourceMetadata *source_metadatapb.MetaData

	// Data is the data to decode and scan.
	Data []byte
	// Verify specifies whether any secrets in the Chunk should be verified.
	Verify bool
}

// Source defines the interface required to implement a source chunker.
type Source interface {
	// Type returns the source type, used for matching against configuration and jobs.
	Type() sourcespb.SourceType
	// SourceID returns the initialized source ID used for tracking relationships in the DB.
	SourceID() int64
	// JobID returns the initialized job ID used for tracking relationships in the DB.
	JobID() int64
	// Init initializes the source.
	Init(aCtx context.Context, name string, jobId, sourceId int64, verify bool, connection *anypb.Any, concurrency int) error
	// Chunks emits data over a channel that is decoded and scanned for secrets.
	Chunks(ctx context.Context, chunksChan chan *Chunk) error
	// GetProgress is the completion progress (percentage) for Scanned Source.
	GetProgress() *Progress
}

// SourceUnitEnumChunker are the two required interfaces to support enumerating
// and chunking of units.
type SourceUnitEnumChunker interface {
	SourceUnitEnumerator
	SourceUnitChunker
}

// SourceUnitUnmarshaller defines an optional interface a Source can implement
// to support units coming from an external source.
type SourceUnitUnmarshaller interface {
	UnmarshalSourceUnit(data []byte) (SourceUnit, error)
}

// SourceUnitEnumerator defines an optional interface a Source can implement to
// support enumerating an initialized Source into SourceUnits.
type SourceUnitEnumerator interface {
	// Enumerate creates 0 or more units from an initialized source,
	// reporting them or any errors to the UnitReporter. This method is
	// synchronous but can be called in a goroutine to support concurrent
	// enumeration and chunking. An error should only be returned from this
	// method in the case of context cancellation, fatal source errors, or
	// errors returned by the reporter All other errors related to unit
	// enumeration are tracked by the UnitReporter.
	Enumerate(ctx context.Context, reporter UnitReporter) error
}

// UnitReporter defines the interface a source will use to report whether a
// unit was found during enumeration. Either method may be called any number of
// times. Implementors of this interface should allow for concurrent calls.
type UnitReporter interface {
	UnitOk(ctx context.Context, unit SourceUnit) error
	UnitErr(ctx context.Context, err error) error
}

// SourceUnitChunker defines an optional interface a Source can implement to
// support chunking a single SourceUnit.
type SourceUnitChunker interface {
	// ChunkUnit creates 0 or more chunks from a unit, reporting them or
	// any errors to the ChunkReporter. An error should only be returned
	// from this method in the case of context cancellation, fatal source
	// errors, or errors returned by the reporter. All other errors related
	// to unit chunking are tracked by the ChunkReporter.
	ChunkUnit(ctx context.Context, unit SourceUnit, reporter ChunkReporter) error
}

// ChunkReporter defines the interface a source will use to report whether a
// chunk was found during unit chunking. Either method may be called any number
// of times. Implementors of this interface should allow for concurrent calls.
type ChunkReporter interface {
	ChunkOk(ctx context.Context, chunk Chunk) error
	ChunkErr(ctx context.Context, err error) error
}

// SourceUnit is an object that represents a Source's unit of work. This is
// used as the output of enumeration, progress reporting, and job distribution.
type SourceUnit interface {
	// SourceUnitID uniquely identifies a source unit.
	SourceUnitID() string
}

// GCSConfig defines the optional configuration for a GCS source.
type GCSConfig struct {
	// CloudCred determines whether to use cloud credentials.
	// This can NOT be used with a secret.
	CloudCred,
	// WithoutAuth is a flag to indicate whether to use authentication.
	WithoutAuth bool
	// ApiKey is the API key to use to authenticate with the source.
	ApiKey,
	// ProjectID is the project ID to use to authenticate with the source.
	ProjectID,
	// ServiceAccount is the service account to use to authenticate with the source.
	ServiceAccount string
	// MaxObjectSize is the maximum object size to scan.
	MaxObjectSize int64
	// Concurrency is the number of concurrent workers to use to scan the source.
	Concurrency int
	// IncludeBuckets is a list of buckets to include in the scan.
	IncludeBuckets,
	// ExcludeBuckets is a list of buckets to exclude from the scan.
	ExcludeBuckets,
	// IncludeObjects is a list of objects to include in the scan.
	IncludeObjects,
	// ExcludeObjects is a list of objects to exclude from the scan.
	ExcludeObjects []string
}

// GitConfig defines the optional configuration for a git source.
type GitConfig struct {
	// RepoPath is the path to the repository to scan.
	RepoPath,
	// HeadRef is the head reference to use to scan from.
	HeadRef,
	// BaseRef is the base reference to use to scan from.
	BaseRef string
	// MaxDepth is the maximum depth to scan the source.
	MaxDepth int
	// Bare is an indicator to handle bare repositories properly.
	Bare bool
	// Filter is the filter to use to scan the source.
	Filter *common.Filter
	// ExcludeGlobs is a list of globs to exclude from the scan.
	// This differs from the Filter exclusions as ExcludeGlobs is applied at the `git log -p` level
	ExcludeGlobs []string

	SinceDate string
}

// GithubConfig defines the optional configuration for a github source.
type GithubConfig struct {
	// Endpoint is the endpoint of the source.
	Endpoint,
	// Token is the token to use to authenticate with the source.
	Token string
	// IncludeForks indicates whether to include forks in the scan.
	IncludeForks,
	// IncludeMembers indicates whether to include members in the scan.
	IncludeMembers bool
	// Concurrency is the number of concurrent workers to use to scan the source.
	Concurrency int
	// Repos is the list of repositories to scan.
	Repos,
	// Orgs is the list of organizations to scan.
	Orgs,
	// ExcludeRepos is a list of repositories to exclude from the scan.
	ExcludeRepos,
	// IncludeRepos is a list of repositories to include in the scan.
	IncludeRepos []string
	// Filter is the filter to use to scan the source.
	Filter *common.Filter
	// MaxDepth is the maximum depth to scan the source.
	// MaxDepth int
	SinceDate string
}

// GitlabConfig defines the optional configuration for a gitlab source.
type GitlabConfig struct {
	// Endpoint is the endpoint of the source.
	Endpoint,
	// Token is the token to use to authenticate with the source.
	Token string
	// Repos is the list of repositories to scan.
	Repos []string
	// Filter is the filter to use to scan the source.
	Filter *common.Filter
}

// FilesystemConfig defines the optional configuration for a filesystem source.
type FilesystemConfig struct {
	// Paths is the list of files and directories to scan.
	Paths []string
	// Filter is the filter to use to scan the source.
	Filter *common.Filter
}

// S3Config defines the optional configuration for an S3 source.
type S3Config struct {
	// CloudCred determines whether to use cloud credentials.
	// This can NOT be used with a secret.
	CloudCred bool
	// Key is any key to use to authenticate with the source.
	Key,
	// Secret is any secret to use to authenticate with the source.
	Secret,
	// Temporary session token associated with a temporary access key id and secret key.
	SessionToken string
	// Buckets is the list of buckets to scan.
	Buckets []string
	// MaxObjectSize is the maximum object size to scan.
	MaxObjectSize int64
}

// SyslogConfig defines the optional configuration for a syslog source.
type SyslogConfig struct {
	// Address used to connect to the source.
	Address,
	// Protocol used to connect to the source.
	Protocol,
	// CertPath is the path to the certificate to use to connect to the source.
	CertPath,
	// Format is the format used to connect to the source.
	Format,
	// KeyPath is the path to the key to use to connect to the source.
	KeyPath string
	// Concurrency is the number of concurrent workers to use to scan the source.
	Concurrency int
}

// Progress is used to update job completion progress across sources.
type Progress struct {
	mut               sync.Mutex
	PercentComplete   int64
	Message           string
	EncodedResumeInfo string
	SectionsCompleted int32
	SectionsRemaining int32
}

// Validator is an interface for validating a source. Sources can optionally implement this interface to validate
// their configuration.
type Validator interface {
	Validate() []error
}

// SetProgressComplete sets job progress information for a running job based on the highest level objects in the source.
// i is the current iteration in the loop of target scope
// scope should be the len(scopedItems)
// message is the public facing user information about the current progress
// encodedResumeInfo is an optional string representing any information necessary to resume the job if interrupted
func (p *Progress) SetProgressComplete(i, scope int, message, encodedResumeInfo string) {
	p.mut.Lock()
	defer p.mut.Unlock()

	p.Message = message
	p.EncodedResumeInfo = encodedResumeInfo
	p.SectionsCompleted = int32(i)
	p.SectionsRemaining = int32(scope)

	// If the iteration and scope are both 0, completion is 100%.
	if i == 0 && scope == 0 {
		p.PercentComplete = 100
		return
	}

	p.PercentComplete = int64((float64(i) / float64(scope)) * 100)
}

// GetProgress gets job completion percentage for metrics reporting.
func (p *Progress) GetProgress() *Progress {
	p.mut.Lock()
	defer p.mut.Unlock()
	return p
}
