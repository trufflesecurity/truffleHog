package sources

import (
	"sync"

	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
)

type (
	SourceID int64
	JobID    int64
)

// Chunk contains data to be decoded and scanned along with context on where it came from.
//
// **Important:** The order of the fields in this struct is specifically designed to optimize
// struct alignment and minimize memory usage. Do not change the field order without carefully considering
// the potential impact on memory consumption.
// Ex: https://go.dev/play/p/Azf4a7O-DhC
type Chunk struct {
	// Data is the data to decode and scan.
	Data []byte

	// SourceName is the name of the Source that produced the chunk.
	SourceName string
	// SourceID is the ID of the source that the Chunk originated from.
	SourceID SourceID
	// JobID is the ID of the job that the Chunk originated from.
	JobID JobID
	// SecretID is the ID of the secret, if it exists.
	// Only secrets that are being reverified will have a SecretID.
	SecretID int64

	// SourceMetadata holds the context of where the Chunk was found.
	SourceMetadata *source_metadatapb.MetaData
	// SourceType is the type of Source that produced the chunk.
	SourceType sourcespb.SourceType

	// Verify specifies whether any secrets in the Chunk should be verified.
	Verify bool
}

// GitSourceMetadata defines a common struct for Git-based source metadata.
type GitSourceMetadata struct {
	Repository string
	Commit     string
	File       string
}

func NewGitSourceMetadata(source sourcespb.SourceType, data *source_metadatapb.MetaData) (*GitSourceMetadata, bool) {
	if data == nil {
		return nil, false
	}

	switch source {
	case sourcespb.SourceType_SOURCE_TYPE_GIT:
		md := data.GetGit()
		return &GitSourceMetadata{md.GetRepository(), md.GetCommit(), md.GetFile()}, true
	case sourcespb.SourceType_SOURCE_TYPE_AZURE_REPOS:
		md := data.GetAzureRepos()
		return &GitSourceMetadata{md.GetRepository(), md.GetCommit(), md.GetFile()}, true
	case sourcespb.SourceType_SOURCE_TYPE_BITBUCKET:
		md := data.GetBitbucket()
		return &GitSourceMetadata{md.GetRepository(), md.GetCommit(), md.GetFile()}, true
	case sourcespb.SourceType_SOURCE_TYPE_GERRIT:
		md := data.GetGerrit()
		return &GitSourceMetadata{md.GetProject(), md.GetCommit(), md.GetFile()}, true
	case sourcespb.SourceType_SOURCE_TYPE_GITHUB:
		md := data.GetGithub()
		return &GitSourceMetadata{md.GetRepository(), md.GetCommit(), md.GetFile()}, true
	case sourcespb.SourceType_SOURCE_TYPE_GITLAB:
		md := data.GetGitlab()
		return &GitSourceMetadata{md.GetRepository(), md.GetCommit(), md.GetFile()}, true
	default:
		return nil, false
	}
}

// ChunkingTarget specifies criteria for a targeted chunking process.
// Instead of collecting data indiscriminately, this struct allows the caller
// to specify particular subsets of data they're interested in. This becomes
// especially useful when one needs to verify or recheck specific data points
// without processing the entire dataset.
type ChunkingTarget struct {
	// QueryCriteria represents specific parameters or conditions to target the chunking process.
	QueryCriteria *source_metadatapb.MetaData
	// SecretID is the ID of the secret.
	SecretID int64
}

// Source defines the interface required to implement a source chunker.
type Source interface {
	// Type returns the source type, used for matching against configuration and jobs.
	Type() sourcespb.SourceType
	// SourceID returns the initialized source ID used for tracking relationships in the DB.
	SourceID() SourceID
	// JobID returns the initialized job ID used for tracking relationships in the DB.
	JobID() JobID
	// Init initializes the source.
	Init(aCtx context.Context, name string, jobId JobID, sourceId SourceID, verify bool, connection *anypb.Any, concurrency int) error
	// Chunks emits data over a channel which is then decoded and scanned for secrets.
	// By default, data is obtained indiscriminately. However, by providing one or more
	// ChunkingTarget parameters, the caller can direct the function to retrieve
	// specific chunks of data. This targeted approach allows for efficient and
	// intentional data processing, beneficial when verifying or rechecking specific data points.
	Chunks(ctx context.Context, chunksChan chan *Chunk, targets ...ChunkingTarget) error
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
	// errors returned by the reporter. All other errors related to unit
	// enumeration are tracked by the UnitReporter.
	Enumerate(ctx context.Context, reporter UnitReporter) error
}

// BaseUnitReporter is a helper struct that implements the UnitReporter interface
// and includes a JobProgress reference.
type baseUnitReporter struct {
	child    UnitReporter
	progress *JobProgress
}

func (b baseUnitReporter) UnitOk(ctx context.Context, unit SourceUnit) error {
	b.progress.ReportUnit(unit)
	if b.child != nil {
		return b.child.UnitOk(ctx, unit)
	}
	return nil
}

func (b baseUnitReporter) UnitErr(ctx context.Context, err error) error {
	b.progress.ReportError(err)
	if b.child != nil {
		return b.child.UnitErr(ctx, err)
	}
	return nil
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

type SourceUnitKind string

// SourceUnit is an object that represents a Source's unit of work. This is
// used as the output of enumeration, progress reporting, and job distribution.
type SourceUnit interface {
	// SourceUnitID uniquely identifies a source unit. It does not need to
	// be human readable or two-way, however, it should be canonical and
	// stable across runs.
	SourceUnitID() (string, SourceUnitKind)

	// Display is the human readable representation of the SourceUnit.
	Display() string
}

// DockerConfig defines the optional configuration for a Docker source.
type DockerConfig struct {
	// Images is the list of images to scan.
	Images []string
	// BearerToken is the token to use to authenticate with the source.
	BearerToken string
	// UseDockerKeychain determines whether to use the Docker keychain.
	UseDockerKeychain bool
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
	// HeadRef is the head reference to use to scan from.
	HeadRef string
	// BaseRef is the base reference to use to scan from.
	BaseRef string
	// MaxDepth is the maximum depth to scan the source.
	MaxDepth int
	// Bare is an indicator to handle bare repositories properly.
	Bare bool
	// URI is the URI of the repository to scan. file://, http://, https:// and ssh:// are supported.
	URI string
	// IncludePathsFile is the path to a file containing a list of regexps to include in the scan.
	IncludePathsFile string
	// ExcludePathsFile is the path to a file containing a list of regexps to exclude from the scan.
	ExcludePathsFile string
	// ExcludeGlobs is a list of comma separated globs to exclude from the scan.
	// This differs from the Filter exclusions as ExcludeGlobs is applied at the `git log -p` level
	ExcludeGlobs string
	// SkipBinaries allows skipping binary files from the scan.
	SkipBinaries bool
}

// GithubConfig defines the optional configuration for a github source.
type GithubConfig struct {
	// Endpoint is the endpoint of the source.
	Endpoint string
	// Token is the token to use to authenticate with the source.
	Token string
	// IncludeForks indicates whether to include forks in the scan.
	IncludeForks bool
	// IncludeMembers indicates whether to include members in the scan.
	IncludeMembers bool
	// Concurrency is the number of concurrent workers to use to scan the source.
	Concurrency int
	// Repos is the list of repositories to scan.
	Repos []string
	// Orgs is the list of organizations to scan.
	Orgs []string
	// ExcludeRepos is a list of repositories to exclude from the scan.
	ExcludeRepos []string
	// IncludeRepos is a list of repositories to include in the scan.
	IncludeRepos []string
	// Filter is the filter to use to scan the source.
	Filter *common.Filter
	// IncludeIssueComments indicates whether to include GitHub issue comments in the scan.
	IncludeIssueComments bool
	// IncludePullRequestComments indicates whether to include GitHub pull request comments in the scan.
	IncludePullRequestComments bool
	// IncludeGistComments indicates whether to include GitHub gist comments in the scan.
	IncludeGistComments bool
	// SkipBinaries allows skipping binary files from the scan.
	SkipBinaries bool
	// IncludeWikis indicates whether to include repository wikis in the scan.
	IncludeWikis bool
	// CommentsTimeframeDays indicates how many days of comments to include in the scan.
	CommentsTimeframeDays uint32
}

// GitHubExperimentalConfig defines the optional configuration for an experimental GitHub source.
type GitHubExperimentalConfig struct {
	// Repository is the repository to scan.
	Repository string
	// Token is the token to use to authenticate with the source.
	Token string
	// ObjectDiscovery indicates whether to discover all commit objects (CFOR) in the repository.
	ObjectDiscovery bool
	// CollisionThreshold is the number of short-sha collisions tolerated during hidden data enumeration. Default is 1.
	CollisionThreshold int
	// DeleteCachedData indicates whether to delete cached data.
	DeleteCachedData bool
}

// GitlabConfig defines the optional configuration for a gitlab source.
type GitlabConfig struct {
	// Endpoint is the endpoint of the source.
	Endpoint string
	// Token is the token to use to authenticate with the source.
	Token string
	// Repos is the list of repositories to scan.
	Repos []string
	// Filter is the filter to use to scan the source.
	Filter *common.Filter
	// SkipBinaries allows skipping binary files from the scan.
	SkipBinaries bool
	// IncludeRepos is a list of repositories to include in the scan.
	IncludeRepos []string
	// ExcludeRepos is a list of repositories to exclude from the scan.
	ExcludeRepos []string
}

// FilesystemConfig defines the optional configuration for a filesystem source.
type FilesystemConfig struct {
	// Paths is the list of files and directories to scan.
	Paths []string
	// IncludePathsFile is the path to a file containing a list of regexps to include in the scan.
	IncludePathsFile string
	// ExcludePathsFile is the path to a file containing a list of regexps to exclude from the scan.
	ExcludePathsFile string
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
	// IgnoreBuckets is the list buckets to ignore.
	IgnoreBuckets []string
	// Roles is the list of Roles to use.
	Roles []string
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

// PostmanConfig defines the optional configuration for a Postman source.
type PostmanConfig struct {
	// Workspace UUID(s) or file path(s) to Postman workspace (.zip)
	Workspaces []string
	// Collection ID(s) or file path(s) to Postman collection (.json)
	Collections []string
	// Environment ID(s) or file path(s) to Postman environment (.json)
	Environments []string
	// Token is the token to use to authenticate with the API.
	Token string
	// IncludeCollections is a list of Collections to include in the scan.
	IncludeCollections []string
	// IncludeEnvironment is a list of Environments to include in the scan.
	IncludeEnvironments []string
	// ExcludeCollections is a list of Collections to exclude in the scan.
	ExcludeCollections []string
	// ExcludeEnvironment is a list of Environments to exclude in the scan.
	ExcludeEnvironments []string
	// Concurrency is the number of concurrent workers to use to scan the source.
	Concurrency int
	// CollectionPaths is the list of paths to Postman collections.
	CollectionPaths []string
	// WorkspacePaths is the list of paths to Postman workspaces.
	WorkspacePaths []string
	// EnvironmentPaths is the list of paths to Postman environments.
	EnvironmentPaths []string
	// Filter is the filter to use to scan the source.
	Filter *common.Filter
}

type ElasticsearchConfig struct {
	Nodes          []string
	Username       string
	Password       string
	CloudID        string
	APIKey         string
	ServiceToken   string
	IndexPattern   string
	QueryJSON      string
	SinceTimestamp string
	BestEffortScan bool
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
	Validate(ctx context.Context) []error
}

// SetProgressComplete sets job progress information for a running job based on the highest level objects in the source.
// i is the current iteration in the loop of target scope
// scope should be the len(scopedItems)
// message is the public facing user information about the current progress
// encodedResumeInfo is an optional string representing any information necessary to resume the job if interrupted
//
//	NOTE: SetProgressOngoing should be used when source does not yet know how many items it is scanning (scope)
//	and does not want to display a percentage complete
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

// SetProgressOngoing sets information about the current running job based on
// the highest level objects in the source.
// message is the public facing user information about the current progress
// encodedResumeInfo is an optional string representing any information necessary to resume the job if interrupted
//
//	NOTE: This method should be used over SetProgressComplete when the source does
//	not yet know how many items it is scanning and does not want to display a percentage complete.
func (p *Progress) SetProgressOngoing(message string, encodedResumeInfo string) {
	p.mut.Lock()
	defer p.mut.Unlock()

	p.Message = message
	p.EncodedResumeInfo = encodedResumeInfo
	// Explicitly set SectionsRemaining to 0 so the frontend does not display a percent.
	p.SectionsRemaining = 0
}

// GetProgress gets job completion percentage for metrics reporting.
func (p *Progress) GetProgress() *Progress {
	p.mut.Lock()
	defer p.mut.Unlock()
	return p
}
