package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/alecthomas/kingpin/v2"
	"github.com/felixge/fgprof"
	"github.com/go-logr/logr"
	"github.com/jpillora/overseer"
	"github.com/mattn/go-isatty"
	"go.uber.org/automaxprocs/maxprocs"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer"
	"github.com/trufflesecurity/trufflehog/v3/pkg/cleantemp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine"
	"github.com/trufflesecurity/trufflehog/v3/pkg/feature"
	"github.com/trufflesecurity/trufflehog/v3/pkg/handlers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/log"
	"github.com/trufflesecurity/trufflehog/v3/pkg/output"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui"
	"github.com/trufflesecurity/trufflehog/v3/pkg/updater"
	"github.com/trufflesecurity/trufflehog/v3/pkg/version"
)

var (
	cli                 = kingpin.New("TruffleHog", "TruffleHog is a tool for finding credentials.")
	cmd                 string
	debug               = cli.Flag("debug", "Run in debug mode.").Bool()
	trace               = cli.Flag("trace", "Run in trace mode.").Bool()
	profile             = cli.Flag("profile", "Enables profiling and sets a pprof and fgprof server on :18066.").Bool()
	localDev            = cli.Flag("local-dev", "Hidden feature to disable overseer for local dev.").Hidden().Bool()
	jsonOut             = cli.Flag("json", "Output in JSON format.").Short('j').Bool()
	jsonLegacy          = cli.Flag("json-legacy", "Use the pre-v3.0 JSON format. Only works with git, gitlab, and github sources.").Bool()
	gitHubActionsFormat = cli.Flag("github-actions", "Output in GitHub Actions format.").Bool()
	concurrency         = cli.Flag("concurrency", "Number of concurrent workers.").Default(strconv.Itoa(runtime.NumCPU())).Int()
	noVerification      = cli.Flag("no-verification", "Don't verify the results.").Bool()
	onlyVerified        = cli.Flag("only-verified", "Only output verified results.").Bool()
	results             = cli.Flag("results", "Specifies which type(s) of results to output: verified, unknown, unverified. Defaults to all types.").Hidden().String()

	allowVerificationOverlap   = cli.Flag("allow-verification-overlap", "Allow verification of similar credentials across detectors").Bool()
	filterUnverified           = cli.Flag("filter-unverified", "Only output first unverified result per chunk per detector if there are more than one results.").Bool()
	filterEntropy              = cli.Flag("filter-entropy", "Filter unverified results with Shannon entropy. Start with 3.0.").Float64()
	scanEntireChunk            = cli.Flag("scan-entire-chunk", "Scan the entire chunk for secrets.").Hidden().Default("false").Bool()
	compareDetectionStrategies = cli.Flag("compare-detection-strategies", "Compare different detection strategies for matching spans").Hidden().Default("false").Bool()
	configFilename             = cli.Flag("config", "Path to configuration file.").ExistingFile()
	// rules = cli.Flag("rules", "Path to file with custom rules.").String()
	printAvgDetectorTime = cli.Flag("print-avg-detector-time", "Print the average time spent on each detector.").Bool()
	noUpdate             = cli.Flag("no-update", "Don't check for updates.").Bool()
	fail                 = cli.Flag("fail", "Exit with code 183 if results are found.").Bool()
	verifiers            = cli.Flag("verifier", "Set custom verification endpoints.").StringMap()
	customVerifiersOnly  = cli.Flag("custom-verifiers-only", "Only use custom verification endpoints.").Bool()
	archiveMaxSize       = cli.Flag("archive-max-size", "Maximum size of archive to scan. (Byte units eg. 512B, 2KB, 4MB)").Bytes()
	archiveMaxDepth      = cli.Flag("archive-max-depth", "Maximum depth of archive to scan.").Int()
	archiveTimeout       = cli.Flag("archive-timeout", "Maximum time to spend extracting an archive.").Duration()
	includeDetectors     = cli.Flag("include-detectors", "Comma separated list of detector types to include. Protobuf name or IDs may be used, as well as ranges.").Default("all").String()
	excludeDetectors     = cli.Flag("exclude-detectors", "Comma separated list of detector types to exclude. Protobuf name or IDs may be used, as well as ranges. IDs defined here take precedence over the include list.").String()
	jobReportFile        = cli.Flag("output-report", "Write a scan report to the provided path.").Hidden().OpenFile(os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)

	// Add feature flags
	forceSkipBinaries  = cli.Flag("force-skip-binaries", "Force skipping binaries.").Bool()
	forceSkipArchives  = cli.Flag("force-skip-archives", "Force skipping archives.").Bool()
	skipAdditionalRefs = cli.Flag("skip-additional-refs", "Skip additional references.").Bool()
	userAgentSuffix    = cli.Flag("user-agent-suffix", "Suffix to add to User-Agent.").String()

	gitScan             = cli.Command("git", "Find credentials in git repositories.")
	gitScanURI          = gitScan.Arg("uri", "Git repository URL. https://, file://, or ssh:// schema expected.").Required().String()
	gitScanIncludePaths = gitScan.Flag("include-paths", "Path to file with newline separated regexes for files to include in scan.").Short('i').String()
	gitScanExcludePaths = gitScan.Flag("exclude-paths", "Path to file with newline separated regexes for files to exclude in scan.").Short('x').String()
	gitScanExcludeGlobs = gitScan.Flag("exclude-globs", "Comma separated list of globs to exclude in scan. This option filters at the `git log` level, resulting in faster scans.").String()
	gitScanSinceCommit  = gitScan.Flag("since-commit", "Commit to start scan from.").String()
	gitScanBranch       = gitScan.Flag("branch", "Branch to scan.").String()
	gitScanMaxDepth     = gitScan.Flag("max-depth", "Maximum depth of commits to scan.").Int()
	gitScanBare         = gitScan.Flag("bare", "Scan bare repository (e.g. useful while using in pre-receive hooks)").Bool()
	_                   = gitScan.Flag("allow", "No-op flag for backwards compat.").Bool()
	_                   = gitScan.Flag("entropy", "No-op flag for backwards compat.").Bool()
	_                   = gitScan.Flag("regex", "No-op flag for backwards compat.").Bool()

	githubScan                  = cli.Command("github", "Find credentials in GitHub repositories.")
	githubScanEndpoint          = githubScan.Flag("endpoint", "GitHub endpoint.").Default("https://api.github.com").String()
	githubScanRepos             = githubScan.Flag("repo", `GitHub repository to scan. You can repeat this flag. Example: "https://github.com/dustin-decker/secretsandstuff"`).Strings()
	githubScanOrgs              = githubScan.Flag("org", `GitHub organization to scan. You can repeat this flag. Example: "trufflesecurity"`).Strings()
	githubScanToken             = githubScan.Flag("token", "GitHub token. Can be provided with environment variable GITHUB_TOKEN.").Envar("GITHUB_TOKEN").String()
	githubIncludeForks          = githubScan.Flag("include-forks", "Include forks in scan.").Bool()
	githubIncludeMembers        = githubScan.Flag("include-members", "Include organization member repositories in scan.").Bool()
	githubIncludeRepos          = githubScan.Flag("include-repos", `Repositories to include in an org scan. This can also be a glob pattern. You can repeat this flag. Must use Github repo full name. Example: "trufflesecurity/trufflehog", "trufflesecurity/t*"`).Strings()
	githubIncludeWikis          = githubScan.Flag("include-wikis", "Include repository wikisin scan.").Bool()
	githubExcludeRepos          = githubScan.Flag("exclude-repos", `Repositories to exclude in an org scan. This can also be a glob pattern. You can repeat this flag. Must use Github repo full name. Example: "trufflesecurity/driftwood", "trufflesecurity/d*"`).Strings()
	githubScanIncludePaths      = githubScan.Flag("include-paths", "Path to file with newline separated regexes for files to include in scan.").Short('i').String()
	githubScanExcludePaths      = githubScan.Flag("exclude-paths", "Path to file with newline separated regexes for files to exclude in scan.").Short('x').String()
	githubScanIssueComments     = githubScan.Flag("issue-comments", "Include issue descriptions and comments in scan.").Bool()
	githubScanPRComments        = githubScan.Flag("pr-comments", "Include pull request descriptions and comments in scan.").Bool()
	githubScanGistComments      = githubScan.Flag("gist-comments", "Include gist comments in scan.").Bool()
	githubCommentsTimeframeDays = githubScan.Flag("comments-timeframe", "Number of days in the past to review when scanning issue, PR, and gist comments.").Uint32()

	// GitHub Cross Fork Object Reference Experimental Feature
	githubExperimentalScan = cli.Command("github-experimental", "Run an experimental GitHub scan. Must specify at least one experimental sub-module to run: object-discovery.")
	// GitHub Experimental SubModules
	githubExperimentalObjectDiscovery = githubExperimentalScan.Flag("object-discovery", "Discover hidden data objects in GitHub repositories.").Bool()
	// GitHub Experimental Options
	githubExperimentalToken              = githubExperimentalScan.Flag("token", "GitHub token. Can be provided with environment variable GITHUB_TOKEN.").Envar("GITHUB_TOKEN").String()
	githubExperimentalRepo               = githubExperimentalScan.Flag("repo", "GitHub repository to scan. Example: https://github.com/<user>/<repo>.git").Required().String()
	githubExperimentalCollisionThreshold = githubExperimentalScan.Flag("collision-threshold", "Threshold for short-sha collisions in object-discovery submodule. Default is 1.").Default("1").Int()
	githubExperimentalDeleteCache        = githubExperimentalScan.Flag("delete-cached-data", "Delete cached data after object-discovery secret scanning.").Bool()

	gitlabScan = cli.Command("gitlab", "Find credentials in GitLab repositories.")
	// TODO: Add more GitLab options
	gitlabScanEndpoint     = gitlabScan.Flag("endpoint", "GitLab endpoint.").Default("https://gitlab.com").String()
	gitlabScanRepos        = gitlabScan.Flag("repo", "GitLab repo url. You can repeat this flag. Leave empty to scan all repos accessible with provided credential. Example: https://gitlab.com/org/repo.git").Strings()
	gitlabScanToken        = gitlabScan.Flag("token", "GitLab token. Can be provided with environment variable GITLAB_TOKEN.").Envar("GITLAB_TOKEN").Required().String()
	gitlabScanIncludePaths = gitlabScan.Flag("include-paths", "Path to file with newline separated regexes for files to include in scan.").Short('i').String()
	gitlabScanExcludePaths = gitlabScan.Flag("exclude-paths", "Path to file with newline separated regexes for files to exclude in scan.").Short('x').String()
	gitlabScanIncludeRepos = gitlabScan.Flag("include-repos", `Repositories to include in an org scan. This can also be a glob pattern. You can repeat this flag. Must use Gitlab repo full name. Example: "trufflesecurity/trufflehog", "trufflesecurity/t*"`).Strings()
	gitlabScanExcludeRepos = gitlabScan.Flag("exclude-repos", `Repositories to exclude in an org scan. This can also be a glob pattern. You can repeat this flag. Must use Gitlab repo full name. Example: "trufflesecurity/driftwood", "trufflesecurity/d*"`).Strings()

	filesystemScan  = cli.Command("filesystem", "Find credentials in a filesystem.")
	filesystemPaths = filesystemScan.Arg("path", "Path to file or directory to scan.").Strings()
	// DEPRECATED: --directory is deprecated in favor of arguments.
	filesystemDirectories = filesystemScan.Flag("directory", "Path to directory to scan. You can repeat this flag.").Strings()
	// TODO: Add more filesystem scan options. Currently only supports scanning a list of directories.
	// filesystemScanRecursive = filesystemScan.Flag("recursive", "Scan recursively.").Short('r').Bool()
	filesystemScanIncludePaths = filesystemScan.Flag("include-paths", "Path to file with newline separated regexes for files to include in scan.").Short('i').String()
	filesystemScanExcludePaths = filesystemScan.Flag("exclude-paths", "Path to file with newline separated regexes for files to exclude in scan.").Short('x').String()

	s3Scan              = cli.Command("s3", "Find credentials in S3 buckets.")
	s3ScanKey           = s3Scan.Flag("key", "S3 key used to authenticate. Can be provided with environment variable AWS_ACCESS_KEY_ID.").Envar("AWS_ACCESS_KEY_ID").String()
	s3ScanRoleArns      = s3Scan.Flag("role-arn", "Specify the ARN of an IAM role to assume for scanning. You can repeat this flag.").Strings()
	s3ScanSecret        = s3Scan.Flag("secret", "S3 secret used to authenticate. Can be provided with environment variable AWS_SECRET_ACCESS_KEY.").Envar("AWS_SECRET_ACCESS_KEY").String()
	s3ScanSessionToken  = s3Scan.Flag("session-token", "S3 session token used to authenticate temporary credentials. Can be provided with environment variable AWS_SESSION_TOKEN.").Envar("AWS_SESSION_TOKEN").String()
	s3ScanCloudEnv      = s3Scan.Flag("cloud-environment", "Use IAM credentials in cloud environment.").Bool()
	s3ScanBuckets       = s3Scan.Flag("bucket", "Name of S3 bucket to scan. You can repeat this flag. Incompatible with --ignore-bucket.").Strings()
	s3ScanIgnoreBuckets = s3Scan.Flag("ignore-bucket", "Name of S3 bucket to ignore. You can repeat this flag. Incompatible with --bucket.").Strings()
	s3ScanMaxObjectSize = s3Scan.Flag("max-object-size", "Maximum size of objects to scan. Objects larger than this will be skipped. (Byte units eg. 512B, 2KB, 4MB)").Default("250MB").Bytes()

	gcsScan           = cli.Command("gcs", "Find credentials in GCS buckets.")
	gcsProjectID      = gcsScan.Flag("project-id", "GCS project ID used to authenticate. Can NOT be used with unauth scan. Can be provided with environment variable GOOGLE_CLOUD_PROJECT.").Envar("GOOGLE_CLOUD_PROJECT").String()
	gcsCloudEnv       = gcsScan.Flag("cloud-environment", "Use Application Default Credentials, IAM credentials to authenticate.").Bool()
	gcsServiceAccount = gcsScan.Flag("service-account", "Path to GCS service account JSON file.").ExistingFile()
	gcsWithoutAuth    = gcsScan.Flag("without-auth", "Scan GCS buckets without authentication. This will only work for public buckets").Bool()
	gcsAPIKey         = gcsScan.Flag("api-key", "GCS API key used to authenticate. Can be provided with environment variable GOOGLE_API_KEY.").Envar("GOOGLE_API_KEY").String()
	gcsIncludeBuckets = gcsScan.Flag("include-buckets", "Buckets to scan. Comma separated list of buckets. You can repeat this flag. Globs are supported").Short('I').Strings()
	gcsExcludeBuckets = gcsScan.Flag("exclude-buckets", "Buckets to exclude from scan. Comma separated list of buckets. Globs are supported").Short('X').Strings()
	gcsIncludeObjects = gcsScan.Flag("include-objects", "Objects to scan. Comma separated list of objects. you can repeat this flag. Globs are supported").Short('i').Strings()
	gcsExcludeObjects = gcsScan.Flag("exclude-objects", "Objects to exclude from scan. Comma separated list of objects. You can repeat this flag. Globs are supported").Short('x').Strings()
	gcsMaxObjectSize  = gcsScan.Flag("max-object-size", "Maximum size of objects to scan. Objects larger than this will be skipped. (Byte units eg. 512B, 2KB, 4MB)").Default("10MB").Bytes()

	syslogScan     = cli.Command("syslog", "Scan syslog")
	syslogAddress  = syslogScan.Flag("address", "Address and port to listen on for syslog. Example: 127.0.0.1:514").String()
	syslogProtocol = syslogScan.Flag("protocol", "Protocol to listen on. udp or tcp").String()
	syslogTLSCert  = syslogScan.Flag("cert", "Path to TLS cert.").String()
	syslogTLSKey   = syslogScan.Flag("key", "Path to TLS key.").String()
	syslogFormat   = syslogScan.Flag("format", "Log format. Can be rfc3164 or rfc5424").String()

	circleCiScan      = cli.Command("circleci", "Scan CircleCI")
	circleCiScanToken = circleCiScan.Flag("token", "CircleCI token. Can also be provided with environment variable").Envar("CIRCLECI_TOKEN").Required().String()

	dockerScan       = cli.Command("docker", "Scan Docker Image")
	dockerScanImages = dockerScan.Flag("image", "Docker image to scan. Use the file:// prefix to point to a local tarball, otherwise a image registry is assumed.").Required().Strings()
	dockerScanToken  = dockerScan.Flag("token", "Docker bearer token. Can also be provided with environment variable").Envar("DOCKER_TOKEN").String()

	travisCiScan      = cli.Command("travisci", "Scan TravisCI")
	travisCiScanToken = travisCiScan.Flag("token", "TravisCI token. Can also be provided with environment variable").Envar("TRAVISCI_TOKEN").Required().String()

	// Postman is hidden for now until we get more feedback from the community.
	postmanScan  = cli.Command("postman", "Scan Postman")
	postmanToken = postmanScan.Flag("token", "Postman token. Can also be provided with environment variable").Envar("POSTMAN_TOKEN").String()

	postmanWorkspaces   = postmanScan.Flag("workspace", "Postman workspace to scan. You can repeat this flag. Deprecated flag.").Hidden().Strings()
	postmanWorkspaceIDs = postmanScan.Flag("workspace-id", "Postman workspace ID to scan. You can repeat this flag.").Strings()

	postmanCollections   = postmanScan.Flag("collection", "Postman collection to scan. You can repeat this flag. Deprecated flag.").Hidden().Strings()
	postmanCollectionIDs = postmanScan.Flag("collection-id", "Postman collection ID to scan. You can repeat this flag.").Strings()

	postmanEnvironments = postmanScan.Flag("environment", "Postman environment to scan. You can repeat this flag.").Strings()

	postmanIncludeCollections   = postmanScan.Flag("include-collections", "Collections to include in scan. You can repeat this flag. Deprecated flag.").Hidden().Strings()
	postmanIncludeCollectionIDs = postmanScan.Flag("include-collection-id", "Collection ID to include in scan. You can repeat this flag.").Strings()

	postmanIncludeEnvironments = postmanScan.Flag("include-environments", "Environments to include in scan. You can repeat this flag.").Strings()

	postmanExcludeCollections   = postmanScan.Flag("exclude-collections", "Collections to exclude from scan. You can repeat this flag. Deprecated flag.").Hidden().Strings()
	postmanExcludeCollectionIDs = postmanScan.Flag("exclude-collection-id", "Collection ID to exclude from scan. You can repeat this flag.").Strings()

	postmanExcludeEnvironments = postmanScan.Flag("exclude-environments", "Environments to exclude from scan. You can repeat this flag.").Strings()
	postmanWorkspacePaths      = postmanScan.Flag("workspace-paths", "Path to Postman workspaces.").Strings()
	postmanCollectionPaths     = postmanScan.Flag("collection-paths", "Path to Postman collections.").Strings()
	postmanEnvironmentPaths    = postmanScan.Flag("environment-paths", "Path to Postman environments.").Strings()

	elasticsearchScan           = cli.Command("elasticsearch", "Scan Elasticsearch")
	elasticsearchNodes          = elasticsearchScan.Flag("nodes", "Elasticsearch nodes").Envar("ELASTICSEARCH_NODES").Strings()
	elasticsearchUsername       = elasticsearchScan.Flag("username", "Elasticsearch username").Envar("ELASTICSEARCH_USERNAME").String()
	elasticsearchPassword       = elasticsearchScan.Flag("password", "Elasticsearch password").Envar("ELASTICSEARCH_PASSWORD").String()
	elasticsearchServiceToken   = elasticsearchScan.Flag("service-token", "Elasticsearch service token").Envar("ELASTICSEARCH_SERVICE_TOKEN").String()
	elasticsearchCloudId        = elasticsearchScan.Flag("cloud-id", "Elasticsearch cloud ID. Can also be provided with environment variable").Envar("ELASTICSEARCH_CLOUD_ID").String()
	elasticsearchAPIKey         = elasticsearchScan.Flag("api-key", "Elasticsearch API key. Can also be provided with environment variable").Envar("ELASTICSEARCH_API_KEY").String()
	elasticsearchIndexPattern   = elasticsearchScan.Flag("index-pattern", "Filters the indices to search").Default("*").Envar("ELASTICSEARCH_INDEX_PATTERN").String()
	elasticsearchQueryJSON      = elasticsearchScan.Flag("query-json", "Filters the documents to search").Envar("ELASTICSEARCH_QUERY_JSON").String()
	elasticsearchSinceTimestamp = elasticsearchScan.Flag("since-timestamp", "Filters the documents to search to those created since this timestamp; overrides any timestamp from --query-json").Envar("ELASTICSEARCH_SINCE_TIMESTAMP").String()
	elasticsearchBestEffortScan = elasticsearchScan.Flag("best-effort-scan", "Attempts to continuously scan a cluster").Envar("ELASTICSEARCH_BEST_EFFORT_SCAN").Bool()

	jenkinsScan                  = cli.Command("jenkins", "Scan Jenkins")
	jenkinsURL                   = jenkinsScan.Flag("url", "Jenkins URL").Envar("JENKINS_URL").Required().String()
	jenkinsUsername              = jenkinsScan.Flag("username", "Jenkins username").Envar("JENKINS_USERNAME").String()
	jenkinsPassword              = jenkinsScan.Flag("password", "Jenkins password").Envar("JENKINS_PASSWORD").String()
	jenkinsInsecureSkipVerifyTLS = jenkinsScan.Flag("insecure-skip-verify-tls", "Skip TLS verification").Envar("JENKINS_INSECURE_SKIP_VERIFY_TLS").Bool()

	huggingfaceScan     = cli.Command("huggingface", "Find credentials in HuggingFace datasets, models and spaces.")
	huggingfaceEndpoint = huggingfaceScan.Flag("endpoint", "HuggingFace endpoint.").Default("https://huggingface.co").String()
	huggingfaceModels   = huggingfaceScan.Flag("model", "HuggingFace model to scan. You can repeat this flag. Example: 'username/model'").Strings()
	huggingfaceSpaces   = huggingfaceScan.Flag("space", "HuggingFace space to scan. You can repeat this flag. Example: 'username/space'").Strings()
	huggingfaceDatasets = huggingfaceScan.Flag("dataset", "HuggingFace dataset to scan. You can repeat this flag. Example: 'username/dataset'").Strings()
	huggingfaceOrgs     = huggingfaceScan.Flag("org", `HuggingFace organization to scan. You can repeat this flag. Example: "trufflesecurity"`).Strings()
	huggingfaceUsers    = huggingfaceScan.Flag("user", `HuggingFace user to scan. You can repeat this flag. Example: "trufflesecurity"`).Strings()
	huggingfaceToken    = huggingfaceScan.Flag("token", "HuggingFace token. Can be provided with environment variable HUGGINGFACE_TOKEN.").Envar("HUGGINGFACE_TOKEN").String()

	huggingfaceIncludeModels      = huggingfaceScan.Flag("include-models", "Models to include in scan. You can repeat this flag. Must use HuggingFace model full name. Example: 'username/model' (Only used with --user or --org)").Strings()
	huggingfaceIncludeSpaces      = huggingfaceScan.Flag("include-spaces", "Spaces to include in scan. You can repeat this flag. Must use HuggingFace space full name. Example: 'username/space' (Only used with --user or --org)").Strings()
	huggingfaceIncludeDatasets    = huggingfaceScan.Flag("include-datasets", "Datasets to include in scan. You can repeat this flag. Must use HuggingFace dataset full name. Example: 'username/dataset' (Only used with --user or --org)").Strings()
	huggingfaceIgnoreModels       = huggingfaceScan.Flag("ignore-models", "Models to ignore in scan. You can repeat this flag. Must use HuggingFace model full name. Example: 'username/model' (Only used with --user or --org)").Strings()
	huggingfaceIgnoreSpaces       = huggingfaceScan.Flag("ignore-spaces", "Spaces to ignore in scan. You can repeat this flag. Must use HuggingFace space full name. Example: 'username/space' (Only used with --user or --org)").Strings()
	huggingfaceIgnoreDatasets     = huggingfaceScan.Flag("ignore-datasets", "Datasets to ignore in scan. You can repeat this flag. Must use HuggingFace dataset full name. Example: 'username/dataset' (Only used with --user or --org)").Strings()
	huggingfaceSkipAllModels      = huggingfaceScan.Flag("skip-all-models", "Skip all model scans. (Only used with --user or --org)").Bool()
	huggingfaceSkipAllSpaces      = huggingfaceScan.Flag("skip-all-spaces", "Skip all space scans. (Only used with --user or --org)").Bool()
	huggingfaceSkipAllDatasets    = huggingfaceScan.Flag("skip-all-datasets", "Skip all dataset scans. (Only used with --user or --org)").Bool()
	huggingfaceIncludeDiscussions = huggingfaceScan.Flag("include-discussions", "Include discussions in scan.").Bool()
	huggingfaceIncludePrs         = huggingfaceScan.Flag("include-prs", "Include pull requests in scan.").Bool()

	analyzeCmd = analyzer.Command(cli)
	usingTUI   = false
)

func init() {
	_, _ = maxprocs.Set()

	for i, arg := range os.Args {
		if strings.HasPrefix(arg, "--") {
			split := strings.SplitN(arg, "=", 2)
			split[0] = strings.ReplaceAll(split[0], "_", "-")
			os.Args[i] = strings.Join(split, "=")
		}
	}

	cli.Version("trufflehog " + version.BuildVersion)

	// Support -h for help
	cli.HelpFlag.Short('h')

	if len(os.Args) <= 1 && isatty.IsTerminal(os.Stdout.Fd()) {
		args := tui.Run()
		if len(args) == 0 {
			os.Exit(0)
		}

		// Overwrite the Args slice so overseer works properly.
		os.Args = os.Args[:1]
		os.Args = append(os.Args, args...)
		usingTUI = true
	}

	cmd = kingpin.MustParse(cli.Parse(os.Args[1:]))

	switch {
	case *trace:
		log.SetLevel(5)
	case *debug:
		log.SetLevel(2)
	}
}

func main() {
	// setup logger
	logFormat := log.WithConsoleSink
	if *jsonOut {
		logFormat = log.WithJSONSink
	}
	logger, sync := log.New("trufflehog", logFormat(os.Stderr, log.WithGlobalRedaction()))
	// make it the default logger for contexts
	context.SetDefaultLogger(logger)

	if *localDev {
		run(overseer.State{})
		os.Exit(0)
	}

	defer func() { _ = sync() }()
	logFatal := logFatalFunc(logger)

	updateCfg := overseer.Config{
		Program:       run,
		Debug:         *debug,
		RestartSignal: syscall.SIGTERM,
		// TODO: Eventually add a PreUpgrade func for signature check w/ x509 PKCS1v15
		// PreUpgrade: checkUpdateSignature(binaryPath string),
	}

	if !*noUpdate {
		topLevelCmd, _, _ := strings.Cut(cmd, " ")
		updateCfg.Fetcher = updater.Fetcher(topLevelCmd, usingTUI)
	}
	if version.BuildVersion == "dev" {
		updateCfg.Fetcher = nil
	}

	err := overseer.RunErr(updateCfg)
	if err != nil {
		logFatal(err, "error occurred with trufflehog updater 🐷")
	}
}

// Function to check if the commit is valid
func isValidCommit(commit string) bool {
	cmd := exec.Command("git", "cat-file", "-t", commit)
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	return strings.TrimSpace(string(output)) == "commit"
}

func run(state overseer.State) {

	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)

	go func() {
		if err := cleantemp.CleanTempArtifacts(ctx); err != nil {
			ctx.Logger().Error(err, "error cleaning temporary artifacts")
		}
	}()

	logger := ctx.Logger()
	logFatal := logFatalFunc(logger)

	killSignal := make(chan os.Signal, 1)
	signal.Notify(killSignal, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		<-killSignal
		logger.Info("Received signal, shutting down.")
		cancel(fmt.Errorf("canceling context due to signal"))

		if err := cleantemp.CleanTempArtifacts(ctx); err != nil {
			logger.Error(err, "error cleaning temporary artifacts")
		} else {
			logger.Info("cleaned temporary artifacts")
		}
		os.Exit(0)
	}()

	logger.V(2).Info(fmt.Sprintf("trufflehog %s", version.BuildVersion))

	if *githubScanToken != "" {
		// NOTE: this kludge is here to do an authenticated shallow commit
		// TODO: refactor to better pass credentials
		os.Setenv("GITHUB_TOKEN", *githubScanToken)
	}

	// When setting a base commit, chunks must be scanned in order.
	if *gitScanSinceCommit != "" {
		*concurrency = 1
		if !isValidCommit(*gitScanSinceCommit) {
			logger.Info("Warning: The provided commit hash appears to be invalid.")
		}
	}

	if *profile {
		runtime.SetBlockProfileRate(1)
		runtime.SetMutexProfileFraction(-1)
		go func() {
			router := http.NewServeMux()
			router.Handle("/debug/pprof/", http.DefaultServeMux)
			router.Handle("/debug/fgprof", fgprof.Handler())
			logger.Info("starting pprof and fgprof server on :18066 /debug/pprof and /debug/fgprof")
			if err := http.ListenAndServe(":18066", router); err != nil {
				logger.Error(err, "error serving pprof and fgprof")
			}
		}()
	}

	// Set feature configurations from CLI flags
	if *forceSkipBinaries {
		feature.ForceSkipBinaries.Store(true)
	}

	if *forceSkipArchives {
		feature.ForceSkipArchives.Store(true)
	}

	if *skipAdditionalRefs {
		feature.SkipAdditionalRefs.Store(true)
	}

	if *userAgentSuffix != "" {
		feature.UserAgentSuffix.Store(*userAgentSuffix)
	}

	conf := &config.Config{}
	if *configFilename != "" {
		var err error
		conf, err = config.Read(*configFilename)
		if err != nil {
			logFatal(err, "error parsing the provided configuration file")
		}
	}

	if *archiveMaxSize != 0 {
		handlers.SetArchiveMaxSize(int(*archiveMaxSize))
	}
	if *archiveMaxDepth != 0 {
		handlers.SetArchiveMaxDepth(*archiveMaxDepth)
	}
	if *archiveTimeout != 0 {
		handlers.SetArchiveMaxTimeout(*archiveTimeout)
	}

	// Set how the engine will print its results.
	var printer engine.Printer
	switch {
	case *jsonLegacy:
		printer = new(output.LegacyJSONPrinter)
	case *jsonOut:
		printer = new(output.JSONPrinter)
	case *gitHubActionsFormat:
		printer = new(output.GitHubActionsPrinter)
	default:
		printer = new(output.PlainPrinter)
	}

	if !*jsonLegacy && !*jsonOut {
		fmt.Fprintf(os.Stderr, "🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷\n\n")
	}

	// Parse --results flag.
	if *onlyVerified {
		r := "verified"
		results = &r
	}
	parsedResults, err := parseResults(results)
	if err != nil {
		logFatal(err, "failed to configure results flag")
	}

	engConf := engine.Config{
		Concurrency: *concurrency,
		// The engine must always be configured with the list of
		// default detectors, which can be further filtered by the
		// user. The filters are applied by the engine and are only
		// subtractive.
		Detectors:             append(engine.DefaultDetectors(), conf.Detectors...),
		Verify:                !*noVerification,
		IncludeDetectors:      *includeDetectors,
		ExcludeDetectors:      *excludeDetectors,
		CustomVerifiersOnly:   *customVerifiersOnly,
		VerifierEndpoints:     *verifiers,
		Dispatcher:            engine.NewPrinterDispatcher(printer),
		FilterUnverified:      *filterUnverified,
		FilterEntropy:         *filterEntropy,
		VerificationOverlap:   *allowVerificationOverlap,
		Results:               parsedResults,
		PrintAvgDetectorTime:  *printAvgDetectorTime,
		ShouldScanEntireChunk: *scanEntireChunk,
	}

	if *compareDetectionStrategies {
		if err := compareScans(ctx, cmd, engConf); err != nil {
			logFatal(err, "error comparing detection strategies")
		}
		return
	}

	topLevelSubCommand, _, _ := strings.Cut(cmd, " ")
	switch topLevelSubCommand {
	case analyzeCmd.FullCommand():
		analyzer.Run(cmd)
	default:
		metrics, err := runSingleScan(ctx, cmd, engConf)
		if err != nil {
			logFatal(err, "error running scan")
		}

		// Print results.
		logger.Info("finished scanning",
			"chunks", metrics.ChunksScanned,
			"bytes", metrics.BytesScanned,
			"verified_secrets", metrics.VerifiedSecretsFound,
			"unverified_secrets", metrics.UnverifiedSecretsFound,
			"scan_duration", metrics.ScanDuration.String(),
			"trufflehog_version", version.BuildVersion,
		)

		if metrics.hasFoundResults && *fail {
			logger.V(2).Info("exiting with code 183 because results were found")
			os.Exit(183)
		}
	}
}

func compareScans(ctx context.Context, cmd string, cfg engine.Config) error {
	var (
		entireMetrics    metrics
		maxLengthMetrics metrics
		err              error
	)

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		// Run scan with entire chunk span calculator.
		cfg.ShouldScanEntireChunk = true
		entireMetrics, err = runSingleScan(ctx, cmd, cfg)
		if err != nil {
			ctx.Logger().Error(err, "error running scan with entire chunk span calculator")
		}
	}()

	// Run scan with max-length span calculator.
	maxLengthMetrics, err = runSingleScan(ctx, cmd, cfg)
	if err != nil {
		return fmt.Errorf("error running scan with custom span calculator: %v", err)
	}

	wg.Wait()

	return compareMetrics(maxLengthMetrics.Metrics, entireMetrics.Metrics)
}

func compareMetrics(customMetrics, entireMetrics engine.Metrics) error {
	fmt.Printf("Comparison of scan results: \n")
	fmt.Printf("Custom span - Chunks: %d, Bytes: %d, Verified Secrets: %d, Unverified Secrets: %d, Duration: %s\n",
		customMetrics.ChunksScanned, customMetrics.BytesScanned, customMetrics.VerifiedSecretsFound, customMetrics.UnverifiedSecretsFound, customMetrics.ScanDuration.String())
	fmt.Printf("Entire chunk - Chunks: %d, Bytes: %d, Verified Secrets: %d, Unverified Secrets: %d, Duration: %s\n",
		entireMetrics.ChunksScanned, entireMetrics.BytesScanned, entireMetrics.VerifiedSecretsFound, entireMetrics.UnverifiedSecretsFound, entireMetrics.ScanDuration.String())

	// Check for differences in scan metrics.
	if customMetrics.ChunksScanned != entireMetrics.ChunksScanned ||
		customMetrics.BytesScanned != entireMetrics.BytesScanned ||
		customMetrics.VerifiedSecretsFound != entireMetrics.VerifiedSecretsFound {
		return fmt.Errorf("scan metrics do not match")
	}

	return nil
}

type metrics struct {
	engine.Metrics
	hasFoundResults bool
}

func runSingleScan(ctx context.Context, cmd string, cfg engine.Config) (metrics, error) {
	var scanMetrics metrics

	// Setup job report writer if provided
	var jobReportWriter io.WriteCloser
	if *jobReportFile != nil {
		jobReportWriter = *jobReportFile
	}

	handleFinishedMetrics := func(ctx context.Context, finishedMetrics <-chan sources.UnitMetrics, jobReportWriter io.WriteCloser) {
		go func() {
			defer func() {
				jobReportWriter.Close()
				if namer, ok := jobReportWriter.(interface{ Name() string }); ok {
					ctx.Logger().Info("report written", "path", namer.Name())
				} else {
					ctx.Logger().Info("report written")
				}
			}()

			for metrics := range finishedMetrics {
				metrics.Errors = common.ExportErrors(metrics.Errors...)
				details, err := json.Marshal(map[string]any{
					"version": 1,
					"data":    metrics,
				})
				if err != nil {
					ctx.Logger().Error(err, "error marshalling job details")
					continue
				}
				if _, err := jobReportWriter.Write(append(details, '\n')); err != nil {
					ctx.Logger().Error(err, "error writing to file")
				}
			}
		}()
	}

	const defaultOutputBufferSize = 64
	opts := []func(*sources.SourceManager){
		sources.WithConcurrentSources(cfg.Concurrency),
		sources.WithConcurrentUnits(cfg.Concurrency),
		sources.WithSourceUnits(),
		sources.WithBufferedOutput(defaultOutputBufferSize),
	}

	if jobReportWriter != nil {
		unitHook, finishedMetrics := sources.NewUnitHook(ctx)
		opts = append(opts, sources.WithReportHook(unitHook))
		handleFinishedMetrics(ctx, finishedMetrics, jobReportWriter)
	}

	cfg.SourceManager = sources.NewManager(opts...)

	eng, err := engine.NewEngine(ctx, &cfg)
	if err != nil {
		return scanMetrics, fmt.Errorf("error initializing engine: %v", err)
	}
	eng.Start(ctx)

	defer func() {
		// Clean up temporary artifacts.
		if err := cleantemp.CleanTempArtifacts(ctx); err != nil {
			ctx.Logger().Error(err, "error cleaning temp artifacts")
		}
	}()

	switch cmd {
	case gitScan.FullCommand():
		gitCfg := sources.GitConfig{
			URI:              *gitScanURI,
			IncludePathsFile: *gitScanIncludePaths,
			ExcludePathsFile: *gitScanExcludePaths,
			HeadRef:          *gitScanBranch,
			BaseRef:          *gitScanSinceCommit,
			MaxDepth:         *gitScanMaxDepth,
			Bare:             *gitScanBare,
			ExcludeGlobs:     *gitScanExcludeGlobs,
		}
		if err = eng.ScanGit(ctx, gitCfg); err != nil {
			return scanMetrics, fmt.Errorf("failed to scan Git: %v", err)
		}
	case githubScan.FullCommand():
		filter, err := common.FilterFromFiles(*githubScanIncludePaths, *githubScanExcludePaths)
		if err != nil {
			return scanMetrics, fmt.Errorf("could not create filter: %v", err)
		}
		if len(*githubScanOrgs) == 0 && len(*githubScanRepos) == 0 {
			return scanMetrics, fmt.Errorf("invalid config: you must specify at least one organization or repository")
		}

		cfg := sources.GithubConfig{
			Endpoint:                   *githubScanEndpoint,
			Token:                      *githubScanToken,
			IncludeForks:               *githubIncludeForks,
			IncludeMembers:             *githubIncludeMembers,
			IncludeWikis:               *githubIncludeWikis,
			Concurrency:                *concurrency,
			ExcludeRepos:               *githubExcludeRepos,
			IncludeRepos:               *githubIncludeRepos,
			Repos:                      *githubScanRepos,
			Orgs:                       *githubScanOrgs,
			IncludeIssueComments:       *githubScanIssueComments,
			IncludePullRequestComments: *githubScanPRComments,
			IncludeGistComments:        *githubScanGistComments,
			CommentsTimeframeDays:      *githubCommentsTimeframeDays,
			Filter:                     filter,
		}
		if err := eng.ScanGitHub(ctx, cfg); err != nil {
			return scanMetrics, fmt.Errorf("failed to scan Github: %v", err)
		}
	case githubExperimentalScan.FullCommand():
		cfg := sources.GitHubExperimentalConfig{
			Token:              *githubExperimentalToken,
			Repository:         *githubExperimentalRepo,
			ObjectDiscovery:    *githubExperimentalObjectDiscovery,
			CollisionThreshold: *githubExperimentalCollisionThreshold,
			DeleteCachedData:   *githubExperimentalDeleteCache,
		}
		if err := eng.ScanGitHubExperimental(ctx, cfg); err != nil {
			return scanMetrics, fmt.Errorf("failed to scan using Github Experimental: %v", err)
		}
	case gitlabScan.FullCommand():
		filter, err := common.FilterFromFiles(*gitlabScanIncludePaths, *gitlabScanExcludePaths)
		if err != nil {
			return scanMetrics, fmt.Errorf("could not create filter: %v", err)
		}

		cfg := sources.GitlabConfig{
			Endpoint:     *gitlabScanEndpoint,
			Token:        *gitlabScanToken,
			Repos:        *gitlabScanRepos,
			IncludeRepos: *gitlabScanIncludeRepos,
			ExcludeRepos: *gitlabScanExcludeRepos,
			Filter:       filter,
		}
		if err := eng.ScanGitLab(ctx, cfg); err != nil {
			return scanMetrics, fmt.Errorf("failed to scan GitLab: %v", err)
		}
	case filesystemScan.FullCommand():
		if len(*filesystemDirectories) > 0 {
			ctx.Logger().Info("--directory flag is deprecated, please pass directories as arguments")
		}
		paths := make([]string, 0, len(*filesystemPaths)+len(*filesystemDirectories))
		paths = append(paths, *filesystemPaths...)
		paths = append(paths, *filesystemDirectories...)
		cfg := sources.FilesystemConfig{
			Paths:            paths,
			IncludePathsFile: *filesystemScanIncludePaths,
			ExcludePathsFile: *filesystemScanExcludePaths,
		}
		if err = eng.ScanFileSystem(ctx, cfg); err != nil {
			return scanMetrics, fmt.Errorf("failed to scan filesystem: %v", err)
		}
	case s3Scan.FullCommand():
		cfg := sources.S3Config{
			Key:           *s3ScanKey,
			Secret:        *s3ScanSecret,
			SessionToken:  *s3ScanSessionToken,
			Buckets:       *s3ScanBuckets,
			IgnoreBuckets: *s3ScanIgnoreBuckets,
			Roles:         *s3ScanRoleArns,
			CloudCred:     *s3ScanCloudEnv,
			MaxObjectSize: int64(*s3ScanMaxObjectSize),
		}
		if err := eng.ScanS3(ctx, cfg); err != nil {
			return scanMetrics, fmt.Errorf("failed to scan S3: %v", err)
		}
	case syslogScan.FullCommand():
		cfg := sources.SyslogConfig{
			Address:     *syslogAddress,
			Format:      *syslogFormat,
			Protocol:    *syslogProtocol,
			CertPath:    *syslogTLSCert,
			KeyPath:     *syslogTLSKey,
			Concurrency: *concurrency,
		}
		if err := eng.ScanSyslog(ctx, cfg); err != nil {
			return scanMetrics, fmt.Errorf("failed to scan syslog: %v", err)
		}
	case circleCiScan.FullCommand():
		if err := eng.ScanCircleCI(ctx, *circleCiScanToken); err != nil {
			return scanMetrics, fmt.Errorf("failed to scan CircleCI: %v", err)
		}
	case travisCiScan.FullCommand():
		if err := eng.ScanTravisCI(ctx, *travisCiScanToken); err != nil {
			return scanMetrics, fmt.Errorf("failed to scan TravisCI: %v", err)
		}
	case gcsScan.FullCommand():
		cfg := sources.GCSConfig{
			ProjectID:      *gcsProjectID,
			CloudCred:      *gcsCloudEnv,
			ServiceAccount: *gcsServiceAccount,
			WithoutAuth:    *gcsWithoutAuth,
			ApiKey:         *gcsAPIKey,
			IncludeBuckets: commaSeparatedToSlice(*gcsIncludeBuckets),
			ExcludeBuckets: commaSeparatedToSlice(*gcsExcludeBuckets),
			IncludeObjects: commaSeparatedToSlice(*gcsIncludeObjects),
			ExcludeObjects: commaSeparatedToSlice(*gcsExcludeObjects),
			Concurrency:    *concurrency,
			MaxObjectSize:  int64(*gcsMaxObjectSize),
		}
		if err := eng.ScanGCS(ctx, cfg); err != nil {
			return scanMetrics, fmt.Errorf("failed to scan GCS: %v", err)
		}
	case dockerScan.FullCommand():
		cfg := sources.DockerConfig{
			BearerToken:       *dockerScanToken,
			Images:            *dockerScanImages,
			UseDockerKeychain: *dockerScanToken == "",
		}
		if err := eng.ScanDocker(ctx, cfg); err != nil {
			return scanMetrics, fmt.Errorf("failed to scan Docker: %v", err)
		}
	case postmanScan.FullCommand():
		// handle deprecated flag
		workspaceIDs := make([]string, 0, len(*postmanWorkspaceIDs)+len(*postmanWorkspaces))
		workspaceIDs = append(workspaceIDs, *postmanWorkspaceIDs...)
		workspaceIDs = append(workspaceIDs, *postmanWorkspaces...)

		// handle deprecated flag
		collectionIDs := make([]string, 0, len(*postmanCollectionIDs)+len(*postmanCollections))
		collectionIDs = append(collectionIDs, *postmanCollectionIDs...)
		collectionIDs = append(collectionIDs, *postmanCollections...)

		// handle deprecated flag
		includeCollectionIDs := make([]string, 0, len(*postmanIncludeCollectionIDs)+len(*postmanIncludeCollections))
		includeCollectionIDs = append(includeCollectionIDs, *postmanIncludeCollectionIDs...)
		includeCollectionIDs = append(includeCollectionIDs, *postmanIncludeCollections...)

		// handle deprecated flag
		excludeCollectionIDs := make([]string, 0, len(*postmanExcludeCollectionIDs)+len(*postmanExcludeCollections))
		excludeCollectionIDs = append(excludeCollectionIDs, *postmanExcludeCollectionIDs...)
		excludeCollectionIDs = append(excludeCollectionIDs, *postmanExcludeCollections...)

		cfg := sources.PostmanConfig{
			Token:               *postmanToken,
			Workspaces:          workspaceIDs,
			Collections:         collectionIDs,
			Environments:        *postmanEnvironments,
			IncludeCollections:  includeCollectionIDs,
			IncludeEnvironments: *postmanIncludeEnvironments,
			ExcludeCollections:  excludeCollectionIDs,
			ExcludeEnvironments: *postmanExcludeEnvironments,
			CollectionPaths:     *postmanCollectionPaths,
			WorkspacePaths:      *postmanWorkspacePaths,
			EnvironmentPaths:    *postmanEnvironmentPaths,
		}
		if err := eng.ScanPostman(ctx, cfg); err != nil {
			return scanMetrics, fmt.Errorf("failed to scan Postman: %v", err)
		}
	case elasticsearchScan.FullCommand():
		cfg := sources.ElasticsearchConfig{
			Nodes:          *elasticsearchNodes,
			Username:       *elasticsearchUsername,
			Password:       *elasticsearchPassword,
			CloudID:        *elasticsearchCloudId,
			APIKey:         *elasticsearchAPIKey,
			ServiceToken:   *elasticsearchServiceToken,
			IndexPattern:   *elasticsearchIndexPattern,
			QueryJSON:      *elasticsearchQueryJSON,
			SinceTimestamp: *elasticsearchSinceTimestamp,
			BestEffortScan: *elasticsearchBestEffortScan,
		}
		if err := eng.ScanElasticsearch(ctx, cfg); err != nil {
			return scanMetrics, fmt.Errorf("failed to scan Elasticsearch: %v", err)
		}
	case jenkinsScan.FullCommand():
		cfg := engine.JenkinsConfig{
			Endpoint:              *jenkinsURL,
			InsecureSkipVerifyTLS: *jenkinsInsecureSkipVerifyTLS,
			Username:              *jenkinsUsername,
			Password:              *jenkinsPassword,
		}
		if err := eng.ScanJenkins(ctx, cfg); err != nil {
			return scanMetrics, fmt.Errorf("failed to scan Jenkins: %v", err)
		}
	case huggingfaceScan.FullCommand():
		if *huggingfaceEndpoint != "" {
			*huggingfaceEndpoint = strings.TrimRight(*huggingfaceEndpoint, "/")
		}

		if len(*huggingfaceModels) == 0 && len(*huggingfaceSpaces) == 0 && len(*huggingfaceDatasets) == 0 && len(*huggingfaceOrgs) == 0 && len(*huggingfaceUsers) == 0 {
			return scanMetrics, fmt.Errorf("invalid config: you must specify at least one organization, user, model, space or dataset")
		}

		cfg := engine.HuggingfaceConfig{
			Endpoint:           *huggingfaceEndpoint,
			Models:             *huggingfaceModels,
			Spaces:             *huggingfaceSpaces,
			Datasets:           *huggingfaceDatasets,
			Organizations:      *huggingfaceOrgs,
			Users:              *huggingfaceUsers,
			Token:              *huggingfaceToken,
			IncludeModels:      *huggingfaceIncludeModels,
			IncludeSpaces:      *huggingfaceIncludeSpaces,
			IncludeDatasets:    *huggingfaceIncludeDatasets,
			IgnoreModels:       *huggingfaceIgnoreModels,
			IgnoreSpaces:       *huggingfaceIgnoreSpaces,
			IgnoreDatasets:     *huggingfaceIgnoreDatasets,
			SkipAllModels:      *huggingfaceSkipAllModels,
			SkipAllSpaces:      *huggingfaceSkipAllSpaces,
			SkipAllDatasets:    *huggingfaceSkipAllDatasets,
			IncludeDiscussions: *huggingfaceIncludeDiscussions,
			IncludePrs:         *huggingfaceIncludePrs,
			Concurrency:        *concurrency,
		}
		if err := eng.ScanHuggingface(ctx, cfg); err != nil {
			return scanMetrics, fmt.Errorf("failed to scan HuggingFace: %v", err)
		}
	default:
		return scanMetrics, fmt.Errorf("invalid command: %s", cmd)
	}

	// Wait for all workers to finish.
	if err = eng.Finish(ctx); err != nil {
		return scanMetrics, fmt.Errorf("engine failed to finish execution: %v", err)
	}

	if *printAvgDetectorTime {
		printAverageDetectorTime(eng)
	}

	return metrics{Metrics: eng.GetMetrics(), hasFoundResults: eng.HasFoundResults()}, nil
}

// parseResults ensures that users provide valid CSV input to `--results`.
//
// This is a work-around to kingpin not supporting CSVs.
// See: https://github.com/trufflesecurity/trufflehog/pull/2372#issuecomment-1983868917
func parseResults(input *string) (map[string]struct{}, error) {
	if *input == "" {
		return nil, nil
	}

	var (
		values  = strings.Split(strings.ToLower(*input), ",")
		results = make(map[string]struct{}, 3)
	)
	for _, value := range values {
		switch value {
		case "verified", "unknown", "unverified", "filtered_unverified":
			results[value] = struct{}{}
		default:
			return nil, fmt.Errorf("invalid value '%s', valid values are 'verified,unknown,unverified,filtered_unverified'", value)
		}
	}
	return results, nil
}

// logFatalFunc returns a log.Fatal style function. Calling the returned
// function will terminate the program without cleanup.
func logFatalFunc(logger logr.Logger) func(error, string, ...any) {
	return func(err error, message string, keyAndVals ...any) {
		logger.Error(err, message, keyAndVals...)
		if err != nil {
			os.Exit(1)
			return
		}
		os.Exit(0)
	}
}

func commaSeparatedToSlice(s []string) []string {
	var result []string
	for _, items := range s {
		for _, item := range strings.Split(items, ",") {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			result = append(result, item)
		}
	}
	return result
}

func printAverageDetectorTime(e *engine.Engine) {
	fmt.Fprintln(
		os.Stderr,
		"Average detector time is the measurement of average time spent on each detector when results are returned.",
	)
	for detectorName, duration := range e.GetDetectorsMetrics() {
		fmt.Fprintf(os.Stderr, "%s: %s\n", detectorName, duration)
	}
}
