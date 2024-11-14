package engine

import (
	"bytes"
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/adrg/strutil"
	"github.com/adrg/strutil/metrics"
	lru "github.com/hashicorp/golang-lru/v2"
	"google.golang.org/protobuf/proto"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/decoders"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	"github.com/trufflesecurity/trufflehog/v3/pkg/giturl"
	"github.com/trufflesecurity/trufflehog/v3/pkg/output"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

const detectionTimeout = 10 * time.Second

var errOverlap = errors.New(
	"More than one detector has found this result. For your safety, verification has been disabled." +
		"You can override this behavior by using the --allow-verification-overlap flag.",
)

// Metrics for the scan engine for external consumption.
type Metrics struct {
	BytesScanned           uint64
	ChunksScanned          uint64
	VerifiedSecretsFound   uint64
	UnverifiedSecretsFound uint64
	AvgDetectorTime        map[string]time.Duration

	scanStartTime time.Time
	ScanDuration  time.Duration
}

// runtimeMetrics for the scan engine for internal use by the engine.
type runtimeMetrics struct {
	mu sync.RWMutex
	Metrics
	detectorAvgTime sync.Map
}

// getScanDuration returns the duration of the scan.
// If the scan is still running, it returns the time since the scan started.
func (m *Metrics) getScanDuration() time.Duration {
	if m.ScanDuration == 0 {
		return time.Since(m.scanStartTime)
	}

	return m.ScanDuration
}

// ResultsDispatcher is an interface for dispatching findings of detected results.
// Implementations can vary from printing results to the console to sending results to an external system.
type ResultsDispatcher interface {
	Dispatch(ctx context.Context, result detectors.ResultWithMetadata) error
}

// Printer is used to format found results and output them to the user. Ex JSON, plain text, etc.
// Please note printer implementations SHOULD BE thread safe.
type Printer interface {
	Print(ctx context.Context, r *detectors.ResultWithMetadata) error
}

// PrinterDispatcher wraps an existing Printer implementation and adapts it to the ResultsDispatcher interface.
type PrinterDispatcher struct{ printer Printer }

// NewPrinterDispatcher creates a new PrinterDispatcher instance with the provided Printer.
func NewPrinterDispatcher(printer Printer) *PrinterDispatcher { return &PrinterDispatcher{printer} }

// Dispatch sends the result to the printer.
func (p *PrinterDispatcher) Dispatch(ctx context.Context, result detectors.ResultWithMetadata) error {
	return p.printer.Print(ctx, &result)
}

// Config used to configure the engine.
type Config struct {
	// Number of concurrent scanner workers,
	// also serves as a multiplier for other worker types (e.g., detector workers, notifier workers)
	Concurrency int

	Decoders                      []decoders.Decoder
	Detectors                     []detectors.Detector
	DetectorVerificationOverrides map[config.DetectorID]bool
	IncludeDetectors              string
	ExcludeDetectors              string
	CustomVerifiersOnly           bool
	VerifierEndpoints             map[string]string

	// Verify determines whether the scanner will verify candidate secrets.
	Verify bool

	// Defines which results will be notified by the engine
	// (e.g., verified, unverified, unknown)
	Results               map[string]struct{}
	LogFilteredUnverified bool

	// FilterEntropy filters out unverified results using Shannon entropy.
	FilterEntropy float64
	// FilterUnverified sets the filterUnverified flag on the engine. If set to
	// true, the engine will only return the first unverified result for a chunk for a detector.
	FilterUnverified      bool
	ShouldScanEntireChunk bool

	Dispatcher ResultsDispatcher

	// SourceManager is used to manage the sources and units.
	// TODO (ahrav): Update this comment, i'm dumb and don't really know what else it does.
	SourceManager *sources.SourceManager

	// PrintAvgDetectorTime sets the printAvgDetectorTime flag on the engine. If set to
	// true, the engine will print the average time taken by each detector.
	// This option allows us to measure the time taken for each detector ONLY if
	// the engine is configured to print the results.
	// Calculating the average time taken by each detector is an expensive operation
	// and should be avoided unless specified by the user.
	PrintAvgDetectorTime bool

	// VerificationOverlap determines whether the scanner will attempt to verify candidate secrets
	// that have been detected by multiple detectors.
	// By default, it is set to true.
	VerificationOverlap bool

	// DetectorWorkerMultiplier is used to determine the number of detector workers to spawn.
	DetectorWorkerMultiplier int

	// NotificationWorkerMultiplier is used to determine the number of notification workers to spawn.
	NotificationWorkerMultiplier int

	// VerificationOverlapWorkerMultiplier is used to determine the number of verification overlap workers to spawn.
	VerificationOverlapWorkerMultiplier int
}

// Engine represents the core scanning engine responsible for detecting secrets in input data.
// It manages the lifecycle of the scanning process, including initialization, worker management,
// and result notification. The engine is designed to be flexible and configurable, allowing for
// customization through various options and configurations.
type Engine struct {
	// CLI flags.
	concurrency int
	decoders    []decoders.Decoder
	detectors   []detectors.Detector
	// Any detectors configured to override sources' verification flags
	detectorVerificationOverrides map[config.DetectorID]bool

	// filterUnverified is used to reduce the number of unverified results.
	// If there are multiple unverified results for the same chunk for the same detector,
	// only the first one will be kept.
	filterUnverified bool
	// entropyFilter is used to filter out unverified results using Shannon entropy.
	filterEntropy           float64
	notifyVerifiedResults   bool
	notifyUnverifiedResults bool
	notifyUnknownResults    bool
	retainFalsePositives    bool
	verificationOverlap     bool
	printAvgDetectorTime    bool
	// By default, the engine will only scan a subset of the chunk if a detector matches the chunk.
	// If this flag is set to true, the engine will scan the entire chunk.
	scanEntireChunk bool

	// ahoCorasickHandler manages the Aho-Corasick trie and related keyword lookups.
	ahoCorasickCore *ahocorasick.Core

	// Engine synchronization primitives.
	sourceManager                 *sources.SourceManager
	results                       chan detectors.ResultWithMetadata
	detectableChunksChan          chan detectableChunk
	verificationOverlapChunksChan chan verificationOverlapChunk
	workersWg                     sync.WaitGroup
	verificationOverlapWg         sync.WaitGroup
	wgDetectorWorkers             sync.WaitGroup
	WgNotifier                    sync.WaitGroup

	// Runtime information.
	metrics runtimeMetrics
	// numFoundResults is used to keep track of the number of results found.
	numFoundResults uint32

	// ResultsDispatcher is used to send results.
	dispatcher ResultsDispatcher

	// dedupeCache is used to deduplicate results by comparing the
	// detector type, raw result, and source metadata
	dedupeCache *lru.Cache[string, detectorspb.DecoderType]

	// verify determines whether the scanner will attempt to verify candidate secrets.
	verify bool

	// Note: bad hack only used for testing.
	verificationOverlapTracker *verificationOverlapTracker

	// detectorWorkerMultiplier is used to calculate the number of detector workers.
	detectorWorkerMultiplier int
	// notificationWorkerMultiplier is used to calculate the number of notification workers.
	notificationWorkerMultiplier int
	// verificationOverlapWorkerMultiplier is used to calculate the number of verification overlap workers.
	verificationOverlapWorkerMultiplier int
}

// NewEngine creates a new Engine instance with the provided configuration.
func NewEngine(ctx context.Context, cfg *Config) (*Engine, error) {
	engine := &Engine{
		concurrency:                         cfg.Concurrency,
		decoders:                            cfg.Decoders,
		detectors:                           cfg.Detectors,
		dispatcher:                          cfg.Dispatcher,
		verify:                              cfg.Verify,
		filterUnverified:                    cfg.FilterUnverified,
		filterEntropy:                       cfg.FilterEntropy,
		printAvgDetectorTime:                cfg.PrintAvgDetectorTime,
		retainFalsePositives:                cfg.LogFilteredUnverified,
		verificationOverlap:                 cfg.VerificationOverlap,
		sourceManager:                       cfg.SourceManager,
		scanEntireChunk:                     cfg.ShouldScanEntireChunk,
		detectorVerificationOverrides:       cfg.DetectorVerificationOverrides,
		detectorWorkerMultiplier:            cfg.DetectorWorkerMultiplier,
		notificationWorkerMultiplier:        cfg.NotificationWorkerMultiplier,
		verificationOverlapWorkerMultiplier: cfg.VerificationOverlapWorkerMultiplier,
	}
	if engine.sourceManager == nil {
		return nil, fmt.Errorf("source manager is required")
	}

	engine.setDefaults(ctx)

	// Build include and exclude detector sets for filtering on engine initialization.
	includeDetectorSet, excludeDetectorSet, err := buildDetectorSets(cfg)
	if err != nil {
		return nil, err
	}

	// Apply include/exclude filters.
	var filters []func(detectors.Detector) bool

	if len(includeDetectorSet) > 0 {
		filters = append(filters, func(d detectors.Detector) bool {
			_, ok := getWithDetectorID(d, includeDetectorSet)
			return ok
		})
	}

	if len(excludeDetectorSet) > 0 {
		filters = append(filters, func(d detectors.Detector) bool {
			_, ok := getWithDetectorID(d, excludeDetectorSet)
			return !ok
		})
	}

	// Apply custom verifier endpoints to detectors that support it.
	detectorsWithCustomVerifierEndpoints, err := parseCustomVerifierEndpoints(cfg.VerifierEndpoints)
	if err != nil {
		return nil, err
	}
	if len(detectorsWithCustomVerifierEndpoints) > 0 {
		filters = append(filters, func(d detectors.Detector) bool {
			urls, ok := getWithDetectorID(d, detectorsWithCustomVerifierEndpoints)
			if !ok {
				return true
			}
			customizer, ok := d.(detectors.EndpointCustomizer)
			if !ok {
				return false
			}

			if cfg.CustomVerifiersOnly && len(urls) > 0 {
				customizer.UseCloudEndpoint(false)
				customizer.UseFoundEndpoints(false)
			}

			if err := customizer.SetConfiguredEndpoints(urls...); err != nil {
				return false
			}

			return true
		})
	}
	engine.applyFilters(filters...)

	if results := cfg.Results; len(results) > 0 {
		_, ok := results["verified"]
		engine.notifyVerifiedResults = ok

		_, ok = results["unknown"]
		engine.notifyUnknownResults = ok

		_, ok = results["unverified"]
		engine.notifyUnverifiedResults = ok

		if _, ok = results["filtered_unverified"]; ok {
			engine.retainFalsePositives = ok
			engine.notifyUnverifiedResults = ok
		}
	}

	if err := engine.initialize(ctx); err != nil {
		return nil, err
	}

	return engine, nil
}

// setDefaults ensures that if specific engine properties aren't provided,
// they're set to reasonable default values. It makes the engine robust to
// incomplete configuration.
func (e *Engine) setDefaults(ctx context.Context) {
	if e.concurrency == 0 {
		numCPU := runtime.NumCPU()
		ctx.Logger().Info("No concurrency specified, defaulting to max", "cpu", numCPU)
		e.concurrency = numCPU
	}

	if e.detectorWorkerMultiplier < 1 {
		// bound by net i/o so it's higher than other workers
		e.detectorWorkerMultiplier = 8
	}

	if e.notificationWorkerMultiplier < 1 {
		e.notificationWorkerMultiplier = 1
	}

	if e.verificationOverlapWorkerMultiplier < 1 {
		e.verificationOverlapWorkerMultiplier = 1
	}

	// Default decoders handle common encoding formats.
	if len(e.decoders) == 0 {
		e.decoders = decoders.DefaultDecoders()
	}

	// Only use the default detectors if none are provided.
	if len(e.detectors) == 0 {
		e.detectors = DefaultDetectors()
	}

	if e.dispatcher == nil {
		e.dispatcher = NewPrinterDispatcher(new(output.PlainPrinter))
	}
	e.notifyVerifiedResults = true
	e.notifyUnverifiedResults = true
	e.notifyUnknownResults = true

	ctx.Logger().V(4).Info("default engine options set")
}

func buildDetectorSets(cfg *Config) (map[config.DetectorID]struct{}, map[config.DetectorID]struct{}, error) {
	includeList, err := config.ParseDetectors(cfg.IncludeDetectors)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid include list detector configuration: %w", err)
	}
	excludeList, err := config.ParseDetectors(cfg.ExcludeDetectors)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid exclude list detector configuration: %w", err)
	}

	includeDetectorSet := detectorTypeToSet(includeList)
	excludeDetectorSet := detectorTypeToSet(excludeList)

	// Verify that all the user-provided detectors support the optional
	// detector features.
	if id, err := verifyDetectorsAreVersioner(includeDetectorSet); err != nil {
		return nil, nil, fmt.Errorf("invalid include list detector configuration id %v: %w", id, err)
	}

	if id, err := verifyDetectorsAreVersioner(excludeDetectorSet); err != nil {
		return nil, nil, fmt.Errorf("invalid exclude list detector configuration id %v: %w", id, err)
	}

	return includeDetectorSet, excludeDetectorSet, nil
}

func parseCustomVerifierEndpoints(endpoints map[string]string) (map[config.DetectorID][]string, error) {
	if len(endpoints) == 0 {
		return nil, nil
	}

	customVerifierEndpoints, err := config.ParseVerifierEndpoints(endpoints)
	if err != nil {
		return nil, fmt.Errorf("invalid verifier detector configuration: %w", err)
	}

	if id, err := verifyDetectorsAreVersioner(customVerifierEndpoints); err != nil {
		return nil, fmt.Errorf("invalid verifier detector configuration id %v: %w", id, err)
	}
	// Extra check for endpoint customization.
	isEndpointCustomizer := DefaultDetectorTypesImplementing[detectors.EndpointCustomizer]()
	for id := range customVerifierEndpoints {
		if _, ok := isEndpointCustomizer[id.ID]; !ok {
			return nil, fmt.Errorf("endpoint provided but detector does not support endpoint customization: %w", err)
		}
	}
	return customVerifierEndpoints, nil
}

// detectorTypeToSet is a helper function to convert a slice of detector IDs into a set.
func detectorTypeToSet(detectors []config.DetectorID) map[config.DetectorID]struct{} {
	out := make(map[config.DetectorID]struct{}, len(detectors))
	for _, d := range detectors {
		out[d] = struct{}{}
	}
	return out
}

// getWithDetectorID is a helper function to get a value from a map using a
// detector's ID. This function behaves like a normal map lookup, with an extra
// step of checking for the non-specific version of a detector.
func getWithDetectorID[T any](d detectors.Detector, data map[config.DetectorID]T) (T, bool) {
	key := config.GetDetectorID(d)
	// Check if the specific ID is provided.
	if t, ok := data[key]; ok || key.Version == 0 {
		return t, ok
	}
	// Check if the generic type is provided without a version.
	// This means "all" versions of a type.
	key.Version = 0
	t, ok := data[key]
	return t, ok
}

// verifyDetectorsAreVersioner checks all keys in a provided map to verify the
// provided type is actually a Versioner.
func verifyDetectorsAreVersioner[T any](data map[config.DetectorID]T) (config.DetectorID, error) {
	isVersioner := DefaultDetectorTypesImplementing[detectors.Versioner]()
	for id := range data {
		if id.Version == 0 {
			// Version not provided.
			continue
		}
		if _, ok := isVersioner[id.ID]; ok {
			// Version provided for a Versioner detector.
			continue
		}
		// Version provided on a non-Versioner detector.
		return id, fmt.Errorf("version provided but detector does not have a version")
	}
	return config.DetectorID{}, nil
}

// applyFilters applies a variable number of filters to the detectors.
func (e *Engine) applyFilters(filters ...func(detectors.Detector) bool) {
	for _, filter := range filters {
		e.detectors = filterDetectors(filter, e.detectors)
	}
}

func filterDetectors(filterFunc func(detectors.Detector) bool, input []detectors.Detector) []detectors.Detector {
	var out []detectors.Detector
	for _, detector := range input {
		if filterFunc(detector) {
			out = append(out, detector)
		}
	}
	return out
}

// initialize prepares the engine's internal structures. The LRU cache optimizes
// deduplication efforts, allowing the engine to quickly check if a chunk has
// been processed before, thereby saving computational overhead.
func (e *Engine) initialize(ctx context.Context) error {
	// TODO (ahrav): Determine the optimal cache size.
	const cacheSize = 512 // number of entries in the LRU cache

	cache, err := lru.New[string, detectorspb.DecoderType](cacheSize)
	if err != nil {
		return fmt.Errorf("failed to initialize LRU cache: %w", err)
	}
	const (
		// detectableChunksChanMultiplier is set to accommodate a high number of concurrent worker goroutines.
		// This multiplier ensures that the detectableChunksChan channel has sufficient buffer capacity
		// to hold messages from multiple worker groups (detector workers/ verificationOverlap workers) without blocking.
		// A large buffer helps accommodate for the fact workers are producing data at a faster rate
		// than it can be consumed.
		detectableChunksChanMultiplier = 50
		// verificationOverlapChunksChanMultiplier uses a smaller buffer compared to detectableChunksChanMultiplier.
		// This reflects the anticipated lower volume of data that needs re-verification.
		// The buffer size is a trade-off between memory usage and the need to prevent blocking.
		verificationOverlapChunksChanMultiplier = 25
		resultsChanMultiplier                   = detectableChunksChanMultiplier
	)

	// Channels are used for communication between different parts of the engine,
	// ensuring that data flows smoothly without race conditions.
	// The buffer sizes for these channels are set to multiples of defaultChannelBuffer,
	// considering the expected concurrency and workload in the system.
	e.detectableChunksChan = make(chan detectableChunk, defaultChannelBuffer*detectableChunksChanMultiplier)
	e.verificationOverlapChunksChan = make(
		chan verificationOverlapChunk, defaultChannelBuffer*verificationOverlapChunksChanMultiplier,
	)
	e.results = make(chan detectors.ResultWithMetadata, defaultChannelBuffer*resultsChanMultiplier)
	e.dedupeCache = cache
	ctx.Logger().V(4).Info("engine initialized")

	// Configure the EntireChunkSpanCalculator if the engine is set to scan the entire chunk.
	var ahoCOptions []ahocorasick.CoreOption
	if e.scanEntireChunk {
		ahoCOptions = append(ahoCOptions, ahocorasick.WithSpanCalculator(new(ahocorasick.EntireChunkSpanCalculator)))
	}

	ctx.Logger().V(4).Info("setting up aho-corasick core")
	e.ahoCorasickCore = ahocorasick.NewAhoCorasickCore(e.detectors, ahoCOptions...)
	ctx.Logger().V(4).Info("set up aho-corasick core")

	return nil
}

type verificationOverlapTracker struct {
	verificationOverlapDuplicateCount int
	mu                                sync.Mutex
}

func (r *verificationOverlapTracker) increment() {
	r.mu.Lock()
	r.verificationOverlapDuplicateCount++
	r.mu.Unlock()
}

const ignoreTag = "trufflehog:ignore"

// HasFoundResults returns true if any results are found.
func (e *Engine) HasFoundResults() bool {
	return atomic.LoadUint32(&e.numFoundResults) > 0
}

// GetMetrics returns a copy of Metrics.
// It's safe for concurrent use, and the caller can't modify the original data.
func (e *Engine) GetMetrics() Metrics {
	e.metrics.mu.RLock()
	defer e.metrics.mu.RUnlock()

	result := e.metrics.Metrics
	result.AvgDetectorTime = make(map[string]time.Duration, len(e.metrics.AvgDetectorTime))

	for detectorName, durations := range e.DetectorAvgTime() {
		var total time.Duration
		for _, d := range durations {
			total += d
		}
		avgDuration := total / time.Duration(len(durations))
		result.AvgDetectorTime[detectorName] = avgDuration
	}

	result.ScanDuration = e.metrics.getScanDuration()

	return result
}

// GetDetectorsMetrics returns a copy of the average time taken by each detector.
func (e *Engine) GetDetectorsMetrics() map[string]time.Duration {
	e.metrics.mu.RLock()
	defer e.metrics.mu.RUnlock()

	result := make(map[string]time.Duration, len(DefaultDetectors()))
	for detectorName, durations := range e.DetectorAvgTime() {
		var total time.Duration
		for _, d := range durations {
			total += d
		}
		avgDuration := total / time.Duration(len(durations))
		result[detectorName] = avgDuration
	}

	return result
}

// DetectorAvgTime returns the average time taken by each detector.
func (e *Engine) DetectorAvgTime() map[string][]time.Duration {
	logger := context.Background().Logger()
	avgTime := map[string][]time.Duration{}
	e.metrics.detectorAvgTime.Range(func(k, v any) bool {
		key, ok := k.(string)
		if !ok {
			logger.Info("expected detectorAvgTime key to be a string")
			return true
		}

		value, ok := v.([]time.Duration)
		if !ok {
			logger.Info("expected detectorAvgTime value to be []time.Duration")
			return true
		}
		avgTime[key] = value
		return true
	})
	return avgTime
}

// Start initializes and activates the engine's processing pipeline.
// It sets up various default configurations, prepares lookup structures for
// detectors, and kickstarts all necessary workers. Once started, the engine
// begins processing input data to identify secrets.
func (e *Engine) Start(ctx context.Context) {
	e.metrics = runtimeMetrics{Metrics: Metrics{scanStartTime: time.Now()}}
	e.sanityChecks(ctx)
	e.startWorkers(ctx)
}

var defaultChannelBuffer = runtime.NumCPU()

// Sanity check detectors for duplicate configuration. Only log in case
// a detector has been configured in a way that isn't represented by
// the DetectorID (type and version).
func (e *Engine) sanityChecks(ctx context.Context) {
	seenDetectors := make(map[config.DetectorID]struct{}, len(e.detectors))
	for _, det := range e.detectors {
		id := config.GetDetectorID(det)
		if _, ok := seenDetectors[id]; ok && id.ID != detectorspb.DetectorType_CustomRegex {
			ctx.Logger().Info("possible duplicate detector configured", "detector", id)
		}
		seenDetectors[id] = struct{}{}
	}
}

// startWorkers initiates all necessary workers. Workers handle processing of
// chunks concurrently. Separating the initialization of different types of
// workers helps in scalability and makes it easier to diagnose issues.
func (e *Engine) startWorkers(ctx context.Context) {
	// Scanner workers process input data and extract chunks for detectors.
	e.startScannerWorkers(ctx)

	// Detector workers apply keyword matching, regexes and API calls to detect secrets in chunks.
	e.startDetectorWorkers(ctx)

	// verificationOverlap workers handle verification of chunks that have been detected by multiple detectors.
	// They ensure that verification is disabled for any secrets that have been detected by multiple detectors.
	e.startVerificationOverlapWorkers(ctx)

	// ResultsDispatcher workers communicate detected issues to the user or any downstream systems.
	// We want 1/4th of the notifier workers as the number of scanner workers.
	e.startNotifierWorkers(ctx)
}

func (e *Engine) startScannerWorkers(ctx context.Context) {
	ctx.Logger().V(2).Info("starting scanner workers", "count", e.concurrency)
	for worker := uint64(0); worker < uint64(e.concurrency); worker++ {
		e.workersWg.Add(1)
		go func() {
			ctx := context.WithValue(ctx, "scanner_worker_id", common.RandomID(5))
			defer common.Recover(ctx)
			defer e.workersWg.Done()
			e.scannerWorker(ctx)
		}()
	}
}

func (e *Engine) startDetectorWorkers(ctx context.Context) {
	numWorkers := e.concurrency * e.detectorWorkerMultiplier

	ctx.Logger().V(2).Info("starting detector workers", "count", numWorkers)
	for worker := 0; worker < numWorkers; worker++ {
		e.wgDetectorWorkers.Add(1)
		go func() {
			ctx := context.WithValue(ctx, "detector_worker_id", common.RandomID(5))
			defer common.Recover(ctx)
			defer e.wgDetectorWorkers.Done()
			e.detectorWorker(ctx)
		}()
	}
}

func (e *Engine) startVerificationOverlapWorkers(ctx context.Context) {
	numWorkers := e.concurrency * e.verificationOverlapWorkerMultiplier

	ctx.Logger().V(2).Info("starting verificationOverlap workers", "count", numWorkers)
	for worker := 0; worker < numWorkers; worker++ {
		e.verificationOverlapWg.Add(1)
		go func() {
			ctx := context.WithValue(ctx, "verification_overlap_worker_id", common.RandomID(5))
			defer common.Recover(ctx)
			defer e.verificationOverlapWg.Done()
			e.verificationOverlapWorker(ctx)
		}()
	}
}

func (e *Engine) startNotifierWorkers(ctx context.Context) {
	numWorkers := e.notificationWorkerMultiplier * e.concurrency

	ctx.Logger().V(2).Info("starting notifier workers", "count", numWorkers)
	for worker := 0; worker < numWorkers; worker++ {
		e.WgNotifier.Add(1)
		go func() {
			ctx := context.WithValue(ctx, "notifier_worker_id", common.RandomID(5))
			defer common.Recover(ctx)
			defer e.WgNotifier.Done()
			e.notifierWorker(ctx)
		}()
	}
}

// Finish waits for running sources to complete and workers to finish scanning
// chunks before closing their respective channels. Once Finish is called, no
// more sources may be scanned by the engine.
func (e *Engine) Finish(ctx context.Context) error {
	defer common.RecoverWithExit(ctx)
	// Wait for the sources to finish putting chunks onto the chunks channel.
	err := e.sourceManager.Wait()

	e.workersWg.Wait() // Wait for the workers to finish scanning chunks.

	close(e.verificationOverlapChunksChan)
	e.verificationOverlapWg.Wait()

	close(e.detectableChunksChan)
	e.wgDetectorWorkers.Wait() // Wait for the detector workers to finish detecting chunks.

	close(e.results)    // Detector workers are done, close the results channel and call it a day.
	e.WgNotifier.Wait() // Wait for the notifier workers to finish notifying results.

	e.metrics.ScanDuration = time.Since(e.metrics.scanStartTime)

	return err
}

func (e *Engine) ChunksChan() <-chan *sources.Chunk {
	return e.sourceManager.Chunks()
}

func (e *Engine) ResultsChan() chan detectors.ResultWithMetadata {
	return e.results
}

// ScanChunk injects a chunk into the output stream of chunks to be scanned.
// This method should rarely be used. TODO(THOG-1577): Remove when dependencies
// no longer rely on this functionality.
func (e *Engine) ScanChunk(chunk *sources.Chunk) {
	e.sourceManager.ScanChunk(chunk)
}

// detectableChunk is a decoded chunk that is ready to be scanned by its detector.
type detectableChunk struct {
	detector *ahocorasick.DetectorMatch
	chunk    sources.Chunk
	decoder  detectorspb.DecoderType
	wgDoneFn func()
}

// verificationOverlapChunk is a decoded chunk that has multiple detectors that match it.
// It will be initially processed with verification disabled, and then reprocessed with verification
// enabled if the same secret was not found by multiple detectors.
type verificationOverlapChunk struct {
	chunk                       sources.Chunk
	decoder                     detectorspb.DecoderType
	detectors                   []*ahocorasick.DetectorMatch
	verificationOverlapWgDoneFn func()
}

func (e *Engine) scannerWorker(ctx context.Context) {
	var wgDetect sync.WaitGroup
	var wgVerificationOverlap sync.WaitGroup

	for chunk := range e.ChunksChan() {
		startTime := time.Now()
		sourceVerify := chunk.Verify
		for _, decoder := range e.decoders {
			decodeStart := time.Now()
			decoded := decoder.FromChunk(chunk)
			decodeTime := time.Since(decodeStart).Microseconds()
			decodeLatency.WithLabelValues(decoder.Type().String(), chunk.SourceName).Observe(float64(decodeTime))

			if decoded == nil {
				ctx.Logger().V(5).Info("decoder not applicable for chunk", "decoder", decoder.Type().String(), "chunk", chunk)
				continue
			}

			matchingDetectors := e.ahoCorasickCore.FindDetectorMatches(decoded.Chunk.Data)
			if len(matchingDetectors) > 1 && !e.verificationOverlap {
				wgVerificationOverlap.Add(1)
				e.verificationOverlapChunksChan <- verificationOverlapChunk{
					chunk:                       *decoded.Chunk,
					detectors:                   matchingDetectors,
					decoder:                     decoded.DecoderType,
					verificationOverlapWgDoneFn: wgVerificationOverlap.Done,
				}
				continue
			}

			for _, detector := range matchingDetectors {
				decoded.Chunk.Verify = e.shouldVerifyChunk(sourceVerify, detector, e.detectorVerificationOverrides)
				wgDetect.Add(1)
				e.detectableChunksChan <- detectableChunk{
					chunk:    *decoded.Chunk,
					detector: detector,
					decoder:  decoded.DecoderType,
					wgDoneFn: wgDetect.Done,
				}
			}
		}

		dataSize := float64(len(chunk.Data))

		scanBytesPerChunk.Observe(dataSize)
		jobBytesScanned.WithLabelValues(
			strconv.Itoa(int(chunk.JobID)),
			chunk.SourceType.String(),
			chunk.SourceName,
		).Add(dataSize)
		chunksScannedLatency.Observe(float64(time.Since(startTime).Microseconds()))
		jobChunksScanned.WithLabelValues(
			strconv.Itoa(int(chunk.JobID)),
			chunk.SourceType.String(),
			chunk.SourceName,
		).Inc()

		atomic.AddUint64(&e.metrics.ChunksScanned, 1)
		atomic.AddUint64(&e.metrics.BytesScanned, uint64(dataSize))
	}

	wgVerificationOverlap.Wait()
	wgDetect.Wait()
	ctx.Logger().V(4).Info("finished scanning chunks")
}

func (e *Engine) shouldVerifyChunk(
	sourceVerify bool,
	detector detectors.Detector,
	detectorVerificationOverrides map[config.DetectorID]bool,
) bool {
	// The verify flag takes precedence over the detector's verification flag.
	if !e.verify {
		return false
	}

	detectorId := config.DetectorID{ID: detector.Type(), Version: 0}

	if v, ok := detector.(detectors.Versioner); ok {
		detectorId.Version = v.Version()
	}

	if detectorVerify, ok := detectorVerificationOverrides[detectorId]; ok {
		return detectorVerify
	}

	// If the user is running with a detector verification override that does not specify a particular detector version,
	// then its override map entry will have version 0. We should check for that too, but if the detector being checked
	// doesn't have any version information then its version is 0, so we've already done the check, and we don't need to
	// do it a second time.
	if detectorId.Version != 0 {
		detectorId.Version = 0

		if detectorVerify, ok := detectorVerificationOverrides[detectorId]; ok {
			return detectorVerify
		}
	}

	return sourceVerify
}

// chunkSecretKey ties secrets to the specific detector that found them. This allows identifying identical
// credentials extracted by multiple different detectors processing the same chunk. Or duplicates found
// by the same detector in the chunk. Exact matches on lookup indicate a duplicate secret for a detector
// in that chunk - which is expected and not malicious. Those intra-detector dupes are still verified.
type chunkSecretKey struct {
	secret      string
	detectorKey ahocorasick.DetectorKey
}

func likelyDuplicate(ctx context.Context, val chunkSecretKey, dupes map[chunkSecretKey]struct{}) bool {
	const similarityThreshold = 0.9

	valStr := val.secret
	for dupeKey := range dupes {
		dupe := dupeKey.secret
		// Avoid comparing strings of vastly different lengths.
		if len(dupe)*10 < len(valStr)*9 || len(dupe)*10 > len(valStr)*11 {
			continue
		}

		// If the detector type is the same, we don't need to compare the strings.
		// These are not duplicates, and should be verified.
		if val.detectorKey.Type() == dupeKey.detectorKey.Type() {
			continue
		}

		if valStr == dupe {
			ctx.Logger().V(2).Info(
				"found exact duplicate",
			)
			return true
		}

		similarity := strutil.Similarity(valStr, dupe, metrics.NewLevenshtein())

		// close enough
		if similarity > similarityThreshold {
			ctx.Logger().V(2).Info(
				"found similar duplicate",
			)
			return true
		}
	}
	return false
}

func (e *Engine) verificationOverlapWorker(ctx context.Context) {
	var wgDetect sync.WaitGroup

	// Reuse the same map and slice to avoid allocations.
	const avgSecretsPerDetector = 8
	detectorKeysWithResults := make(map[ahocorasick.DetectorKey]*ahocorasick.DetectorMatch, avgSecretsPerDetector)
	chunkSecrets := make(map[chunkSecretKey]struct{}, avgSecretsPerDetector)

	for chunk := range e.verificationOverlapChunksChan {
		for _, detector := range chunk.detectors {
			isFalsePositive := detectors.GetFalsePositiveCheck(detector.Detector)

			// DO NOT VERIFY at this stage of the pipeline.
			matchedBytes := detector.Matches()
			for _, match := range matchedBytes {
				ctx, cancel := context.WithTimeout(ctx, time.Second*2)
				results, err := detector.FromData(ctx, false, match)
				cancel()
				if err != nil {
					ctx.Logger().V(2).Error(
						err, "error finding results in chunk during verification overlap",
						"detector", detector.Key.Type().String(),
					)
				}

				if len(results) == 0 {
					continue
				}
				if _, ok := detectorKeysWithResults[detector.Key]; !ok {
					detectorKeysWithResults[detector.Key] = detector
				}

				// If results filtration eliminates a rotated secret, then that rotation will never be reported. This
				// problem can theoretically occur for any scan, but we've only actually seen it in practice during
				// targeted scans. (The reason for this discrepancy is unclear.) The simplest fix is therefore to
				// disable filtration for targeted scans, but if you're here because this problem surfaced for a
				// non-targeted scan then we'll have to solve it correctly.
				if chunk.chunk.SecretID == 0 {
					results = e.filterResults(ctx, detector, results)
				}

				for _, res := range results {
					var val []byte
					if res.RawV2 != nil {
						val = res.RawV2
					} else {
						val = res.Raw
					}

					// Use levenstein distance to determine if the secret is likely the same.
					// Ex:
					// - postman api key: PMAK-qnwfsLyRSyfCwfpHaQP1UzDhrgpWvHjbYzjpRCMshjt417zWcrzyHUArs7r
					// - malicious detector "api key": qnwfsLyRSyfCwfpHaQP1UzDhrgpWvHjbYzjpRCMshjt417zWcrzyHUArs7r
					key := chunkSecretKey{secret: string(val), detectorKey: detector.Key}
					if _, ok := chunkSecrets[key]; ok {
						continue
					}

					if likelyDuplicate(ctx, key, chunkSecrets) {
						// This indicates that the same secret was found by multiple detectors.
						// We should NOT VERIFY this chunk's data.
						if e.verificationOverlapTracker != nil {
							e.verificationOverlapTracker.increment()
						}
						res.SetVerificationError(errOverlap)
						e.processResult(
							ctx,
							detectableChunk{
								chunk:    chunk.chunk,
								detector: detector,
								decoder:  chunk.decoder,
								wgDoneFn: wgDetect.Done,
							},
							res,
							isFalsePositive,
						)

						// Remove the detector key from the list of detector keys with results.
						// This is to ensure that the chunk is not reprocessed with verification enabled
						// for this detector.
						delete(detectorKeysWithResults, detector.Key)
					}
					chunkSecrets[key] = struct{}{}
				}
			}
		}

		for _, detector := range detectorKeysWithResults {
			wgDetect.Add(1)
			chunk.chunk.Verify = e.shouldVerifyChunk(chunk.chunk.Verify, detector, e.detectorVerificationOverrides)
			e.detectableChunksChan <- detectableChunk{
				chunk:    chunk.chunk,
				detector: detector,
				decoder:  chunk.decoder,
				wgDoneFn: wgDetect.Done,
			}
		}

		// Empty the dupes and detectors slice
		for k := range chunkSecrets {
			delete(chunkSecrets, k)
		}
		for k := range detectorKeysWithResults {
			delete(detectorKeysWithResults, k)
		}

		chunk.verificationOverlapWgDoneFn()
	}

	wgDetect.Wait()
}

func (e *Engine) detectorWorker(ctx context.Context) {
	for data := range e.detectableChunksChan {
		start := time.Now()
		e.detectChunk(ctx, data)
		chunksDetectedLatency.Observe(float64(time.Since(start).Milliseconds()))
	}
}

func (e *Engine) detectChunk(ctx context.Context, data detectableChunk) {
	var start time.Time
	if e.printAvgDetectorTime {
		start = time.Now()
	}
	defer common.Recover(ctx)

	ctx = context.WithValue(ctx, "detector", data.detector.Key.Loggable())

	isFalsePositive := detectors.GetFalsePositiveCheck(data.detector.Detector)

	var matchCount int
	// To reduce the overhead of regex calls in the detector,
	// we limit the amount of data passed to each detector.
	// The matches field of the DetectorMatch struct contains the
	// relevant portions of the chunk data that were matched.
	// This avoids the need for additional regex processing on the entire chunk data.
	matches := data.detector.Matches()
	for _, matchBytes := range matches {
		matchCount++
		detectBytesPerMatch.Observe(float64(len(matchBytes)))

		ctx, cancel := context.WithTimeout(ctx, detectionTimeout)
		t := time.AfterFunc(detectionTimeout+1*time.Second, func() {
			ctx.Logger().Error(nil, "a detector ignored the context timeout")
		})
		results, err := data.detector.Detector.FromData(ctx, data.chunk.Verify, matchBytes)
		t.Stop()
		cancel()
		if err != nil {
			ctx.Logger().Error(err, "error finding results in chunk")
			continue
		}

		detectorExecutionCount.WithLabelValues(
			data.detector.Type().String(),
			strconv.Itoa(int(data.chunk.JobID)),
			data.chunk.SourceName,
		).Inc()
		detectorExecutionDuration.WithLabelValues(
			data.detector.Type().String(),
		).Observe(float64(time.Since(start).Milliseconds()))

		if e.printAvgDetectorTime && len(results) > 0 {
			elapsed := time.Since(start)
			detectorName := results[0].DetectorType.String()
			avgTimeI, ok := e.metrics.detectorAvgTime.Load(detectorName)
			var avgTime []time.Duration
			if ok {
				avgTime, ok = avgTimeI.([]time.Duration)
				if !ok {
					return
				}
			}
			avgTime = append(avgTime, elapsed)
			e.metrics.detectorAvgTime.Store(detectorName, avgTime)
		}

		// If results filtration eliminates a rotated secret, then that rotation will never be reported. This problem
		// can theoretically occur for any scan, but we've only actually seen it in practice during targeted scans. (The
		// reason for this discrepancy is unclear.) The simplest fix is therefore to disable filtration for targeted
		// scans, but if you're here because this problem surfaced for a non-targeted scan then we'll have to solve it
		// correctly.
		if data.chunk.SecretID == 0 {
			results = e.filterResults(ctx, data.detector, results)
		}

		for _, res := range results {
			e.processResult(ctx, data, res, isFalsePositive)
		}
	}

	matchesPerChunk.Observe(float64(matchCount))

	data.wgDoneFn()
}

func (e *Engine) filterResults(
	ctx context.Context,
	detector *ahocorasick.DetectorMatch,
	results []detectors.Result,
) []detectors.Result {
	clean := detectors.CleanResults
	ignoreConfig := false
	if cleaner, ok := detector.Detector.(detectors.CustomResultsCleaner); ok {
		clean = cleaner.CleanResults
		ignoreConfig = cleaner.ShouldCleanResultsIrrespectiveOfConfiguration()
	}
	if e.filterUnverified || ignoreConfig {
		results = clean(results)
	}

	if !e.retainFalsePositives {
		results = detectors.FilterKnownFalsePositives(ctx, detector.Detector, results)
	}

	if e.filterEntropy != 0 {
		results = detectors.FilterResultsWithEntropy(ctx, results, e.filterEntropy, e.retainFalsePositives)
	}

	return results
}

func (e *Engine) processResult(
	ctx context.Context,
	data detectableChunk,
	res detectors.Result,
	isFalsePositive func(detectors.Result) (bool, string),
) {
	ignoreLinePresent := false
	if SupportsLineNumbers(data.chunk.SourceType) {
		copyChunk := data.chunk
		copyMetaDataClone := proto.Clone(data.chunk.SourceMetadata)
		if copyMetaData, ok := copyMetaDataClone.(*source_metadatapb.MetaData); ok {
			copyChunk.SourceMetadata = copyMetaData
		}
		fragStart, mdLine, link := FragmentFirstLineAndLink(&copyChunk)
		ignoreLinePresent = SetResultLineNumber(&copyChunk, &res, fragStart, mdLine)
		if err := UpdateLink(ctx, copyChunk.SourceMetadata, link, *mdLine); err != nil {
			ctx.Logger().Error(err, "error setting link")
			return
		}
		data.chunk = copyChunk
	}
	if ignoreLinePresent {
		return
	}

	secret := detectors.CopyMetadata(&data.chunk, res)
	secret.DecoderType = data.decoder
	secret.DetectorDescription = data.detector.Detector.Description()

	if !res.Verified && res.Raw != nil {
		isFp, _ := isFalsePositive(res)
		secret.IsWordlistFalsePositive = isFp
	}

	e.results <- secret
}

func (e *Engine) notifierWorker(ctx context.Context) {
	for result := range e.ResultsChan() {
		startTime := time.Now()
		// Filter unwanted results, based on `--results`.
		if !result.Verified {
			if result.VerificationError() != nil {
				if !e.notifyUnknownResults {
					// Skip results with verification errors.
					continue
				}
			} else if !e.notifyUnverifiedResults {
				// Skip unverified results.
				continue
			}
		} else if !e.notifyVerifiedResults {
			// Skip verified results.
			// TODO: Is this a legitimate use case?
			continue
		}
		atomic.AddUint32(&e.numFoundResults, 1)

		// Dedupe results by comparing the detector type, raw result, and source metadata.
		// We want to avoid duplicate results with different decoder types, but we also
		// want to include duplicate results with the same decoder type.
		// Duplicate results with the same decoder type SHOULD have their own entry in the
		// results list, this would happen if the same secret is found multiple times.
		// Note: If the source type is postman, we dedupe the results regardless of decoder type.
		key := fmt.Sprintf("%s%s%s%+v", result.DetectorType.String(), result.Raw, result.RawV2, result.SourceMetadata)
		if val, ok := e.dedupeCache.Get(key); ok && (val != result.DecoderType ||
			result.SourceType == sourcespb.SourceType_SOURCE_TYPE_POSTMAN) {
			continue
		}
		e.dedupeCache.Add(key, result.DecoderType)

		if result.Verified {
			atomic.AddUint64(&e.metrics.VerifiedSecretsFound, 1)
		} else {
			atomic.AddUint64(&e.metrics.UnverifiedSecretsFound, 1)
		}

		if err := e.dispatcher.Dispatch(ctx, result); err != nil {
			ctx.Logger().Error(err, "error notifying result")
		}

		chunksNotifiedLatency.Observe(float64(time.Since(startTime).Milliseconds()))
	}
}

// SupportsLineNumbers determines if a line number can be found for a source type.
func SupportsLineNumbers(sourceType sourcespb.SourceType) bool {
	switch sourceType {
	case sourcespb.SourceType_SOURCE_TYPE_GIT,
		sourcespb.SourceType_SOURCE_TYPE_GITHUB,
		sourcespb.SourceType_SOURCE_TYPE_GITLAB,
		sourcespb.SourceType_SOURCE_TYPE_BITBUCKET,
		sourcespb.SourceType_SOURCE_TYPE_GERRIT,
		sourcespb.SourceType_SOURCE_TYPE_GITHUB_UNAUTHENTICATED_ORG,
		sourcespb.SourceType_SOURCE_TYPE_PUBLIC_GIT,
		sourcespb.SourceType_SOURCE_TYPE_FILESYSTEM,
		sourcespb.SourceType_SOURCE_TYPE_AZURE_REPOS:
		return true
	default:
		return false
	}
}

// FragmentLineOffset sets the line number for a provided source chunk with a given detector result.
func FragmentLineOffset(chunk *sources.Chunk, result *detectors.Result) (int64, bool) {
	before, after, found := bytes.Cut(chunk.Data, result.Raw)
	if !found {
		return 0, false
	}
	lineNumber := int64(bytes.Count(before, []byte("\n")))
	// If the line contains the ignore tag, we should ignore the result.
	endLine := bytes.Index(after, []byte("\n"))
	if endLine == -1 {
		endLine = len(after)
	}
	if bytes.Contains(after[:endLine], []byte(ignoreTag)) {
		return lineNumber, true
	}
	return lineNumber, false
}

// FragmentFirstLineAndLink extracts the first line number and the link from the chunk metadata.
// It returns:
//   - The first line number of the fragment.
//   - A pointer to the line number, facilitating direct updates.
//   - The link associated with the fragment. This link may be updated in the chunk metadata
//     if there's a change in the line number.
func FragmentFirstLineAndLink(chunk *sources.Chunk) (int64, *int64, string) {
	if chunk.SourceMetadata == nil {
		return 0, nil, ""
	}

	var (
		fragmentStart *int64
		link          string
	)
	switch metadata := chunk.SourceMetadata.GetData().(type) {
	case *source_metadatapb.MetaData_Git:
		fragmentStart = &metadata.Git.Line
	case *source_metadatapb.MetaData_Github:
		fragmentStart = &metadata.Github.Line
		link = metadata.Github.Link
	case *source_metadatapb.MetaData_Gitlab:
		fragmentStart = &metadata.Gitlab.Line
		link = metadata.Gitlab.Link
	case *source_metadatapb.MetaData_Bitbucket:
		fragmentStart = &metadata.Bitbucket.Line
		link = metadata.Bitbucket.Link
	case *source_metadatapb.MetaData_Gerrit:
		fragmentStart = &metadata.Gerrit.Line
	case *source_metadatapb.MetaData_Filesystem:
		fragmentStart = &metadata.Filesystem.Line
		link = metadata.Filesystem.Link
	case *source_metadatapb.MetaData_AzureRepos:
		fragmentStart = &metadata.AzureRepos.Line
		link = metadata.AzureRepos.Link
	default:
		return 1, nil, ""
	}

	// Ensure we maintain 1-based line indexing if fragmentStart is not set or is 0.
	if *fragmentStart == 0 {
		*fragmentStart = 1
	}

	return *fragmentStart, fragmentStart, link
}

// SetResultLineNumber sets the line number in the provided result.
func SetResultLineNumber(chunk *sources.Chunk, result *detectors.Result, fragStart int64, mdLine *int64) bool {
	offset, skip := FragmentLineOffset(chunk, result)
	*mdLine = fragStart + offset
	return skip
}

// UpdateLink updates the link of the provided source metadata.
func UpdateLink(ctx context.Context, metadata *source_metadatapb.MetaData, link string, line int64) error {
	if metadata == nil {
		return fmt.Errorf("metadata is nil when setting the link")
	}

	if link == "" {
		ctx.Logger().V(4).Info("link is empty, skipping update")
		return nil
	}

	newLink := giturl.UpdateLinkLineNumber(ctx, link, line)

	switch meta := metadata.GetData().(type) {
	case *source_metadatapb.MetaData_Github:
		meta.Github.Link = newLink
	case *source_metadatapb.MetaData_Gitlab:
		meta.Gitlab.Link = newLink
	case *source_metadatapb.MetaData_Bitbucket:
		meta.Bitbucket.Link = newLink
	case *source_metadatapb.MetaData_Filesystem:
		meta.Filesystem.Link = newLink
	case *source_metadatapb.MetaData_AzureRepos:
		meta.AzureRepos.Link = newLink
	default:
		return fmt.Errorf("unsupported metadata type")
	}
	return nil
}
