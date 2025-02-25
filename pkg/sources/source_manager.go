package sources

import (
	"fmt"
	"io"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/marusama/semaphore/v2"
	"golang.org/x/sync/errgroup"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
)

// SourceManager provides an interface for starting and managing running
// sources.
type SourceManager struct {
	api   apiClient
	hooks []JobProgressHook
	// Pool limiting the amount of concurrent sources running.
	sem         semaphore.Semaphore
	prioritySem semaphore.Semaphore
	wg          sync.WaitGroup
	// Max number of units to scan concurrently per source.
	concurrentUnits int
	// Run the sources using source unit enumeration / chunking if available.
	// Checked at runtime to allow feature flagging.
	useSourceUnitsFunc func() bool
	// Downstream chunks channel to be scanned.
	outputChunks chan *Chunk
	// Set when Wait() returns.
	firstErr chan error
	waitErr  error
	done     bool
}

// apiClient is an interface for optionally communicating with an external API.
type apiClient interface {
	// GetIDs informs the API of the source that's about to run and returns
	// two identifiers used during source initialization.
	GetIDs(ctx context.Context, name string, kind sourcespb.SourceType) (SourceID, JobID, error)
}

// WithAPI adds an API client to the manager for tracking jobs and progress. If
// the API is also a JobProgressHook, it will be added to the list of event hooks.
func WithAPI(api apiClient) func(*SourceManager) {
	return func(mgr *SourceManager) { mgr.api = api }
}

// WithReportHook adds a hook to the SourceManager's reporting feature for
// customizing data aggregation.
func WithReportHook(hook JobProgressHook) func(*SourceManager) {
	return func(mgr *SourceManager) {
		mgr.hooks = append(mgr.hooks, hook)
	}
}

// WithConcurrentSources limits the concurrent number of sources a manager can run.
func WithConcurrentSources(concurrency int) func(*SourceManager) {
	return func(mgr *SourceManager) {
		mgr.sem.SetLimit(concurrency)
	}
}

// WithConcurrentTargets limits the concurrent number of targets a manager can run.
func WithConcurrentTargets(concurrency int) func(*SourceManager) {
	return func(mgr *SourceManager) {
		mgr.prioritySem.SetLimit(concurrency)
	}
}

// WithBufferedOutput sets the size of the buffer used for the Chunks() channel.
func WithBufferedOutput(size int) func(*SourceManager) {
	return func(mgr *SourceManager) { mgr.outputChunks = make(chan *Chunk, size) }
}

// WithSourceUnits enables using source unit enumeration and chunking if the
// source supports it.
func WithSourceUnits() func(*SourceManager) {
	return func(mgr *SourceManager) {
		mgr.useSourceUnitsFunc = func() bool { return true }
	}
}

// WithSourceUnitsFunc dynamically configures whether to use source unit
// enumeration and chunking if the source supports it. If the function returns
// true and the source supports it, then units will be used. Otherwise, the
// legacy scanning method will be used.
func WithSourceUnitsFunc(f func() bool) func(*SourceManager) {
	return func(mgr *SourceManager) { mgr.useSourceUnitsFunc = f }
}

// WithConcurrentUnits limits the number of units to be scanned concurrently.
// The default is unlimited.
func WithConcurrentUnits(n int) func(*SourceManager) {
	return func(mgr *SourceManager) { mgr.concurrentUnits = n }
}

// The default channel size for all the channels that are used to transport chunks.
const defaultChannelSize = 64

// NewManager creates a new manager with the provided options.
func NewManager(opts ...func(*SourceManager)) *SourceManager {
	mgr := SourceManager{
		// Default to the headless API. Can be overwritten by the WithAPI option.
		api:          &headlessAPI{},
		sem:          semaphore.New(runtime.NumCPU()),
		prioritySem:  semaphore.New(runtime.NumCPU()),
		outputChunks: make(chan *Chunk, defaultChannelSize),
		firstErr:     make(chan error, 1),
	}
	for _, opt := range opts {
		opt(&mgr)
	}
	return &mgr
}

func (s *SourceManager) GetIDs(ctx context.Context, sourceName string, kind sourcespb.SourceType) (SourceID, JobID, error) {
	return s.api.GetIDs(ctx, sourceName, kind)
}

// EnumerateAndScan blocks until a resource is available to run the source, then
// asynchronously runs it. Error information is stored and accessible via the
// JobProgressRef as it becomes available.
func (s *SourceManager) EnumerateAndScan(ctx context.Context, sourceName string, source Source, targets ...ChunkingTarget) (JobProgressRef, error) {
	sourceID, jobID := source.SourceID(), source.JobID()
	// Do preflight checks before waiting on the pool.
	if err := s.preflightChecks(ctx); err != nil {
		return JobProgressRef{
			SourceName: sourceName,
			SourceID:   sourceID,
			JobID:      jobID,
		}, err
	}
	// Create a JobProgress object for tracking progress.
	sem := s.sem
	if len(targets) > 0 {
		sem = s.prioritySem
	}
	ctx, cancel := context.WithCancelCause(ctx)
	progress := NewJobProgress(jobID, sourceID, sourceName, WithHooks(s.hooks...), WithCancel(cancel))
	if err := sem.Acquire(ctx, 1); err != nil {
		// Context cancelled.
		progress.ReportError(Fatal{err})
		return progress.Ref(), Fatal{err}
	}
	s.wg.Add(1)
	go func() {
		// Call Finish after the semaphore has been released.
		defer progress.Finish()
		defer sem.Release(1)
		defer s.wg.Done()
		ctx := context.WithValues(ctx,
			"source_manager_worker_id", common.RandomID(5),
		)
		defer common.Recover(ctx)
		defer cancel(nil)
		if err := s.run(ctx, source, progress, targets...); err != nil {
			select {
			case s.firstErr <- err:
			default:
			}
		}
	}()
	return progress.Ref(), nil
}

func (s *SourceManager) Enumerate(ctx context.Context, sourceName string, source Source, reporter UnitReporter) (JobProgressRef, error) {
	sourceID, jobID := source.SourceID(), source.JobID()
	// Do preflight checks before waiting on the pool.
	if err := s.preflightChecks(ctx); err != nil {
		return JobProgressRef{
			SourceName: sourceName,
			SourceID:   sourceID,
			JobID:      jobID,
		}, err
	}

	// Create a JobProgress object for tracking progress.
	sem := s.sem
	ctx, cancel := context.WithCancelCause(ctx)
	progress := NewJobProgress(jobID, sourceID, sourceName, WithHooks(s.hooks...), WithCancel(cancel))
	if err := sem.Acquire(ctx, 1); err != nil {
		// Context cancelled.
		progress.ReportError(Fatal{err})
		return progress.Ref(), Fatal{err}
	}

	// Wrap the passed in reporter so we update the progress information.
	reporter = baseUnitReporter{
		child:    reporter,
		progress: progress,
	}

	s.wg.Add(1)
	go func() {
		// Call Finish after the semaphore has been released.
		defer progress.Finish()
		defer sem.Release(1)
		defer s.wg.Done()
		ctx := context.WithValues(ctx,
			"source_manager_worker_id", common.RandomID(5),
		)
		defer common.Recover(ctx)
		defer cancel(nil)
		if err := s.enumerate(ctx, source, progress, reporter); err != nil {
			select {
			case s.firstErr <- err:
			default:
			}
			progress.ReportError(Fatal{err})
		}
	}()
	return progress.Ref(), nil
}

// Scan blocks until a resource is available to run the source against a single
// SourceUnit, then asynchronously runs it. Error information is stored and
// accessible via the JobProgressRef as it becomes available.
func (s *SourceManager) Scan(ctx context.Context, sourceName string, source Source, unit SourceUnit) (JobProgressRef, error) {
	sourceID, jobID := source.SourceID(), source.JobID()
	// Do preflight checks before waiting on the pool.
	if err := s.preflightChecks(ctx); err != nil {
		return JobProgressRef{
			SourceName: sourceName,
			SourceID:   sourceID,
			JobID:      jobID,
		}, err
	}
	// Create a JobProgress object for tracking progress.
	ctx, cancel := context.WithCancelCause(ctx)
	progress := NewJobProgress(jobID, sourceID, sourceName, WithHooks(s.hooks...), WithCancel(cancel))
	if err := s.sem.Acquire(ctx, 1); err != nil {
		// Context cancelled.
		progress.ReportError(Fatal{err})
		return progress.Ref(), Fatal{err}
	}
	s.wg.Add(1)
	go func() {
		// Call Finish after the semaphore has been released.
		defer progress.Finish()
		defer s.sem.Release(1)
		defer s.wg.Done()
		ctx := context.WithValues(ctx,
			"source_manager_worker_id", common.RandomID(5),
		)
		defer common.Recover(ctx)
		defer cancel(nil)
		if err := s.scan(ctx, source, progress, unit); err != nil {
			select {
			case s.firstErr <- err:
			default:
			}
			progress.ReportError(Fatal{err})
		}
	}()
	return progress.Ref(), nil
}

// Chunks returns the read only channel of all the chunks produced by all of
// the sources managed by this manager.
func (s *SourceManager) Chunks() <-chan *Chunk {
	return s.outputChunks
}

// Wait blocks until all running sources are completed and closes the channel
// returned by Chunks(). The manager should not be reused after calling this
// method. This current implementation is not thread safe and should only be
// called by one thread.
func (s *SourceManager) Wait() error {
	// Check if the manager has been Waited.
	if s.done {
		return s.waitErr
	}
	s.done = true

	// Return the first error returned by run.
	s.wg.Wait()
	select {
	case s.waitErr = <-s.firstErr:
	default:
	}
	close(s.outputChunks)
	close(s.firstErr)
	for _, hook := range s.hooks {
		if hookCloser, ok := hook.(io.Closer); ok {
			_ = hookCloser.Close()
		}
	}
	return s.waitErr
}

// ScanChunk injects a chunk into the output stream of chunks to be scanned.
// This method should rarely be used. TODO(THOG-1577): Remove when dependencies
// no longer rely on this functionality.
func (s *SourceManager) ScanChunk(chunk *Chunk) {
	s.outputChunks <- chunk
}

// AvailableCapacity returns the number of concurrent jobs the manager can
// accommodate at this time.
func (s *SourceManager) AvailableCapacity() int {
	return s.sem.GetLimit() - s.sem.GetCount()
}

// MaxConcurrentSources returns the maximum configured limit of concurrent
// sources the manager will run.
func (s *SourceManager) MaxConcurrentSources() int {
	return s.sem.GetLimit()
}

// ConcurrentSources returns the current number of concurrently running
// sources.
func (s *SourceManager) ConcurrentSources() int {
	return s.sem.GetCount()
}

// SetMaxConcurrentSources sets the maximum number of concurrently running
// sources. If the count is lower than the already existing number of
// concurrently running sources, no sources will be scheduled to run until the
// existing sources complete.
func (s *SourceManager) SetMaxConcurrentSources(maxRunCount int) {
	s.sem.SetLimit(maxRunCount)
}

// preflightChecks is a helper method to check the Manager or the context isn't
// done.
func (s *SourceManager) preflightChecks(ctx context.Context) error {
	// Check if the manager has been Waited.
	if s.done {
		return fmt.Errorf("manager is done")
	}
	return ctx.Err()
}

// run is a helper method to synchronously run the source. It does not check for
// acquired resources. An error is returned if there was a fatal error during
// the run. This information is also recorded in the JobProgress.
func (s *SourceManager) run(ctx context.Context, source Source, report *JobProgress, targets ...ChunkingTarget) error {
	report.Start(time.Now())
	defer func() { report.End(time.Now()) }()

	defer func() {
		if err := context.Cause(ctx); err != nil {
			report.ReportError(Fatal{err})
		}
	}()

	report.TrackProgress(source.GetProgress())
	if ctx.Value("job_id") == "" {
		ctx = context.WithValue(ctx, "job_id", report.JobID)
	}
	if ctx.Value("source_id") == "" {
		ctx = context.WithValue(ctx, "source_id", report.SourceID)
	}
	if ctx.Value("source_name") == "" {
		ctx = context.WithValue(ctx, "source_name", report.SourceName)
	}
	if ctx.Value("source_type") == "" {
		ctx = context.WithValue(ctx, "source_type", source.Type().String())
	}

	// Check if source units are supported and configured.
	canUseSourceUnits := len(targets) == 0 && s.useSourceUnitsFunc != nil
	if enumChunker, ok := source.(SourceUnitEnumChunker); ok && canUseSourceUnits && s.useSourceUnitsFunc() {
		ctx.Logger().Info("running source",
			"with_units", true)
		return s.runWithUnits(ctx, enumChunker, report)
	}
	ctx.Logger().Info("running source",
		"with_units", false,
		"target_count", len(targets),
		"source_manager_units_configurable", s.useSourceUnitsFunc != nil)
	return s.runWithoutUnits(ctx, source, report, targets...)
}

// enumerate is a helper method to enumerate a Source.
func (s *SourceManager) enumerate(ctx context.Context, source Source, report *JobProgress, reporter UnitReporter) error {
	report.Start(time.Now())
	defer func() { report.End(time.Now()) }()

	defer func() {
		if err := context.Cause(ctx); err != nil {
			report.ReportError(Fatal{err})
		}
	}()

	report.TrackProgress(source.GetProgress())
	if ctx.Value("job_id") == "" {
		ctx = context.WithValue(ctx, "job_id", report.JobID)
	}
	if ctx.Value("source_id") == "" {
		ctx = context.WithValue(ctx, "source_id", report.SourceID)
	}
	if ctx.Value("source_name") == "" {
		ctx = context.WithValue(ctx, "source_name", report.SourceName)
	}
	if ctx.Value("source_type") == "" {
		ctx = context.WithValue(ctx, "source_type", source.Type().String())
	}

	// Check if source units are supported and configured.
	canUseSourceUnits := s.useSourceUnitsFunc != nil
	if enumChunker, ok := source.(SourceUnitEnumerator); ok && canUseSourceUnits && s.useSourceUnitsFunc() {
		ctx.Logger().Info("running source", "with_units", true)
		return s.enumerateWithUnits(ctx, enumChunker, report, reporter)
	}
	return fmt.Errorf("Enumeration not supported or configured for source: %s", source.Type().String())
}

// scan runs a scan against a single SourceUnit as its only job. This method
// manages the lifecycle of the provided report.
func (s *SourceManager) scan(ctx context.Context, source Source, report *JobProgress, unit SourceUnit) error {
	report.Start(time.Now())
	defer func() { report.End(time.Now()) }()

	defer func() {
		if err := context.Cause(ctx); err != nil {
			report.ReportError(Fatal{err})
		}
	}()

	report.TrackProgress(source.GetProgress())
	if ctx.Value("job_id") == "" {
		ctx = context.WithValue(ctx, "job_id", report.JobID)
	}
	if ctx.Value("source_id") == "" {
		ctx = context.WithValue(ctx, "source_id", report.SourceID)
	}
	if ctx.Value("source_name") == "" {
		ctx = context.WithValue(ctx, "source_name", report.SourceName)
	}
	if ctx.Value("source_type") == "" {
		ctx = context.WithValue(ctx, "source_type", source.Type().String())
	}

	// Check if source units are supported and configured.
	canUseSourceUnits := s.useSourceUnitsFunc != nil
	if unitChunker, ok := source.(SourceUnitChunker); ok && canUseSourceUnits && s.useSourceUnitsFunc() {
		ctx.Logger().Info("running source",
			"with_units", true)
		return s.scanWithUnit(ctx, unitChunker, report, unit)
	}
	return fmt.Errorf("source units not supported or configured for source: %s (%s)", report.SourceName, source.Type().String())
}

// enumerateWithUnits is a helper method to enumerate a Source that is also a
// SourceUnitEnumerator. This allows better introspection of what is getting
// enumerated and any errors encountered.
func (s *SourceManager) enumerateWithUnits(ctx context.Context, source SourceUnitEnumerator, report *JobProgress, reporter UnitReporter) error {
	// Create a function that will save the first error encountered (if
	// any) and discard the rest.
	fatalErr := make(chan error, 1)
	catchFirstFatal := func(err error) {
		select {
		case fatalErr <- err:
		default:
		}
	}

	// Produce units.
	func() {
		// TODO: Catch panics and add to report.
		report.StartEnumerating(time.Now())
		defer func() { report.EndEnumerating(time.Now()) }()
		ctx.Logger().V(2).Info("enumerating source with units")
		if err := source.Enumerate(ctx, reporter); err != nil {
			report.ReportError(Fatal{err})
			catchFirstFatal(Fatal{err})
		}
	}()

	select {
	case err := <-fatalErr:
		return err
	default:
		return nil
	}
}

// runWithoutUnits is a helper method to run a Source. It has coarse-grained
// job reporting.
func (s *SourceManager) runWithoutUnits(ctx context.Context, source Source, report *JobProgress, targets ...ChunkingTarget) error {
	// Introspect on the chunks we get from the Chunks method.
	ch := make(chan *Chunk, defaultChannelSize)
	var wg sync.WaitGroup
	// Consume chunks and export chunks.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for chunk := range ch {
			chunk.JobID = source.JobID()
			report.ReportChunk(nil, chunk)
			s.outputChunks <- chunk
		}
	}()

	// Don't return from this function until the goroutine has finished
	// outputting chunks to the downstream channel. Closing the channel
	// will stop the goroutine, so that needs to happen first in the defer
	// stack.
	defer wg.Wait()
	defer close(ch)
	if err := source.Chunks(ctx, ch, targets...); err != nil {
		report.ReportError(Fatal{err})
		return Fatal{err}
	}
	return nil
}

// runWithUnits is a helper method to run a Source that is also a
// SourceUnitEnumChunker. This allows better introspection of what is getting
// scanned and any errors encountered.
func (s *SourceManager) runWithUnits(ctx context.Context, source SourceUnitEnumChunker, report *JobProgress) error {
	unitReporter := &mgrUnitReporter{
		unitCh: make(chan SourceUnit, 1),
		report: report,
	}
	// Create a function that will save the first error encountered (if
	// any) and discard the rest.
	fatalErr := make(chan error, 1)
	catchFirstFatal := func(err error) {
		select {
		case fatalErr <- err:
		default:
		}
	}
	// Produce units.
	go func() {
		// TODO: Catch panics and add to report.
		report.StartEnumerating(time.Now())
		defer func() { report.EndEnumerating(time.Now()) }()
		defer close(unitReporter.unitCh)
		ctx.Logger().V(2).Info("enumerating source")
		if err := source.Enumerate(ctx, unitReporter); err != nil {
			report.ReportError(Fatal{err})
			catchFirstFatal(Fatal{err})
		}
	}()
	var wg sync.WaitGroup
	// TODO: Maybe switch to using a semaphore.Weighted.
	var unitPool errgroup.Group
	if s.concurrentUnits != 0 {
		// Negative values indicated no limit.
		unitPool.SetLimit(s.concurrentUnits)
	}
	for unit := range unitReporter.unitCh {
		chunkReporter := &mgrChunkReporter{
			unit:    unit,
			chunkCh: make(chan *Chunk, defaultChannelSize),
			report:  report,
		}
		// Consume units and produce chunks.
		unitPool.Go(func() error {
			report.StartUnitChunking(unit, time.Now())
			// TODO: Catch panics and add to report.
			defer close(chunkReporter.chunkCh)
			id, kind := unit.SourceUnitID()
			ctx := context.WithValues(ctx, "unit_kind", kind, "unit", id)
			ctx.Logger().V(3).Info("chunking unit")
			if err := source.ChunkUnit(ctx, unit, chunkReporter); err != nil {
				report.ReportError(Fatal{ChunkError{Unit: unit, Err: err}})
				catchFirstFatal(Fatal{err})
			}
			return nil
		})
		// Consume chunks and export chunks.
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { report.EndUnitChunking(unit, time.Now()) }()
			for chunk := range chunkReporter.chunkCh {
				if src, ok := source.(Source); ok {
					chunk.JobID = src.JobID()
				}
				s.outputChunks <- chunk
			}
		}()
	}
	wg.Wait()
	select {
	case err := <-fatalErr:
		return err
	default:
		return nil
	}
}

// scanWithUnit produces chunks from a single SourceUnit.
func (s *SourceManager) scanWithUnit(ctx context.Context, source SourceUnitChunker, report *JobProgress, unit SourceUnit) error {
	// Create a function that will save the first error encountered (if
	// any) and discard the rest.
	chunkReporter := &mgrChunkReporter{
		unit:    unit,
		chunkCh: make(chan *Chunk, defaultChannelSize),
		report:  report,
	}
	// Produce chunks from the given unit.
	var chunkErr error
	go func() {
		report.StartUnitChunking(unit, time.Now())
		// TODO: Catch panics and add to report.
		defer close(chunkReporter.chunkCh)
		id, kind := unit.SourceUnitID()
		ctx := context.WithValues(ctx, "unit_kind", kind, "unit", id)
		ctx.Logger().V(3).Info("chunking unit")
		if err := source.ChunkUnit(ctx, unit, chunkReporter); err != nil {
			report.ReportError(Fatal{ChunkError{Unit: unit, Err: err}})
			chunkErr = Fatal{err}
		}
	}()
	// Consume chunks and export chunks.
	// This anonymous function blocks until the chunkReporter.chunkCh is
	// closed in the above goroutine.
	func() {
		defer func() { report.EndUnitChunking(unit, time.Now()) }()
		for chunk := range chunkReporter.chunkCh {
			if src, ok := source.(Source); ok {
				chunk.JobID = src.JobID()
			}
			s.outputChunks <- chunk
		}
	}()
	return chunkErr
}

// headlessAPI implements the apiClient interface locally.
type headlessAPI struct {
	// Counters for assigning source and job IDs.
	sourceIDCounter int64
	jobIDCounter    int64
}

func (api *headlessAPI) GetIDs(context.Context, string, sourcespb.SourceType) (SourceID, JobID, error) {
	return SourceID(atomic.AddInt64(&api.sourceIDCounter, 1)), JobID(atomic.AddInt64(&api.jobIDCounter, 1)), nil
}

// mgrUnitReporter implements the UnitReporter interface.
var _ UnitReporter = (*mgrUnitReporter)(nil)

type mgrUnitReporter struct {
	unitCh chan SourceUnit
	report *JobProgress
}

// UnitOk implements the UnitReporter interface by recording the unit in the
// report and sending it on the SourceUnit channel.
func (s *mgrUnitReporter) UnitOk(ctx context.Context, unit SourceUnit) {
	s.report.ReportUnit(unit)
	_ = common.CancellableWrite(ctx, s.unitCh, unit)
}

// UnitErr implements the UnitReporter interface by recording the error in the
// report.
func (s *mgrUnitReporter) UnitErr(ctx context.Context, err error) {
	s.report.ReportError(err)
}

// mgrChunkReporter implements the ChunkReporter interface.
var _ ChunkReporter = (*mgrChunkReporter)(nil)

type mgrChunkReporter struct {
	unit    SourceUnit
	chunkCh chan *Chunk
	report  *JobProgress
}

// ChunkOk implements the ChunkReporter interface by recording the chunk and
// its associated unit in the report and sending it on the Chunk channel.
func (s *mgrChunkReporter) ChunkOk(ctx context.Context, chunk Chunk) {
	s.report.ReportChunk(s.unit, &chunk)
	_ = common.CancellableWrite(ctx, s.chunkCh, &chunk)
}

// ChunkErr implements the ChunkReporter interface by recording the error and
// its associated unit in the report.
func (s *mgrChunkReporter) ChunkErr(ctx context.Context, err error) {
	s.report.ReportError(ChunkError{s.unit, err})
}
