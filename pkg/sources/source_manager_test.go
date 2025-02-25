package sources

import (
	"errors"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
)

// DummySource implements Source and is used for testing a SourceManager.
type DummySource struct {
	sourceID SourceID
	jobID    JobID
	chunker
}

func (d *DummySource) Type() sourcespb.SourceType { return 1337 }
func (d *DummySource) SourceID() SourceID         { return d.sourceID }
func (d *DummySource) JobID() JobID               { return d.jobID }
func (d *DummySource) Init(_ context.Context, _ string, jobID JobID, sourceID SourceID, _ bool, _ *anypb.Any, _ int) error {
	d.sourceID = sourceID
	d.jobID = jobID
	return nil
}
func (d *DummySource) GetProgress() *Progress { return nil }

// Interface to easily test different chunking methods.
type chunker interface {
	Chunks(context.Context, chan *Chunk, ...ChunkingTarget) error
	SourceUnitEnumChunker
}

// Chunk method that writes count bytes to the channel before returning.
type counterChunker struct {
	chunkCounter byte
	count        int
}

func (c *counterChunker) Chunks(ctx context.Context, ch chan *Chunk, _ ...ChunkingTarget) error {
	for i := 0; i < c.count; i++ {
		select {
		case ch <- &Chunk{Data: []byte{c.chunkCounter}}:
			c.chunkCounter++
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// countChunk implements SourceUnit.
type countChunk byte

func (c countChunk) SourceUnitID() (string, SourceUnitKind) {
	return fmt.Sprintf("countChunk(%d)", c), "test"
}

func (c countChunk) Display() string {
	id, _ := c.SourceUnitID()
	return id
}

func (c *counterChunker) Enumerate(ctx context.Context, reporter UnitReporter) error {
	for i := 0; i < c.count; i++ {
		reporter.UnitOk(ctx, countChunk(byte(i)))
	}
	return nil
}

func (c *counterChunker) ChunkUnit(ctx context.Context, unit SourceUnit, reporter ChunkReporter) error {
	reporter.ChunkOk(ctx, Chunk{Data: []byte{byte(unit.(countChunk))}})
	return nil
}

// Chunk method that always returns an error.
type errorChunker struct{ error }

func (c errorChunker) Chunks(context.Context, chan *Chunk, ...ChunkingTarget) error { return c }
func (c errorChunker) Enumerate(context.Context, UnitReporter) error                { return c }
func (c errorChunker) ChunkUnit(context.Context, SourceUnit, ChunkReporter) error   { return c }

// buildDummy is a helper function to enroll a DummySource with a SourceManager.
func buildDummy(chunkMethod chunker) (Source, error) {
	source := &DummySource{chunker: chunkMethod}
	if err := source.Init(context.Background(), "dummy", 123, 456, true, nil, 42); err != nil {
		return nil, err
	}
	return source, nil
}

// tryRead is a helper function that will try to read from a channel and return
// an error if it cannot.
func tryRead(ch <-chan *Chunk) (*Chunk, error) {
	select {
	case chunk := <-ch:
		return chunk, nil
	default:
		return nil, fmt.Errorf("no chunk available")
	}
}

func TestSourceManagerRun(t *testing.T) {
	mgr := NewManager(WithBufferedOutput(8))
	source, err := buildDummy(&counterChunker{count: 1})
	assert.NoError(t, err)
	for i := 0; i < 3; i++ {
		ref, err := mgr.EnumerateAndScan(context.Background(), "dummy", source)
		<-ref.Done()
		assert.NoError(t, err)
		assert.NoError(t, ref.Snapshot().FatalError())
		chunk, err := tryRead(mgr.Chunks())
		assert.NoError(t, err)
		assert.Equal(t, []byte{byte(i)}, chunk.Data)
		// The Chunks channel should be empty now.
		_, err = tryRead(mgr.Chunks())
		assert.Error(t, err)
	}
}

func TestSourceManagerWait(t *testing.T) {
	mgr := NewManager()
	source, err := buildDummy(&counterChunker{count: 1})
	assert.NoError(t, err)
	// Asynchronously run the source.
	_, err = mgr.EnumerateAndScan(context.Background(), "dummy", source)
	assert.NoError(t, err)
	// Read the 1 chunk we're expecting so Waiting completes.
	<-mgr.Chunks()
	// Wait for all resources to complete.
	assert.NoError(t, mgr.Wait())
	// Run should return an error now.
	_, err = buildDummy(&counterChunker{count: 1})
	assert.NoError(t, err)
	_, err = mgr.EnumerateAndScan(context.Background(), "dummy", source)
	assert.Error(t, err)
}

func TestSourceManagerError(t *testing.T) {
	mgr := NewManager()
	source, err := buildDummy(errorChunker{fmt.Errorf("oops")})
	assert.NoError(t, err)
	ref, err := mgr.EnumerateAndScan(context.Background(), "dummy", source)
	assert.NoError(t, err)
	<-ref.Done()
	assert.Error(t, ref.Snapshot().FatalError())
	assert.Error(t, mgr.Wait())
}

func TestSourceManagerReport(t *testing.T) {
	for _, opts := range [][]func(*SourceManager){
		{WithBufferedOutput(8)},
		{WithBufferedOutput(8), WithSourceUnits()},
		{WithBufferedOutput(8), WithSourceUnits(), WithConcurrentUnits(1)},
	} {
		mgr := NewManager(opts...)
		source, err := buildDummy(&counterChunker{count: 4})
		assert.NoError(t, err)
		ref, err := mgr.EnumerateAndScan(context.Background(), "dummy", source)
		assert.NoError(t, err)
		<-ref.Done()
		assert.Equal(t, 0, len(ref.Snapshot().Errors))
		assert.Equal(t, uint64(4), ref.Snapshot().TotalChunks)
	}
}

func TestSourceManagerEnumerate(t *testing.T) {
	mgr := NewManager(WithBufferedOutput(8), WithSourceUnits())
	source, err := buildDummy(&counterChunker{count: 1})
	assert.NoError(t, err)
	var enumeratedUnits []SourceUnit
	reporter := visitorUnitReporter{
		ok: func(_ context.Context, unit SourceUnit) {
			enumeratedUnits = append(enumeratedUnits, unit)
		},
	}
	for i := 0; i < 3; i++ {
		ref, err := mgr.Enumerate(context.Background(), "dummy", source, reporter)
		<-ref.Done()
		assert.NoError(t, err)
		assert.NoError(t, ref.Snapshot().FatalError())
		// The Chunks channel should be empty because we only enumerated.
		_, err = tryRead(mgr.Chunks())
		assert.Error(t, err)
		// Each time the loop iterates, we add 1 unit to the slice.
		assert.Equal(t, i+1, len(enumeratedUnits), ref.Snapshot())
	}
}

func TestSourceManagerScan(t *testing.T) {
	mgr := NewManager(WithBufferedOutput(8), WithSourceUnits())
	source, err := buildDummy(&counterChunker{count: 1})
	assert.NoError(t, err)
	for i := 0; i < 3; i++ {
		ref, err := mgr.Scan(context.Background(), "dummy", source, countChunk(123))
		<-ref.Done()
		assert.NoError(t, err)
		assert.NoError(t, ref.Snapshot().FatalError())
		chunk, err := tryRead(mgr.Chunks())
		assert.NoError(t, err)
		assert.Equal(t, []byte{123}, chunk.Data)
		// The Chunks channel should be empty now.
		_, err = tryRead(mgr.Chunks())
		assert.Error(t, err)
	}
}

type visitorUnitReporter struct {
	ok  func(context.Context, SourceUnit)
	err func(context.Context, error)
}

func (v visitorUnitReporter) UnitOk(ctx context.Context, u SourceUnit) { v.ok(ctx, u) }
func (v visitorUnitReporter) UnitErr(ctx context.Context, err error)   { v.err(ctx, err) }

type unitChunk struct {
	unit   string
	output string
	err    string
}

type unitChunker struct{ steps []unitChunk }

func (c *unitChunker) Chunks(ctx context.Context, ch chan *Chunk, _ ...ChunkingTarget) error {
	for _, step := range c.steps {
		if step.err != "" {
			continue
		}
		if err := common.CancellableWrite(ctx, ch, &Chunk{Data: []byte(step.output)}); err != nil {
			return err
		}
	}
	return nil
}
func (c *unitChunker) Enumerate(ctx context.Context, rep UnitReporter) error {
	for _, step := range c.steps {
		rep.UnitOk(ctx, CommonSourceUnit{ID: step.unit})
	}
	return nil
}
func (c *unitChunker) ChunkUnit(ctx context.Context, unit SourceUnit, rep ChunkReporter) error {
	for _, step := range c.steps {
		id, _ := unit.SourceUnitID()
		if id != step.unit {
			continue
		}
		if step.err != "" {
			rep.ChunkErr(ctx, fmt.Errorf("%s", step.err))
		}
		if step.output == "" {
			continue
		}
		rep.ChunkOk(ctx, Chunk{Data: []byte(step.output)})
	}
	return nil
}

func TestSourceManagerNonFatalError(t *testing.T) {
	input := []unitChunk{
		{unit: "one", output: "bar"},
		{unit: "two", err: "oh no"},
		{unit: "three", err: "not again"},
	}
	mgr := NewManager(WithBufferedOutput(8), WithSourceUnits())
	source, err := buildDummy(&unitChunker{input})
	assert.NoError(t, err)
	ref, err := mgr.EnumerateAndScan(context.Background(), "dummy", source)
	assert.NoError(t, err)
	<-ref.Done()
	report := ref.Snapshot()
	assert.Equal(t, len(input), int(report.TotalUnits))
	assert.Equal(t, len(input), int(report.FinishedUnits))
	assert.Equal(t, 1, int(report.TotalChunks))
	assert.Equal(t, 2, len(report.Errors))
	assert.True(t, report.DoneEnumerating)
}

func TestSourceManagerContextCancelled(t *testing.T) {
	mgr := NewManager(WithBufferedOutput(16))
	source, err := buildDummy(&counterChunker{count: 100})
	assert.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	ref, err := mgr.EnumerateAndScan(ctx, "dummy", source)
	assert.NoError(t, err)

	cancel()
	<-ref.Done()
	report := ref.Snapshot()
	assert.Error(t, report.FatalError())
}

type DummyAPI struct {
	registerSource func(context.Context, string, sourcespb.SourceType) (SourceID, error)
	getJobID       func(context.Context, SourceID) (JobID, error)
}

func (api DummyAPI) RegisterSource(ctx context.Context, name string, kind sourcespb.SourceType) (SourceID, error) {
	return api.registerSource(ctx, name, kind)
}

func (api DummyAPI) GetJobID(ctx context.Context, id SourceID) (JobID, error) {
	return api.getJobID(ctx, id)
}

// Chunk method that has a custom callback for the Chunks method.
type callbackChunker struct {
	cb func(context.Context, chan *Chunk) error
}

func (c callbackChunker) Chunks(ctx context.Context, ch chan *Chunk, _ ...ChunkingTarget) error {
	return c.cb(ctx, ch)
}
func (c callbackChunker) Enumerate(context.Context, UnitReporter) error              { return nil }
func (c callbackChunker) ChunkUnit(context.Context, SourceUnit, ChunkReporter) error { return nil }

func TestSourceManagerCancelRun(t *testing.T) {
	mgr := NewManager(WithBufferedOutput(8))
	var returnedErr error
	source, err := buildDummy(callbackChunker{func(ctx context.Context, _ chan *Chunk) error {
		// The context passed to Chunks should get cancelled when ref.CancelRun() is called.
		<-ctx.Done()
		returnedErr = fmt.Errorf("oh no: %w", ctx.Err())
		return returnedErr
	}})
	assert.NoError(t, err)

	ref, err := mgr.EnumerateAndScan(context.Background(), "dummy", source)
	assert.NoError(t, err)

	cancelErr := fmt.Errorf("abort! abort!")
	ref.CancelRun(cancelErr)
	<-ref.Done()
	assert.Error(t, ref.Snapshot().FatalError())
	assert.True(t, errors.Is(ref.Snapshot().FatalError(), returnedErr))
	assert.True(t, errors.Is(ref.Snapshot().FatalErrors(), cancelErr))
}

func TestSourceManagerAvailableCapacity(t *testing.T) {
	mgr := NewManager(WithConcurrentSources(1337))
	start, end := make(chan struct{}), make(chan struct{})
	source, err := buildDummy(callbackChunker{func(context.Context, chan *Chunk) error {
		start <- struct{}{} // Send start signal.
		<-end               // Wait for end signal.
		return nil
	}})
	assert.NoError(t, err)

	assert.Equal(t, 1337, mgr.AvailableCapacity())
	ref, err := mgr.EnumerateAndScan(context.Background(), "dummy", source)
	assert.NoError(t, err)

	<-start // Wait for start signal.
	assert.Equal(t, 1336, mgr.AvailableCapacity())
	end <- struct{}{} // Send end signal.
	<-ref.Done()      // Wait for the job to finish.
	assert.Equal(t, 1337, mgr.AvailableCapacity())
}

func TestSourceManagerUnitHook(t *testing.T) {
	hook, ch := NewUnitHook(context.TODO())

	input := []unitChunk{
		{unit: "1 one", output: "bar"},
		{unit: "2 two", err: "oh no"},
		{unit: "3 three", err: "not again"},
	}
	mgr := NewManager(
		WithBufferedOutput(8),
		WithSourceUnits(), WithConcurrentUnits(1),
		WithReportHook(hook),
	)
	source, err := buildDummy(&unitChunker{input})
	assert.NoError(t, err)
	ref, err := mgr.EnumerateAndScan(context.Background(), "dummy", source)
	assert.NoError(t, err)
	<-ref.Done()
	assert.NoError(t, mgr.Wait())

	assert.Equal(t, 0, len(hook.InProgressSnapshot()))
	var metrics []UnitMetrics
	for metric := range ch {
		metrics = append(metrics, metric)
	}
	justID := func(unit SourceUnit) string {
		id, _ := unit.SourceUnitID()
		return id
	}
	sort.Slice(metrics, func(i, j int) bool {
		return justID(metrics[i].Unit) < justID(metrics[j].Unit)
	})
	m0, m1, m2 := metrics[0], metrics[1], metrics[2]

	assert.Equal(t, "1 one", justID(m0.Unit))
	assert.Equal(t, uint64(1), m0.TotalChunks)
	assert.Equal(t, uint64(3), m0.TotalBytes)
	assert.NotZero(t, m0.StartTime)
	assert.NotZero(t, m0.EndTime)
	assert.NotZero(t, m0.ElapsedTime())
	assert.Equal(t, 0, len(m0.Errors))

	assert.Equal(t, "2 two", justID(m1.Unit))
	assert.Equal(t, uint64(0), m1.TotalChunks)
	assert.Equal(t, uint64(0), m1.TotalBytes)
	assert.NotZero(t, m1.StartTime)
	assert.NotZero(t, m1.EndTime)
	assert.NotZero(t, m1.ElapsedTime())
	assert.Equal(t, 1, len(m1.Errors))

	assert.Equal(t, "3 three", justID(m2.Unit))
	assert.Equal(t, uint64(0), m2.TotalChunks)
	assert.Equal(t, uint64(0), m2.TotalBytes)
	assert.NotZero(t, m2.StartTime)
	assert.NotZero(t, m2.EndTime)
	assert.NotZero(t, m2.ElapsedTime())
	assert.Equal(t, 1, len(m2.Errors))
}

// TestSourceManagerUnitHookBackPressure tests that the UnitHook blocks if the
// finished metrics aren't handled fast enough.
func TestSourceManagerUnitHookBackPressure(t *testing.T) {
	hook, ch := NewUnitHook(context.TODO(), WithUnitHookFinishBufferSize(0))

	input := []unitChunk{
		{unit: "one", output: "bar"},
		{unit: "two", err: "oh no"},
		{unit: "three", err: "not again"},
	}
	mgr := NewManager(
		WithBufferedOutput(8),
		WithSourceUnits(), WithConcurrentUnits(1),
		WithReportHook(hook),
	)
	source, err := buildDummy(&unitChunker{input})
	assert.NoError(t, err)
	ref, err := mgr.EnumerateAndScan(context.Background(), "dummy", source)
	assert.NoError(t, err)

	var metrics []UnitMetrics
	for i := 0; i < len(input); i++ {
		select {
		case <-ref.Done():
			t.Fatal("job should not finish until metrics have been collected")
		case <-time.After(1 * time.Millisecond):
		}
		metrics = append(metrics, <-ch)
	}

	assert.NoError(t, mgr.Wait())
	assert.Equal(t, 3, len(metrics), metrics)
}

// TestSourceManagerUnitHookNoUnits tests whether the UnitHook works for
// sources that don't support units.
func TestSourceManagerUnitHookNoUnits(t *testing.T) {
	hook, ch := NewUnitHook(context.TODO())

	mgr := NewManager(
		WithBufferedOutput(8),
		WithReportHook(hook),
	)
	source, err := buildDummy(&counterChunker{count: 5})
	assert.NoError(t, err)

	ref, err := mgr.EnumerateAndScan(context.Background(), "dummy", source)
	assert.NoError(t, err)
	<-ref.Done()
	assert.NoError(t, mgr.Wait())

	var metrics []UnitMetrics
	for metric := range ch {
		metrics = append(metrics, metric)
	}
	assert.Equal(t, 1, len(metrics))

	m := metrics[0]
	assert.Equal(t, nil, m.Unit)
	assert.Equal(t, uint64(5), m.TotalChunks)
	assert.Equal(t, uint64(5), m.TotalBytes)
	assert.NotZero(t, m.StartTime)
	assert.NotZero(t, m.EndTime)
	assert.NotZero(t, m.ElapsedTime())
	assert.Equal(t, 0, len(m.Errors))
}
