package sourcestest

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

type reporter interface {
	sources.UnitReporter
	sources.ChunkReporter
}

var _ reporter = (*TestReporter)(nil)

// TestReporter is a helper struct that implements both UnitReporter and
// ChunkReporter by simply recording the values passed in the methods.
type TestReporter struct {
	Units     []sources.SourceUnit
	UnitErrs  []error
	Chunks    []sources.Chunk
	ChunkErrs []error
}

func (t *TestReporter) UnitOk(_ context.Context, unit sources.SourceUnit) {
	t.Units = append(t.Units, unit)
}
func (t *TestReporter) UnitErr(_ context.Context, err error) {
	t.UnitErrs = append(t.UnitErrs, err)
}
func (t *TestReporter) ChunkOk(_ context.Context, chunk sources.Chunk) {
	t.Chunks = append(t.Chunks, chunk)
}
func (t *TestReporter) ChunkErr(_ context.Context, err error) {
	t.ChunkErrs = append(t.ChunkErrs, err)
}
