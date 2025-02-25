package sources

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

var _ ChunkReporter = (*ChanReporter)(nil)

// ChanReporter is a ChunkReporter that writes to a channel.
type ChanReporter struct {
	Ch chan<- *Chunk
}

func (c ChanReporter) ChunkOk(ctx context.Context, chunk Chunk) {
	_ = common.CancellableWrite(ctx, c.Ch, &chunk)
}

func (ChanReporter) ChunkErr(ctx context.Context, err error) {
	ctx.Logger().Error(err, "error chunking")
}

var _ UnitReporter = (*VisitorReporter)(nil)

// VisitorReporter is a UnitReporter that will call the provided callbacks for
// finding units and reporting errors. VisitErr is optional; if unset it will
// log the error.
type VisitorReporter struct {
	VisitUnit func(context.Context, SourceUnit)
	VisitErr  func(context.Context, error)
}

func (v VisitorReporter) UnitOk(ctx context.Context, unit SourceUnit) {
	v.VisitUnit(ctx, unit)
}

func (v VisitorReporter) UnitErr(ctx context.Context, err error) {
	if v.VisitErr == nil {
		ctx.Logger().Error(err, "error enumerating")
		return
	}
	v.VisitErr(ctx, err)
}
