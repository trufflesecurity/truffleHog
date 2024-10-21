package handlers

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/sassoftware/go-rpmutils"

	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/feature"
)

// rpmHandler specializes archiveHandler to manage RPM package files.
type rpmHandler struct{ *defaultHandler }

// newRPMHandler creates an rpmHandler with the provided metrics.
func newRPMHandler() *rpmHandler {
	return &rpmHandler{defaultHandler: newDefaultHandler(rpmHandlerType)}
}

// HandleFile processes RPM formatted files. Further implementation is required to appropriately
// handle RPM specific archive operations.
func (h *rpmHandler) HandleFile(ctx logContext.Context, input fileReader) chan DataOrErr {
	dataOrErrChan := make(chan DataOrErr, defaultBufferSize)

	if feature.ForceSkipArchives.Load() {
		close(dataOrErrChan)
		return dataOrErrChan
	}

	go func() {
		defer close(dataOrErrChan)

		start := time.Now()

		// Defer a panic recovery to handle any panics that occur during the RPM processing.
		defer func() {
			if r := recover(); r != nil {
				var panicErr error
				if e, ok := r.(error); ok {
					panicErr = e
				} else {
					panicErr = fmt.Errorf("panic occurred: %v", r)
				}
				dataOrErrChan <- DataOrErr{
					Err: fmt.Errorf("%w: panic error: %v", ErrProcessingFatal, panicErr),
				}
			}
		}()

		rpm, err := rpmutils.ReadRpm(input)
		if err != nil {
			dataOrErrChan <- DataOrErr{
				Err: fmt.Errorf("%w: reading rpm error: %v", ErrProcessingFatal, err),
			}
			return
		}

		reader, err := rpm.PayloadReaderExtended()
		if err != nil {
			dataOrErrChan <- DataOrErr{
				Err: fmt.Errorf("%w: uncompressing rpm error: %v", ErrProcessingFatal, err),
			}
			return
		}

		err = h.processRPMFiles(ctx, reader, dataOrErrChan)
		if err == nil {
			h.metrics.incFilesProcessed()
		}

		// Update the metrics for the file processing and handle any errors.
		h.measureLatencyAndHandleErrors(ctx, start, err, dataOrErrChan)
	}()

	return dataOrErrChan
}

func (h *rpmHandler) processRPMFiles(
	ctx logContext.Context,
	reader rpmutils.PayloadReader,
	dataOrErrChan chan DataOrErr,
) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			fileInfo, err := reader.Next()
			if err != nil {
				if errors.Is(err, io.EOF) {
					ctx.Logger().V(3).Info("RPM payload archive fully processed")
					return nil
				}
				return fmt.Errorf("error reading RPM payload: %w", err)
			}

			fileSize := fileInfo.Size()
			fileCtx := logContext.WithValues(ctx, "filename", fileInfo.Name, "size", fileSize)

			rdr, err := newMimeTypeReader(reader)
			if err != nil {
				return fmt.Errorf("error creating mime-type reader: %w", err)
			}

			if err := h.handleNonArchiveContent(fileCtx, rdr, dataOrErrChan); err != nil {
				dataOrErrChan <- DataOrErr{
					Err: fmt.Errorf("%w: error processing RPM archive: %v", ErrProcessingWarning, err),
				}
				h.metrics.incErrors()
			}

			h.metrics.incFilesProcessed()
			h.metrics.observeFileSize(fileSize)
		}
	}
}
