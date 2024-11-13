package handlers

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// defaultHandler is a handler for non-archive files.
// It is embedded in other specialized handlers to provide a consistent way of handling non-archive content
// once it has been extracted or decompressed by the specific handler.
// This allows the specialized handlers to focus on their specific archive formats while leveraging
// the common functionality provided by the defaultHandler for processing the extracted content.
type defaultHandler struct{ metrics *metrics }

// newDefaultHandler creates a defaultHandler with metrics configured based on the provided handlerType.
// The handlerType parameter is used to initialize the metrics instance with the appropriate handler type,
// ensuring that the metrics recorded within the defaultHandler methods are correctly attributed to the
// specific handler that invoked them.
func newDefaultHandler(handlerType handlerType) *defaultHandler {
	return &defaultHandler{metrics: newHandlerMetrics(handlerType)}
}

// HandleFile processes the input as either an archive or non-archive based on its content,
// utilizing a single output channel. It first tries to identify the input as an archive. If it is an archive,
// it processes it accordingly; otherwise, it handles the input as non-archive content.
// The function returns a channel that will receive the extracted data bytes and an error if the initial setup fails.
func (h *defaultHandler) HandleFile(ctx logContext.Context, input fileReader) (chan []byte, error) {
	// Shared channel for both archive and non-archive content.
	dataChan := make(chan []byte, defaultBufferSize)

	go func() {
		defer close(dataChan)

		// Update the metrics for the file processing.
		start := time.Now()
		var err error
		defer func() {
			h.measureLatencyAndHandleErrors(start, err)
			h.metrics.incFilesProcessed()
		}()

		if err = h.handleNonArchiveContent(ctx, newMimeTypeReaderFromFileReader(input), dataChan); err != nil {
			ctx.Logger().Error(err, "error handling non-archive content.")
		}
	}()

	return dataChan, nil
}

// measureLatencyAndHandleErrors measures the latency of the file processing and updates the metrics accordingly.
// It also records errors and timeouts in the metrics.
func (h *defaultHandler) measureLatencyAndHandleErrors(start time.Time, err error) {
	if err == nil {
		h.metrics.observeHandleFileLatency(time.Since(start).Milliseconds())
		return
	}

	h.metrics.incErrors()
	if errors.Is(err, context.DeadlineExceeded) {
		h.metrics.incFileProcessingTimeouts()
	}
}

// handleNonArchiveContent processes files that do not contain nested archives, serving as the final stage in the
// extraction/decompression process. It reads the content to detect its MIME type and decides whether to skip based
// on the type, particularly for binary files. It manages reading file chunks and writing them to the archive channel,
// effectively collecting the final bytes for further processing. This function is a key component in ensuring that all
// file content, regardless of being an archive or not, is handled appropriately.
func (h *defaultHandler) handleNonArchiveContent(ctx logContext.Context, reader mimeTypeReader, archiveChan chan []byte) error {
	mimeExt := reader.mimeExt

	if common.SkipFile(mimeExt) || common.IsBinary(mimeExt) {
		ctx.Logger().V(3).Info("skipping file: extension is ignored", "ext", mimeExt)
		h.metrics.incFilesSkipped()
		// Make sure we consume the reader to avoid potentially blocking indefinitely.
		_, _ = io.Copy(io.Discard, reader)
		return nil
	}

	chunkReader := sources.NewChunkReader()
	for data := range chunkReader(ctx, reader) {
		if err := data.Error(); err != nil {
			ctx.Logger().Error(err, "error reading chunk")
			h.metrics.incErrors()
			continue
		}

		if err := common.CancellableWrite(ctx, archiveChan, data.Bytes()); err != nil {
			return err
		}
		h.metrics.incBytesProcessed(len(data.Bytes()))
	}
	return nil
}
