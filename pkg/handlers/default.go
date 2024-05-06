package handlers

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/gabriel-vasile/mimetype"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"

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

// newNonArchiveHandler creates a defaultHandler with metrics configured based on the provided handlerType.
// The handlerType parameter is used to initialize the metrics instance with the appropriate handler type,
// ensuring that the metrics recorded within the defaultHandler methods are correctly attributed to the
// specific handler that invoked them.
func newNonArchiveHandler(handlerType handlerType) *defaultHandler {
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

		if err = h.handleNonArchiveContent(ctx, input, dataChan); err != nil {
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
func (h *defaultHandler) handleNonArchiveContent(ctx logContext.Context, reader io.Reader, archiveChan chan []byte) error {
	bufReader := bufio.NewReaderSize(reader, defaultBufferSize)
	// A buffer of 512 bytes is used since many file formats store their magic numbers within the first 512 bytes.
	// If fewer bytes are read, MIME type detection may still succeed.
	buffer, err := bufReader.Peek(defaultBufferSize)
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("unable to read file for MIME type detection: %w", err)
	}

	mime := mimetype.Detect(buffer)
	mimeT := mimeType(mime.String())

	if common.SkipFile(mime.Extension()) || common.IsBinary(mime.Extension()) {
		ctx.Logger().V(5).Info("skipping file", "ext", mimeT)
		h.metrics.incFilesSkipped()
		return nil
	}

	chunkReader := sources.NewChunkReader()
	chunkResChan := chunkReader(ctx, bufReader)
	for data := range chunkResChan {
		if err := data.Error(); err != nil {
			ctx.Logger().Error(err, "error reading chunk")
			h.metrics.incErrors()
			continue
		}

		contentCtx, span := otel.Tracer("scanner").Start(ctx, "handleNonArchiveContent")
		span.AddEvent("content chunk processed, writing to archive channel")
		span.SetAttributes(attribute.Key("content_size_bytes").Int64(int64(len(data.Bytes()))))
		if err := common.CancellableWrite(logContext.AddLogger(contentCtx), archiveChan, data.Bytes()); err != nil {
			span.End()
			return err
		}
		span.End()
		h.metrics.incBytesProcessed(len(data.Bytes()))
	}

	return nil
}
