package sources

import (
	"bufio"
	"errors"
	"fmt"
	"io"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

const (
	// ChunkSize is the maximum size of a chunk.
	ChunkSize = 10 * 1024
	// PeekSize is the size of the peek into the previous chunk.
	PeekSize = 3 * 1024
	// TotalChunkSize is the total size of a chunk with peek data.
	TotalChunkSize = ChunkSize + PeekSize

	// smallChunkThresholdRatio represents the ratio of the chunk size
	// below which a chunk is considered "small" and will be optimized
	// by creating a smaller byte slice to only accommodate the data.
	// This prevents a mostly empty buffer, saving memory, reducing the
	// application's memory footprint, and allowing the garbage collector
	// to reclaim the extra space. It could also improve cache efficiency,
	// though most operations use the slice length rather than capacity.
	// It's expressed as a value between 0 and 1.
	smallChunkThresholdRatio = 0.3
)

type chunkReaderConfig struct {
	chunkSize int
	totalSize int
	peekSize  int

	// smallChunkThreshold is the size below which a chunk is considered "small"
	// and will be optimized by creating a new, smaller slice.
	// Chunks larger than this threshold will use the original, larger slice.
	smallChunkThreshold int
}

// ConfigOption is a function that configures a chunker.
type ConfigOption func(*chunkReaderConfig)

// WithChunkSize sets the chunk size.
func WithChunkSize(size int) ConfigOption {
	return func(c *chunkReaderConfig) { c.chunkSize = size }
}

// WithPeekSize sets the peek size.
func WithPeekSize(size int) ConfigOption {
	return func(c *chunkReaderConfig) { c.peekSize = size }
}

// ChunkResult is the output unit of a ChunkReader,
// it contains the data and error of a chunk.
type ChunkResult struct {
	data []byte
	err  error
}

// Bytes for a ChunkResult.
func (cr ChunkResult) Bytes() []byte {
	return cr.data
}

// Error for a ChunkResult.
func (cr ChunkResult) Error() error {
	return cr.err
}

// ChunkReader reads chunks from a reader and returns a channel of chunks and a channel of errors.
// The channel of chunks is closed when the reader is closed.
// This should be used whenever a large amount of data is read from a reader.
// Ex: reading attachments, archives, etc.
type ChunkReader func(ctx context.Context, reader io.Reader) <-chan ChunkResult

// NewChunkReader returns a ChunkReader with the given options.
func NewChunkReader(opts ...ConfigOption) ChunkReader {
	config := applyOptions(opts)
	return createReaderFn(config)
}

func applyOptions(opts []ConfigOption) *chunkReaderConfig {
	threshold := float64(ChunkSize+PeekSize) * smallChunkThresholdRatio
	// Set defaults.
	config := &chunkReaderConfig{
		chunkSize:           ChunkSize, // default
		peekSize:            PeekSize,  // default
		smallChunkThreshold: int(threshold),
	}

	for _, opt := range opts {
		opt(config)
	}

	config.totalSize = config.chunkSize + config.peekSize

	return config
}

func createReaderFn(config *chunkReaderConfig) ChunkReader {
	return func(ctx context.Context, reader io.Reader) <-chan ChunkResult {
		return readInChunks(ctx, reader, config)
	}
}

func readInChunks(ctx context.Context, reader io.Reader, config *chunkReaderConfig) <-chan ChunkResult {
	const channelSize = 64
	chunkReader := bufio.NewReaderSize(reader, config.chunkSize)
	chunkResultChan := make(chan ChunkResult, channelSize)

	go func() {
		defer close(chunkResultChan)

		// Defer a panic recovery to handle any panics that occur while reading, which can sometimes unavoidably happen
		// due to third-party library bugs.
		defer func() {
			if r := recover(); r != nil {
				var panicErr error
				if e, ok := r.(error); ok {
					panicErr = e
				} else {
					panicErr = fmt.Errorf("panic occurred: %v", r)
				}
				chunkResultChan <- ChunkResult{
					err: fmt.Errorf("panic error: %w", panicErr),
				}
			}
		}()

		for {
			chunkRes := ChunkResult{}
			chunkBytes := make([]byte, config.totalSize)
			chunkBytes = chunkBytes[:config.chunkSize]
			n, err := io.ReadFull(chunkReader, chunkBytes)
			if n > 0 {
				peekData, _ := chunkReader.Peek(config.totalSize - n)
				if n+len(peekData) < config.smallChunkThreshold {
					optimizedChunk := make([]byte, n+len(peekData))
					copy(optimizedChunk, chunkBytes[:n])
					copy(optimizedChunk[n:], peekData)
					chunkRes.data = optimizedChunk
				} else {
					chunkBytes = append(chunkBytes[:n], peekData...)
					chunkRes.data = chunkBytes
				}
			}

			// If there is an error other than EOF, or if we have read some bytes, send the chunk.
			// io.ReadFull will only return io.EOF when n == 0.
			switch {
			case isErrAndNotEOF(err):
				ctx.Logger().Error(err, "error reading chunk")
				chunkRes.err = err
			case n > 0:
				chunkRes.err = nil
			default:
				return
			}

			select {
			case <-ctx.Done():
				return
			case chunkResultChan <- chunkRes:
			}

			if err != nil {
				return
			}
		}
	}()
	return chunkResultChan
}

// reportableErr checks whether the error is one we are interested in flagging.
func isErrAndNotEOF(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return false
	}
	return true
}
