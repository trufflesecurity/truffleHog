package sources

import (
	"bufio"
	"errors"
	"fmt"
	"io"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

const (
	// DefaultChunkSize used by the chunker.
	DefaultChunkSize = 10 * 1024
	// DefaultPeekSize is the size of the peek into the previous chunk.
	DefaultPeekSize = 3 * 1024
	// TotalChunkSize is the total size of a chunk with peek data.
	TotalChunkSize = DefaultChunkSize + DefaultPeekSize
)

type chunkReaderConfig struct {
	chunkSize int
	totalSize int
	peekSize  int
	fileSize  int
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

// WithFileSize sets the file size.
// Note: If WithChunkSize is also provided, WithChunkSize takes precedence.
func WithFileSize(size int) ConfigOption {
	return func(c *chunkReaderConfig) { c.fileSize = size }
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

const (
	// Size thresholds.
	xsmallFileSizeThreshold = 4 * 1024        // 4KB
	smallFileSizeThreshold  = 10 * 1024       // 10KB
	mediumFileSizeThreshold = 100 * 1024      // 100KB
	largeFileSizeThreshold  = 1 * 1024 * 1024 // 1MB

	// Chunk sizes.
	xsmallFileChunkSize = 1 << 12 // 4KB
	smallFileChunkSize  = 1 << 13 // 8KB
	mediumFileChunkSize = 1 << 14 // 16KB
	largeFileChunkSize  = 1 << 15 // 32KB
	xlargeFileChunkSize = 1 << 16 // 64KB
)

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
	// Set defaults.
	config := &chunkReaderConfig{
		chunkSize: DefaultChunkSize, // default
		peekSize:  DefaultPeekSize,  // default
	}

	for _, opt := range opts {
		opt(config)
	}

	// Prioritize chunkSize over fileSize if both are provided.
	if config.fileSize != 0 && config.chunkSize == DefaultChunkSize {
		config.chunkSize = calculateOptimalChunkSize(config.fileSize)
	}

	config.totalSize = config.chunkSize + config.peekSize

	return config
}

func calculateOptimalChunkSize(fileSize int) int {
	switch {
	case fileSize < xsmallFileSizeThreshold:
		return xsmallFileChunkSize
	case fileSize < smallFileSizeThreshold:
		return smallFileChunkSize
	case fileSize < mediumFileSizeThreshold:
		return mediumFileChunkSize
	case fileSize < largeFileSizeThreshold:
		return largeFileChunkSize
	default:
		return xlargeFileChunkSize
	}
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
				chunkBytes = append(chunkBytes[:n], peekData...)
				chunkRes.data = chunkBytes
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
