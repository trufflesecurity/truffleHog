package sources

import (
	"bytes"
	"io"
	"math/rand"
	"runtime"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

func TestNewChunkedReader(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		chunkSize  int
		peekSize   int
		wantChunks []string
		wantErr    bool
	}{
		{
			name:       "Smaller data than default chunkSize and peekSize",
			input:      "example input",
			chunkSize:  DefaultChunkSize,
			peekSize:   DefaultPeekSize,
			wantChunks: []string{"example input"},
			wantErr:    false,
		},
		{
			name:       "Reader with no data",
			input:      "",
			chunkSize:  1024,
			peekSize:   512,
			wantChunks: []string{},
			wantErr:    false,
		},
		{
			name:       "Smaller data than chunkSize and peekSize",
			input:      "small data",
			chunkSize:  1024,
			peekSize:   512,
			wantChunks: []string{"small data"},
			wantErr:    false,
		},
		{
			name:       "Equal to chunkSize",
			input:      strings.Repeat("a", 1024),
			chunkSize:  1024,
			peekSize:   512,
			wantChunks: []string{strings.Repeat("a", 1024)},
			wantErr:    false,
		},
		{
			name:       "Equal to chunkSize + peekSize",
			input:      strings.Repeat("a", 1536),
			chunkSize:  1024,
			peekSize:   512,
			wantChunks: []string{strings.Repeat("a", 1536), strings.Repeat("a", 512)},
			wantErr:    false,
		},
		{
			name:       "EOF during peeking",
			input:      strings.Repeat("a", 1300),
			chunkSize:  1024,
			peekSize:   512,
			wantChunks: []string{strings.Repeat("a", 1300), strings.Repeat("a", 276)},
			wantErr:    false,
		},
		{
			name:       "EOF during reading",
			input:      strings.Repeat("a", 512),
			chunkSize:  1024,
			peekSize:   512,
			wantChunks: []string{strings.Repeat("a", 512)},
			wantErr:    false,
		},
		{
			name:       "Equal to totalSize",
			input:      strings.Repeat("a", 2048),
			chunkSize:  1024,
			peekSize:   1024,
			wantChunks: []string{strings.Repeat("a", 2048), strings.Repeat("a", 1024)},
			wantErr:    false,
		},
		{
			name:       "Larger than totalSize",
			input:      strings.Repeat("a", 4096),
			chunkSize:  1024,
			peekSize:   1024,
			wantChunks: []string{strings.Repeat("a", 2048), strings.Repeat("a", 2048), strings.Repeat("a", 2048), strings.Repeat("a", 1024)},
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			readerFunc := NewChunkReader(WithChunkSize(tt.chunkSize), WithPeekSize(tt.peekSize))
			reader := strings.NewReader(tt.input)
			ctx := context.Background()
			chunkResChan := readerFunc(ctx, reader)

			var err error
			chunks := make([]string, 0)
			for data := range chunkResChan {
				chunks = append(chunks, string(data.Bytes()))
				err = data.Error()
			}

			assert.Equal(t, tt.wantChunks, chunks, "Chunks do not match")
			if tt.wantErr {
				assert.Error(t, err, "Expected an error")
			} else {
				assert.NoError(t, err, "Unexpected error")
			}
		})
	}
}

type panicReader struct{}

var _ io.Reader = (*panicReader)(nil)

func (_ panicReader) Read([]byte) (int, error) {
	panic("panic for testing")
}

func TestChunkReader_UnderlyingReaderPanics_DoesNotPanic(t *testing.T) {
	require.NotPanics(t, func() {
		for range NewChunkReader()(context.Background(), &panicReader{}) {
		}
	})
}

func BenchmarkChunkReader(b *testing.B) {
	var bigChunk = make([]byte, 1<<24) // 16MB

	reader := bytes.NewReader(bigChunk)
	chunkReader := NewChunkReader(WithChunkSize(DefaultChunkSize), WithPeekSize(DefaultPeekSize))

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		b.StartTimer()
		chunkResChan := chunkReader(context.Background(), reader)

		// Drain the channel.
		for range chunkResChan {
		}

		b.StopTimer()
		_, err := reader.Seek(0, 0)
		assert.Nil(b, err)
	}
}

func TestFlakyChunkReader(t *testing.T) {
	a := "aaaa"
	b := "bbbb"

	reader := iotest.OneByteReader(strings.NewReader(a + b))

	chunkReader := NewChunkReader()
	chunkResChan := chunkReader(context.TODO(), reader)

	var chunks []ChunkResult
	for chunk := range chunkResChan {
		chunks = append(chunks, chunk)
	}

	assert.Equal(t, 1, len(chunks))
	chunk := chunks[0]
	assert.NoError(t, chunk.Error())
	assert.Equal(t, a+b, string(chunk.Bytes()))
}

func TestReadInChunksWithCancellation(t *testing.T) {
	largeData := strings.Repeat("large test data ", 1024*1024) // Large data string.

	for i := 0; i < 10; i++ {
		initialGoroutines := runtime.NumGoroutine()

		for j := 0; j < 5; j++ { // Call readInChunks multiple times
			ctx, cancel := context.WithCancel(context.Background())

			reader := strings.NewReader(largeData)
			chunkReader := NewChunkReader()

			chunkChan := chunkReader(ctx, reader)

			if rand.Intn(2) == 0 { // Randomly decide to cancel the context
				cancel()
			} else {
				for range chunkChan {
				}
			}
		}

		// Allow for goroutine finalization.
		time.Sleep(time.Millisecond * 100)

		// Check for goroutine leaks.
		if runtime.NumGoroutine() > initialGoroutines {
			t.Error("Potential goroutine leak detected")
		}
	}
}
