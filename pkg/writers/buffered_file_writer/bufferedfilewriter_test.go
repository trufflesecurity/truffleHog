package bufferedfilewriter

import (
	"bytes"
	"io"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/trufflesecurity/trufflehog/v3/pkg/buffers/pool"
)

func TestBufferedFileWriterNewThreshold(t *testing.T) {
	t.Parallel()

	const (
		defaultThreshold = 10 * 1024 * 1024 // 10MB
		customThreshold  = 20 * 1024 * 1024 // 20MB
	)

	tests := []struct {
		name              string
		options           []Option
		expectedThreshold uint64
	}{
		{name: "Default Threshold", expectedThreshold: defaultThreshold},
		{name: "Custom Threshold", options: []Option{WithThreshold(customThreshold)}, expectedThreshold: customThreshold},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			writer := New(tc.options...)
			assert.Equal(t, tc.expectedThreshold, writer.threshold)
			// The state should always be writeOnly when created.
			assert.Equal(t, writeOnly, writer.state)
		})
	}
}

func TestBufferedFileWriterString(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name            string
		input           []byte
		expectedStr     string
		additionalInput []byte
		threshold       uint64
	}{
		{name: "Empty", input: []byte(""), expectedStr: ""},
		{name: "Nil", input: nil, expectedStr: ""},
		{name: "Small content, buffer only", input: []byte("hello"), expectedStr: "hello"},
		{
			name:        "Large content, buffer only",
			input:       []byte("longer string with more characters"),
			expectedStr: "longer string with more characters",
		},
		{
			name:        "Large content, file only",
			input:       []byte("longer string with more characters"),
			expectedStr: "longer string with more characters",
			threshold:   5,
		},
		{
			name:            "Content in both file and buffer",
			input:           []byte("initial content exceeding threshold"),
			additionalInput: []byte(" more content in buffer"),
			expectedStr:     "initial content exceeding threshold more content in buffer",
			threshold:       10, // Set a threshold that the initial content exceeds
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			writer := New(WithThreshold(tc.threshold))
			// First write, should go to file if it exceeds the threshold.
			_, err := writer.Write(tc.input)
			assert.NoError(t, err)

			// Second write, should go to buffer
			if tc.additionalInput != nil {
				_, err = writer.Write(tc.additionalInput)
				assert.NoError(t, err)
			}

			got, err := writer.String()
			assert.NoError(t, err)
			err = writer.CloseForWriting()
			assert.NoError(t, err)

			assert.Equal(t, tc.expectedStr, got, "String content mismatch")
		})
	}
}

const (
	smallBuffer  = 2 << 5  // 64B
	mediumBuffer = 2 << 10 // 2KB
	smallFile    = 2 << 25 // 32MB
	mediumFile   = 2 << 28 // 256MB
)

func BenchmarkBufferedFileWriterString_BufferOnly_Small(b *testing.B) {
	data := bytes.Repeat([]byte("a"), smallBuffer)

	writer := New()

	_, err := writer.Write(data)
	assert.NoError(b, err)

	benchmarkBufferedFileWriterString(b, writer)

	err = writer.CloseForWriting()
	assert.NoError(b, err)

	rc, err := writer.ReadCloser()
	assert.NoError(b, err)
	rc.Close()
}

func BenchmarkBufferedFileWriterString_BufferOnly_Medium(b *testing.B) {
	data := bytes.Repeat([]byte("a"), mediumBuffer)
	writer := New()

	_, err := writer.Write(data)
	assert.NoError(b, err)

	benchmarkBufferedFileWriterString(b, writer)

	err = writer.CloseForWriting()
	assert.NoError(b, err)

	rc, err := writer.ReadCloser()
	assert.NoError(b, err)
	rc.Close()
}

func BenchmarkBufferedFileWriterString_OnlyFile_Small(b *testing.B) {
	data := bytes.Repeat([]byte("a"), smallFile)

	writer := New()

	_, err := writer.Write(data)
	assert.NoError(b, err)

	benchmarkBufferedFileWriterString(b, writer)

	err = writer.CloseForWriting()
	assert.NoError(b, err)

	rc, err := writer.ReadCloser()
	assert.NoError(b, err)
	rc.Close()
}

func BenchmarkBufferedFileWriterString_OnlyFile_Medium(b *testing.B) {
	data := bytes.Repeat([]byte("a"), mediumFile)

	writer := New()

	_, err := writer.Write(data)
	assert.NoError(b, err)

	benchmarkBufferedFileWriterString(b, writer)

	err = writer.CloseForWriting()
	assert.NoError(b, err)

	rc, err := writer.ReadCloser()
	assert.NoError(b, err)
	rc.Close()
}

func BenchmarkBufferedFileWriterString_BufferWithFile_Small(b *testing.B) {
	data := bytes.Repeat([]byte("a"), smallFile)

	writer := New()

	_, err := writer.Write(data)
	assert.NoError(b, err)

	// Write again so we also fill up the buffer.
	_, err = writer.Write(data)
	assert.NoError(b, err)

	benchmarkBufferedFileWriterString(b, writer)

	err = writer.CloseForWriting()
	assert.NoError(b, err)

	rc, err := writer.ReadCloser()
	assert.NoError(b, err)
	rc.Close()
}

func BenchmarkBufferedFileWriterString_BufferWithFile_Medium(b *testing.B) {
	data := bytes.Repeat([]byte("a"), mediumFile)

	writer := New()

	_, err := writer.Write(data)
	assert.NoError(b, err)

	// Write again so we also fill up the buffer.
	_, err = writer.Write(data)
	assert.NoError(b, err)

	benchmarkBufferedFileWriterString(b, writer)

	err = writer.CloseForWriting()
	assert.NoError(b, err)

	rc, err := writer.ReadCloser()
	assert.NoError(b, err)
	rc.Close()
}

func benchmarkBufferedFileWriterString(b *testing.B, w *BufferedFileWriter) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := w.String()
		assert.NoError(b, err)
	}
	b.StopTimer()
}

func TestBufferedFileWriterLen(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		input       []byte
		expectedLen int
	}{
		{name: "Empty", input: []byte(""), expectedLen: 0},
		{name: "Nil", input: nil, expectedLen: 0},
		{name: "Small content", input: []byte("hello"), expectedLen: 5},
		{name: "Large content", input: []byte("longer string with more characters"), expectedLen: 34},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			writer := New()
			_, err := writer.Write(tc.input)
			assert.NoError(t, err)

			length := writer.Len()
			assert.Equal(t, tc.expectedLen, length)
		})
	}
}

// TestBufferedFileWriterWriteWithinThreshold tests that data is written to the buffer when the threshold
// is not exceeded.
func TestBufferedFileWriterWriteWithinThreshold(t *testing.T) {
	t.Parallel()

	data := []byte("hello world")

	writer := New(WithThreshold(64))
	_, err := writer.Write(data)
	assert.NoError(t, err)

	assert.Equal(t, data, writer.buf.Bytes())
}

// TestBufferedFileWriterWriteExceedsThreshold tests that data is written to a file when the threshold
// is exceeded.
func TestBufferedFileWriterWriteExceedsThreshold(t *testing.T) {
	t.Parallel()

	data := []byte("hello world")

	writer := New(WithThreshold(5))
	_, err := writer.Write(data)
	assert.NoError(t, err)

	defer func() {
		err := writer.CloseForWriting()
		assert.NoError(t, err)
	}()

	assert.NotNil(t, writer.file)
	assert.Len(t, writer.buf.Bytes(), 0)
	fileContents, err := os.ReadFile(writer.filename)
	assert.NoError(t, err)
	assert.Equal(t, data, fileContents)
}

// TestBufferedFileWriterWriteAfterFlush tests that data is written to a file when the threshold
// is exceeded, and subsequent writes are to the buffer until the threshold is exceeded again.
func TestBufferedFileWriterWriteAfterFlush(t *testing.T) {
	t.Parallel()

	initialData := []byte("initial data is longer than subsequent data")
	subsequentData := []byte("subsequent data")

	// Initialize writer with a threshold that initialData will exceed.
	writer := New(WithThreshold(uint64(len(initialData) - 1)))
	_, err := writer.Write(initialData)
	assert.NoError(t, err)

	defer func() {
		err := writer.CloseForWriting()
		assert.NoError(t, err)
	}()

	// Get the file modification time after the initial write.
	initialModTime, err := getFileModTime(t, writer.filename)
	assert.NoError(t, err)
	fileContents, err := os.ReadFile(writer.filename)
	assert.NoError(t, err)
	assert.Equal(t, initialData, fileContents)

	// Perform a subsequent write with data under the threshold.
	_, err = writer.Write(subsequentData)
	assert.NoError(t, err)

	assert.Equal(t, subsequentData, writer.buf.Bytes()) // Check buffer contents
	finalModTime, err := getFileModTime(t, writer.filename)
	assert.NoError(t, err)
	assert.Equal(t, initialModTime, finalModTime) // File should not be modified again
}

func getFileModTime(t *testing.T, fileName string) (time.Time, error) {
	t.Helper()

	fileInfo, err := os.Stat(fileName)
	if err != nil {
		return time.Time{}, err
	}
	return fileInfo.ModTime(), nil
}

func TestBufferedFileWriterClose(t *testing.T) {
	t.Parallel()

	const threshold = 10

	tests := []struct {
		name              string
		prepareWriter     func(*BufferedFileWriter) // Function to prepare the writer for the test
		expectFileContent string
	}{
		{
			name: "No File Created, Only Buffer Data",
			prepareWriter: func(w *BufferedFileWriter) {
				// Write data under the threshold
				_, _ = w.Write([]byte("small data"))
			},
			expectFileContent: "",
		},
		{
			name: "File Created, No Data in Buffer",
			prepareWriter: func(w *BufferedFileWriter) {
				// Write data over the threshold to create a file
				_, _ = w.Write([]byte("large data is more than the threshold"))
			},
			expectFileContent: "large data is more than the threshold",
		},
		{
			name: "File Created, Data in Buffer",
			prepareWriter: func(w *BufferedFileWriter) {
				// Write data over the threshold to create a file, then write more data
				_, _ = w.Write([]byte("large data is more than the threshold"))
				_, _ = w.Write([]byte(" more data"))
			},
			expectFileContent: "large data is more than the threshold more data",
		},
		{
			name: "File Created, Buffer Cleared",
			prepareWriter: func(w *BufferedFileWriter) {
				// Write data over the threshold to create a file, then clear the buffer.
				_, _ = w.Write([]byte("large data is more than the threshold"))
				w.buf.Reset()
			},
			expectFileContent: "large data is more than the threshold",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			writer := New(WithThreshold(threshold))

			tc.prepareWriter(writer)

			err := writer.CloseForWriting()
			assert.NoError(t, err)

			if writer.file != nil {
				fileContents, err := os.ReadFile(writer.filename)
				assert.NoError(t, err)
				assert.Equal(t, tc.expectFileContent, string(fileContents))
				return
			}

			// If no file was created, the buffer should be empty.
			assert.Equal(t, tc.expectFileContent, "")
		})
	}
}

func TestBufferedFileWriterStateTransitionOnClose(t *testing.T) {
	t.Parallel()
	writer := New()

	// Initially, the writer should be in write-only mode.
	assert.Equal(t, writeOnly, writer.state)

	// Perform some write operation.
	_, err := writer.Write([]byte("test data"))
	assert.NoError(t, err)

	// Close the writer.
	err = writer.CloseForWriting()
	assert.NoError(t, err)

	// After closing, the writer should be in read-only mode.
	assert.Equal(t, readOnly, writer.state)
}

func TestBufferedFileWriterWriteInReadOnlyState(t *testing.T) {
	t.Parallel()
	writer := New()
	_ = writer.CloseForWriting() // Transition to read-only mode

	// Attempt to write in read-only mode.
	_, err := writer.Write([]byte("should fail"))
	assert.Error(t, err)
}

func BenchmarkBufferedFileWriterWriteLarge(b *testing.B) {
	data := make([]byte, 1024*1024*10) // 10MB
	for i := range data {
		data[i] = byte(i % 256) // Simple pattern to avoid uniform zero data
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Threshold is smaller than the data size, data should get flushed to the file.
		writer := New(WithThreshold(1024))

		b.StartTimer()
		{
			_, err := writer.Write(data)
			assert.NoError(b, err)
		}
		b.StopTimer()

		// Ensure proper cleanup after each write operation, including closing the file
		err := writer.CloseForWriting()
		assert.NoError(b, err)

		rc, err := writer.ReadCloser()
		assert.NoError(b, err)
		rc.Close()
	}
}

func BenchmarkBufferedFileWriterWriteSmall(b *testing.B) {
	data := make([]byte, 1024*1024) // 1MB
	for i := range data {
		data[i] = byte(i % 256) // Simple pattern to avoid uniform zero data
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Threshold is the same as the buffer size, data should always be written to the buffer.
		writer := New(WithThreshold(1024 * 1024))

		b.StartTimer()
		{
			_, err := writer.Write(data)
			assert.NoError(b, err)
		}
		b.StopTimer()

		// Ensure proper cleanup after each write operation, including closing the file.
		err := writer.CloseForWriting()
		assert.NoError(b, err)

		rc, err := writer.ReadCloser()
		assert.NoError(b, err)
		rc.Close()
	}
}

func TestBufferWriterCloseForWritingWithFile(t *testing.T) {
	bufPool := pool.NewBufferPool(defaultBufferSize)

	buf := bufPool.Get()
	writer := &BufferedFileWriter{
		threshold: 10,
		bufPool:   bufPool,
		buf:       buf,
	}

	// Write data exceeding the threshold to ensure a file is created.
	data := []byte("this is a longer string exceeding the threshold")
	_, err := writer.Write(data)
	assert.NoError(t, err)

	err = writer.CloseForWriting()
	assert.NoError(t, err)
	assert.Equal(t, readOnly, writer.state)

	rdr, err := writer.ReadCloser()
	assert.NoError(t, err)
	defer rdr.Close()

	// Get a buffer from the pool and check if it is the same buffer used in the writer.
	bufFromPool := bufPool.Get()
	assert.Same(t, buf, bufFromPool, "Buffer should be returned to the pool")
	bufPool.Put(bufFromPool)
}

func TestBufferedFileWriter_ReadFrom(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		expectedOutput string
		expectedSize   int64
	}{
		{
			name:           "Empty input",
			input:          "",
			expectedOutput: "",
			expectedSize:   0,
		},
		{
			name:           "Small input",
			input:          "Hello, World!",
			expectedOutput: "Hello, World!",
			expectedSize:   13,
		},
		{
			name:           "Large input",
			input:          string(make([]byte, 1<<20)), // 1MB input
			expectedOutput: string(make([]byte, 1<<20)),
			expectedSize:   1 << 20,
		},
		{
			name:           "Input slightly greater than threshold",
			input:          string(make([]byte, defaultThreshold+1)),
			expectedOutput: string(make([]byte, defaultThreshold+1)),
			expectedSize:   defaultThreshold + 1,
		},
		// Test to ensure that anytime the buffer exceeds the threshold, the data is written to a file
		// and the buffer is cleared.
		{
			name:           "Input much greater than threshold",
			input:          string(make([]byte, (2*defaultThreshold)+largeBufferSize+1)),
			expectedOutput: string(make([]byte, (2*defaultThreshold)+largeBufferSize+1)),
			expectedSize:   (2 * defaultThreshold) + largeBufferSize + 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			writer := New()
			reader := bytes.NewReader([]byte(tc.input))
			size, err := writer.ReadFrom(reader)
			assert.NoError(t, err)

			if writer.buf != nil && writer.file != nil {
				assert.Len(t, writer.buf.Bytes(), 0)
			}

			err = writer.CloseForWriting()
			assert.NoError(t, err)

			assert.Equal(t, tc.expectedSize, size)
			if size == 0 {
				return
			}

			rc, err := writer.ReadCloser()
			assert.NoError(t, err)
			defer rc.Close()

			var result bytes.Buffer

			_, err = io.Copy(&result, rc)
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedOutput, result.String())
		})
	}
}
