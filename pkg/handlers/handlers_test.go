package handlers

import (
	"archive/zip"
	"bytes"
	stdctx "context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/stretchr/testify/assert"
	diskbufferreader "github.com/trufflesecurity/disk-buffer-reader"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func TestHandleFileCancelledContext(t *testing.T) {
	reporter := sources.ChanReporter{Ch: make(chan *sources.Chunk, 2)}

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	reader, err := diskbufferreader.New(strings.NewReader("file"))
	assert.NoError(t, err)
	assert.Error(t, HandleFile(canceledCtx, reader, &sources.Chunk{}, reporter))
}

func TestHandleFile(t *testing.T) {
	reporter := sources.ChanReporter{Ch: make(chan *sources.Chunk, 513)}

	// Only one chunk is sent on the channel.
	// TODO: Embed a zip without making an HTTP request.
	resp, err := http.Get("https://raw.githubusercontent.com/bill-rich/bad-secrets/master/aws-canary-creds.zip")
	assert.NoError(t, err)
	defer func() {
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
	}()

	assert.Equal(t, 0, len(reporter.Ch))
	assert.NoError(t, HandleFile(context.Background(), resp.Body, &sources.Chunk{}, reporter))
	assert.Equal(t, 1, len(reporter.Ch))
}

func TestHandleHTTPJson(t *testing.T) {
	resp, err := http.Get("https://raw.githubusercontent.com/ahrav/nothing-to-see-here/main/sm_random_data.json")
	assert.NoError(t, err)
	defer func() {
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
	}()

	chunkCh := make(chan *sources.Chunk, 1)
	go func() {
		defer close(chunkCh)
		err := HandleFile(context.Background(), resp.Body, &sources.Chunk{}, sources.ChanReporter{Ch: chunkCh})
		assert.NoError(t, err)
	}()

	wantCount := 513
	count := 0
	for range chunkCh {
		count++
	}
	assert.Equal(t, wantCount, count)
}

func TestHandleHTTPJsonZip(t *testing.T) {
	resp, err := http.Get("https://raw.githubusercontent.com/ahrav/nothing-to-see-here/main/sm.zip")
	assert.NoError(t, err)
	defer func() {
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
	}()

	chunkCh := make(chan *sources.Chunk, 1)
	go func() {
		defer close(chunkCh)
		err := HandleFile(context.Background(), resp.Body, &sources.Chunk{}, sources.ChanReporter{Ch: chunkCh})
		assert.NoError(t, err)
	}()

	wantCount := 513
	count := 0
	for range chunkCh {
		count++
	}
	assert.Equal(t, wantCount, count)
}

func BenchmarkHandleHTTPJsonZip(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		func() {
			resp, err := http.Get("https://raw.githubusercontent.com/ahrav/nothing-to-see-here/main/sm.zip")
			assert.NoError(b, err)

			defer func() {
				if resp != nil && resp.Body != nil {
					resp.Body.Close()
				}
			}()

			chunkCh := make(chan *sources.Chunk, 1)

			b.StartTimer()
			go func() {
				defer close(chunkCh)
				err := HandleFile(context.Background(), resp.Body, &sources.Chunk{}, sources.ChanReporter{Ch: chunkCh})
				assert.NoError(b, err)
			}()

			for range chunkCh {
			}

			b.StopTimer()
		}()
	}
}

func BenchmarkHandleFile(b *testing.B) {
	file, err := os.Open("testdata/test.tgz")
	assert.Nil(b, err)
	defer file.Close()

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sourceChan := make(chan *sources.Chunk, 1)
		b.StartTimer()
		go func() {
			defer close(sourceChan)
			err := HandleFile(context.Background(), file, &sources.Chunk{}, sources.ChanReporter{Ch: sourceChan})
			assert.NoError(b, err)
		}()

		for range sourceChan {
		}
		b.StopTimer()

		_, err = file.Seek(0, io.SeekStart)
		assert.NoError(b, err)
	}
}

func TestSkipArchive(t *testing.T) {
	file, err := os.Open("testdata/test.tgz")
	assert.Nil(t, err)

	chunkCh := make(chan *sources.Chunk)
	go func() {
		defer close(chunkCh)
		err := HandleFile(context.Background(), file, &sources.Chunk{}, sources.ChanReporter{Ch: chunkCh}, WithSkipArchives(true))
		assert.NoError(t, err)
	}()

	wantCount := 0
	count := 0
	for range chunkCh {
		count++
	}
	assert.Equal(t, wantCount, count)
}

func TestHandleNestedArchives(t *testing.T) {
	file, err := os.Open("testdata/nested-dirs.zip")
	assert.Nil(t, err)

	chunkCh := make(chan *sources.Chunk)
	go func() {
		defer close(chunkCh)
		err := HandleFile(context.Background(), file, &sources.Chunk{}, sources.ChanReporter{Ch: chunkCh})
		assert.NoError(t, err)
	}()

	wantCount := 8
	count := 0
	for range chunkCh {
		count++
	}
	assert.Equal(t, wantCount, count)
}

func TestHandleCompressedZip(t *testing.T) {
	file, err := os.Open("testdata/example.zip.gz")
	assert.Nil(t, err)

	chunkCh := make(chan *sources.Chunk)
	go func() {
		defer close(chunkCh)
		err := HandleFile(context.Background(), file, &sources.Chunk{}, sources.ChanReporter{Ch: chunkCh})
		assert.NoError(t, err)
	}()

	wantCount := 2
	count := 0
	for range chunkCh {
		count++
	}
	assert.Equal(t, wantCount, count)
}

func TestHandleNestedCompressedArchive(t *testing.T) {
	file, err := os.Open("testdata/nested-compressed-archive.tar.gz")
	assert.Nil(t, err)

	chunkCh := make(chan *sources.Chunk)
	go func() {
		defer close(chunkCh)
		err := HandleFile(context.Background(), file, &sources.Chunk{}, sources.ChanReporter{Ch: chunkCh})
		assert.NoError(t, err)
	}()

	wantCount := 4
	count := 0
	for range chunkCh {
		count++
	}
	assert.Equal(t, wantCount, count)
}

func TestExtractTarContent(t *testing.T) {
	file, err := os.Open("testdata/test.tgz")
	assert.Nil(t, err)

	chunkCh := make(chan *sources.Chunk)
	go func() {
		defer close(chunkCh)
		err := HandleFile(context.Background(), file, &sources.Chunk{}, sources.ChanReporter{Ch: chunkCh})
		assert.NoError(t, err)
	}()

	wantCount := 4
	count := 0
	for range chunkCh {
		count++
	}
	assert.Equal(t, wantCount, count)
}

func TestNestedDirArchive(t *testing.T) {
	file, err := os.Open("testdata/dir-archive.zip")
	assert.Nil(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sourceChan := make(chan *sources.Chunk, 1)

	go func() {
		defer close(sourceChan)
		err := HandleFile(ctx, file, &sources.Chunk{}, sources.ChanReporter{Ch: sourceChan})
		assert.NoError(t, err)
	}()

	count := 0
	want := 4
	for range sourceChan {
		count++
	}
	assert.Equal(t, want, count)
}

func TestHandleFileRPM(t *testing.T) {
	wantChunkCount := 179
	reporter := sources.ChanReporter{Ch: make(chan *sources.Chunk, wantChunkCount)}

	file, err := os.Open("testdata/test.rpm")
	assert.Nil(t, err)

	assert.Equal(t, 0, len(reporter.Ch))
	assert.NoError(t, HandleFile(context.Background(), file, &sources.Chunk{}, reporter))
	assert.Equal(t, wantChunkCount, len(reporter.Ch))
}

func TestHandleFileAR(t *testing.T) {
	wantChunkCount := 102
	reporter := sources.ChanReporter{Ch: make(chan *sources.Chunk, wantChunkCount)}

	file, err := os.Open("testdata/test.deb")
	assert.Nil(t, err)

	assert.Equal(t, 0, len(reporter.Ch))
	assert.NoError(t, HandleFile(context.Background(), file, &sources.Chunk{}, reporter))
	assert.Equal(t, wantChunkCount, len(reporter.Ch))
}

func BenchmarkHandleAR(b *testing.B) {
	file, err := os.Open("testdata/test.deb")
	assert.Nil(b, err)
	defer file.Close()

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sourceChan := make(chan *sources.Chunk, 1)

		b.StartTimer()
		go func() {
			defer close(sourceChan)
			err := HandleFile(context.Background(), file, &sources.Chunk{}, sources.ChanReporter{Ch: sourceChan})
			assert.NoError(b, err)
		}()

		for range sourceChan {
		}
		b.StopTimer()

		_, err = file.Seek(0, io.SeekStart)
		assert.NoError(b, err)
	}
}

func TestHandleFileNonArchive(t *testing.T) {
	wantChunkCount := 6
	reporter := sources.ChanReporter{Ch: make(chan *sources.Chunk, wantChunkCount)}

	file, err := os.Open("testdata/nonarchive.txt")
	assert.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	assert.NoError(t, HandleFile(ctx, file, &sources.Chunk{}, reporter))
	assert.NoError(t, err)
	assert.Equal(t, wantChunkCount, len(reporter.Ch))
}

func TestExtractTarContentWithEmptyFile(t *testing.T) {
	file, err := os.Open("testdata/testdir.zip")
	assert.Nil(t, err)

	chunkCh := make(chan *sources.Chunk, 1)
	go func() {
		defer close(chunkCh)
		err := HandleFile(context.Background(), file, &sources.Chunk{}, sources.ChanReporter{Ch: chunkCh})
		assert.NoError(t, err)
	}()

	wantCount := 4
	count := 0
	for range chunkCh {
		count++
	}
	assert.Equal(t, wantCount, count)
}

func TestHandleTar(t *testing.T) {
	file, err := os.Open("testdata/test.tar")
	assert.Nil(t, err)
	defer file.Close()

	chunkCh := make(chan *sources.Chunk, 1)
	go func() {
		defer close(chunkCh)
		err := HandleFile(context.Background(), file, &sources.Chunk{}, sources.ChanReporter{Ch: chunkCh})
		assert.NoError(t, err)
	}()

	wantCount := 1
	count := 0
	for range chunkCh {
		count++
	}
	assert.Equal(t, wantCount, count)
}

func BenchmarkHandleTar(b *testing.B) {
	file, err := os.Open("testdata/test.tar")
	assert.Nil(b, err)
	defer file.Close()

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sourceChan := make(chan *sources.Chunk, 1)

		b.StartTimer()
		go func() {
			defer close(sourceChan)
			err := HandleFile(context.Background(), file, &sources.Chunk{}, sources.ChanReporter{Ch: sourceChan})
			assert.NoError(b, err)
		}()

		for range sourceChan {
		}
		b.StopTimer()

		_, err = file.Seek(0, io.SeekStart)
		assert.NoError(b, err)
	}
}

func TestHandleLargeHTTPJson(t *testing.T) {
	resp, err := http.Get("https://raw.githubusercontent.com/ahrav/nothing-to-see-here/main/md_random_data.json.zip")
	if !assert.NoError(t, err) {
		return
	}

	defer func() {
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
	}()

	chunkCh := make(chan *sources.Chunk, 1)
	go func() {
		defer close(chunkCh)
		err := HandleFile(context.Background(), resp.Body, &sources.Chunk{}, sources.ChanReporter{Ch: chunkCh})
		assert.NoError(t, err)
	}()

	wantCount := 5121
	count := 0
	for range chunkCh {
		count++
	}
	assert.Equal(t, wantCount, count)
}

func TestHandlePipe(t *testing.T) {
	r, w := io.Pipe()

	go func() {
		defer w.Close()
		file, err := os.Open("testdata/test.tar")
		assert.NoError(t, err)
		defer file.Close()
		_, err = io.Copy(w, file)
		assert.NoError(t, err)
	}()

	chunkCh := make(chan *sources.Chunk, 1)
	go func() {
		defer close(chunkCh)
		err := HandleFile(context.Background(), r, &sources.Chunk{}, sources.ChanReporter{Ch: chunkCh})
		assert.NoError(t, err)
	}()

	wantCount := 1
	count := 0
	for range chunkCh {
		count++
	}
	assert.Equal(t, wantCount, count)
}

func TestHandleZipCommandStdoutPipe(t *testing.T) {
	cmd := exec.Command("zip", "-j", "-", "testdata/nested-dirs.zip")
	stdout, err := cmd.StdoutPipe()
	assert.NoError(t, err)

	err = cmd.Start()
	assert.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	chunkCh := make(chan *sources.Chunk, 1)
	go func() {
		defer close(chunkCh)
		err := HandleFile(ctx, stdout, &sources.Chunk{}, sources.ChanReporter{Ch: chunkCh})
		assert.NoError(t, err)
	}()

	wantCount := 8
	count := 0
	for range chunkCh {
		count++
	}

	// cmd.Wait() should be called after all the reading from the pipe is done.
	// https://cs.opensource.google/go/go/+/refs/tags/go1.23.2:src/os/exec/exec.go;l=1051-1053
	err = cmd.Wait()
	assert.NoError(t, err)

	assert.Equal(t, wantCount, count)
}

func TestHandleGitCatFile(t *testing.T) {
	tests := []struct {
		name           string
		fileName       string
		fileSize       int
		supportedType  bool
		expectedChunks int
	}{
		{
			name:           "LargeBlob",
			fileName:       "largefile.bin",
			fileSize:       50 * 1024 * 1024, // 50 MB
			supportedType:  true,
			expectedChunks: 5120,
		},
		{
			name:           "UnsupportedType",
			fileName:       "unsupported.so",
			fileSize:       1024 * 1024, // 1 MB
			supportedType:  false,
			expectedChunks: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up a temporary git repository with the specified file.
			var gitDir string
			if tt.supportedType {
				gitDir = setupTempGitRepo(t, tt.fileName, tt.fileSize)
			} else {
				gitDir = setupTempGitRepoWithUnsupportedFile(t, tt.fileName, tt.fileSize)
			}
			defer os.RemoveAll(gitDir)

			cmd := exec.Command("git", "-C", gitDir, "rev-parse", "HEAD")
			hashBytes, err := cmd.Output()
			assert.NoError(t, err, "Failed to get commit hash")
			commitHash := strings.TrimSpace(string(hashBytes))

			// Create a pipe to simulate the git cat-file stdout.
			cmd = exec.Command("git", "-C", gitDir, "cat-file", "blob", fmt.Sprintf("%s:%s", commitHash, tt.fileName))

			var stderr bytes.Buffer
			cmd.Stderr = &stderr

			stdout, err := cmd.StdoutPipe()
			assert.NoError(t, err, "Failed to create stdout pipe")

			err = cmd.Start()
			assert.NoError(t, err, "Failed to start git cat-file command")

			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()

			chunkCh := make(chan *sources.Chunk, 1000)

			go func() {
				defer close(chunkCh)
				err := HandleFile(ctx, stdout, &sources.Chunk{}, sources.ChanReporter{Ch: chunkCh}, WithSkipArchives(false))
				assert.NoError(t, err, "HandleFile should not return an error")
			}()

			count := 0
			for range chunkCh {
				count++
			}

			// cmd.Wait() should be called after all the reading from the pipe is done.
			// https://cs.opensource.google/go/go/+/refs/tags/go1.23.2:src/os/exec/exec.go;l=1051-1053
			err = cmd.Wait()
			assert.NoError(t, err, "git cat-file command should complete without error")

			assert.Equal(t, tt.expectedChunks, count, "Number of chunks should match the expected value")
		})
	}
}

func setupTempGitRepoWithUnsupportedFile(t *testing.T, fileName string, fileSize int) string {
	t.Helper()
	return setupTempGitRepoCommon(t, fileName, fileSize, true)
}

func setupTempGitRepo(t *testing.T, archiveName string, fileSize int) string {
	t.Helper()
	return setupTempGitRepoCommon(t, archiveName, fileSize, false)
}

func setupTempGitRepoCommon(t *testing.T, fileName string, fileSize int, isUnsupported bool) string {
	t.Helper()

	tempDir := t.TempDir()

	cmd := exec.Command("git", "init", tempDir)
	var initStderr bytes.Buffer
	cmd.Stderr = &initStderr
	err := cmd.Run()
	if err != nil {
		t.Fatalf("Failed to initialize git repository: %v, stderr: %s", err, initStderr.String())
	}

	cmds := [][]string{
		{"git", "-C", tempDir, "config", "user.name", "Test User"},
		{"git", "-C", tempDir, "config", "user.email", "test@example.com"},
	}

	for _, cmdArgs := range cmds {
		cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...) //nolint:gosec
		var cmdStderr bytes.Buffer
		cmd.Stderr = &cmdStderr
		err := cmd.Run()
		if err != nil {
			t.Fatalf("Failed to set git config: %v, stderr: %s", err, cmdStderr.String())
		}
	}

	filePath := filepath.Join(tempDir, fileName)

	// Create the file with appropriate content.
	f, err := os.Create(filePath)
	if err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}
	defer f.Close()

	if isUnsupported {
		// Write ELF header for unsupported file.
		// https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.eheader.html
		elfHeader := []byte{
			0x7f, 'E', 'L', 'F', // ELF magic number
			2,                   // 64-bit format
			1,                   // Little endian
			1,                   // Current version of ELF
			0,                   // Target OS ABI
			0,                   // ABI Version
			0, 0, 0, 0, 0, 0, 0, // 7 bytes of padding
			3, 0, // Relocatable file
			0x3e, 0, // AMD x86-64 architecture
			1, 0, 0, 0, // ELF version
			0, 0, 0, 0, 0, 0, 0, 0, // Entry point
			0, 0, 0, 0, 0, 0, 0, 0, // Program header offset
			0, 0, 0, 0, 0, 0, 0, 0, // Section header offset
		}
		_, err = f.Write(elfHeader)
		if err != nil {
			t.Fatalf("Failed to write ELF header: %v", err)
		}
	} else {
		// Write ZIP content for supported file.
		zipWriter := zip.NewWriter(f)
		header := &zip.FileHeader{
			Name:   "largefile.txt",
			Method: zip.Store, // No compression
		}
		zipFileWriter, err := zipWriter.CreateHeader(header)
		if err != nil {
			t.Fatalf("Failed to create file in ZIP archive: %v", err)
		}

		dataChunk := bytes.Repeat([]byte("A"), 1024) // 1KB chunk
		totalWritten := 0
		for totalWritten < fileSize {
			remaining := fileSize - totalWritten
			if remaining < len(dataChunk) {
				_, err = zipFileWriter.Write(dataChunk[:remaining])
				if err != nil {
					t.Fatalf("Failed to write to inner file in ZIP archive: %v", err)
				}
				totalWritten += remaining
			} else {
				_, err = zipFileWriter.Write(dataChunk)
				if err != nil {
					t.Fatalf("Failed to write to inner file in ZIP archive: %v", err)
				}
				totalWritten += len(dataChunk)
			}
		}

		if err := zipWriter.Close(); err != nil {
			t.Fatalf("Failed to close ZIP writer: %v", err)
		}
	}

	// Add and commit the file to Git.
	cmd = exec.Command("git", "-C", tempDir, "add", fileName)
	var addStderr bytes.Buffer
	cmd.Stderr = &addStderr
	err = cmd.Run()
	if err != nil {
		t.Fatalf("Failed to add file to git: %v, stderr: %s", err, addStderr.String())
	}

	cmd = exec.Command("git", "-C", tempDir, "commit", "-m", "Add file")
	var commitStderr bytes.Buffer
	cmd.Stderr = &commitStderr
	err = cmd.Run()
	if err != nil {
		t.Fatalf("Failed to commit file to git: %v, stderr: %s", err, commitStderr.String())
	}

	return tempDir
}

func TestHandleFileNewFileReaderFailure(t *testing.T) {
	customReader := iotest.ErrReader(errors.New("simulated newFileReader error"))

	chunkSkel := &sources.Chunk{}
	chunkCh := make(chan *sources.Chunk)
	reporter := sources.ChanReporter{Ch: chunkCh}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := HandleFile(ctx, customReader, chunkSkel, reporter)

	assert.Error(t, err, "HandleFile should return an error when newFileReader fails")
}

// errorInjectingReader is a custom io.Reader that injects an error after reading a certain number of bytes.
type errorInjectingReader struct {
	reader        io.Reader
	injectAfter   int64 // Number of bytes after which to inject the error
	injected      bool
	bytesRead     int64
	errorToInject error
}

func (eir *errorInjectingReader) Read(p []byte) (int, error) {
	if eir.injectAfter > 0 && eir.bytesRead >= eir.injectAfter && !eir.injected {
		eir.injected = true
		return 0, eir.errorToInject
	}

	n, err := eir.reader.Read(p)
	eir.bytesRead += int64(n)
	return n, err
}

// TestHandleGitCatFileWithPipeError tests that when an error is injected during the HandleFile processing,
// the error is reported and the git cat-file command completes successfully.
func TestHandleGitCatFileWithPipeError(t *testing.T) {
	fileName := "largefile_with_error.bin"
	fileSize := 100 * 1024               // 100 KB
	injectErrorAfter := int64(50 * 1024) // Inject error after 50 KB
	simulatedError := errors.New("simulated error during newFileReader")

	gitDir := setupTempGitRepo(t, fileName, fileSize)
	defer os.RemoveAll(gitDir)

	commitHash := getGitCommitHash(t, gitDir)

	cmd := exec.Command("git", "-C", gitDir, "cat-file", "blob", fmt.Sprintf("%s:%s", commitHash, fileName))

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	stdout, err := cmd.StdoutPipe()
	assert.NoError(t, err, "Failed to create stdout pipe")

	err = cmd.Start()
	assert.NoError(t, err, "Failed to start git cat-file command")

	// Wrap the stdout with errorInjectingReader to simulate an error after reading injectErrorAfter bytes.
	wrappedReader := &errorInjectingReader{
		reader:        stdout,
		injectAfter:   injectErrorAfter,
		injected:      false,
		bytesRead:     0,
		errorToInject: simulatedError,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	chunkCh := make(chan *sources.Chunk, 1000)

	go func() {
		defer close(chunkCh)
		err = HandleFile(ctx, wrappedReader, &sources.Chunk{}, sources.ChanReporter{Ch: chunkCh}, WithSkipArchives(false))
		assert.NoError(t, err, "HandleFile should not return an error")
	}()

	for range chunkCh {
	}

	err = cmd.Wait()
	assert.NoError(t, err, "git cat-file command should complete without error")
}

// getGitCommitHash retrieves the current commit hash of the Git repository.
func getGitCommitHash(t *testing.T, gitDir string) string {
	t.Helper()
	cmd := exec.Command("git", "-C", gitDir, "rev-parse", "HEAD")
	hashBytes, err := cmd.Output()
	assert.NoError(t, err, "Failed to get commit hash")
	commitHash := strings.TrimSpace(string(hashBytes))
	return commitHash
}

type mockReporter struct{ reportedChunks int }

func (m *mockReporter) ChunkOk(context.Context, sources.Chunk) {
	m.reportedChunks++
}

func (m *mockReporter) ChunkErr(context.Context, error) {}

func TestHandleChunksWithError(t *testing.T) {
	tests := []struct {
		name                   string
		input                  []DataOrErr
		expectedErr            error
		expectedReportedChunks int
	}{
		{
			name:  "Non-Critical Error",
			input: []DataOrErr{{Err: ErrProcessingWarning}},
		},
		{
			name:        "Critical Error",
			input:       []DataOrErr{{Err: ErrProcessingFatal}},
			expectedErr: ErrProcessingFatal,
		},
		{
			name: "No Error",
			input: []DataOrErr{
				{Data: []byte("test data")},
				{Data: []byte("more data")},
			},
			expectedReportedChunks: 2,
		},
		{
			name:        "Context Canceled",
			input:       []DataOrErr{{Err: stdctx.Canceled}},
			expectedErr: stdctx.Canceled,
		},
		{
			name:        "Context Deadline Exceeded",
			input:       []DataOrErr{{Err: stdctx.DeadlineExceeded}},
			expectedErr: stdctx.DeadlineExceeded,
		},
		{
			name:  "EOF Error",
			input: []DataOrErr{{Err: io.EOF}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			chunkSkel := &sources.Chunk{}
			reporter := new(mockReporter)

			dataErrChan := make(chan DataOrErr, len(tc.input))
			for _, de := range tc.input {
				dataErrChan <- de
			}
			close(dataErrChan)

			err := handleChunksWithError(ctx, dataErrChan, chunkSkel, reporter)

			if tc.expectedErr != nil {
				assert.ErrorIs(t, err, tc.expectedErr, "handleChunksWithError should return the expected error")
			} else {
				assert.NoError(t, err, "handleChunksWithError should not return an error for non-critical errors")
			}

			assert.Equal(t, tc.expectedReportedChunks, reporter.reportedChunks, "should have reported the expected number of chunks")
		})
	}
}
