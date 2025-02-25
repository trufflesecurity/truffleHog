package filesystem

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/kylelemons/godebug/pretty"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sourcestest"
)

func TestSource_Scan(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()

	type init struct {
		name       string
		verify     bool
		connection *sourcespb.Filesystem
	}
	tests := []struct {
		name               string
		init               init
		wantSourceMetadata *source_metadatapb.MetaData
		wantErr            bool
	}{
		{
			name: "get a chunk",
			init: init{
				name: "this repo",
				connection: &sourcespb.Filesystem{
					Paths: []string{"."},
				},
				verify: true,
			},
			wantSourceMetadata: &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_Filesystem{
					Filesystem: &source_metadatapb.Filesystem{
						File: "filesystem.go",
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Source{}

			conn, err := anypb.New(tt.init.connection)
			if err != nil {
				t.Fatal(err)
			}

			err = s.Init(ctx, tt.init.name, 0, 0, tt.init.verify, conn, 5)
			if (err != nil) != tt.wantErr {
				t.Errorf("Source.Init() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			chunksCh := make(chan *sources.Chunk, 1)
			// TODO: this is kind of bad, if it errors right away we don't see it as a test failure.
			// Debugging this usually requires setting a breakpoint on L78 and running test w/ debug.
			go func() {
				defer close(chunksCh)
				err = s.Chunks(ctx, chunksCh)
				if (err != nil) != tt.wantErr {
					t.Errorf("Source.Chunks() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
			}()
			var counter int
			for chunk := range chunksCh {
				if chunk.SourceMetadata.GetFilesystem().GetFile() == "filesystem.go" {
					counter++
					if diff := pretty.Compare(chunk.SourceMetadata, tt.wantSourceMetadata); diff != "" {
						t.Errorf("Source.Chunks() %s diff: (-got +want)\n%s", tt.name, diff)
					}
				}
			}
			assert.Equal(t, 1, counter)
		})
	}
}

func TestScanFile(t *testing.T) {
	chunkSize := sources.DefaultChunkSize
	secretPart1 := "SECRET"
	secretPart2 := "SPLIT"
	// Split the secret into two parts and pad the rest of the chunk with A's.
	data := strings.Repeat("A", chunkSize-len(secretPart1)) + secretPart1 + secretPart2 + strings.Repeat("A", chunkSize-len(secretPart2))

	tmpfile, cleanup, err := createTempFile("", data)
	assert.Nil(t, err)
	defer cleanup()

	source := &Source{}
	chunksChan := make(chan *sources.Chunk, 2)

	ctx := context.WithLogger(context.Background(), logr.Discard())
	go func() {
		defer close(chunksChan)
		err = source.scanFile(ctx, tmpfile.Name(), chunksChan)
		assert.Nil(t, err)
	}()

	// Read from the channel and validate the secrets.
	foundSecret := ""
	for chunkCh := range chunksChan {
		foundSecret += string(chunkCh.Data)
	}

	assert.Contains(t, foundSecret, secretPart1+secretPart2)
}

func TestEnumerate(t *testing.T) {
	// TODO: refactor to allow a virtual filesystem.
	t.Parallel()
	ctx := context.Background()

	// Setup the connection to test enumeration.
	dir, err := os.MkdirTemp("", "trufflehog-test-enumerate")
	assert.NoError(t, err)
	defer os.RemoveAll(dir)

	units := []string{
		"/one", "/two", "/three",
		"/path/to/dir/", "/path/to/another/dir/",
	}
	// Prefix the units with the tempdir and create files on disk.
	for i, unit := range units {
		fullPath := filepath.Join(dir, unit)
		units[i] = fullPath
		if i < 3 {
			f, err := os.Create(fullPath)
			assert.NoError(t, err)
			f.Close()
		} else {
			assert.NoError(t, os.MkdirAll(fullPath, 0755))
			// Create a file in the directory for enumeration to find.
			f, err := os.CreateTemp(fullPath, "file")
			assert.NoError(t, err)
			units[i] = f.Name()
			f.Close()
		}
	}
	conn, err := anypb.New(&sourcespb.Filesystem{
		Paths:       units[0:3],
		Directories: units[3:],
	})
	assert.NoError(t, err)

	// Initialize the source.
	s := Source{}
	err = s.Init(ctx, "test enumerate", 0, 0, true, conn, 1)
	assert.NoError(t, err)

	reporter := sourcestest.TestReporter{}
	err = s.Enumerate(ctx, &reporter)
	assert.NoError(t, err)

	assert.Equal(t, len(units), len(reporter.Units))
	assert.Equal(t, 0, len(reporter.UnitErrs))
	for _, unit := range reporter.Units {
		path, _ := unit.SourceUnitID()
		assert.Contains(t, units, path)
	}
	for _, unit := range units {
		assert.Contains(t, reporter.Units, sources.CommonSourceUnit{ID: unit})
	}
}

func TestChunkUnit(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Setup test file to chunk.
	fileContents := "TestChunkUnit"
	tmpfile, cleanup, err := createTempFile("", fileContents)
	assert.NoError(t, err)
	defer cleanup()

	tmpdir, cleanup, err := createTempDir("", "foo", "bar", "baz")
	assert.NoError(t, err)
	defer cleanup()

	conn, err := anypb.New(&sourcespb.Filesystem{})
	assert.NoError(t, err)

	// Initialize the source.
	s := Source{}
	err = s.Init(ctx, "test chunk unit", 0, 0, true, conn, 1)
	assert.NoError(t, err)

	// Happy path single file.
	reporter := sourcestest.TestReporter{}
	err = s.ChunkUnit(ctx, sources.CommonSourceUnit{
		ID: tmpfile.Name(),
	}, &reporter)
	assert.NoError(t, err)

	// Happy path directory.
	err = s.ChunkUnit(ctx, sources.CommonSourceUnit{
		ID: tmpdir,
	}, &reporter)
	assert.NoError(t, err)

	// Error path.
	err = s.ChunkUnit(ctx, sources.CommonSourceUnit{
		ID: "/file/not/found",
	}, &reporter)
	assert.NoError(t, err)

	assert.Equal(t, 4, len(reporter.Chunks))
	assert.Equal(t, 1, len(reporter.ChunkErrs))
	dataFound := make(map[string]struct{}, 4)
	for _, chunk := range reporter.Chunks {
		dataFound[string(chunk.Data)] = struct{}{}
	}
	assert.Contains(t, dataFound, fileContents)
	assert.Contains(t, dataFound, "foo")
	assert.Contains(t, dataFound, "bar")
	assert.Contains(t, dataFound, "baz")
}

func TestEnumerateReporterErr(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Setup the connection to test enumeration.
	units := []string{
		"/one", "/two", "/three",
		"/path/to/dir/", "/path/to/another/dir/",
	}
	conn, err := anypb.New(&sourcespb.Filesystem{
		Paths:       units[0:3],
		Directories: units[3:],
	})
	assert.NoError(t, err)

	// Initialize the source.
	s := Source{}
	err = s.Init(ctx, "test enumerate", 0, 0, true, conn, 1)
	assert.NoError(t, err)

	// Enumerate should always return an error if the reporter returns an
	// error.
	reporter := sourcestest.ErrReporter{}
	err = s.Enumerate(ctx, &reporter)
	assert.Error(t, err)
}

func TestChunkUnitReporterErr(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Setup test file to chunk.
	tmpfile, err := os.CreateTemp("", "example.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	fileContents := []byte("TestChunkUnit")
	_, err = tmpfile.Write(fileContents)
	assert.NoError(t, err)
	assert.NoError(t, tmpfile.Close())

	conn, err := anypb.New(&sourcespb.Filesystem{})
	assert.NoError(t, err)

	// Initialize the source.
	s := Source{}
	err = s.Init(ctx, "test chunk unit", 0, 0, true, conn, 1)
	assert.NoError(t, err)

	// Happy path. ChunkUnit should always return an error if the reporter
	// returns an error.
	reporter := sourcestest.ErrReporter{}
	err = s.ChunkUnit(ctx, sources.CommonSourceUnit{
		ID: tmpfile.Name(),
	}, &reporter)
	assert.Error(t, err)

	// Error path. ChunkUnit should always return an error if the reporter
	// returns an error.
	err = s.ChunkUnit(ctx, sources.CommonSourceUnit{
		ID: "/file/not/found",
	}, &reporter)
	assert.Error(t, err)
}

// createTempFile is a helper function to create a temporary file in the given
// directory with the provided contents. If dir is "", the operating system's
// temp directory is used.
func createTempFile(dir string, contents string) (*os.File, func(), error) {
	tmpfile, err := os.CreateTemp(dir, "trufflehogtest")
	if err != nil {
		return nil, nil, err
	}

	if _, err := tmpfile.Write([]byte(contents)); err != nil {
		_ = os.Remove(tmpfile.Name())
		return nil, nil, err
	}
	if err := tmpfile.Close(); err != nil {
		_ = os.Remove(tmpfile.Name())
		return nil, nil, err
	}
	return tmpfile, func() { _ = os.Remove(tmpfile.Name()) }, nil
}

// createTempDir is a helper function to create a temporary directory in the
// given directory with files containing the provided contents. If dir is "",
// the operating system's temp directory is used.
func createTempDir(dir string, contents ...string) (string, func(), error) {
	tmpdir, err := os.MkdirTemp(dir, "trufflehogtest")
	if err != nil {
		return "", nil, err
	}

	for _, content := range contents {
		if _, _, err := createTempFile(tmpdir, content); err != nil {
			_ = os.RemoveAll(tmpdir)
			return "", nil, err
		}
	}
	return tmpdir, func() { _ = os.RemoveAll(tmpdir) }, nil
}
