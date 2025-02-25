package handlers

import (
	"archive/zip"
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"

	"github.com/gabriel-vasile/mimetype"
	"github.com/mholt/archives"

	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/feature"
	"github.com/trufflesecurity/trufflehog/v3/pkg/iobuf"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// fileReader is a custom reader that wraps an io.Reader and provides additional functionality for identifying
// and handling different file types. It abstracts away the complexity of detecting file formats, MIME types,
// and archive types, allowing for a more modular and extensible file handling process.
//
// fileReader leverages the archiver and mimetype packages for file type identification and provides information
// about the detected file format, MIME type, and whether the file is an archive. This information can be
// used by FileHandler implementations to make decisions on how to process the file.
//
// The IsGenericArchive field indicates whether the file represents an archive format that is supported by the
// archiver library. This allows FileHandler implementations to determine if the file can be processed using
// the default archive handling capabilities provided by the archiver package.
//
// By encapsulating the file type detection logic, fileReader simplifies the implementation of FileHandler and
// promotes a more cohesive and maintainable codebase. It also embeds a BufferedFileReader to provide efficient
// random access to the file content.
type fileReader struct {
	format           archives.Format
	mime             *mimetype.MIME
	isGenericArchive bool

	*iobuf.BufferedReadSeeker
}

var (
	ErrEmptyReader = errors.New("reader is empty")

	// ErrProcessingFatal indicates a severe error that requires stopping the file processing.
	ErrProcessingFatal = errors.New("fatal error processing file")

	// ErrProcessingWarning indicates a recoverable error that can be logged,
	// allowing processing to continue.
	ErrProcessingWarning = errors.New("error processing file")
)

type readerConfig struct{ fileExtension string }

type readerOption func(*readerConfig)

func withFileExtension(ext string) readerOption {
	return func(c *readerConfig) { c.fileExtension = ext }
}

// mimeTypeReader wraps an io.Reader with MIME type information.
// This type is used to pass content through the processing pipeline
// while carrying its detected MIME type, avoiding redundant type detection.
type mimeTypeReader struct {
	mimeExt  string
	mimeName mimeType
	io.Reader
}

// newMimeTypeReaderFromFileReader creates a new mimeTypeReader from a fileReader.
func newMimeTypeReaderFromFileReader(r fileReader) mimeTypeReader {
	return mimeTypeReader{
		mimeExt:  r.mime.Extension(),
		mimeName: mimeType(r.mime.String()),
		Reader:   r.BufferedReadSeeker,
	}
}

// newMimeTypeReader creates a new mimeTypeReader from an io.Reader.
// It uses a bufio.Reader to perform MIME type detection on the input reader
// without consuming it, by peeking into the first 3072 bytes of the input.
// This encapsulates both the original reader and the detected MIME type information.
// This function is particularly useful for specialized archive handlers
// that need to pass extracted content to the default handler without modifying the original reader.
func newMimeTypeReader(r io.Reader) (mimeTypeReader, error) {
	const defaultMinBufferSize = 3072
	bufReader := bufio.NewReaderSize(r, defaultMinBufferSize)
	// A buffer of 512 bytes is used since many file formats store their magic numbers within the first 512 bytes.
	// If fewer bytes are read, MIME type detection may still succeed.
	buffer, err := bufReader.Peek(defaultMinBufferSize)
	if err != nil && !errors.Is(err, io.EOF) {
		return mimeTypeReader{}, fmt.Errorf("unable to read file for MIME type detection: %w", err)
	}

	mime := mimetype.Detect(buffer)

	return mimeTypeReader{mimeExt: mime.Extension(), mimeName: mimeType(mime.String()), Reader: bufReader}, nil
}

// newFileReader creates a fileReader from an io.Reader, optionally using BufferedFileWriter for certain formats.
// The caller is responsible for closing the reader when it is no longer needed.
func newFileReader(ctx context.Context, r io.Reader, options ...readerOption) (fReader fileReader, err error) {
	var cfg readerConfig

	for _, opt := range options {
		opt(&cfg)
	}
	// To detect the MIME type of the input data, we need a reader that supports seeking.
	// This allows us to read the data multiple times if necessary without losing the original position.
	// We use a BufferedReaderSeeker to wrap the original reader, enabling this functionality.
	fReader.BufferedReadSeeker = iobuf.NewBufferedReaderSeeker(r)

	// If an error occurs during MIME type detection, it is important we close the BufferedReaderSeeker
	// to release any resources it holds (checked out buffers or temp file).
	defer func() {
		if err != nil {
			if closeErr := fReader.Close(); closeErr != nil {
				err = fmt.Errorf("%w; error closing reader: %w", err, closeErr)
			}
		}
	}()

	var mime *mimetype.MIME
	mime, err = mimetype.DetectReader(fReader)
	if err != nil {
		return fReader, fmt.Errorf("unable to detect MIME type: %w", err)
	}
	fReader.mime = mime

	// Reset the reader to the beginning because DetectReader consumes the reader.
	if _, err = fReader.Seek(0, io.SeekStart); err != nil {
		return fReader, fmt.Errorf("error resetting reader after MIME detection: %w", err)
	}

	// Check for APK files
	if shouldHandleAsAPK(cfg, fReader) {
		isAPK, err := isAPKFile(&fReader)
		if err != nil {
			return fReader, fmt.Errorf("error checking for APK: %w", err)
		}
		if isAPK {
			return handleAPKFile(&fReader)
		}
	}

	// If a MIME type is known to not be an archive type, we might as well return here rather than
	// paying the I/O penalty of an archiver.Identify() call that won't identify anything.
	if _, ok := skipArchiverMimeTypes[mimeType(mime.String())]; ok {
		return fReader, nil
	}

	var format archives.Format
	format, _, err = archives.Identify(ctx, "", fReader)
	switch {
	case err == nil:
		fReader.isGenericArchive = true
		fReader.format = format

	case errors.Is(err, archives.NoMatch):
		// Not an archive handled by archiver.
		// Continue with the default reader.
	default:
		return fReader, fmt.Errorf("error identifying archive: %w", err)
	}

	// Reset the reader to the beginning again to allow the handler to read from the start.
	// This is necessary because Identify consumes the reader.
	if _, err = fReader.Seek(0, io.SeekStart); err != nil {
		return fReader, fmt.Errorf("error resetting reader after archive identification: %w", err)
	}

	return fReader, nil
}

// DataOrErr represents a result that can either contain data or an error.
// The Data field holds the byte slice of data, and the Err field holds any error that occurred.
// This structure is used to handle asynchronous file processing where each chunk of data
// or potential error needs to be communicated back to the caller. It allows for
// efficient streaming of file contents while also providing a way to propagate errors
// that may occur during the file handling process.
type DataOrErr struct {
	Data []byte
	Err  error
}

// FileHandler represents a handler for files.
// It has a single method, HandleFile, which takes a context and a fileReader as input,
// and returns a channel of byte slices and an error.
type FileHandler interface {
	HandleFile(ctx logContext.Context, reader fileReader) chan DataOrErr
}

// fileHandlingConfig encapsulates configuration settings that control the behavior of file processing.
type fileHandlingConfig struct{ skipArchives bool }

// newFileHandlingConfig creates a default fileHandlingConfig with default settings.
// Optional functional parameters can customize the configuration.
func newFileHandlingConfig(options ...func(*fileHandlingConfig)) fileHandlingConfig {
	config := fileHandlingConfig{}
	for _, option := range options {
		option(&config)
	}

	return config
}

// WithSkipArchives sets the skipArchives field of the fileHandlingConfig.
// If skip is true, the FileHandler will skip archive files.
func WithSkipArchives(skip bool) func(*fileHandlingConfig) {
	return func(c *fileHandlingConfig) { c.skipArchives = skip }
}

type handlerType string

const (
	archiveHandlerType handlerType = "archive"
	arHandlerType      handlerType = "ar"
	rpmHandlerType     handlerType = "rpm"
	apkHandlerType     handlerType = "apk"
	defaultHandlerType handlerType = "default"
	apkExt                         = ".apk"
)

type mimeType string

const (
	rpmMime      mimeType = "application/x-rpm"
	cpioMime     mimeType = "application/cpio"
	unixArMime   mimeType = "application/x-unix-archive"
	arMime       mimeType = "application/x-archive"
	debMime      mimeType = "application/vnd.debian.binary-package"
	textMime     mimeType = "text/plain; charset=utf-8"
	xmlMime      mimeType = "text/xml"
	jsonMime     mimeType = "application/json"
	csvMime      mimeType = "text/csv"
	tsvMime      mimeType = "text/tab-separated-values"
	geoJSONMine  mimeType = "application/vnd.geo+json"
	ndjsonMime   mimeType = "application/x-ndjson"
	htmlMime     mimeType = "text/html"
	phpTextMime  mimeType = "text/x-php"
	rtfTextMime  mimeType = "text/rtf"
	jsAppMime    mimeType = "application/javascript"
	jsTextMime   mimeType = "text/javascript"
	jsMime       mimeType = "application/x-javascript"
	srtMime      mimeType = "application/x-subrip"
	srtXMime     mimeType = "application/x-srt"
	srtTextMime  mimeType = "text/x-srt"
	vttMime      mimeType = "text/vtt"
	luaMime      mimeType = "text/x-lua"
	perlMime     mimeType = "text/x-perl"
	pythonMime   mimeType = "text/x-python"
	pyAppMime    mimeType = "application/x-python"
	pyScriptMime mimeType = "application/x-script.python"
	tclTextMime  mimeType = "text/x-tcl"
	tclMime      mimeType = "application/x-tcl"
	apkMime      mimeType = "application/vnd.android.package-archive"
	zipMime      mimeType = "application/zip"
	jarMime      mimeType = "application/java-archive"
)

// skipArchiverMimeTypes is a set of MIME types that should bypass archiver library processing because they are either
// text-based or archives not supported by the library.
var skipArchiverMimeTypes = map[mimeType]struct{}{
	arMime:       {},
	unixArMime:   {},
	debMime:      {},
	rpmMime:      {},
	cpioMime:     {},
	textMime:     {},
	xmlMime:      {},
	jsonMime:     {},
	csvMime:      {},
	tsvMime:      {},
	geoJSONMine:  {},
	ndjsonMime:   {},
	htmlMime:     {},
	phpTextMime:  {},
	rtfTextMime:  {},
	jsAppMime:    {},
	jsTextMime:   {},
	jsMime:       {},
	srtMime:      {},
	srtXMime:     {},
	srtTextMime:  {},
	vttMime:      {},
	luaMime:      {},
	perlMime:     {},
	pythonMime:   {},
	pyAppMime:    {},
	pyScriptMime: {},
	tclTextMime:  {},
	tclMime:      {},
	apkMime:      {},
}

// selectHandler dynamically selects and configures a FileHandler based on the provided |mimetype| type and archive flag.
// The fileReader contains information about the MIME type and whether the file is an archive.
// This method uses specialized handlers for specific file types:
// - arHandler is used for Unix archives and Debian packages ('arMime', 'unixArMime', and 'debMime').
// - rpmHandler is used for RPM and CPIO archives ('rpmMime' and 'cpioMime').
// - apkHandler is used for APK archives ('apkMime').
// - archiveHandler is used for common archive formats supported by the archiver library (.zip, .tar, .gz, etc.).
// - defaultHandler is used for non-archive files.
// The selected handler is then returned, ready to handle the file according to its specific format and requirements.
func selectHandler(mimeT mimeType, isGenericArchive bool) FileHandler {
	switch mimeT {
	case arMime, unixArMime, debMime:
		return newARHandler()
	case rpmMime, cpioMime:
		return newRPMHandler()
	case apkMime:
		return newAPKHandler()
	default:
		if isGenericArchive {
			return newArchiveHandler()
		}
		return newDefaultHandler(defaultHandlerType)
	}
}

// HandleFile orchestrates the complete file handling process for a given file.
// It determines the MIME type of the file,
// selects the appropriate handler based on this type, and processes the file.
// This function initializes the handling process and delegates to the specific
// handler to manage file extraction or processing.
//
// The function will return nil (success) in the following cases:
// - If the reader is empty (ErrEmptyReader)
// - If skipArchives option is true and the file is detected as an archive
// - If all chunks are processed successfully without critical errors
//
// The function will return an error in the following cases:
// - If the reader is nil
// - If there's an error creating the file reader
// - If there's an error closing the reader
// - If a critical error occurs during chunk processing (context cancellation, deadline exceeded, or ErrProcessingFatal)
// - If there's an error reporting a chunk
//
// Non-critical errors during chunk processing are logged
// but do not cause the function to return an error.
func HandleFile(
	ctx logContext.Context,
	reader io.Reader,
	chunkSkel *sources.Chunk,
	reporter sources.ChunkReporter,
	options ...func(*fileHandlingConfig),
) error {
	if reader == nil {
		return errors.New("reader is nil")
	}

	readerOption := withFileExtension(getFileExtension(chunkSkel))
	rdr, err := newFileReader(ctx, reader, readerOption)
	if err != nil {
		if errors.Is(err, ErrEmptyReader) {
			ctx.Logger().V(5).Info("empty reader, skipping file")
			return nil
		}
		return fmt.Errorf("unable to HandleFile, error creating file reader: %w", err)
	}
	defer func() {
		// Ensure all data is read to prevent broken pipe.
		if closeErr := rdr.Close(); closeErr != nil {
			if err != nil {
				err = errors.Join(err, closeErr)
			} else {
				err = fmt.Errorf("error closing reader: %w", closeErr)
			}
		}
	}()

	ctx = logContext.WithValues(ctx, "mime", rdr.mime.String())

	mimeT := mimeType(rdr.mime.String())
	config := newFileHandlingConfig(options...)
	if config.skipArchives && rdr.isGenericArchive {
		ctx.Logger().V(5).Info("skipping archive file", "mime", mimeT)
		return nil
	}

	processingCtx, cancel := logContext.WithTimeout(ctx, maxTimeout)
	defer cancel()

	handler := selectHandler(mimeT, rdr.isGenericArchive)
	dataOrErrChan := handler.HandleFile(processingCtx, rdr) // Delegate to the specific handler to process the file.

	return handleChunksWithError(processingCtx, dataOrErrChan, chunkSkel, reporter)
}

// handleChunksWithError processes data and errors received from the dataErrChan channel.
// For each DataOrErr received:
// - If it contains data, the function creates a chunk based on chunkSkel and reports it through the reporter.
// - If it contains an error, the function handles it based on severity:
//   - Fatal errors (context cancellation, deadline exceeded, ErrProcessingFatal) cause immediate termination
//   - Non-fatal errors (ErrProcessingWarning and others) are logged and processing continues
//
// The function also listens for context cancellation to gracefully terminate processing if the context is done.
// It returns nil upon successful processing of all data, or the first encountered fatal error.
func handleChunksWithError(
	ctx logContext.Context,
	dataErrChan <-chan DataOrErr,
	chunkSkel *sources.Chunk,
	reporter sources.ChunkReporter,
) error {
	for {
		select {
		case dataOrErr, ok := <-dataErrChan:
			if !ok {
				// Channel closed, processing complete.
				ctx.Logger().V(5).Info("dataErrChan closed, all chunks processed")
				return nil
			}
			if dataOrErr.Err != nil {
				if isFatal(dataOrErr.Err) {
					return dataOrErr.Err
				}
				ctx.Logger().Error(dataOrErr.Err, "non-critical error processing chunk")
				continue
			}
			if len(dataOrErr.Data) > 0 {
				chunk := *chunkSkel
				chunk.Data = dataOrErr.Data
				reporter.ChunkOk(ctx, chunk)
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// isFatal determines whether the given error is a fatal error that should
// terminate processing the current file, or a non-critical error that can be logged and ignored.
// "Fatal" errors include context cancellation, deadline exceeded, and the
// ErrProcessingFatal error. Non-fatal errors include the ErrProcessingWarning
// error as well as any other error that is not one of the fatal errors.
func isFatal(err error) bool {
	switch {
	case errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, ErrProcessingFatal):
		return true
	case errors.Is(err, ErrProcessingWarning):
		return false
	default:
		return false
	}
}

// getFileExtension extracts the file extension from the chunk's SourceMetadata.
// It considers all sources defined in the MetaData message.
// Note: Probably should add this as a method to the source_metadatapb object.
// then it'd just be chunkSkel.SourceMetadata.GetFileExtension()
func getFileExtension(chunkSkel *sources.Chunk) string {
	if chunkSkel == nil || chunkSkel.SourceMetadata == nil {
		return ""
	}

	var fileName string

	// Inspect the SourceMetadata to determine the source type
	switch metadata := chunkSkel.SourceMetadata.Data.(type) {
	case *source_metadatapb.MetaData_Artifactory:
		fileName = metadata.Artifactory.Path
	case *source_metadatapb.MetaData_Azure:
		fileName = metadata.Azure.File
	case *source_metadatapb.MetaData_AzureRepos:
		fileName = metadata.AzureRepos.File
	case *source_metadatapb.MetaData_Bitbucket:
		fileName = metadata.Bitbucket.File
	case *source_metadatapb.MetaData_Buildkite:
		fileName = metadata.Buildkite.Link
	case *source_metadatapb.MetaData_Circleci:
		fileName = metadata.Circleci.Link
	case *source_metadatapb.MetaData_Confluence:
		fileName = metadata.Confluence.File
	case *source_metadatapb.MetaData_Docker:
		fileName = metadata.Docker.File
	case *source_metadatapb.MetaData_Ecr:
		fileName = metadata.Ecr.File
	case *source_metadatapb.MetaData_Filesystem:
		fileName = metadata.Filesystem.File
	case *source_metadatapb.MetaData_Git:
		fileName = metadata.Git.File
	case *source_metadatapb.MetaData_Github:
		fileName = metadata.Github.File
	case *source_metadatapb.MetaData_Gitlab:
		fileName = metadata.Gitlab.File
	case *source_metadatapb.MetaData_Gcs:
		fileName = metadata.Gcs.Filename
	case *source_metadatapb.MetaData_GoogleDrive:
		fileName = metadata.GoogleDrive.File
	case *source_metadatapb.MetaData_Huggingface:
		fileName = metadata.Huggingface.File
	case *source_metadatapb.MetaData_Jira:
		fileName = metadata.Jira.Link
	case *source_metadatapb.MetaData_Jenkins:
		fileName = metadata.Jenkins.Link
	case *source_metadatapb.MetaData_Npm:
		fileName = metadata.Npm.File
	case *source_metadatapb.MetaData_Pypi:
		fileName = metadata.Pypi.File
	case *source_metadatapb.MetaData_S3:
		fileName = metadata.S3.File
	case *source_metadatapb.MetaData_Slack:
		fileName = metadata.Slack.File
	case *source_metadatapb.MetaData_Sharepoint:
		fileName = metadata.Sharepoint.Link
	case *source_metadatapb.MetaData_Gerrit:
		fileName = metadata.Gerrit.File
	case *source_metadatapb.MetaData_Test:
		fileName = metadata.Test.File
	case *source_metadatapb.MetaData_Teams:
		fileName = metadata.Teams.File
	case *source_metadatapb.MetaData_TravisCI:
		fileName = metadata.TravisCI.Link
	// Add other sources if they have a file or equivalent field
	// Skipping Syslog, Forager, Postman, Vector, Webhook and Elasticsearch
	default:
		return ""
	}

	// Use filepath.Ext to extract the file extension from the file name
	ext := filepath.Ext(fileName)
	return ext
}

// shouldHandleAsAPK checks if the file should be handled as an APK based on config and MIME type.
// Note: We can't extend the mimetype package with an APK detection function b/c it would require adjusting settings
// so that all files are fully read into a byte slice for detection (mimetype.SetLimit(0)), which would bloat memory.
// Instead we call the isAPKFile function in here after ensuring it's a zip/jar file and has an .apk extension.
func shouldHandleAsAPK(cfg readerConfig, fReader fileReader) bool {
	return feature.EnableAPKHandler.Load() &&
		cfg.fileExtension == apkExt &&
		(fReader.mime.String() == string(zipMime) || fReader.mime.String() == string(jarMime))
}

func isAPKFile(r *fileReader) (bool, error) {
	size, _ := r.Size()
	zipReader, err := zip.NewReader(r, size)
	if err != nil {
		return false, fmt.Errorf("error creating zip reader: %w", err)
	}

	hasManifest := false
	hasClasses := false

	for _, file := range zipReader.File {
		switch file.Name {
		case "AndroidManifest.xml":
			hasManifest = true
		case "classes.dex":
			hasClasses = true
		default:
			// Skip other files.
		}
		if hasManifest && hasClasses {
			return true, nil
		}
	}

	return false, nil
}

// handleAPKFile configures the MIME type for an APK and resets the reader.
func handleAPKFile(fReader *fileReader) (fileReader, error) {
	// Extend the MIME type to recognize APK files
	mimetype.Lookup("application/zip").Extend(func(r []byte, l uint32) bool { return false }, string(apkMime), ".apk")
	fReader.mime = mimetype.Lookup(string(apkMime))

	// Reset reader for further handling
	if _, err := fReader.Seek(0, io.SeekStart); err != nil {
		return *fReader, fmt.Errorf("error resetting reader after APK detection: %w", err)
	}
	return *fReader, nil
}
