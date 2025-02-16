package gitparse

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-logr/logr"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	bufferwriter "github.com/trufflesecurity/trufflehog/v3/pkg/writers/buffer_writer"
	bufferedfilewriter "github.com/trufflesecurity/trufflehog/v3/pkg/writers/buffered_file_writer"
)

const (
	// defaultDateFormat is the standard date format for git.
	defaultDateFormat = "Mon Jan 2 15:04:05 2006 -0700"

	// defaultMaxDiffSize is the maximum size for a diff. Larger diffs will be cut off.
	defaultMaxDiffSize int64 = 2 * 1024 * 1024 * 1024 // 2GB

	// defaultMaxCommitSize is the maximum size for a commit. Larger commits will be cut off.
	defaultMaxCommitSize int64 = 2 * 1024 * 1024 * 1024 // 2GB
)

// contentWriter defines a common interface for writing, reading, and managing diff content.
// It abstracts the underlying storage mechanism, allowing flexibility in how content is handled.
// This interface enables the use of different content storage strategies (e.g., in-memory buffer, file-based storage)
// based on performance needs or resource constraints, providing a unified way to interact with different content types.
type contentWriter interface { // Write appends data to the content storage.
	// Write appends data to the content storage.
	Write(data []byte) (int, error)
	// ReadCloser provides a reader for accessing stored content.
	ReadCloser() (io.ReadCloser, error)
	// CloseForWriting closes the content storage for writing.
	CloseForWriting() error
	// Len returns the current size of the content.
	Len() int
	// String returns the content as a string or an error if the content cannot be converted to a string.
	String() (string, error)
}

// Diff contains the information about a file diff in a commit.
// It abstracts the underlying content representation, allowing for flexible handling of diff content.
// The use of contentWriter enables the management of diff data either in memory or on disk,
// based on its size, optimizing resource usage and performance.
type Diff struct {
	PathB     string
	LineStart int
	IsBinary  bool

	Commit *Commit

	contentWriter contentWriter
}

type diffOption func(*Diff)

// withPathB sets the PathB option.
func withPathB(pathB string) diffOption { return func(d *Diff) { d.PathB = pathB } }

// withCustomContentWriter sets the useCustomContentWriter option.
func withCustomContentWriter(cr contentWriter) diffOption {
	return func(d *Diff) { d.contentWriter = cr }
}

// newDiff creates a new Diff with a threshold and an associated commit.
// All Diffs must have an associated commit.
// The contentWriter is used to manage the diff's content, allowing for flexible handling of diff data.
// By default, a buffer is used as the contentWriter, but this can be overridden with a custom contentWriter.
func newDiff(commit *Commit, opts ...diffOption) *Diff {
	diff := &Diff{Commit: commit}
	for _, opt := range opts {
		opt(diff)
	}

	if diff.contentWriter == nil {
		diff.contentWriter = bufferwriter.New()
	}

	return diff
}

// Len returns the length of the storage.
func (d *Diff) Len() int { return d.contentWriter.Len() }

// ReadCloser returns a ReadCloser for the contentWriter.
func (d *Diff) ReadCloser() (io.ReadCloser, error) { return d.contentWriter.ReadCloser() }

// write delegates to the contentWriter.
func (d *Diff) write(p []byte) error {
	_, err := d.contentWriter.Write(p)
	return err
}

// finalize ensures proper closure of resources associated with the Diff.
// handle the final flush in the finalize method, in case there's data remaining in the buffer.
// This method should be called to release resources, especially when writing to a file.
func (d *Diff) finalize() error { return d.contentWriter.CloseForWriting() }

// Commit contains commit header info and diffs.
type Commit struct {
	Hash string
	// The source of a commit, if it doesn't exist in the repository's history.
	Source    string
	Author    string
	Committer string
	Date      time.Time
	Message   strings.Builder
	Size      int // in bytes

	hasDiffs bool
}

// Parser sets values used in GitParse.
type Parser struct {
	maxDiffSize   int64
	maxCommitSize int64
	dateFormat    string

	useCustomContentWriter bool
}

type ParseState int

const (
	Initial ParseState = iota
	CommitLine
	MergeLine
	AuthorLine
	AuthorDateLine
	CommitterLine
	CommitterDateLine
	MessageStartLine
	MessageLine
	MessageEndLine
	NotesStartLine
	NotesLine
	NotesEndLine
	DiffLine
	ModeLine
	IndexLine
	FromFileLine
	ToFileLine
	BinaryFileLine
	HunkLineNumberLine
	HunkContentLine
	ParseFailure
)

func (state ParseState) String() string {
	return [...]string{
		"Initial",
		"CommitLine",
		"MergeLine",
		"AuthorLine",
		"AuthorDateLine",
		"CommitterLine",
		"CommitterDateLine",
		"MessageStartLine",
		"MessageLine",
		"MessageEndLine",
		"NotesStartLine",
		"NotesLine",
		"NotesEndLine",
		"DiffLine",
		"ModeLine",
		"IndexLine",
		"FromFileLine",
		"ToFileLine",
		"BinaryFileLine",
		"HunkLineNumberLine",
		"HunkContentLine",
		"ParseFailure",
	}[state]
}

// UseCustomContentWriter sets useCustomContentWriter option.
func UseCustomContentWriter() Option {
	return func(parser *Parser) { parser.useCustomContentWriter = true }
}

// WithMaxDiffSize sets maxDiffSize option. Diffs larger than maxDiffSize will
// be truncated.
func WithMaxDiffSize(maxDiffSize int64) Option {
	return func(parser *Parser) {
		parser.maxDiffSize = maxDiffSize
	}
}

// WithMaxCommitSize sets maxCommitSize option. Commits larger than maxCommitSize
// will be put in the commit channel and additional diffs will be added to a
// new commit.
func WithMaxCommitSize(maxCommitSize int64) Option {
	return func(parser *Parser) {
		parser.maxCommitSize = maxCommitSize
	}
}

// Option is used for adding options to Config.
type Option func(*Parser)

// NewParser creates a GitParse config from options and sets defaults.
func NewParser(options ...Option) *Parser {
	parser := &Parser{
		dateFormat:    defaultDateFormat,
		maxDiffSize:   defaultMaxDiffSize,
		maxCommitSize: defaultMaxCommitSize,
	}
	for _, option := range options {
		option(parser)
	}
	return parser
}

// RepoPath parses the output of the `git log` command for the `source` path.
// The Diff chan will return diffs in the order they are parsed from the log.
func (c *Parser) RepoPath(
	ctx context.Context,
	source string,
	head string,
	abbreviatedLog bool,
	excludedGlobs []string,
	isBare bool,
	additionalArgs ...string,
) (chan *Diff, error) {
	args := []string{
		"-C", source,
		"--no-replace-objects",
		"log",
		"--patch", // https://git-scm.com/docs/git-log#Documentation/git-log.txt---patch
		"--full-history",
		"--date=format:%a %b %d %H:%M:%S %Y %z",
		"--pretty=fuller", // https://git-scm.com/docs/git-log#_pretty_formats
		"--notes",         // https://git-scm.com/docs/git-log#Documentation/git-log.txt---notesltrefgt
		"--source",        // https://git-scm.com/docs/git-log#Documentation/git-log.txt---source
	}
	if abbreviatedLog {
		// https://git-scm.com/docs/git-log#Documentation/git-log.txt---diff-filterACDMRTUXB82308203
		args = append(args, "--diff-filter=AM")
	}
	if head != "" {
		args = append(args, head)
	} else {
		// https://git-scm.com/docs/git-log#Documentation/git-log.txt---all
		args = append(args, "--all")
	}
	args = append(args, additionalArgs...) // These need to come before --
	for _, glob := range excludedGlobs {
		args = append(args, "--", ".", ":(exclude)"+glob)
	}

	cmd := exec.Command("git", args...)
	absPath, err := filepath.Abs(source)
	if err == nil {
		if !isBare {
			cmd.Env = append(cmd.Env, "GIT_DIR="+filepath.Join(absPath, ".git"))
		} else {
			cmd.Env = append(cmd.Env,
				"GIT_DIR="+absPath,
			)
			// We need those variables to handle incoming commits
			// while using trufflehog in pre-receive hooks
			if dir := os.Getenv("GIT_OBJECT_DIRECTORY"); dir != "" {
				cmd.Env = append(cmd.Env, "GIT_OBJECT_DIRECTORY="+dir)
			}
			if dir := os.Getenv("GIT_ALTERNATE_OBJECT_DIRECTORIES"); dir != "" {
				cmd.Env = append(cmd.Env, "GIT_ALTERNATE_OBJECT_DIRECTORIES="+dir)
			}
		}
	}

	return c.executeCommand(ctx, cmd, false)
}

// Staged parses the output of the `git diff` command for the `source` path.
func (c *Parser) Staged(ctx context.Context, source string) (chan *Diff, error) {
	// Provide the --cached flag to diff to get the diff of the staged changes.
	args := []string{"-C", source, "diff", "-p", "--cached", "--full-history", "--diff-filter=AM", "--date=format:%a %b %d %H:%M:%S %Y %z"}

	cmd := exec.Command("git", args...)

	absPath, err := filepath.Abs(source)
	if err == nil {
		cmd.Env = append(cmd.Env, "GIT_DIR="+filepath.Join(absPath, ".git"))
	}

	return c.executeCommand(ctx, cmd, true)
}

// executeCommand runs an exec.Cmd, reads stdout and stderr, and waits for the Cmd to complete.
func (c *Parser) executeCommand(ctx context.Context, cmd *exec.Cmd, isStaged bool) (chan *Diff, error) {
	diffChan := make(chan *Diff, 64)

	stdOut, err := cmd.StdoutPipe()
	if err != nil {
		return diffChan, err
	}
	stdErr, err := cmd.StderrPipe()
	if err != nil {
		return diffChan, err
	}

	err = cmd.Start()
	if err != nil {
		return diffChan, err
	}

	go func() {
		scanner := bufio.NewScanner(stdErr)
		for scanner.Scan() {
			ctx.Logger().V(2).Info(scanner.Text())
		}
	}()

	go func() {
		defer func() {
			if err := cmd.Wait(); err != nil {
				ctx.Logger().V(2).Info("Error waiting for git command to complete.", "error", err)
			}
		}()
		c.FromReader(ctx, stdOut, diffChan, isStaged)
		if err := stdOut.Close(); err != nil {
			ctx.Logger().V(2).Info("Error closing git stdout pipe.", "error", err)
		}
	}()

	return diffChan, nil
}

func (c *Parser) FromReader(ctx context.Context, stdOut io.Reader, diffChan chan *Diff, isStaged bool) {
	outReader := bufio.NewReader(stdOut)
	var (
		currentCommit *Commit
		totalLogSize  int
		latestState   = Initial
	)

	diff := func(c *Commit, opts ...diffOption) *Diff {
		opts = append(opts, withCustomContentWriter(bufferwriter.New()))
		return newDiff(c, opts...)
	}
	if c.useCustomContentWriter {
		diff = func(c *Commit, opts ...diffOption) *Diff {
			opts = append(opts, withCustomContentWriter(bufferedfilewriter.New()))
			return newDiff(c, opts...)
		}
	}
	currentDiff := diff(currentCommit)

	defer common.RecoverWithExit(ctx)
	defer close(diffChan)
	for {
		if common.IsDone(ctx) {
			break
		}

		line, err := outReader.ReadBytes([]byte("\n")[0])
		if err != nil && len(line) == 0 {
			break
		}

		switch {
		case isCommitLine(isStaged, latestState, line):
			latestState = CommitLine

			// If there is a currentDiff, add it to currentCommit.
			if currentDiff.Len() > 0 || currentDiff.IsBinary {
				if err := currentDiff.finalize(); err != nil {
					ctx.Logger().Error(
						err,
						"failed to finalize diff",
						"commit", currentCommit.Hash,
						"diff", currentDiff.PathB,
						"size", currentDiff.Len(),
						"latest_state", latestState.String(),
					)
				}
				diffChan <- currentDiff
				currentCommit.Size += currentDiff.Len()
				currentCommit.hasDiffs = true
			}
			// If there is a currentCommit, send it to the channel.
			if currentCommit != nil {
				totalLogSize += currentCommit.Size
				if !currentCommit.hasDiffs {
					// Initialize an empty Diff instance associated with the given commit.
					// Since this diff represents "no changes", we only need to set the commit.
					// This is required to ensure commits that have no diffs are still processed.
					diffChan <- &Diff{Commit: currentCommit}
				}
			}

			// Create a new currentDiff and currentCommit
			currentCommit = &Commit{Message: strings.Builder{}}
			currentDiff = diff(currentCommit)

			hash, ref := parseCommitLine(line)
			if hash == nil || ref == nil {
				ctx.Logger().Error(
					fmt.Errorf(`expected line to match 'commit <hash> <ref>', got %q`, line),
					"Failed to parse CommitLine")
				latestState = ParseFailure
				continue
			}

			currentCommit.Hash = string(hash)
			currentCommit.Source = parseSourceRef(ref)
		case isMergeLine(isStaged, latestState, line):
			latestState = MergeLine
		case isAuthorLine(isStaged, latestState, line):
			latestState = AuthorLine
			currentCommit.Author = strings.TrimSpace(string(line[8:]))
		case isAuthorDateLine(isStaged, latestState, line):
			latestState = AuthorDateLine

			date, err := time.Parse(c.dateFormat, strings.TrimSpace(string(line[12:])))
			if err != nil {
				ctx.Logger().Error(err, "failed to parse commit date", "commit", currentCommit.Hash, "latestState", latestState.String())
				latestState = ParseFailure
				continue
			}
			currentCommit.Date = date
		case isCommitterLine(isStaged, latestState, line):
			latestState = CommitterLine
			currentCommit.Committer = strings.TrimSpace(string(line[8:]))
		case isCommitterDateLine(isStaged, latestState, line):
			latestState = CommitterDateLine
			// NoOp
		case isMessageStartLine(isStaged, latestState, line):
			latestState = MessageStartLine
			// NoOp
		case isMessageLine(isStaged, latestState, line):
			latestState = MessageLine
			currentCommit.Message.Write(line[4:]) // Messages are indented by 4 spaces.

		case isMessageEndLine(isStaged, latestState, line):
			latestState = MessageEndLine
			// NoOp
		case isNotesStartLine(isStaged, latestState, line):
			latestState = NotesStartLine

			currentCommit.Message.WriteString("\n")
			currentCommit.Message.Write(line)
		case isNotesLine(isStaged, latestState, line):
			latestState = NotesLine
			currentCommit.Message.Write(line[4:]) // Notes are indented by 4 spaces.
		case isNotesEndLine(isStaged, latestState, line):
			latestState = NotesEndLine
			// NoOp
		case isDiffLine(isStaged, latestState, line):
			latestState = DiffLine

			if currentDiff.Len() > 0 || currentDiff.IsBinary {
				if err := currentDiff.finalize(); err != nil {
					ctx.Logger().Error(err,
						"failed to finalize diff",
						"commit", currentCommit.Hash,
						"diff", currentDiff.PathB,
						"size", currentDiff.Len(),
						"latest_state", latestState.String(),
					)
				}
				diffChan <- currentDiff
				currentCommit.hasDiffs = true
			}

			// This should never be nil, but check in case the stdin stream is messed up.
			if currentCommit == nil {
				currentCommit = &Commit{}
			}
			currentDiff = diff(currentCommit)
		case isModeLine(latestState, line):
			latestState = ModeLine
			// NoOp
		case isIndexLine(latestState, line):
			latestState = IndexLine
			// NoOp
		case isBinaryLine(latestState, line):
			latestState = BinaryFileLine

			path, ok := pathFromBinaryLine(line)
			if !ok {
				err = fmt.Errorf(`expected line to match 'Binary files a/fileA and b/fileB differ', got "%s"`, line)
				ctx.Logger().Error(err, "Failed to parse BinaryFileLine")
				latestState = ParseFailure
				continue
			}

			// Don't do anything if the file is deleted. (pathA has file path, pathB is /dev/null)
			if path != "" {
				currentDiff.PathB = path
				currentDiff.IsBinary = true
			}
		case isFromFileLine(latestState, line):
			latestState = FromFileLine
			// NoOp
		case isToFileLine(latestState, line):
			latestState = ToFileLine

			path, ok := pathFromToFileLine(line)
			if !ok {
				err = fmt.Errorf(`expected line to match format '+++ b/path/to/file.go', got '%s'`, line)
				ctx.Logger().Error(err, "Failed to parse ToFileLine")
				latestState = ParseFailure
				continue
			}

			currentDiff.PathB = path
		case isHunkLineNumberLine(latestState, line):
			latestState = HunkLineNumberLine

			if currentDiff.Len() > 0 || currentDiff.IsBinary {
				if err := currentDiff.finalize(); err != nil {
					ctx.Logger().Error(
						err,
						"failed to finalize diff",
						"commit", currentCommit.Hash,
						"diff", currentDiff.PathB,
						"size", currentDiff.Len(),
						"latest_state", latestState.String(),
					)
				}
				diffChan <- currentDiff
			}
			currentDiff = diff(currentCommit, withPathB(currentDiff.PathB))

			words := bytes.Split(line, []byte(" "))
			if len(words) >= 3 {
				startSlice := bytes.Split(words[2], []byte(","))
				lineStart, err := strconv.Atoi(string(startSlice[0]))
				if err == nil {
					currentDiff.LineStart = lineStart
				}
			}
		case isHunkContextLine(latestState, line):
			if latestState != HunkContentLine {
				latestState = HunkContentLine
			}
			// TODO: Why do we care about this? It creates empty lines in the diff. If there are no plusLines, it's just newlines.
			if err := currentDiff.write([]byte("\n")); err != nil {
				ctx.Logger().Error(err, "failed to write to diff")
			}
		case isHunkPlusLine(latestState, line):
			if latestState != HunkContentLine {
				latestState = HunkContentLine
			}

			if err := currentDiff.write(line[1:]); err != nil {
				ctx.Logger().Error(err, "failed to write to diff")
			}
			// NoOp. We only care about additions.
		case isHunkMinusLine(latestState, line),
			isHunkNewlineWarningLine(latestState, line),
			isHunkEmptyLine(latestState, line):
			if latestState != HunkContentLine {
				latestState = HunkContentLine
			}
			// NoOp
		case isCommitSeparatorLine(latestState, line):
			// NoOp
		default:
			// Skip ahead until we find the next diff or commit.
			if latestState == ParseFailure {
				continue
			}

			// Here be dragons...
			// Build an informative error message.
			err := fmt.Errorf(`invalid line "%s" after state "%s"`, line, latestState)
			var logger logr.Logger
			if currentCommit != nil && currentCommit.Hash != "" {
				logger = ctx.Logger().WithValues("commit", currentCommit.Hash)
			} else {
				logger = ctx.Logger()
			}
			logger.Error(err, "failed to parse Git input. Recovering at the latest commit or diff...")

			latestState = ParseFailure
		}

		if int64(currentDiff.Len()) > c.maxDiffSize {
			ctx.Logger().V(2).Info(fmt.Sprintf(
				"Diff for %s exceeded MaxDiffSize(%d)", currentDiff.PathB, c.maxDiffSize,
			))
			break
		}
	}
	cleanupParse(ctx, currentCommit, currentDiff, diffChan, &totalLogSize)

	ctx.Logger().V(2).Info("finished parsing git log.", "total_log_size", totalLogSize)
}

func isMergeLine(isStaged bool, latestState ParseState, line []byte) bool {
	if isStaged || latestState != CommitLine {
		return false
	}
	if len(line) > 6 && bytes.Equal(line[:6], []byte("Merge:")) {
		return true
	}
	return false
}

// commit 7a95bbf0199e280a0e42dbb1d1a3f56cdd0f6e05
func isCommitLine(isStaged bool, latestState ParseState, line []byte) bool {
	if isStaged || !(latestState == Initial ||
		latestState == MessageStartLine ||
		latestState == MessageEndLine ||
		latestState == ModeLine ||
		latestState == IndexLine ||
		latestState == BinaryFileLine ||
		latestState == ToFileLine ||
		latestState == HunkContentLine ||
		latestState == ParseFailure) {
		return false
	}

	if len(line) > 7 && bytes.Equal(line[:7], []byte("commit ")) {
		return true
	}
	return false
}

func parseCommitLine(line []byte) (hash []byte, ref []byte) {
	// Check that the commit line contains a 40-character hash and set it.
	// `commit e5575cd6f2d21d3a1a604287c7bf4a7eab2266e0\n`
	if len(line) >= 47 {
		hash = line[7:47]
	}

	// Check if the commit line includes branch references.
	// `commit 2dbbb28727c7c2954438666dafba57bb8c714d3b refs/heads/fix/github-enterprise-gist\n`
	if len(line) > 48 {
		ref = line[48 : len(line)-1]
	}

	return
}

// ParseCommitSource s
// https://git-scm.com/docs/git-log#Documentation/git-log.txt---source
func parseSourceRef(ref []byte) string {
	// We don't care about 'normal' refs.
	if bytes.HasPrefix(ref, []byte("refs/heads/")) || bytes.HasPrefix(ref, []byte("refs/tags/")) {
		return ""
	}

	// Handle GitHub pull requests.
	// e.g., `refs/pull/238/head` or `refs/pull/1234/merge`
	if after, ok := bytes.CutPrefix(ref, []byte("refs/pull/")); ok {
		prNumber := after[:bytes.Index(after, []byte("/"))]
		return "Pull request #" + string(prNumber)
	}

	// Handle GitLab merge requests
	// e.g., `refs/merge-requests/238/head` or `refs/merge-requests/1234/merge`
	if after, ok := bytes.CutPrefix(ref, []byte("refs/merge-requests/")); ok {
		mrNumber := after[:bytes.Index(after, []byte("/"))]
		return "Merge request #" + string(mrNumber)
	}

	return fmt.Sprintf("%s (hidden ref)", string(ref))
}

// Author: Bill Rich <bill.rich@trufflesec.com>
func isAuthorLine(isStaged bool, latestState ParseState, line []byte) bool {
	if isStaged || !(latestState == CommitLine || latestState == MergeLine) {
		return false
	}
	if len(line) > 8 && bytes.Equal(line[:7], []byte("Author:")) {
		return true
	}
	return false
}

// AuthorDate:   Tue Aug 10 15:20:40 2021 +0100
func isAuthorDateLine(isStaged bool, latestState ParseState, line []byte) bool {
	if isStaged || latestState != AuthorLine {
		return false
	}
	if len(line) > 10 && bytes.Equal(line[:11], []byte("AuthorDate:")) {
		return true
	}
	return false
}

// Commit: Bill Rich <bill.rich@trufflesec.com>
func isCommitterLine(isStaged bool, latestState ParseState, line []byte) bool {
	if isStaged || latestState != AuthorDateLine {
		return false
	}
	if len(line) > 8 && bytes.Equal(line[:7], []byte("Commit:")) {
		return true
	}
	return false
}

// CommitDate: Wed Apr 17 19:59:28 2024 -0400
func isCommitterDateLine(isStaged bool, latestState ParseState, line []byte) bool {
	if isStaged || latestState != CommitterLine {
		return false
	}
	if len(line) > 10 && bytes.Equal(line[:11], []byte("CommitDate:")) {
		return true
	}
	return false
}

// Line directly after CommitterDate with only a newline.
func isMessageStartLine(isStaged bool, latestState ParseState, line []byte) bool {
	if isStaged || latestState != CommitterDateLine {
		return false
	}
	// TODO: Improve the implementation of this and isMessageEndLine
	if len(strings.TrimRight(string(line[:]), "\r\n")) == 0 {
		return true
	}
	return false
}

// Line that starts with 4 spaces
func isMessageLine(isStaged bool, latestState ParseState, line []byte) bool {
	if isStaged || !(latestState == MessageStartLine || latestState == MessageLine) {
		return false
	}
	if len(line) > 4 && bytes.Equal(line[:4], []byte("    ")) {
		return true
	}
	return false
}

// Line directly after MessageLine with only a newline.
func isMessageEndLine(isStaged bool, latestState ParseState, line []byte) bool {
	if isStaged || latestState != MessageLine {
		return false
	}
	if len(strings.TrimRight(string(line[:]), "\r\n")) == 0 {
		return true
	}
	return false
}

// `Notes:` or `Notes (context):`
// See https://tylercipriani.com/blog/2022/11/19/git-notes-gits-coolest-most-unloved-feature/
func isNotesStartLine(isStaged bool, latestState ParseState, line []byte) bool {
	if isStaged || latestState != MessageEndLine {
		return false
	}
	if len(line) > 5 && bytes.Equal(line[:5], []byte("Notes")) {
		return true
	}
	return false
}

// Line after NotesStartLine that starts with 4 spaces
func isNotesLine(isStaged bool, latestState ParseState, line []byte) bool {
	if isStaged || !(latestState == NotesStartLine || latestState == NotesLine) {
		return false
	}
	if len(line) > 4 && bytes.Equal(line[:4], []byte("    ")) {
		return true
	}
	return false
}

// Line directly after NotesLine with only a newline.
func isNotesEndLine(isStaged bool, latestState ParseState, line []byte) bool {
	if isStaged || latestState != NotesLine {
		return false
	}
	if len(strings.TrimRight(string(line[:]), "\r\n")) == 0 {
		return true
	}
	return false
}

// diff --git a/internal/addrs/move_endpoint_module.go b/internal/addrs/move_endpoint_module.go
func isDiffLine(isStaged bool, latestState ParseState, line []byte) bool {
	if !(latestState == MessageStartLine || // Empty commit messages can go from MessageStart->Diff
		latestState == MessageEndLine ||
		latestState == NotesEndLine ||
		latestState == BinaryFileLine ||
		latestState == ModeLine ||
		latestState == IndexLine ||
		latestState == HunkContentLine ||
		latestState == ParseFailure) {
		if !(isStaged && latestState == Initial) {
			return false
		}
	}
	if len(line) > 11 && bytes.Equal(line[:11], []byte("diff --git ")) {
		return true
	}
	return false
}

// old mode 100644
// new mode 100755
// new file mode 100644
// similarity index 100%
// rename from old.txt
// rename to new.txt
// deleted file mode 100644
func isModeLine(latestState ParseState, line []byte) bool {
	if !(latestState == DiffLine || latestState == ModeLine) {
		return false
	}
	// This could probably be better written.
	if (len(line) > 17 && bytes.Equal(line[:17], []byte("deleted file mode"))) ||
		(len(line) > 16 && bytes.Equal(line[:16], []byte("similarity index"))) ||
		(len(line) > 13 && bytes.Equal(line[:13], []byte("new file mode"))) ||
		(len(line) > 11 && bytes.Equal(line[:11], []byte("rename from"))) ||
		(len(line) > 9 && bytes.Equal(line[:9], []byte("rename to"))) ||
		(len(line) > 8 && bytes.Equal(line[:8], []byte("old mode"))) ||
		(len(line) > 8 && bytes.Equal(line[:8], []byte("new mode"))) {
		return true
	}
	return false
}

// index 1ed6fbee1..aea1e643a 100644
// index 00000000..e69de29b
func isIndexLine(latestState ParseState, line []byte) bool {
	if !(latestState == DiffLine || latestState == ModeLine) {
		return false
	}
	if len(line) > 6 && bytes.Equal(line[:6], []byte("index ")) {
		return true
	}
	return false
}

// Binary files /dev/null and b/plugin.sig differ
func isBinaryLine(latestState ParseState, line []byte) bool {
	if latestState != IndexLine {
		return false
	}
	if len(line) > 7 && bytes.Equal(line[:6], []byte("Binary")) {
		return true
	}
	return false
}

// Get the b/ file path. Ignoring the edge case of files having `and /b` in the name for simplicity.
func pathFromBinaryLine(line []byte) (string, bool) {
	if bytes.Contains(line, []byte("and /dev/null")) {
		return "", true
	}

	var (
		path string
		err  error
	)
	if _, after, ok := bytes.Cut(line, []byte(" and b/")); ok {
		// drop the " differ\n"
		path = string(after[:len(after)-8])
	} else if _, after, ok = bytes.Cut(line, []byte(` and "b/`)); ok {
		// Edge case where the path is quoted.
		// https://github.com/trufflesecurity/trufflehog/issues/2384

		// Drop the `" differ\n` and handle escaped characters in the path.
		// e.g., "\342\200\224" instead of "—".
		// See https://github.com/trufflesecurity/trufflehog/issues/2418
		path, err = strconv.Unquote(`"` + string(after[:len(after)-9]) + `"`)
		if err != nil {
			return "", false
		}
	} else {
		// Unknown format.
		return "", false
	}

	return path, true
}

// --- a/internal/addrs/move_endpoint_module.go
// --- /dev/null
func isFromFileLine(latestState ParseState, line []byte) bool {
	if !(latestState == IndexLine || latestState == ModeLine) {
		return false
	}
	if len(line) >= 6 && bytes.Equal(line[:4], []byte("--- ")) {
		return true
	}
	return false
}

// +++ b/internal/addrs/move_endpoint_module.go
func isToFileLine(latestState ParseState, line []byte) bool {
	if latestState != FromFileLine {
		return false
	}
	if len(line) >= 6 && bytes.Equal(line[:4], []byte("+++ ")) {
		return true
	}
	return false
}

// Get the b/ file path.
func pathFromToFileLine(line []byte) (string, bool) {
	// Normalize paths, as they can end in `\n`, `\t\n`, etc.
	// See https://github.com/trufflesecurity/trufflehog/issues/1060
	line = bytes.TrimSpace(line)

	// File was deleted.
	if bytes.Equal(line, []byte("+++ /dev/null")) {
		return "", true
	}

	var (
		path string
		err  error
	)
	if _, after, ok := bytes.Cut(line, []byte("+++ b/")); ok {
		path = string(after)
	} else if _, after, ok = bytes.Cut(line, []byte(`+++ "b/`)); ok {
		// Edge case where the path is quoted.
		// e.g., `+++ "b/C++/1 \320\243\321\200\320\276\320\272/B.c"`

		// Drop the trailing `"` and handle escaped characters in the path
		// e.g., "\342\200\224" instead of "—".
		// See https://github.com/trufflesecurity/trufflehog/issues/2418
		path, err = strconv.Unquote(`"` + string(after[:len(after)-1]) + `"`)
		if err != nil {
			return "", false
		}
	} else {
		// Unknown format.
		return "", false
	}

	return path, true
}

// @@ -298 +298 @@ func maxRetryErrorHandler(resp *http.Response, err error, numTries int)
func isHunkLineNumberLine(latestState ParseState, line []byte) bool {
	if !(latestState == ToFileLine || latestState == HunkContentLine) {
		return false
	}
	if len(line) >= 8 && bytes.Equal(line[:2], []byte("@@")) {
		return true
	}
	return false
}

// fmt.Println("ok")
// (There's a space before `fmt` that gets removed by the formatter.)
func isHunkContextLine(latestState ParseState, line []byte) bool {
	if !(latestState == HunkLineNumberLine || latestState == HunkContentLine) {
		return false
	}
	if len(line) >= 1 && bytes.Equal(line[:1], []byte(" ")) {
		return true
	}
	return false
}

// +fmt.Println("ok")
func isHunkPlusLine(latestState ParseState, line []byte) bool {
	if !(latestState == HunkLineNumberLine || latestState == HunkContentLine) {
		return false
	}
	if len(line) >= 1 && bytes.Equal(line[:1], []byte("+")) {
		return true
	}
	return false
}

// -fmt.Println("ok")
func isHunkMinusLine(latestState ParseState, line []byte) bool {
	if !(latestState == HunkLineNumberLine || latestState == HunkContentLine) {
		return false
	}
	if len(line) >= 1 && bytes.Equal(line[:1], []byte("-")) {
		return true
	}
	return false
}

// \ No newline at end of file
func isHunkNewlineWarningLine(latestState ParseState, line []byte) bool {
	if latestState != HunkContentLine {
		return false
	}
	if len(line) >= 27 && bytes.Equal(line[:27], []byte("\\ No newline at end of file")) {
		return true
	}
	return false
}

// Newline after hunk, or an empty line, e.g.
// +}
//
// commit 00920984e3435057f09cee5468850f7546dfa637 (tag: v3.42.0)
func isHunkEmptyLine(latestState ParseState, line []byte) bool {
	if !(latestState == HunkLineNumberLine || latestState == HunkContentLine) {
		return false
	}
	// TODO: Can this also be `\n\r`?
	if len(line) == 1 && bytes.Equal(line[:1], []byte("\n")) {
		return true
	}
	return false
}

func isCommitSeparatorLine(latestState ParseState, line []byte) bool {
	if (latestState == ModeLine || latestState == IndexLine || latestState == BinaryFileLine || latestState == ToFileLine) &&
		len(line) == 1 && bytes.Equal(line[:1], []byte("\n")) {
		return true
	}
	return false
}

func cleanupParse(ctx context.Context, currentCommit *Commit, currentDiff *Diff, diffChan chan *Diff, totalLogSize *int) {
	if err := currentDiff.finalize(); err != nil {
		ctx.Logger().Error(err, "failed to finalize diff")
		return
	}

	// Ignore empty or binary diffs (this condition may be redundant).
	if currentDiff != nil && (currentDiff.Len() > 0 || currentDiff.IsBinary) {
		currentDiff.Commit = currentCommit
		diffChan <- currentDiff
	}
	if currentCommit != nil {
		if totalLogSize != nil {
			*totalLogSize += currentCommit.Size
		}
	}
}
