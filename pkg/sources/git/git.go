package git

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	diskbufferreader "github.com/bill-rich/disk-buffer-reader"
	"github.com/go-errors/errors"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/google/go-github/v42/github"
	"github.com/rs/zerolog"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"golang.org/x/sync/semaphore"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/gitparse"
	"github.com/trufflesecurity/trufflehog/v3/pkg/handlers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sanitizer"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

type Source struct {
	name     string
	sourceId int64
	jobId    int64
	verify   bool
	git      *Git
	aCtx     context.Context
	sources.Progress
	conn *sourcespb.Git
}

type Git struct {
	sourceType         sourcespb.SourceType
	sourceName         string
	sourceID           int64
	jobID              int64
	sourceMetadataFunc func(file, email, commit, timestamp, repository string, line int64) *source_metadatapb.MetaData
	verify             bool
	concurrency        *semaphore.Weighted
}

func NewGit(sourceType sourcespb.SourceType, jobID, sourceID int64, sourceName string, verify bool, concurrency int,
	sourceMetadataFunc func(file, email, commit, timestamp, repository string, line int64) *source_metadatapb.MetaData,
) *Git {
	return &Git{
		sourceType:         sourceType,
		sourceName:         sourceName,
		sourceID:           sourceID,
		jobID:              jobID,
		sourceMetadataFunc: sourceMetadataFunc,
		verify:             verify,
		concurrency:        semaphore.NewWeighted(int64(concurrency)),
	}
}

// Ensure the Source satisfies the interface at compile time.
var _ sources.Source = (*Source)(nil)

// Type returns the type of source.
// It is used for matching source types in configuration and job input.
func (s *Source) Type() sourcespb.SourceType {
	return sourcespb.SourceType_SOURCE_TYPE_GIT
}

func (s *Source) SourceID() int64 {
	return s.sourceId
}

func (s *Source) JobID() int64 {
	return s.jobId
}

// Init returns an initialized GitHub source.
func (s *Source) Init(aCtx context.Context, name string, jobId, sourceId int64, verify bool, connection *anypb.Any, concurrency int) error {

	s.aCtx = aCtx
	s.name = name
	s.sourceId = sourceId
	s.jobId = jobId
	s.verify = verify

	var conn sourcespb.Git
	if err := anypb.UnmarshalTo(connection, &conn, proto.UnmarshalOptions{}); err != nil {
		return errors.WrapPrefix(err, "error unmarshalling connection", 0)
	}

	s.conn = &conn

	if concurrency == 0 {
		concurrency = runtime.NumCPU()
	}

	s.git = NewGit(s.Type(), s.jobId, s.sourceId, s.name, s.verify, concurrency,
		func(file, email, commit, timestamp, repository string, line int64) *source_metadatapb.MetaData {
			return &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_Git{
					Git: &source_metadatapb.Git{
						Commit:     sanitizer.UTF8(commit),
						File:       sanitizer.UTF8(file),
						Email:      sanitizer.UTF8(email),
						Repository: sanitizer.UTF8(repository),
						Timestamp:  sanitizer.UTF8(timestamp),
						Line:       line,
					},
				},
			}
		})
	return nil
}

// Chunks emits chunks of bytes over a channel.
func (s *Source) Chunks(ctx context.Context, chunksChan chan *sources.Chunk) error {
	// TODO: refactor to remove duplicate code
	switch cred := s.conn.GetCredential().(type) {
	case *sourcespb.Git_BasicAuth:
		user := cred.BasicAuth.Username
		token := cred.BasicAuth.Password

		for i, repoURI := range s.conn.Repositories {
			s.SetProgressComplete(i, len(s.conn.Repositories), fmt.Sprintf("Repo: %s", repoURI), "")
			if len(repoURI) == 0 {
				continue
			}
			err := func(repoURI string) error {
				path, repo, err := CloneRepoUsingToken(token, repoURI, user)
				defer os.RemoveAll(path)
				if err != nil {
					return err
				}
				return s.git.ScanRepo(ctx, repo, path, NewScanOptions(), chunksChan)
			}(repoURI)
			if err != nil {
				return err
			}
		}
	case *sourcespb.Git_Unauthenticated:
		for i, repoURI := range s.conn.Repositories {
			s.SetProgressComplete(i, len(s.conn.Repositories), fmt.Sprintf("Repo: %s", repoURI), "")
			if len(repoURI) == 0 {
				continue
			}
			err := func(repoURI string) error {
				path, repo, err := CloneRepoUsingUnauthenticated(repoURI)
				defer os.RemoveAll(path)
				if err != nil {
					return err
				}
				return s.git.ScanRepo(ctx, repo, path, NewScanOptions(), chunksChan)
			}(repoURI)
			if err != nil {
				return err
			}
		}
	case *sourcespb.Git_SshAuth:
		for i, repoURI := range s.conn.Repositories {
			s.SetProgressComplete(i, len(s.conn.Repositories), fmt.Sprintf("Repo: %s", repoURI), "")
			if len(repoURI) == 0 {
				continue
			}
			err := func(repoURI string) error {
				path, repo, err := CloneRepoUsingSSH(repoURI)
				defer os.RemoveAll(path)
				if err != nil {
					return err
				}
				return s.git.ScanRepo(ctx, repo, path, NewScanOptions(), chunksChan)
			}(repoURI)
			if err != nil {
				return err
			}
		}
	default:
		return errors.New("invalid connection type for git source")
	}

	for i, u := range s.conn.Directories {
		s.SetProgressComplete(i, len(s.conn.Repositories), fmt.Sprintf("Repo: %s", u), "")

		if len(u) == 0 {
			continue
		}
		if !strings.HasSuffix(u, "git") {
			// try paths instead of url
			repo, err := RepoFromPath(u)
			if err != nil {
				return err
			}

			err = func(repoPath string) error {
				if strings.HasPrefix(repoPath, filepath.Join(os.TempDir(), "trufflehog")) {
					defer os.RemoveAll(repoPath)
				}

				return s.git.ScanRepo(ctx, repo, repoPath, NewScanOptions(), chunksChan)
			}(u)
			if err != nil {
				return err
			}
		}

	}
	s.SetProgressComplete(len(s.conn.Repositories), len(s.conn.Repositories), fmt.Sprintf("Completed scanning source %s", s.name), "")
	return nil
}

func RepoFromPath(path string) (*git.Repository, error) {
	return git.PlainOpen(path)
}

func CleanOnError(err *error, path string) {
	if *err != nil {
		os.RemoveAll(path)
	}
}

func gitURLParse(gitURL string) (*url.URL, error) {
	parsedURL, originalError := url.Parse(gitURL)
	if originalError != nil {
		var err error
		gitURLBytes := []byte("ssh://" + gitURL)
		colonIndex := bytes.LastIndex(gitURLBytes, []byte(":"))
		gitURLBytes[colonIndex] = byte('/')
		parsedURL, err = url.Parse(string(gitURLBytes))
		if err != nil {
			return nil, originalError
		}
	}
	return parsedURL, nil
}

func CloneRepo(userInfo *url.Userinfo, gitUrl string, args ...string) (clonePath string, repo *git.Repository, err error) {
	if err = GitCmdCheck(); err != nil {
		return
	}
	clonePath, err = ioutil.TempDir(os.TempDir(), "trufflehog")
	if err != nil {
		err = errors.New(err)
		return
	}
	defer CleanOnError(&err, clonePath)
	cloneURL, err := gitURLParse(gitUrl)
	if err != nil {
		return "", nil, err
	}
	if cloneURL.User == nil {
		cloneURL.User = userInfo
	}

	gitArgs := []string{"clone", cloneURL.String(), clonePath}
	gitArgs = append(gitArgs, args...)
	cloneCmd := exec.Command("git", gitArgs...)

	output, err := cloneCmd.CombinedOutput()
	if err != nil {
		err = errors.WrapPrefix(err, "error running 'git clone'", 0)
	}

	if cloneCmd.ProcessState == nil {
		return "", nil, errors.New("clone command exited with no output")
	}
	if cloneCmd.ProcessState != nil && cloneCmd.ProcessState.ExitCode() != 0 {
		safeUrl, err := stripPassword(gitUrl)
		if err != nil {
			log.WithError(err).Errorf("failed to strip credentials from git url")
		}
		log.WithField("exit_code", cloneCmd.ProcessState.ExitCode()).WithField("repo", safeUrl).WithField("output", string(output)).Errorf("failed to clone repo")
		return "", nil, fmt.Errorf("could not clone repo: %s", safeUrl)
	}
	repo, err = git.PlainOpen(clonePath)
	if err != nil {
		err = errors.WrapPrefix(err, "could not open cloned repo", 0)
		return
	}
	log.WithField("clone_path", clonePath).WithField("repo", gitUrl).Debug("cloned repo")
	return
}

// CloneRepoUsingToken clones a repo using a provided token.
func CloneRepoUsingToken(token, gitUrl, user string, args ...string) (string, *git.Repository, error) {
	userInfo := url.UserPassword(user, token)
	return CloneRepo(userInfo, gitUrl, args...)
}

// CloneRepoUsingUnauthenticated clones a repo with no authentication required.
func CloneRepoUsingUnauthenticated(url string, args ...string) (string, *git.Repository, error) {
	return CloneRepo(nil, url, args...)
}

// CloneRepoUsingUnauthenticated clones a repo with no authentication required.
func CloneRepoUsingSSH(gitUrl string, args ...string) (string, *git.Repository, error) {
	userInfo := url.User("git")
	return CloneRepo(userInfo, gitUrl, args...)
}

func GitCmdCheck() error {
	if errors.Is(exec.Command("git").Run(), exec.ErrNotFound) {
		return fmt.Errorf("'git' command not found in $PATH. Make sure git is installed and included in $PATH")
	}
	return nil
}

func (s *Git) ScanCommits(ctx context.Context, repo *git.Repository, path string, scanOptions *ScanOptions, chunksChan chan *sources.Chunk) error {
	if err := GitCmdCheck(); err != nil {
		return err
	}
	if log.GetLevel() < log.DebugLevel {
		zerolog.SetGlobalLevel(zerolog.Disabled)
	}

	commitChan, err := gitparse.RepoPath(ctx, path, scanOptions.HeadHash)
	if err != nil {
		return err
	}
	if commitChan == nil {
		return nil
	}

	// get the URL metadata for reporting (may be empty)
	urlMetadata := getSafeRemoteURL(repo, "origin")

	var depth int64
	var reachedBase = false
	log.WithField("repo", urlMetadata).Debugf("Scanning repo")
	for commit := range commitChan {
		log.Tracef("Scanning commit %s", commit.Hash)
		if scanOptions.MaxDepth > 0 && depth >= scanOptions.MaxDepth {
			log.Debugf("reached max depth")
			break
		}
		depth++
		if reachedBase && commit.Hash != scanOptions.BaseHash {
			break
		}
		if len(scanOptions.BaseHash) > 0 {
			if commit.Hash == scanOptions.BaseHash {
				log.Debugf("Reached base commit. Finishing scanning files.")
				reachedBase = true
			}
		}
		for _, diff := range commit.Diffs {
			log.WithField("commit", commit.Hash).WithField("file", diff.PathB).Trace("Scanning file from git")

			if !scanOptions.Filter.Pass(diff.PathB) {
				continue
			}

			fileName := diff.PathB
			if fileName == "" {
				continue
			}
			var email, hash, when string
			email = commit.Author
			hash = commit.Hash
			when = commit.Date.String()

			// Handle binary files by reading the entire file rather than using the diff.
			if diff.IsBinary {
				commitHash := plumbing.NewHash(hash)
				metadata := s.sourceMetadataFunc(fileName, email, hash, when, urlMetadata, 0)
				chunkSkel := &sources.Chunk{
					SourceName:     s.sourceName,
					SourceID:       s.sourceID,
					SourceType:     s.sourceType,
					SourceMetadata: metadata,
					Verify:         s.verify,
				}
				if err := handleBinary(ctx, repo, chunksChan, chunkSkel, commitHash, fileName); err != nil {
					log.WithError(err).WithField("file", fileName).Debug("Error handling binary file")
				}
				continue
			}

			if diff.Content.Len() > sources.ChunkSize+sources.PeekSize {
				s.gitChunk(diff, fileName, email, hash, when, urlMetadata, chunksChan)
				continue
			}
			metadata := s.sourceMetadataFunc(fileName, email, hash, when, urlMetadata, int64(diff.LineStart))
			chunksChan <- &sources.Chunk{
				SourceName:     s.sourceName,
				SourceID:       s.sourceID,
				SourceType:     s.sourceType,
				SourceMetadata: metadata,
				Data:           diff.Content.Bytes(),
				Verify:         s.verify,
			}
		}
	}
	return nil
}

func (s *Git) gitChunk(diff gitparse.Diff, fileName, email, hash, when, urlMetadata string, chunksChan chan *sources.Chunk) {
	originalChunk := bufio.NewScanner(&diff.Content)
	newChunkBuffer := bytes.Buffer{}
	lastOffset := 0
	for offset := 0; originalChunk.Scan(); offset++ {
		line := originalChunk.Bytes()
		if len(line) > sources.ChunkSize || len(line)+newChunkBuffer.Len() > sources.ChunkSize {
			// Add oversize chunk info
			if newChunkBuffer.Len() > 0 {
				// Send the existing fragment.
				metadata := s.sourceMetadataFunc(fileName, email, hash, when, urlMetadata, int64(diff.LineStart+lastOffset))
				chunksChan <- &sources.Chunk{
					SourceName:     s.sourceName,
					SourceID:       s.sourceID,
					SourceType:     s.sourceType,
					SourceMetadata: metadata,
					Data:           append([]byte{}, newChunkBuffer.Bytes()...),
					Verify:         s.verify,
				}
				newChunkBuffer.Reset()
				lastOffset = offset
			}
			if len(line) > sources.ChunkSize {
				// Send the oversize line.
				metadata := s.sourceMetadataFunc(fileName, email, hash, when, urlMetadata, int64(diff.LineStart+offset))
				chunksChan <- &sources.Chunk{
					SourceName:     s.sourceName,
					SourceID:       s.sourceID,
					SourceType:     s.sourceType,
					SourceMetadata: metadata,
					Data:           line,
					Verify:         s.verify,
				}
				continue
			}
		}

		_, err := newChunkBuffer.Write(line)
		if err != nil {
			log.WithError(err).Error("Could not write line to git diff buffer.")
		}
	}
	// Send anything still in the new chunk buffer
	if newChunkBuffer.Len() > 0 {
		metadata := s.sourceMetadataFunc(fileName, email, hash, when, urlMetadata, int64(diff.LineStart+lastOffset))
		chunksChan <- &sources.Chunk{
			SourceName:     s.sourceName,
			SourceID:       s.sourceID,
			SourceType:     s.sourceType,
			SourceMetadata: metadata,
			Data:           append([]byte{}, newChunkBuffer.Bytes()...),
			Verify:         s.verify,
		}
	}
}

// ScanUnstaged chunks unstaged changes.
func (s *Git) ScanUnstaged(ctx context.Context, repo *git.Repository, path string, scanOptions *ScanOptions, chunksChan chan *sources.Chunk) error {
	// get the URL metadata for reporting (may be empty)
	urlMetadata := getSafeRemoteURL(repo, "origin")

	commitChan, err := gitparse.Unstaged(ctx, path)
	if err != nil {
		return err
	}
	if commitChan == nil {
		return nil
	}

	var depth int64
	var reachedBase = false
	log.Debugf("Scanning repo")
	for commit := range commitChan {
		for _, diff := range commit.Diffs {
			log.WithField("commit", commit.Hash).WithField("file", diff.PathB).Trace("Scanning file from git")
			if scanOptions.MaxDepth > 0 && depth >= scanOptions.MaxDepth {
				log.Debugf("reached max depth")
				break
			}
			depth++
			if reachedBase && commit.Hash != scanOptions.BaseHash {
				break
			}
			if len(scanOptions.BaseHash) > 0 {
				if commit.Hash == scanOptions.BaseHash {
					log.Debugf("Reached base commit. Finishing scanning files.")
					reachedBase = true
				}
			}

			if !scanOptions.Filter.Pass(diff.PathB) {
				continue
			}

			fileName := diff.PathB
			if fileName == "" {
				continue
			}
			var email, hash, when string
			email = commit.Author
			hash = commit.Hash
			when = commit.Date.String()

			// Handle binary files by reading the entire file rather than using the diff.
			if diff.IsBinary {
				commitHash := plumbing.NewHash(hash)
				metadata := s.sourceMetadataFunc(fileName, email, "Unstaged", when, urlMetadata, 0)
				chunkSkel := &sources.Chunk{
					SourceName:     s.sourceName,
					SourceID:       s.sourceID,
					SourceType:     s.sourceType,
					SourceMetadata: metadata,
					Verify:         s.verify,
				}
				if err := handleBinary(ctx, repo, chunksChan, chunkSkel, commitHash, fileName); err != nil {
					log.WithError(err).WithField("file", fileName).Debug("Error handling binary file")
				}
				continue
			}

			metadata := s.sourceMetadataFunc(fileName, email, "Unstaged", when, urlMetadata, int64(diff.LineStart))
			chunksChan <- &sources.Chunk{
				SourceName:     s.sourceName,
				SourceID:       s.sourceID,
				SourceType:     s.sourceType,
				SourceMetadata: metadata,
				Data:           diff.Content.Bytes(),
				Verify:         s.verify,
			}
		}
	}
	return nil
}

func (s *Git) ScanRepo(ctx context.Context, repo *git.Repository, repoPath string, scanOptions *ScanOptions, chunksChan chan *sources.Chunk) error {
	if err := normalizeConfig(scanOptions, repo); err != nil {
		return err
	}
	start := time.Now().UnixNano()
	if err := s.ScanCommits(ctx, repo, repoPath, scanOptions, chunksChan); err != nil {
		return err
	}
	if err := s.ScanUnstaged(ctx, repo, repoPath, scanOptions, chunksChan); err != nil {
		log.WithError(err).Error("Error scanning unstaged changes")
	}
	scanTime := time.Now().UnixNano() - start
	log.Debugf("Scanning complete. Scan time: %f", time.Duration(scanTime).Seconds())
	return nil
}

func normalizeConfig(scanOptions *ScanOptions, repo *git.Repository) (err error) {
	var baseCommit *object.Commit
	if len(scanOptions.BaseHash) > 0 {
		baseHash := plumbing.NewHash(scanOptions.BaseHash)
		if !plumbing.IsHash(scanOptions.BaseHash) {
			base, err := TryAdditionalBaseRefs(repo, scanOptions.BaseHash)
			if err != nil {
				return errors.WrapPrefix(err, "unable to resolve base ref", 0)
			}
			scanOptions.BaseHash = base.String()
			baseCommit, _ = repo.CommitObject(plumbing.NewHash(scanOptions.BaseHash))
		} else {
			baseCommit, err = repo.CommitObject(baseHash)
			if err != nil {
				return errors.WrapPrefix(err, "unable to resolve base ref", 0)
			}
		}
	}

	var headCommit *object.Commit
	if len(scanOptions.HeadHash) > 0 {
		headHash := plumbing.NewHash(scanOptions.HeadHash)
		if !plumbing.IsHash(scanOptions.HeadHash) {
			head, err := TryAdditionalBaseRefs(repo, scanOptions.HeadHash)
			if err != nil {
				return errors.WrapPrefix(err, "unable to resolve head ref", 0)
			}
			scanOptions.HeadHash = head.String()
			headCommit, _ = repo.CommitObject(plumbing.NewHash(scanOptions.HeadHash))
		} else {
			headCommit, err = repo.CommitObject(headHash)
			if err != nil {
				return errors.WrapPrefix(err, "unable to resolve head ref", 0)
			}
		}
	}

	// If baseCommit is an ancestor of headCommit, update c.BaseRef to be the common ancestor.
	if headCommit != nil && baseCommit != nil {
		mergeBase, err := headCommit.MergeBase(baseCommit)
		if err != nil || len(mergeBase) < 1 {
			return errors.WrapPrefix(err, "could not find common base between the given references", 0)
		}
		scanOptions.BaseHash = mergeBase[0].Hash.String()
	}

	return nil
}

// GenerateLink crafts a link to the specific file from a commit. This works in most major git providers (Github/Gitlab)
func GenerateLink(repo, commit, file string) string {
	// bitbucket links are commits not commit...
	if strings.Contains(repo, "bitbucket.org/") {
		return repo[:len(repo)-4] + "/commits/" + commit
	}
	link := repo[:len(repo)-4] + "/blob/" + commit + "/" + file

	if file == "" {
		link = repo[:len(repo)-4] + "/commit/" + commit
	}
	return link
}

func stripPassword(u string) (string, error) {
	if strings.HasPrefix(u, "git@") {
		return u, nil
	}

	repoURL, err := url.Parse(u)
	if err != nil {
		return "", errors.WrapPrefix(err, "repo remote cannot be sanitized as URI", 0)
	}

	repoURL.User = nil

	return repoURL.String(), nil
}

// TryAdditionalBaseRefs looks for additional possible base refs for a repo and returns a hash if found.
func TryAdditionalBaseRefs(repo *git.Repository, base string) (*plumbing.Hash, error) {
	revisionPrefixes := []string{
		"",
		"refs/heads/",
		"refs/remotes/origin/",
	}
	for _, prefix := range revisionPrefixes {
		outHash, err := repo.ResolveRevision(plumbing.Revision(prefix + base))
		if err == plumbing.ErrReferenceNotFound {
			continue
		}
		if err != nil {
			return nil, err
		}
		return outHash, nil
	}

	return nil, fmt.Errorf("no base refs succeeded for base: %q", base)
}

// PrepareRepoSinceCommit clones a repo starting at the given commitHash and returns the cloned repo path.
func PrepareRepoSinceCommit(uriString, commitHash string) (string, bool, error) {
	if commitHash == "" {
		return PrepareRepo(uriString)
	}
	// TODO: refactor with PrepareRepo to remove duplicated logic

	// The git CLI doesn't have an option to shallow clone starting at a commit
	// hash, but it does have an option to shallow clone since a timestamp. If
	// the uriString is github.com, then we query the API for the timestamp of the
	// hash and use that to clone.

	uri, err := gitURLParse(uriString)
	if err != nil {
		return "", false, fmt.Errorf("unable to parse Git URI: %s", err)
	}

	if uri.Scheme == "file" || uri.Host != "github.com" {
		return PrepareRepo(uriString)
	}

	uriPath := strings.TrimPrefix(uri.Path, "/")
	owner, repoName, found := strings.Cut(uriPath, "/")
	if !found {
		return PrepareRepo(uriString)
	}

	client := github.NewClient(nil)
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		ts := oauth2.StaticTokenSource(
			&oauth2.Token{AccessToken: token},
		)
		tc := oauth2.NewClient(context.TODO(), ts)
		client = github.NewClient(tc)
	}

	commit, _, err := client.Git.GetCommit(context.Background(), owner, repoName, commitHash)
	if err != nil {
		return PrepareRepo(uriString)
	}
	var timestamp string
	{
		author := commit.GetAuthor()
		if author == nil {
			return PrepareRepo(uriString)
		}
		timestamp = author.GetDate().Format(time.RFC3339)
	}

	remotePath := uri.String()
	var path string
	switch {
	case uri.User != nil:
		log.Debugf("Cloning remote Git repo with authentication")
		password, ok := uri.User.Password()
		if !ok {
			return "", true, fmt.Errorf("password must be included in Git repo URL when username is provided")
		}
		path, _, err = CloneRepoUsingToken(password, remotePath, uri.User.Username(), "--shallow-since", timestamp)
		if err != nil {
			return path, true, fmt.Errorf("failed to clone authenticated Git repo (%s): %s", remotePath, err)
		}
	default:
		log.Debugf("Cloning remote Git repo without authentication")
		path, _, err = CloneRepoUsingUnauthenticated(remotePath, "--shallow-since", timestamp)
		if err != nil {
			return path, true, fmt.Errorf("failed to clone unauthenticated Git repo (%s): %s", remotePath, err)
		}
	}
	log.Debugf("Git repo local path: %s", path)
	return path, true, nil
}

// PrepareRepo clones a repo if possible and returns the cloned repo path.
func PrepareRepo(uriString string) (string, bool, error) {
	var path string
	uri, err := gitURLParse(uriString)
	if err != nil {
		return "", false, fmt.Errorf("unable to parse Git URI: %s", err)
	}

	remote := false
	switch uri.Scheme {
	case "file":
		path = fmt.Sprintf("%s%s", uri.Host, uri.Path)
	case "http", "https":
		remotePath := uri.String()
		remote = true
		switch {
		case uri.User != nil:
			log.Debugf("Cloning remote Git repo with authentication")
			password, ok := uri.User.Password()
			if !ok {
				return "", remote, fmt.Errorf("password must be included in Git repo URL when username is provided")
			}
			path, _, err = CloneRepoUsingToken(password, remotePath, uri.User.Username())
			if err != nil {
				return path, remote, fmt.Errorf("failed to clone authenticated Git repo (%s): %s", remotePath, err)
			}
		default:
			log.Debugf("Cloning remote Git repo without authentication")
			path, _, err = CloneRepoUsingUnauthenticated(remotePath)
			if err != nil {
				return path, remote, fmt.Errorf("failed to clone unauthenticated Git repo (%s): %s", remotePath, err)
			}
		}
	case "ssh":
		remotePath := uri.String()
		remote = true
		path, _, err = CloneRepoUsingSSH(remotePath)
		if err != nil {
			return path, remote, fmt.Errorf("failed to clone unauthenticated Git repo (%s): %s", remotePath, err)
		}
	default:
		return "", remote, fmt.Errorf("unsupported Git URI: %s", uriString)
	}
	log.Debugf("Git repo local path: %s", path)
	return path, remote, nil
}

// getSafeRemoteURL is a helper function that will attempt to get a safe URL first
// from the preferred remote name, falling back to the first remote name
// available, or an empty string if there are no remotes.
func getSafeRemoteURL(repo *git.Repository, preferred string) string {
	remote, err := repo.Remote(preferred)
	if err != nil {
		var remotes []*git.Remote
		if remotes, err = repo.Remotes(); err != nil {
			return ""
		}
		if len(remotes) == 0 {
			return ""
		}
		remote = remotes[0]
	}
	// URLs is guaranteed to be non-empty
	safeURL, err := stripPassword(remote.Config().URLs[0])
	if err != nil {
		return ""
	}
	return safeURL
}

func handleBinary(ctx context.Context, repo *git.Repository, chunksChan chan *sources.Chunk, chunkSkel *sources.Chunk, commitHash plumbing.Hash, path string) error {
	log.WithField("path", path).Trace("Binary file found in repository.")
	commit, err := repo.CommitObject(commitHash)
	if err != nil {
		return err
	}

	file, err := commit.File(path)
	if err != nil {
		return err
	}

	fileReader, err := file.Reader()
	if err != nil {
		return err
	}
	defer fileReader.Close()

	reader, err := diskbufferreader.New(fileReader)
	if err != nil {
		return err
	}

	if handlers.HandleFile(ctx, reader, chunkSkel, chunksChan) {
		return nil
	}

	log.WithField("path", path).Trace("Binary file is not recognized by file handlers. Chunking raw.")
	if err := reader.Reset(); err != nil {
		return err
	}
	reader.Stop()

	chunkData, err := io.ReadAll(reader)
	if err != nil {
		return err
	}

	chunk := *chunkSkel
	chunk.Data = chunkData
	chunksChan <- &chunk

	return nil
}
