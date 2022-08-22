package gitparse

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// DateFormat is the standard date format for git.
const DateFormat = "Mon Jan 02 15:04:05 2006 -0700"

// Commit contains commit header info and diffs.
type Commit struct {
	Hash    string
	Author  string
	Date    time.Time
	Message strings.Builder
	Diffs   []Diff
}

// Diff contains the info about a file diff in a commit.
type Diff struct {
	PathA     string
	PathB     string
	LineStart int
	Content   bytes.Buffer
	IsBinary  bool
}

// RepoPath parses the output of the `git log` command for the `source` path.
func RepoPath(source string, head string) (chan Commit, error) {
	commitChan := make(chan Commit)

	args := []string{"-C", source, "log", "-p", "-U0", "--full-history", "--diff-filter=AM", "--date=format:%a %b %d %H:%M:%S %Y %z"}
	if head != "" {
		args = append(args, head)
	} else {
		args = append(args, "--all")
	}

	cmd := exec.Command("git", args...)

	absPath, err := filepath.Abs(source)
	if err == nil {
		cmd.Env = append(cmd.Env, fmt.Sprintf("GIT_DIR=%s", filepath.Join(absPath, ".git")))
	}

	stdOut, err := cmd.StdoutPipe()
	if err != nil {
		return commitChan, err
	}
	// stdErr, err := cmd.StderrPipe()
	// if err != nil {
	// 	return commitChan, err
	// }

	err = cmd.Start()
	if err != nil {
		return commitChan, err
	}

	//errReader := bufio.NewReader(stdErr)
	outReader := bufio.NewReader(stdOut)
	var currentCommit *Commit
	var currentDiff *Diff

	go func() {
		for {
			/*
				errLine, _, err := errReader.ReadLine()
				if err != nil && !errors.Is(err, io.EOF) {
					log.WithError(err).Debug("Could not read stderr.")
				}
				log.WithError(fmt.Errorf(string(errLine))).Debug("Error received from git command.")
			*/
		}
	}()

	go func() {
		for {
			line, err := outReader.ReadBytes([]byte("\n")[0])
			if err != nil && len(line) == 0 {
				break
			}
			switch {
			case isCommitLine(line):
				// If there is a currentDiff, add it to currentCommit.
				if currentDiff != nil {
					currentCommit.Diffs = append(currentCommit.Diffs, *currentDiff)
				}
				// If there is a currentCommit, send it to the channel.
				if currentCommit != nil {
					commitChan <- *currentCommit
				}
				// Create a new currentDiff and currentCommit
				currentDiff = &Diff{}
				currentCommit = &Commit{
					Message: strings.Builder{},
				}
				// Check that the commit line contains a hash and set it.
				if len(line) >= 47 {
					currentCommit.Hash = string(line[7:47])
				}
			case isAuthorLine(line):
				currentCommit.Author = string(line[8:])
			case isDateLine(line):
				date, err := time.Parse(DateFormat, strings.TrimSpace(string(line[6:])))
				if err != nil {
					log.WithError(err).Debug("Could not parse date from git stream.")
				}
				currentCommit.Date = date
			case isDiffLine(line):
				// This should never be nil, but check in case the stdin stream is messed up.
				if currentDiff != nil {
					currentCommit.Diffs = append(currentCommit.Diffs, *currentDiff)
				}
				currentDiff = &Diff{}
			case isModeLine(line):
				// NoOp
			case isIndexLine(line):
				// NoOp
			case isPlusFileLine(line):
				currentDiff.PathB = strings.TrimRight(string(line[6:]), "\n")
			case isMinusFileLine(line):
				currentDiff.PathA = strings.TrimRight(string(line[6:]), "\n")
			case isPlusDiffLine(line):
				currentDiff.Content.Write(line[1:])
			case isMinusDiffLine(line):
				// NoOp. We only care about additions.
			case isMessageLine(line):
				currentCommit.Message.Write(line[4:])
			case isBinaryLine(line):
				currentDiff.IsBinary = true
				currentDiff.PathB = pathFromBinaryLine(line)
			}

		}
		if currentDiff != nil && currentDiff.Content.Len() > 0 {
			currentCommit.Diffs = append(currentCommit.Diffs, *currentDiff)
		}
		if currentCommit != nil {
			commitChan <- *currentCommit
		}
		cmd.Wait()
		close(commitChan)
	}()
	return commitChan, nil
}

// Date:   Tue Aug 10 15:20:40 2021 +0100
func isDateLine(line []byte) bool {
	if len(line) > 7 && bytes.Equal(line[:5], []byte("Date:")) {
		return true
	}
	return false
}

// Author: Bill Rich <bill.rich@trufflesec.com>
func isAuthorLine(line []byte) bool {
	if len(line) > 8 && bytes.Equal(line[:7], []byte("Author:")) {
		return true
	}
	return false
}

// commit 7a95bbf0199e280a0e42dbb1d1a3f56cdd0f6e05
func isCommitLine(line []byte) bool {
	if len(line) > 7 && bytes.Equal(line[:6], []byte("commit")) {
		return true
	}
	return false
}

// diff --git a/internal/addrs/move_endpoint_module.go b/internal/addrs/move_endpoint_module.go
func isDiffLine(line []byte) bool {
	if len(line) > 5 && bytes.Equal(line[:4], []byte("diff")) {
		return true
	}
	return false
}

// index 1ed6fbee1..aea1e643a 100644
func isIndexLine(line []byte) bool {
	if len(line) > 6 && bytes.Equal(line[:5], []byte("index")) {
		return true
	}
	return false
}

// new file mode 100644
func isModeLine(line []byte) bool {
	if len(line) > 13 && bytes.Equal(line[:13], []byte("new file mode")) {
		return true
	}
	return false
}

// --- a/internal/addrs/move_endpoint_module.go
func isMinusFileLine(line []byte) bool {
	if len(line) > 3 && bytes.Equal(line[:3], []byte("---")) {
		return true
	}
	return false
}

// +++ b/internal/addrs/move_endpoint_module.go
func isPlusFileLine(line []byte) bool {
	if len(line) > 3 && bytes.Equal(line[:3], []byte("+++")) {
		return true
	}
	return false
}

// +fmt.Println("ok")
func isPlusDiffLine(line []byte) bool {
	if len(line) >= 1 && bytes.Equal(line[:1], []byte("+")) {
		return true
	}
	return false
}

// -fmt.Println("ok")
func isMinusDiffLine(line []byte) bool {
	if len(line) >= 1 && bytes.Equal(line[:1], []byte("-")) {
		return true
	}
	return false
}

// Line that starts with 4 spaces
func isMessageLine(line []byte) bool {
	if len(line) > 4 && bytes.Equal(line[:4], []byte("    ")) {
		return true
	}
	return false
}

// Binary files /dev/null and b/plugin.sig differ
func isBinaryLine(line []byte) bool {
	if len(line) > 7 && bytes.Equal(line[:6], []byte("Binary")) {
		return true
	}
	return false
}

// Get the b/ file path.
func pathFromBinaryLine(line []byte) string {
	sbytes := bytes.Split(line, []byte(" and "))
	if len(sbytes) != 2 {
		log.Debugf("Expected binary line to be in 'Binary files a/filaA and b/fileB differ' format. Got: %s", line)
		return ""
	}
	bRaw := sbytes[1]
	return string(bRaw[2 : len(bRaw)-7]) // drop the "b/" and " differ"
}
