package gitparse

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/process"
	bufferwriter "github.com/trufflesecurity/trufflehog/v3/pkg/writers/buffer_writer"
	bufferedfilewriter "github.com/trufflesecurity/trufflehog/v3/pkg/writers/buffered_file_writer"
)

type testCaseLine struct {
	latestState ParseState
	line        []byte
}

func TestLineChecksWithStaged(t *testing.T) {
	type testCase struct {
		passes   []testCaseLine
		fails    []testCaseLine
		function func(bool, ParseState, []byte) bool
	}

	tests := map[string]testCase{
		"commitLine": {
			passes: []testCaseLine{
				{
					Initial,
					[]byte("commit 15c6105be1a18eeed1247478340dca69d02196ed"),
				},
				{
					ModeLine,
					[]byte("commit 7bd16429f1f708746dabf970e54b05d2b4734997 (HEAD -> master)\n"),
				},
				{
					IndexLine,
					[]byte("commit 9d60549cea17c830df3f99398993e8f6fd154468"),
				},
				{
					MessageStartLine,
					[]byte("commit 4727ffb7ad6dc5130bf4b4dd166e00705abdd018"),
				},
				{
					MessageEndLine,
					[]byte("commit 2a057632d7f5fa3d1c77b9aa037263211c0e0290"),
				},
				{
					HunkContentLine,
					[]byte("commit b38857edb46bd0e2c86db53615ff469aa7b7966b (HEAD -> feat/git-diff-parse, origin/main, origin/HEAD, main)"),
				},
				{
					BinaryFileLine,
					[]byte("commit fb76eaf17b2b923bcc3e59314cf3605bce9a8bcd (tag: v3.40.0)"),
				},
			},
			fails: []testCaseLine{
				{
					Initial,
					[]byte(`fatal: ambiguous argument 'branch_2..branch_1': unknown revision or path not in the working tree.
					Use '--' to separate paths from revisions, like this:
					'git <command> [<revision>...] -- [<file>...]'`),
				},
				{
					CommitLine,
					[]byte("commit 15c6105be1a18eeed1247478340dca69d02196ed"),
				},
			},
			function: isCommitLine,
		},
		"mergeLine": {
			passes: []testCaseLine{
				{
					CommitLine,
					[]byte("Merge: f21a95535a2 ed08d10bcf5"),
				},
			},
			fails: []testCaseLine{
				{
					CommitterDateLine,
					[]byte("    Merge pull request #34511 from cescoffier/duplicated-context-doc"),
				},
				{
					CommitLine,
					[]byte("notcorrect"),
				},
			},
			function: isMergeLine,
		},
		"authorLine": {
			passes: []testCaseLine{
				{
					CommitLine,
					[]byte("Author: Zachary Rice <zachary.rice@trufflesec.com>"),
				},
				{
					CommitLine,
					[]byte("Author: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>"),
				},
			},
			fails: []testCaseLine{
				{
					CommitLine,
					[]byte("Date:   Tue Jun 20 13:55:31 2023 -0500"),
				},
				{
					AuthorLine,
					[]byte("Author: Bill Rich <bill.rich@trufflesec.com>"),
				},
			},
			function: isAuthorLine,
		},
		"authorDateLine": {
			passes: []testCaseLine{
				{
					AuthorLine,
					[]byte("AuthorDate:   Tue Jan 18 16:59:18 2022 -0800"),
				},
			},
			fails: []testCaseLine{
				{
					AuthorDateLine,
					[]byte(""),
				},
				{
					AuthorLine,
					[]byte("notcorrect"),
				},
			},
			function: isAuthorDateLine,
		},
		"committerLine": {
			passes: []testCaseLine{
				{
					AuthorDateLine,
					[]byte("Commit: Zachary Rice <zachary.rice@trufflesec.com>"),
				},
				{
					AuthorDateLine,
					[]byte("Commit: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>"),
				},
			},
			fails: []testCaseLine{
				{
					CommitLine,
					[]byte("Date:   Tue Jun 20 13:55:31 2023 -0500"),
				},
				{
					AuthorLine,
					[]byte("Author: Bill Rich <bill.rich@trufflesec.com>"),
				},
			},
			function: isCommitterLine,
		},
		"committerDateLine": {
			passes: []testCaseLine{
				{
					CommitterLine,
					[]byte("CommitDate:   Tue Jan 18 16:59:18 2022 -0800"),
				},
			},
			fails: []testCaseLine{
				{
					CommitterDateLine,
					[]byte(""),
				},
				{
					CommitterLine,
					[]byte("notcorrect"),
				},
			},
			function: isCommitterDateLine,
		},
		"messageStartLine": {
			passes: []testCaseLine{
				{
					CommitterDateLine,
					[]byte(""),
				},
			},
			fails: []testCaseLine{
				{
					AuthorLine,
					[]byte("Date:   Tue Jun 20 13:21:19 2023 -0700"),
				},
				{
					CommitterDateLine,
					[]byte("notcorrect"),
				},
			},
			function: isMessageStartLine,
		},
		"messageLine": {
			passes: []testCaseLine{
				{
					MessageStartLine,
					[]byte("    Initial docs and release automation (#5)"),
				},
				{
					MessageLine,
					[]byte("    Bump github.com/googleapis/gax-go/v2 from 2.10.0 to 2.11.0 (#1406)"),
				},
			},
			fails: []testCaseLine{
				{
					AuthorLine,
					[]byte("Date:   Tue Jun 20 13:21:19 2023 -0700"),
				},
				{
					CommitterDateLine,
					[]byte("notcorrect"),
				},
			},
			function: isMessageLine,
		},
		"messageEndLine": {
			passes: []testCaseLine{
				{
					MessageLine,
					[]byte(""),
				},
			},
			fails: []testCaseLine{
				{
					MessageStartLine,
					[]byte("    Initial commit"),
				},
				{
					MessageLine,
					[]byte("notcorrect"),
				},
			},
			function: isMessageEndLine,
		},
		"notesStartLine": {
			passes: []testCaseLine{
				{
					MessageEndLine,
					[]byte("Notes:"),
				},
				{
					MessageEndLine,
					[]byte("Notes (review):"),
				},
			},
			fails: []testCaseLine{
				{
					MessageStartLine,
					[]byte(""),
				},
				{
					MessageEndLine,
					[]byte("notcorrect"),
				},
			},
			function: isNotesStartLine,
		},
		"notesLine": {
			passes: []testCaseLine{
				{
					NotesStartLine,
					[]byte("    Submitted-by: Random J Developer <random@developer.example.org>"),
				},
			},
			fails: []testCaseLine{
				{
					MessageEndLine,
					[]byte(""),
				},
				{
					MessageEndLine,
					[]byte("notcorrect"),
				},
			},
			function: isNotesLine,
		},
		"notesEndLine": {
			passes: []testCaseLine{
				{
					NotesLine,
					[]byte("\n"),
				},
			},
			fails: []testCaseLine{
				{
					MessageEndLine,
					[]byte("\n"),
				},
				{
					NotesLine,
					[]byte("notcorrect"),
				},
			},
			function: isNotesEndLine,
		},
		"diffLine": {
			passes: []testCaseLine{
				{
					MessageEndLine,
					[]byte("diff --git a/pkg/sources/source_unit.go b/pkg/sources/source_unit.go"),
				},
				{
					MessageEndLine,
					[]byte("diff --git a/ Lunch and Learn - HCDiag.pdf b/ Lunch and Learn - HCDiag.pdf"),
				},
				{
					NotesEndLine,
					[]byte("diff --git \"a/one.txt\" \"b/one.txt\""),
				},
				{
					BinaryFileLine,
					[]byte("diff --git a/pkg/decoders/utf16_test.go b/pkg/decoders/utf16_test.go"),
				},
				{
					HunkContentLine,
					[]byte("diff --git a/pkg/decoders/utf8.go b/pkg/decoders/utf8.go"),
				},
				{
					ModeLine,
					[]byte("diff --git a/pkg/decoders/utf8.go b/pkg/decoders/utf8.go"),
				},
			},
			fails: []testCaseLine{
				{
					CommitterDateLine,
					[]byte("    Make trace error message so newlines aren't escaped (#1396)"),
				},
				{
					MessageLine,
					[]byte("notcorrect"),
				},
				{
					NotesLine,
					[]byte("diff --git a/pkg/decoders/utf8.go b/pkg/decoders/utf8.go"),
				},
			},
			function: isDiffLine,
		},
	}

	for name, test := range tests {
		for _, pass := range test.passes {
			if !test.function(false, pass.latestState, pass.line) {
				t.Errorf("%s: Parser did not recognize correct line. (%s)", name, string(pass.line))
			}
		}
		for _, fail := range test.fails {
			if test.function(false, fail.latestState, fail.line) {
				t.Errorf("%s: Parser did not recognize incorrect line. (%s)", name, string(fail.line))
			}
		}
	}
}

func TestLineChecksNoStaged(t *testing.T) {
	type testCase struct {
		passes   []testCaseLine
		fails    []testCaseLine
		function func(ParseState, []byte) bool
	}

	tests := map[string]testCase{
		"modeLine": {
			passes: []testCaseLine{
				{
					DiffLine,
					[]byte("old mode 100644"),
				},
				{
					ModeLine,
					[]byte("new mode 100755"),
				},
				{
					DiffLine,
					[]byte("new file mode 100644"),
				},
				{
					DiffLine,
					[]byte("similarity index 100%"),
				},
				{
					ModeLine,
					[]byte("rename from old.txt"),
				},
				{
					ModeLine,
					[]byte("rename to new.txt"),
				},
				{
					DiffLine,
					[]byte("deleted file mode 100644"),
				},
			},
			fails: []testCaseLine{
				{
					MessageLine,
					[]byte("diff --git a/pkg/common/recover.go b/pkg/common/recover.go"),
				},
				{
					DiffLine,
					[]byte("notcorrect"),
				},
			},
			function: isModeLine,
		},
		"indexLine": {
			passes: []testCaseLine{
				{
					DiffLine,
					[]byte("index 0a7a5b4..7682212 100644"),
				},
				{
					ModeLine,
					[]byte("index 1ed6fbee1..aea1e643a 100644"),
				},
				{
					ModeLine,
					[]byte("index 00000000..e69de29b"),
				},
			},
			fails: []testCaseLine{
				{
					MessageLine,
					[]byte("diff --git a/pkg/sources/gitlab/gitlab.go b/pkg/sources/gitlab/gitlab.go"),
				},
				{
					DiffLine,
					[]byte("notcorrect"),
				},
			},
			function: isIndexLine,
		},
		"binaryLine": {
			passes: []testCaseLine{
				{
					IndexLine,
					[]byte("Binary files /dev/null and b/plugin.sig differ"),
				},
				{
					IndexLine,
					[]byte("Binary files /dev/null and b/ Lunch and Learn - HCDiag.pdf differ"),
				},
			},
			fails: []testCaseLine{
				{
					DiffLine,
					[]byte("index eb54cf4f..00000000"),
				},
				{
					IndexLine,
					[]byte("notcorrect"),
				},
			},
			function: isBinaryLine,
		},
		"fromFileLine": {
			passes: []testCaseLine{
				{
					IndexLine,
					[]byte("--- a/internal/addrs/move_endpoint_module.go"),
				},
				{
					IndexLine,
					[]byte("--- /dev/null"),
				},
				// New file (https://github.com/trufflesecurity/trufflehog/issues/2109)
				// diff --git a/libs/Unfit-1.0 b/libs/Unfit-1.0
				// new file mode 160000
				{
					ModeLine,
					[]byte("--- /dev/null"),
				},
				// Uncommon but valid prefixes. Will these ever show up?
				// https://stackoverflow.com/a/2530012
				// https://git-scm.com/docs/git-config#Documentation/git-config.txt-diffmnemonicPrefix
				{
					IndexLine,
					[]byte("--- i/pkg/sources/filesystem/filesystem.go"),
				},
				{
					IndexLine,
					[]byte("--- w/pkg/sources/gcs/gcs.go"),
				},
				{
					IndexLine,
					[]byte("--- c/pkg/sources/git/git.go"),
				},
				{
					IndexLine,
					[]byte("--- o/pkg/sources/github/github.go"),
				},
			},
			fails: []testCaseLine{
				{
					ModeLine,
					[]byte("index 00000000..05370a3c"),
				},
				{
					IndexLine,
					[]byte("notcorrect"),
				},
			},
			function: isFromFileLine,
		},
		"toFileLine": {
			passes: []testCaseLine{
				{
					FromFileLine,
					[]byte("+++ a/internal/addrs/move_endpoint_module.go"),
				},
				{
					FromFileLine,
					[]byte("+++ /dev/null"),
				},
				// Uncommon but valid prefixes. Will these ever show up?
				// https://stackoverflow.com/a/2530012
				// https://git-scm.com/docs/git-config#Documentation/git-config.txt-diffmnemonicPrefix
				{
					FromFileLine,
					[]byte("+++ i/pkg/sources/filesystem/filesystem.go"),
				},
				{
					FromFileLine,
					[]byte("+++ w/pkg/sources/gcs/gcs.go"),
				},
				{
					FromFileLine,
					[]byte("+++ c/pkg/sources/git/git.go"),
				},
				{
					FromFileLine,
					[]byte("+++ o/pkg/sources/github/github.go"),
				},
			},
			fails: []testCaseLine{
				{
					IndexLine,
					[]byte("--- a/pkg/detectors/shortcut/shortcut_test.go"),
				},
				{
					FromFileLine,
					[]byte("notcorrect"),
				},
				{
					HunkContentLine,
					[]byte("+++ The application will interface with REDACTED and REDACTED (REDACTED team)"),
				},
			},
			function: isToFileLine,
		},
		"lineNumberLine": {
			passes: []testCaseLine{
				{
					ToFileLine,
					[]byte("@@ -298 +298 @@ func maxRetryErrorHandler(resp *http.Response, err error, numTries int)"),
				},
				{
					HunkContentLine,
					[]byte("@@ -121 +121 @@ require ("),
				},
			},
			fails: []testCaseLine{
				{
					FromFileLine,
					[]byte("+++ b/Dockerfile"),
				},
				{
					ToFileLine,
					[]byte("notcorrect"),
				},
			},
			function: isHunkLineNumberLine,
		},
		"hunkContextLine": {
			passes: []testCaseLine{
				{
					HunkLineNumberLine,
					[]byte(" fmt.Println"),
				},
				{
					HunkContentLine,
					[]byte("        ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)"),
				},
			},
			fails: []testCaseLine{
				{
					ToFileLine,
					[]byte("@@ -176 +176 @@ require ("),
				},
				{
					HunkLineNumberLine,
					[]byte("+import ("),
				},
			},
			function: isHunkContextLine,
		},
		"hunkPlusLine": {
			passes: []testCaseLine{
				{
					HunkLineNumberLine,
					[]byte("+       github.com/googleapis/enterprise-certificate-proxy v0.2.5 // indirect"),
				},
				{
					HunkContentLine,
					[]byte("+cloud.google.com/go/storage v1.31.0/go.mod h1:81ams1PrhW16L4kF7qg+4mTq7SRs5HsbDTM0bWvrwJ0="),
				},
			},
			fails: []testCaseLine{
				{
					ToFileLine,
					[]byte("@@ -176 +176 @@ require ("),
				},
				{
					HunkLineNumberLine,
					[]byte("-import ("),
				},
				{
					HunkLineNumberLine,
					[]byte("notcorrect"),
				},
			},
			function: isHunkPlusLine,
		},
		"hunkMinusLine": {
			passes: []testCaseLine{
				{
					HunkLineNumberLine,
					[]byte("-fmt.Println"),
				},
				{
					HunkContentLine,
					[]byte(`-       return []string{"sql", "database", "Data Source"}`),
				},
			},
			fails: []testCaseLine{
				{
					ToFileLine,
					[]byte("@@ -176 +176 @@ require ("),
				},
				{
					HunkLineNumberLine,
					[]byte("+import ("),
				},
				{
					HunkLineNumberLine,
					[]byte("notcorrect"),
				},
			},
			function: isHunkMinusLine,
		},
		"hunkNewlineWarningLine": {
			passes: []testCaseLine{
				{
					HunkContentLine,
					[]byte("\\ No newline at end of file"),
				},
			},
			fails: []testCaseLine{
				{
					ToFileLine,
					[]byte("@@ -176 +176 @@ require ("),
				},
				{
					HunkContentLine,
					[]byte(" \\ No newline at end of file is the current error"),
				},
			},
			function: isHunkNewlineWarningLine,
		},
		"hunkEmptyLine": {
			passes: []testCaseLine{
				{
					HunkContentLine,
					[]byte("\n"),
				},
			},
			fails: []testCaseLine{
				{
					HunkLineNumberLine,
					[]byte(`               return "", errors.WrapPrefix(err, "repo remote cannot be sanitized as URI", 0)`),
				},
				{
					HunkContentLine,
					[]byte(" \n"),
				},
			},
			function: isHunkEmptyLine,
		},
	}

	for name, test := range tests {
		for _, pass := range test.passes {
			if !test.function(pass.latestState, pass.line) {
				t.Errorf("%s: Parser did not recognize correct line. (%s)", name, string(pass.line))
			}
		}
		for _, fail := range test.fails {
			if test.function(fail.latestState, fail.line) {
				t.Errorf("%s: Parser did not recognize incorrect line. (%s)", name, string(fail.line))
			}
		}
	}
}

func Test_parseCommitLine(t *testing.T) {
	cases := map[string][]string{
		"commit 198c63cb8212a99cc4352bc72f25e5444a786291 refs/heads/main\n":                       {"198c63cb8212a99cc4352bc72f25e5444a786291", "refs/heads/main"},
		"commit e76dfb98ab9001daa869191b6aebe8cf4cd3b22a refs/remotes/origin/debug/aws-logging\n": {"e76dfb98ab9001daa869191b6aebe8cf4cd3b22a", "refs/remotes/origin/debug/aws-logging"},
	}

	for line, expected := range cases {
		hash, ref := parseCommitLine([]byte(line))
		if string(hash) != expected[0] {
			t.Errorf("Expected: %s, Got: %s", expected[0], hash)
		}
		if string(ref) != expected[1] {
			t.Errorf("Expected: %s, Got: %s", expected[1], ref)
		}
	}
}

func Test_parseSourceRef(t *testing.T) {
	cases := map[string]string{
		"refs/heads/master": "",
		"refs/tags/v3.0.5":  "",
		// refs/merge-requests/33/head
		"refs/heads/thog/mr/33/head": "Merge request #33",
		// refs/merge-requests/19/merge
		"refs/heads/thog/mr/19/merge": "Merge request #19",
		// refs/pull/980/head
		"refs/heads/thog/pr/980/head": "Pull request #980",
		// refs/pull/1644/merge
		"refs/heads/thog/pr/1644/merge": "Pull request #1644",
	}

	for line, expected := range cases {
		source := parseSourceRef([]byte(line))
		if source != expected {
			t.Errorf("Expected: %s, Got: %s", expected, source)
		}
	}
}

func TestBinaryPathParse(t *testing.T) {
	cases := map[string]string{
		"Binary files a/trufflehog_3.42.0_linux_arm64.tar.gz and /dev/null differ\n":                                                                                         "",
		"Binary files /dev/null and b/plugin.sig differ\n":                                                                                                                   "plugin.sig",
		"Binary files /dev/null and b/ Lunch and Learn - HCDiag.pdf differ\n":                                                                                                " Lunch and Learn - HCDiag.pdf",
		"Binary files /dev/null and \"b/assets/retailers/ON-ikony-Platforma-ecom \\342\\200\\224 kopia.png\" differ\n":                                                       "assets/retailers/ON-ikony-Platforma-ecom — kopia.png",
		"Binary files /dev/null and \"b/\\346\\267\\261\\345\\272\\246\\345\\255\\246\\344\\271\\240500\\351\\227\\256-Tan-00\\347\\233\\256\\345\\275\\225.docx\" differ\n": "深度学习500问-Tan-00目录.docx",
	}

	for name, expected := range cases {
		filename, ok := pathFromBinaryLine([]byte(name))
		if !ok {
			t.Errorf("Failed to get path: %s", name)
		}
		if filename != expected {
			t.Errorf("Expected: %s, Got: %s", expected, filename)
		}
	}
}

func TestToFileLinePathParse(t *testing.T) {
	cases := map[string]string{
		"+++ /dev/null\n":      "",
		"+++ b/embeds.xml\t\n": "embeds.xml",
		"+++ \"b/C++/1 \\320\\243\\321\\200\\320\\276\\320\\272/B.c\"\t\n": "C++/1 Урок/B.c",
	}

	for name, expected := range cases {
		filename, ok := pathFromToFileLine([]byte(name))
		if !ok {
			t.Errorf("Failed to get path: %s", name)
		}
		if filename != expected {
			t.Errorf("Expected: %s, Got: %s", expected, filename)
		}
	}
}

// Equal compares the content of two Commits to determine if they are the same.
func (d1 *Diff) Equal(ctx context.Context, d2 *Diff) bool {
	// isEqualString handles the error-prone String() method calls and compares the results.
	isEqualContentString := func(s1, s2 contentWriter) (bool, error) {
		// If the content is nil, it's likely a binary so there won't be any content to compare.
		if s1.Len() == 0 && s2.Len() == 0 {
			return true, nil
		}

		str1, err := s1.String()
		if err != nil {
			return false, err
		}
		str2, err := s2.String()
		if err != nil {
			return false, err
		}
		return str1 == str2, nil
	}

	switch {
	case d1.PathB != d2.PathB:
		return false
	case d1.Commit.Hash != d2.Commit.Hash:
		return false
	case d1.Commit.Author != d2.Commit.Author:
		return false
	case d1.Commit.Date != d2.Commit.Date:
		return false
	case d1.Commit.Message.String() != d2.Commit.Message.String():
		return false
	case d1.LineStart != d2.LineStart:
		return false
	case d1.IsBinary != d2.IsBinary:
		return false
	default:
		if d1.contentWriter != nil && d2.contentWriter != nil {
			equal, err := isEqualContentString(d1.contentWriter, d2.contentWriter)
			if err != nil || !equal {
				ctx.Logger().Error(err, "failed to compare diff content")
				return false
			}
		}
	}
	return true
}

func TestCommitParsing(t *testing.T) {
	expected := expectedDiffs()

	beforeProcesses := process.GetGitProcessList()

	r := bytes.NewReader([]byte(commitLog))
	diffChan := make(chan *Diff)
	parser := NewParser()
	go func() {
		parser.FromReader(context.Background(), r, diffChan, false)
	}()
	i := 0
	for diff := range diffChan {
		if len(expected) <= i {
			t.Errorf("Missing expected case for commit: %+v", diff)
			break
		}

		if !diff.Equal(context.Background(), expected[i]) {
			t.Errorf("Diff does not match.\nexpected: %+v\n%s\nactual  : %+v\n%s", expected[i], expected[i].Commit.Hash, diff, diff.Commit.Hash)
		}
		i++
	}

	afterProcesses := process.GetGitProcessList()
	zombies := process.DetectGitZombies(beforeProcesses, afterProcesses)

	if len(zombies) > 0 {
		t.Errorf("Detected %d zombie git processes: %v", len(zombies), zombies)
	}
}

func newBufferedFileWriterWithContent(content []byte) *bufferedfilewriter.BufferedFileWriter {
	b := bufferedfilewriter.New()
	_, err := b.Write(content) // Using Write method to add content
	if err != nil {
		panic(err)
	}
	return b
}

func newBufferWithContent(content []byte) *bufferwriter.BufferWriter {
	b := bufferwriter.New()
	_, _ = b.Write(content) // Using Write method to add content
	return b
}

func TestStagedDiffParsing(t *testing.T) {
	expected := []*Diff{
		{
			PathB:     "aws",
			LineStart: 1,
			Commit: &Commit{
				Hash:    "",
				Author:  "",
				Date:    newTime("0001-01-01 00:00:00 +0000 UTC"),
				Message: strings.Builder{},
			},
			contentWriter: newBufferWithContent([]byte("[default]\naws_access_key_id = AKIAXYZDQCEN4B6JSJQI\naws_secret_access_key = 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\noutput = json\nregion = us-east-2\n")),
			IsBinary:      false,
		},
		{
			PathB:     "aws2",
			LineStart: 1,
			Commit: &Commit{
				Hash:    "",
				Author:  "",
				Date:    newTime("0001-01-01 00:00:00 +0000 UTC"),
				Message: strings.Builder{},
			},
			contentWriter: newBufferWithContent([]byte("\n\nthis is the secret: [Default]\nAccess key Id: AKIAILE3JG6KMS3HZGCA\nSecret Access Key: 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\n\nokay thank you bye\n")),
			IsBinary:      false,
		},
		{
			PathB:     "core/runtime/src/main/java/io/quarkus/runtime/QuarkusApplication.java",
			LineStart: 3,
			Commit: &Commit{
				Hash:    "",
				Author:  "",
				Date:    newTime("0001-01-01 00:00:00 +0000 UTC"),
				Message: strings.Builder{},
			},
			contentWriter: newBufferWithContent([]byte("/**\n * This is usually used for command mode applications with a startup logic. The logic is executed inside\n * {@link QuarkusApplication#run} method before the main application exits.\n */\n")),
			IsBinary:      false,
		},
		{
			PathB:    "trufflehog_3.42.0_linux_arm64.tar.gz",
			IsBinary: true,
			Commit: &Commit{
				Hash:    "",
				Author:  "",
				Date:    newTime("0001-01-01 00:00:00 +0000 UTC"),
				Message: strings.Builder{},
			},
			contentWriter: newBufferWithContent(nil),
		},
		{
			PathB:     "tzu",
			LineStart: 11,
			Commit: &Commit{
				Hash:    "",
				Author:  "",
				Date:    newTime("0001-01-01 00:00:00 +0000 UTC"),
				Message: strings.Builder{},
			},
			contentWriter: newBufferWithContent([]byte("\n\n\n\nSource: https://www.gnu.org/software/diffutils/manual/diffutils.html#An-Example-of-Unified-Format\n")),
			IsBinary:      false,
		},
		{
			PathB:     "lao",
			LineStart: 1,
			Commit: &Commit{
				Hash:    "",
				Author:  "",
				Date:    newTime("0001-01-01 00:00:00 +0000 UTC"),
				Message: strings.Builder{},
			},
			contentWriter: newBufferWithContent([]byte("The Way that can be told of is not the eternal Way;\nThe name that can be named is not the eternal name.\nThe Nameless is the origin of Heaven and Earth;\nThe Named is the mother of all things.\nTherefore let there always be non-being,\n  so we may see their subtlety,\nAnd let there always be being,\n  so we may see their outcome.\nThe two are the same,\nBut after they are produced,\n  they have different names.\n")),
			IsBinary:      false,
		},
		{
			PathB:     "tzu",
			LineStart: 1,
			Commit: &Commit{
				Hash:    "",
				Author:  "",
				Date:    newTime("0001-01-01 00:00:00 +0000 UTC"),
				Message: strings.Builder{},
			},
			contentWriter: newBufferWithContent([]byte("The Nameless is the origin of Heaven and Earth;\nThe named is the mother of all things.\n\nTherefore let there always be non-being,\n  so we may see their subtlety,\nAnd let there always be being,\n  so we may see their outcome.\nThe two are the same,\nBut after they are produced,\n  they have different names.\nThey both may be called deep and profound.\nDeeper and more profound,\nThe door of all subtleties!\n")),
			IsBinary:      false,
		},
	}

	r := bytes.NewReader([]byte(stagedDiffs))
	diffChan := make(chan *Diff)
	parser := NewParser()
	go func() {
		parser.FromReader(context.Background(), r, diffChan, true)
	}()
	i := 0
	for diff := range diffChan {
		if len(expected) <= i {
			t.Errorf("Missing expected case for commit: %+v", diff)
			break
		}

		if !diff.Equal(context.Background(), expected[i]) {
			t.Errorf("Diff does not match.\nexpected:\n%+v\n\nactual:\n%+v\n", expected[i], diff)
		}
		i++
	}
}

func TestStagedDiffParsingBufferedFileWriter(t *testing.T) {
	expected := []*Diff{
		{
			PathB:     "aws",
			LineStart: 1,
			Commit: &Commit{
				Hash:    "",
				Author:  "",
				Date:    newTime("0001-01-01 00:00:00 +0000 UTC"),
				Message: strings.Builder{},
			},
			contentWriter: newBufferedFileWriterWithContent([]byte("[default]\naws_access_key_id = AKIAXYZDQCEN4B6JSJQI\naws_secret_access_key = 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\noutput = json\nregion = us-east-2\n")),
			IsBinary:      false,
		},
		{
			PathB:     "aws2",
			LineStart: 1,
			Commit: &Commit{
				Hash:    "",
				Author:  "",
				Date:    newTime("0001-01-01 00:00:00 +0000 UTC"),
				Message: strings.Builder{},
			},
			contentWriter: newBufferedFileWriterWithContent([]byte("\n\nthis is the secret: [Default]\nAccess key Id: AKIAILE3JG6KMS3HZGCA\nSecret Access Key: 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\n\nokay thank you bye\n")),
			IsBinary:      false,
		},
		{
			PathB:     "core/runtime/src/main/java/io/quarkus/runtime/QuarkusApplication.java",
			LineStart: 3,
			Commit: &Commit{
				Hash:    "",
				Author:  "",
				Date:    newTime("0001-01-01 00:00:00 +0000 UTC"),
				Message: strings.Builder{},
			},
			contentWriter: newBufferedFileWriterWithContent([]byte("/**\n * This is usually used for command mode applications with a startup logic. The logic is executed inside\n * {@link QuarkusApplication#run} method before the main application exits.\n */\n")),
			IsBinary:      false,
		},
		{
			PathB:    "trufflehog_3.42.0_linux_arm64.tar.gz",
			IsBinary: true,
			Commit: &Commit{
				Hash:    "",
				Author:  "",
				Date:    newTime("0001-01-01 00:00:00 +0000 UTC"),
				Message: strings.Builder{},
			},
			contentWriter: newBufferedFileWriterWithContent(nil),
		},
		{
			PathB:     "tzu",
			LineStart: 11,
			Commit: &Commit{
				Hash:    "",
				Author:  "",
				Date:    newTime("0001-01-01 00:00:00 +0000 UTC"),
				Message: strings.Builder{},
			},
			contentWriter: newBufferedFileWriterWithContent([]byte("\n\n\n\nSource: https://www.gnu.org/software/diffutils/manual/diffutils.html#An-Example-of-Unified-Format\n")),
			IsBinary:      false,
		},
		{
			PathB:     "lao",
			LineStart: 1,
			Commit: &Commit{
				Hash:    "",
				Author:  "",
				Date:    newTime("0001-01-01 00:00:00 +0000 UTC"),
				Message: strings.Builder{},
			},
			contentWriter: newBufferedFileWriterWithContent([]byte("The Way that can be told of is not the eternal Way;\nThe name that can be named is not the eternal name.\nThe Nameless is the origin of Heaven and Earth;\nThe Named is the mother of all things.\nTherefore let there always be non-being,\n  so we may see their subtlety,\nAnd let there always be being,\n  so we may see their outcome.\nThe two are the same,\nBut after they are produced,\n  they have different names.\n")),
			IsBinary:      false,
		},
		{
			PathB:     "tzu",
			LineStart: 1,
			Commit: &Commit{
				Hash:    "",
				Author:  "",
				Date:    newTime("0001-01-01 00:00:00 +0000 UTC"),
				Message: strings.Builder{},
			},
			contentWriter: newBufferedFileWriterWithContent([]byte("The Nameless is the origin of Heaven and Earth;\nThe named is the mother of all things.\n\nTherefore let there always be non-being,\n  so we may see their subtlety,\nAnd let there always be being,\n  so we may see their outcome.\nThe two are the same,\nBut after they are produced,\n  they have different names.\nThey both may be called deep and profound.\nDeeper and more profound,\nThe door of all subtleties!\n")),
			IsBinary:      false,
		},
	}

	r := bytes.NewReader([]byte(stagedDiffs))
	diffChan := make(chan *Diff)
	parser := NewParser()
	go func() {
		parser.FromReader(context.Background(), r, diffChan, true)
	}()
	i := 0
	for diff := range diffChan {
		if len(expected) <= i {
			t.Errorf("Missing expected case for commit: %+v", diff)
			break
		}

		if !diff.Equal(context.Background(), expected[i]) {
			t.Errorf("Diff does not match.\nexpected:\n%+v\n\nactual:\n%+v\n", expected[i], diff)
		}
		i++
	}
}

func TestCommitParseFailureRecovery(t *testing.T) {
	expected := []*Diff{
		{
			PathB:     ".travis.yml",
			LineStart: 1,
			Commit: &Commit{
				Hash:      "df393b4125c2aa217211b2429b8963d0cefcee27",
				Author:    "Stephen <stephen@egroat.com>",
				Committer: "Stephen <stephen@egroat.com>",
				Date:      newTime("Wed Dec 06 14:44:41 2017 -0800"),
				Message:   newStringBuilderValue("Add travis testing\n"),
			},
			contentWriter: newBufferWithContent([]byte("language: python\npython:\n  - \"2.6\"\n  - \"2.7\"\n  - \"3.2\"\n  - \"3.3\"\n  - \"3.4\"\n  - \"3.5\"\n  - \"3.5-dev\" # 3.5 development branch\n  - \"3.6\"\n  - \"3.6-dev\" # 3.6 development branch\n  - \"3.7-dev\" # 3.7 development branch\n  - \"nightly\"\n")),
			IsBinary:      false,
		},
		{
			Commit: &Commit{
				Hash:      "3d76a97faad96e0f326afb61c232b9c2a18dca35",
				Author:    "John Smith <john.smith@example.com>",
				Committer: "John Smith <john.smith@example.com>",
				Date:      newTime("Tue Jul 11 18:03:54 2023 -0400"),
				Message:   strings.Builder{},
			},
		},
		{
			PathB:     "tzu",
			LineStart: 11,
			Commit: &Commit{
				Hash:      "7bd16429f1f708746dabf970e54b05d2b4734997",
				Author:    "John Smith <john.smith@example.com>",
				Committer: "John Smith <john.smith@example.com>",
				Date:      newTime("Tue Jul 11 18:10:49 2023 -0400"),
				Message:   newStringBuilderValue("Change file\n"),
			},
			contentWriter: newBufferWithContent([]byte("\n\n\n\nSource: https://www.gnu.org/software/diffutils/manual/diffutils.html#An-Example-of-Unified-Format\n")),
			IsBinary:      false,
		},
	}

	r := bytes.NewReader([]byte(recoverableCommits))
	diffChan := make(chan *Diff)
	parser := NewParser()
	go func() {
		parser.FromReader(context.Background(), r, diffChan, false)
	}()
	i := 0
	for diff := range diffChan {
		if !diff.Equal(context.Background(), expected[i]) {
			t.Errorf("Diff does not match.\nexpected: %+v\n\nactual  : %+v\n", expected[i], diff)
		}
		i++
	}
}

func TestCommitParseFailureRecoveryBufferedFileWriter(t *testing.T) {
	expected := []*Diff{
		{
			PathB:     ".travis.yml",
			LineStart: 1,
			Commit: &Commit{
				Hash:      "df393b4125c2aa217211b2429b8963d0cefcee27",
				Author:    "Stephen <stephen@egroat.com>",
				Committer: "Stephen <stephen@egroat.com>",
				Date:      newTime("Wed Dec 06 14:44:41 2017 -0800"),
				Message:   newStringBuilderValue("Add travis testing\n"),
			},
			contentWriter: newBufferedFileWriterWithContent([]byte("language: python\npython:\n  - \"2.6\"\n  - \"2.7\"\n  - \"3.2\"\n  - \"3.3\"\n  - \"3.4\"\n  - \"3.5\"\n  - \"3.5-dev\" # 3.5 development branch\n  - \"3.6\"\n  - \"3.6-dev\" # 3.6 development branch\n  - \"3.7-dev\" # 3.7 development branch\n  - \"nightly\"\n")),
			IsBinary:      false,
		},
		{
			Commit: &Commit{
				Hash:      "3d76a97faad96e0f326afb61c232b9c2a18dca35",
				Author:    "John Smith <john.smith@example.com>",
				Committer: "John Smith <john.smith@example.com>",
				Date:      newTime("Tue Jul 11 18:03:54 2023 -0400"),
				Message:   strings.Builder{},
			},
		},
		{
			PathB:     "tzu",
			LineStart: 11,
			Commit: &Commit{
				Hash:      "7bd16429f1f708746dabf970e54b05d2b4734997",
				Author:    "John Smith <john.smith@example.com>",
				Committer: "John Smith <john.smith@example.com>",
				Date:      newTime("Tue Jul 11 18:10:49 2023 -0400"),
				Message:   newStringBuilderValue("Change file\n"),
			},
			contentWriter: newBufferedFileWriterWithContent([]byte("\n\n\n\nSource: https://www.gnu.org/software/diffutils/manual/diffutils.html#An-Example-of-Unified-Format\n")),
			IsBinary:      false,
		},
	}

	r := bytes.NewReader([]byte(recoverableCommits))
	diffChan := make(chan *Diff)
	parser := NewParser()
	go func() {
		parser.FromReader(context.Background(), r, diffChan, false)
	}()
	i := 0
	for diff := range diffChan {
		if len(expected) <= i {
			t.Errorf("Missing expected case for commit: %+v", diff)
			break
		}

		if !diff.Equal(context.Background(), expected[i]) {
			t.Errorf("Diff does not match.\nexpected: %+v\n\nactual  : %+v\n", expected[i], diff)
		}
		i++
	}
}

const recoverableCommits = `commit df393b4125c2aa217211b2429b8963d0cefcee27
Author: Stephen <stephen@egroat.com>
AuthorDate:   Wed Dec 06 14:44:41 2017 -0800
Commit: Stephen <stephen@egroat.com>
CommitDate:   Wed Dec 06 14:44:41 2017 -0800

    Add travis testing

diff --git a/.gitignore b/.gitignore
index ede6aa39..bb85dcc3 100644
--- a/.gitignore
+++ b/.gitignore
>>>>ERRANT LINE<<<<
 /build/
 /dist/
 /truffleHog.egg-info/
-*/__pycache__/
+**/__pycache__/
+**/*.pyc
diff --git a/.travis.yml b/.travis.yml
new file mode 100644
index 00000000..33b6f107
--- /dev/null
+++ b/.travis.yml
@@ -0,0 +1,13 @@
+language: python
+python:
+  - "2.6"
+  - "2.7"
+  - "3.2"
+  - "3.3"
+  - "3.4"
+  - "3.5"
+  - "3.5-dev" # 3.5 development branch
+  - "3.6"
+  - "3.6-dev" # 3.6 development branch
+  - "3.7-dev" # 3.7 development branch
+  - "nightly"
diff --git a/requirements.txt b/requirements.txt
new file mode 100644
index 00000000..e69de29b

commit 3d76a97faad96e0f326afb61c232b9c2a18dca35 (HEAD -> master)
Author: John Smith <john.smith@example.com>
AuthorDate:   Tue Jul 11 18:03:54 2023 -0400
Commit: John Smith <john.smith@example.com>
CommitDate:   Tue Jul 11 18:03:54 2023 -0400

diff --git a/sample.txt b/sample.txt
new file mode 100644
index 0000000..af5626b
--- /dev/null
+++ b/sample.txt
@@ -0,0 +1 @@
!!!ERROR!!!

commit 7bd16429f1f708746dabf970e54b05d2b4734997 (HEAD -> master)
Author: John Smith <john.smith@example.com>
AuthorDate:   Tue Jul 11 18:10:49 2023 -0400
Commit: John Smith <john.smith@example.com>
CommitDate:   Tue Jul 11 18:10:49 2023 -0400

    Change file

diff --git a/tzu b/tzu
index 5af88a8..c729cdb 100644
--- a/tzu
+++ b/tzu
@@ -11,3 +11,5 @@ But after they are produced,
 They both may be called deep and profound.
 Deeper and more profound,
 The door of all subtleties!
+
+Source: https://www.gnu.org/software/diffutils/manual/diffutils.html#An-Example-of-Unified-Format
`

func TestDiffParseFailureRecovery(t *testing.T) {
	expected := []*Diff{
		{
			PathB:     "aws",
			LineStart: 1,
			Commit: &Commit{
				Hash:    "",
				Author:  "",
				Date:    newTime("0001-01-01 00:00:00 +0000 UTC"),
				Message: strings.Builder{},
			},
			contentWriter: newBufferWithContent([]byte("[default]\naws_access_key_id = AKIAXYZDQCEN4B6JSJQI\naws_secret_access_key = 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\noutput = json\nregion = us-east-2\n")),
			IsBinary:      false,
		},
		{
			PathB:     "tzu",
			LineStart: 11,
			Commit: &Commit{
				Hash:    "",
				Author:  "",
				Date:    newTime("0001-01-01 00:00:00 +0000 UTC"),
				Message: strings.Builder{},
			},
			contentWriter: newBufferWithContent([]byte("\n\n\n\nSource: https://www.gnu.org/software/diffutils/manual/diffutils.html#An-Example-of-Unified-Format\n")),
			IsBinary:      false,
		},
		{
			PathB:     "tzu",
			LineStart: 1,
			Commit: &Commit{
				Hash:    "",
				Author:  "",
				Date:    newTime("0001-01-01 00:00:00 +0000 UTC"),
				Message: strings.Builder{},
			},
			contentWriter: newBufferWithContent([]byte("The Nameless is the origin of Heaven and Earth;\nThe named is the mother of all things.\n\nTherefore let there always be non-being,\n  so we may see their subtlety,\nAnd let there always be being,\n  so we may see their outcome.\nThe two are the same,\nBut after they are produced,\n  they have different names.\nThey both may be called deep and profound.\nDeeper and more profound,\nThe door of all subtleties!\n")),
			IsBinary:      false,
		},
	}

	r := bytes.NewReader([]byte(recoverableDiffs))
	diffChan := make(chan *Diff)
	parser := NewParser()
	go func() {
		parser.FromReader(context.Background(), r, diffChan, true)
	}()
	i := 0
	for diff := range diffChan {
		if len(expected) <= i {
			t.Errorf("Missing expected case for commit: %+v", diff)
			break
		}

		if !diff.Equal(context.Background(), expected[i]) {
			t.Errorf("Diff does not match.\nexpected: %+v\n\nactual  : %+v\n", expected[i], diff)
		}
		i++
	}
}

func TestDiffParseFailureRecoveryBufferedFileWriter(t *testing.T) {
	expected := []*Diff{
		{
			PathB:     "aws",
			LineStart: 1,
			Commit: &Commit{
				Hash:    "",
				Author:  "",
				Date:    newTime("0001-01-01 00:00:00 +0000 UTC"),
				Message: strings.Builder{},
			},
			contentWriter: newBufferWithContent([]byte("[default]\naws_access_key_id = AKIAXYZDQCEN4B6JSJQI\naws_secret_access_key = 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\noutput = json\nregion = us-east-2\n")),
			IsBinary:      false,
		},
		{
			PathB:     "tzu",
			LineStart: 11,
			Commit: &Commit{
				Hash:    "",
				Author:  "",
				Date:    newTime("0001-01-01 00:00:00 +0000 UTC"),
				Message: strings.Builder{},
			},
			contentWriter: newBufferWithContent([]byte("\n\n\n\nSource: https://www.gnu.org/software/diffutils/manual/diffutils.html#An-Example-of-Unified-Format\n")),
			IsBinary:      false,
		},
		{
			PathB:     "tzu",
			LineStart: 1,
			Commit: &Commit{
				Hash:    "",
				Author:  "",
				Date:    newTime("0001-01-01 00:00:00 +0000 UTC"),
				Message: strings.Builder{},
			},
			contentWriter: newBufferWithContent([]byte("The Nameless is the origin of Heaven and Earth;\nThe named is the mother of all things.\n\nTherefore let there always be non-being,\n  so we may see their subtlety,\nAnd let there always be being,\n  so we may see their outcome.\nThe two are the same,\nBut after they are produced,\n  they have different names.\nThey both may be called deep and profound.\nDeeper and more profound,\nThe door of all subtleties!\n")),
			IsBinary:      false,
		},
	}

	r := bytes.NewReader([]byte(recoverableDiffs))
	diffChan := make(chan *Diff)
	parser := NewParser()
	go func() {
		parser.FromReader(context.Background(), r, diffChan, true)
	}()
	i := 0
	for diff := range diffChan {
		if len(expected) <= i {
			t.Errorf("Missing expected case for commit: %+v", diff)
			break
		}

		if !diff.Equal(context.Background(), expected[i]) {
			t.Errorf("Diff does not match.\nexpected: %+v\n\nactual  : %+v\n", expected[i], diff)
		}
		i++
	}
}

const recoverableDiffs = `diff --git a/aws b/aws
index 2ee133b..12b4843 100644
--- a/aws
+++ b/aws
@@ -1,7 +1,5 @@
-blah blaj
-
-this is the secret: [Default]
-Access key Id: AKIAILE3JG6KMS3HZGCA
-Secret Access Key: 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
-
-okay thank you bye
+[default]
+aws_access_key_id = AKIAXYZDQCEN4B6JSJQI
+aws_secret_access_key = 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
+output = json
+region = us-east-2

diff --git a/aws2 b/aws2
index 239b415..2ee133b 100644
--- a/aws2
+++ b/aws2
!!!ERROR!!!
 blah blaj
 
-this is the secret: AKIA2E0A8F3B244C9986
+this is the secret: [Default]
+Access key Id: AKIAILE3JG6KMS3HZGCA
+Secret Access Key: 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
 
-okay thank you bye
\ No newline at end of file
+okay thank you bye

diff --git c/requirements.txt i/requirements.txt
new file mode 100644
index 00000000..e69de29b

diff --git a/tzu b/tzu
index 5af88a8..c729cdb 100644
--- a/tzu
+++ b/tzu
@@ -11,3 +11,5 @@ But after they are produced,
 They both may be called deep and profound.
 Deeper and more profound,
 The door of all subtleties!
+
+Source: https://www.gnu.org/software/diffutils/manual/diffutils.html#An-Example-of-Unified-Format

diff --git a/lao b/lao
new file mode 100644
!!!ERROR!!!!
--- /dev/null
+++ b/lao
@@ -0,0 +1,11 @@
+The Way that can be told of is not the eternal Way;
+The name that can be named is not the eternal name.
+The Nameless is the origin of Heaven and Earth;
+The Named is the mother of all things.
+Therefore let there always be non-being,
+  so we may see their subtlety,
+And let there always be being,
+  so we may see their outcome.
+The two are the same,
+But after they are produced,
+  they have different names.
diff --git a/tzu b/tzu
new file mode 100644
index 0000000..5af88a8
--- /dev/null
+++ b/tzu
@@ -0,0 +1,13 @@
+The Nameless is the origin of Heaven and Earth;
+The named is the mother of all things.
+
+Therefore let there always be non-being,
+  so we may see their subtlety,
+And let there always be being,
+  so we may see their outcome.
+The two are the same,
+But after they are produced,
+  they have different names.
+They both may be called deep and profound.
+Deeper and more profound,
+The door of all subtleties!
`

func TestMaxDiffSize(t *testing.T) {
	parser := NewParser()
	builder := strings.Builder{}
	builder.WriteString(singleCommitSingleDiff)

	// Generate a diff that is larger than the maxDiffSize.
	for i := int64(0); i <= parser.maxDiffSize/1024+10; i++ {
		builder.WriteString("+" + strings.Repeat("0", 1024) + "\n")
	}
	bigReader := strings.NewReader(builder.String())

	diffChan := make(chan *Diff, 1)                                          // Buffer to prevent blocking
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second) // Timeout to prevent long wait
	defer cancel()

	go func() {
		parser.FromReader(ctx, bigReader, diffChan, false)
	}()

	select {
	case diff := <-diffChan:
		if int64(diff.Len()) > parser.maxDiffSize+1024 {
			t.Errorf("diff did not match MaxDiffSize. Got: %d, expected (max): %d", diff.Len(), parser.maxDiffSize+1024)
		}
	case <-ctx.Done():
		t.Fatal("Test timed out")
	}
}

func TestMaxCommitSize(t *testing.T) {
	parser := NewParser(WithMaxCommitSize(1))
	commitText := bytes.Buffer{}
	commitText.WriteString(singleCommitMultiDiff)
	diffChan := make(chan *Diff)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(1)*time.Second)
	defer cancel()
	go func() {
		parser.FromReader(ctx, &commitText, diffChan, false)
	}()
	diffCount := 0
	for range diffChan {
		diffCount++
	}
	if diffCount != 2 {
		t.Errorf("Commit count does not match. Got: %d, expected: %d", diffCount, 2)
	}

}

const commitLog = `commit e50b135fd29e91b2fbb25923797f5ecffe59f359
Author: lionzxy <nikita@kulikof.ru>
AuthorDate:   Wed Mar 1 18:20:04 2017 +0300
Commit: lionzxy <nikita@kulikof.ru>
CommitDate:   Wed Mar 1 18:20:04 2017 +0300

    Все работает, но он не принимает :(

diff --git "a/C++/1 \320\243\321\200\320\276\320\272/.idea/workspace.xml" "b/C++/1 \320\243\321\200\320\276\320\272/.idea/workspace.xml"
index 85bfb17..89b08b5 100644
--- "a/C++/1 \320\243\321\200\320\276\320\272/.idea/workspace.xml"
+++ "b/C++/1 \320\243\321\200\320\276\320\272/.idea/workspace.xml"
@@ -29,8 +29,8 @@
       <file leaf-file-name="CMakeLists.txt" pinned="false" current-in-tab="false">
         <entry file="file://$PROJECT_DIR$/CMakeLists.txt">
           <provider selected="true" editor-type-id="text-editor">
-            <state relative-caret-position="0">
-              <caret line="0" column="0" lean-forward="false" selection-start-line="0" selection-start-column="0" selection-end-line="0" selection-end-column="0" />
+            <state relative-caret-position="72">
+              <caret line="4" column="0" lean-forward="false" selection-start-line="4" selection-start-column="0" selection-end-line="4" selection-end-column="0" />
               <folding />
             </state>
           </provider>

commit fd6e99e7a80199b76a694603be57c5ade1de18e7
Author: Jaliborc <jaliborc@gmail.com>
AuthorDate:   Mon Apr 25 16:28:06 2011 +0100
Commit: Jaliborc <jaliborc@gmail.com>
CommitDate:   Mon Apr 25 16:28:06 2011 +0100

    Added Unusable coloring

Notes:
    Message-Id: <1264640755-22447-1-git-send-email-user@example.de>

diff --git a/components/item.lua b/components/item.lua
index fc74534..f8d7d50 100755
--- a/components/item.lua
+++ b/components/item.lua
@@ -9,6 +9,7 @@ ItemSlot:Hide()
 Bagnon.ItemSlot = ItemSlot

 local ItemSearch = LibStub('LibItemSearch-1.0')
+local Unfit = LibStub('Unfit-1.0')

 local function hasBlizzQuestHighlight()
        return GetContainerItemQuestInfo and true or false
diff --git a/embeds.xml b/embeds.xml
index d3f4e7c..0c2df69 100755
--- a/embeds.xml
+++ b/embeds.xml
@@ -6,6 +6,7 @@
        <Include file="libs\AceConsole-3.0\AceConsole-3.0.xml"/>
        <Include file="libs\AceLocale-3.0\AceLocale-3.0.xml"/>

+       <Script file="libs\Unfit-1.0\Unfit-1.0.lua"/>
        <Script file="libs\LibDataBroker-1.1.lua"/>
        <Script file="libs\LibItemSearch-1.0\LibItemSearch-1.0.lua"/>
 </Ui>
\ No newline at end of file
diff --git a/libs/Unfit-1.0 b/libs/Unfit-1.0
new file mode 160000
--- /dev/null
+++ b/libs/Unfit-1.0
@@ -0,0 +1 @@
+Subproject commit 0000000000000000000000000000000000000000

commit 4727ffb7ad6dc5130bf4b4dd166e00705abdd018 (HEAD -> master)
Author: John Smith <john.smith@example.com>
AuthorDate:   Tue Jul 11 22:26:11 2023 -0400
Commit: John Smith <john.smith@example.com>
CommitDate:   Tue Jul 11 22:26:11 2023 -0400

commit c904e0f5cd9f30ae520c66bd5f70806219fe7ca2 (HEAD -> master)
Author: John Smith <john.smith@example.com>
AuthorDate:   Mon Jul 10 10:17:11 2023 -0400
Commit: John Smith <john.smith@example.com>
CommitDate:   Mon Jul 10 10:17:11 2023 -0400

    Empty Commit

commit 3d76a97faad96e0f326afb61c232b9c2a18dca35 (HEAD -> master)
Author: John Smith <john.smith@example.com>
AuthorDate:   Tue Jul 11 18:03:54 2023 -0400
Commit: John Smith <john.smith@example.com>
CommitDate:   Tue Jul 11 18:03:54 2023 -0400

diff --git a/sample.txt b/sample.txt
new file mode 100644
index 0000000..af5626b
--- /dev/null
+++ b/sample.txt
@@ -0,0 +1 @@
+Hello, world!

commit df393b4125c2aa217211b2429b8963d0cefcee27
Author: Stephen <stephen@egroat.com>
AuthorDate:   Wed Dec 06 14:44:41 2017 -0800
Commit: Stephen <stephen@egroat.com>
CommitDate:   Wed Dec 06 14:44:41 2017 -0800

    Add travis testing

diff --git a/.gitignore b/.gitignore
index ede6aa39..bb85dcc3 100644
--- a/.gitignore
+++ b/.gitignore
@@ -1,4 +1,5 @@
 /build/
 /dist/
 /truffleHog.egg-info/
-*/__pycache__/
+**/__pycache__/
+**/*.pyc
diff --git a/.travis.yml b/.travis.yml
new file mode 100644
index 00000000..33b6f107
--- /dev/null
+++ b/.travis.yml
@@ -0,0 +1,13 @@
+language: python
+python:
+  - "2.6"
+  - "2.7"
+  - "3.2"
+  - "3.3"
+  - "3.4"
+  - "3.5"
+  - "3.5-dev" # 3.5 development branch
+  - "3.6"
+  - "3.6-dev" # 3.6 development branch
+  - "3.7-dev" # 3.7 development branch
+  - "nightly"
diff --git a/requirements.txt b/requirements.txt
new file mode 100644
index 00000000..e69de29b

commit 4218c39d99b5f30153f62471c1be1c1596f0a4d4
Author: Dustin Decker <dustin@trufflesec.com>
AuthorDate:   Thu Jan 13 12:02:24 2022 -0800
Commit: Dustin Decker <dustin@trufflesec.com>
CommitDate:   Thu Jan 13 12:02:24 2022 -0800

    Initial CLI w/ partially implemented Git source and demo detector (#1)

diff --git a/Dockerfile b/Dockerfile
new file mode 100644
index 00000000..e69de29b
diff --git a/Makefile b/Makefile
new file mode 100644
index 00000000..453cf52c
--- /dev/null
+++ b/Makefile
@@ -0,0 +1,32 @@
+PROTOS_IMAGE=us-docker.pkg.dev/thog-artifacts/public/go-ci-1.17-1
+
+.PHONY: check
+.PHONY: test
+.PHONY: test-race
+.PHONY: run
+.PHONY: install
+.PHONY: protos
+.PHONY: protos-windows
+.PHONY: vendor
+
+install:
+       CGO_ENABLED=0 go install .
+
+check:
+       go fmt $(shell go list ./... | grep -v /vendor/)
+       go vet $(shell go list ./... | grep -v /vendor/)
+
+test:
+       CGO_ENABLED=0 go test $(shell go list ./... | grep -v /vendor/)
+
+test-race:
+       CGO_ENABLED=1 go test -race $(shell go list ./... | grep -v /vendor/)
+
+bench:
+       CGO_ENABLED=0 go test $(shell go list ./pkg/secrets/... | grep -v /vendor/) -benchmem -run=xxx -bench .
+
+run:
+       CGO_ENABLED=0 go run . git file://.
+
+protos:
+       docker run -u "$(shell id -u)" -v "$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))":/pwd "${PROTOS_IMAGE}" bash -c "cd /pwd; /pwd/scripts/gen_proto.sh"
diff --git a/README.md b/README.md
new file mode 100644
index 00000000..e69de29b
diff --git a/go.mod b/go.mod
new file mode 100644
index 00000000..7fb2f73c
--- /dev/null
+++ b/go.mod

commit 934cf5d255fd8e28b33f5a6ba64276caf0b284bf (HEAD -> master)
Author: John Smith <john.smith@example.com>
AuthorDate:   Tue Jul 11 18:43:22 2023 -0400
Commit: John Smith <john.smith@example.com>
CommitDate:   Tue Jul 11 18:43:22 2023 -0400

    Test toFile/plusLine parsing

diff --git a/plusLine.txt b/plusLine.txt
new file mode 100644
index 0000000..451be67
--- /dev/null
+++ b/plusLine.txt
@@ -0,0 +1,3 @@
+-- test
+++ test
+

commit 2a5d703b02b52d65c65ee9f7928f158b919ab741
Author: Sergey Beryozkin <sberyozkin@gmail.com>
AuthorDate:   Fri Jul 7 17:44:26 2023 +0100
Commit: Sergey Beryozkin <sberyozkin@gmail.com>
CommitDate:   Fri Jul 7 17:44:26 2023 +0100

    Do not refresh OIDC session if the user is requesting logout

diff --git a/extensions/oidc/runtime/src/main/java/io/quarkus/oidc/runtime/BackChannelLogoutTokenCache.java b/extensions/oidc/runtime/src/main/java/io/quarkus/oidc/runtime/BackChannelLogoutTokenCache.java
index 096f5b4b092..4150096851c 100644
--- a/extensions/oidc/runtime/src/main/java/io/quarkus/oidc/runtime/BackChannelLogoutTokenCache.java
+++ b/extensions/oidc/runtime/src/main/java/io/quarkus/oidc/runtime/BackChannelLogoutTokenCache.java
@@ -45,6 +45,10 @@ public TokenVerificationResult removeTokenVerification(String token) {
         return entry == null ? null : entry.result;
     }

+    public boolean containsTokenVerification(String token) {
+        return cacheMap.containsKey(token);
+    }
+
     public void clearCache() {
         cacheMap.clear();
         size.set(0);
diff --git a/extensions/oidc/runtime/src/main/java/io/quarkus/oidc/runtime/CodeAuthenticationMechanism.java b/extensions/oidc/runtime/src/main/java/io/quarkus/oidc/runtime/CodeAuthenticationMechanism.java
index a9a9699eecd..435cefdf313 100644
--- a/extensions/oidc/runtime/src/main/java/io/quarkus/oidc/runtime/CodeAuthenticationMechanism.java
+++ b/extensions/oidc/runtime/src/main/java/io/quarkus/oidc/runtime/CodeAuthenticationMechanism.java
@@ -1014,7 +1023,7 @@ private String buildUri(RoutingContext context, boolean forceHttps, String autho
                 .toString();
     }

-    private boolean isLogout(RoutingContext context, TenantConfigContext configContext) {
+    private boolean isRpInitiatedLogout(RoutingContext context, TenantConfigContext configContext) {
         return isEqualToRequestPath(configContext.oidcConfig.logout.path, context, configContext);
     }

@@ -1205,4 +1214,38 @@ static String getCookieSuffix(OidcTenantConfig oidcConfig) {
                 ? (tenantIdSuffix + UNDERSCORE + oidcConfig.authentication.cookieSuffix.get())
                 : tenantIdSuffix;
     }
+
+    private class LogoutCall implements Function<SecurityIdentity, Uni<?>> {
+        RoutingContext context;
+        TenantConfigContext configContext;
+        String idToken;
+
+        LogoutCall(RoutingContext context, TenantConfigContext configContext, String idToken) {
+            this.context = context;
+            this.configContext = configContext;
+            this.idToken = idToken;
+        }
+
+        @Override
+        public Uni<Void> apply(SecurityIdentity identity) {
+            if (isRpInitiatedLogout(context, configContext)) {
+                LOG.debug("Performing an RP initiated logout");
+                fireEvent(SecurityEvent.Type.OIDC_LOGOUT_RP_INITIATED, identity);
+                return buildLogoutRedirectUriUni(context, configContext, idToken);
+            }
+            if (isBackChannelLogoutPendingAndValid(configContext, identity)
+                    || isFrontChannelLogoutValid(context, configContext,
+                            identity)) {
+                return removeSessionCookie(context, configContext.oidcConfig)
+                        .map(new Function<Void, Void>() {
+                            @Override
+                            public Void apply(Void t) {
+                                throw new LogoutException();
+                            }
+                        });
+
+            }
+            return VOID_UNI;
+        }
+    }
 }
diff --git a/integration-tests/oidc-wiremock/src/main/resources/application.properties b/integration-tests/oidc-wiremock/src/main/resources/application.properties
index bb6917d30bc..4e8bfb21b4c 100644
--- a/integration-tests/oidc-wiremock/src/main/resources/application.properties
+++ b/integration-tests/oidc-wiremock/src/main/resources/application.properties
@@ -20,6 +20,8 @@ quarkus.oidc.code-flow.logout.extra-params.client_id=${quarkus.oidc.code-flow.cl
 quarkus.oidc.code-flow.credentials.secret=secret
 quarkus.oidc.code-flow.application-type=web-app
 quarkus.oidc.code-flow.token.audience=https://server.example.com
+quarkus.oidc.code-flow.token.refresh-expired=true
+quarkus.oidc.code-flow.token.refresh-token-time-skew=5M

 quarkus.oidc.code-flow-encrypted-id-token-jwk.auth-server-url=${keycloak.url}/realms/quarkus/
 quarkus.oidc.code-flow-encrypted-id-token-jwk.client-id=quarkus-web-app
diff --git a/integration-tests/oidc-wiremock/src/test/java/io/quarkus/it/keycloak/CodeFlowAuthorizationTest.java b/integration-tests/oidc-wiremock/src/test/java/io/quarkus/it/keycloak/CodeFlowAuthorizationTest.java
index 51e1b9a932d..472c2743bc4 100644
--- a/integration-tests/oidc-wiremock/src/test/java/io/quarkus/it/keycloak/CodeFlowAuthorizationTest.java
+++ b/integration-tests/oidc-wiremock/src/test/java/io/quarkus/it/keycloak/CodeFlowAuthorizationTest.java
@@ -6,7 +6,6 @@
 import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
 import static com.github.tomakehurst.wiremock.client.WireMock.matching;
 import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;
-import static com.github.tomakehurst.wiremock.client.WireMock.verify;
 import static org.junit.jupiter.api.Assertions.assertEquals;
 import static org.junit.jupiter.api.Assertions.assertNotNull;
 import static org.junit.jupiter.api.Assertions.assertNull;
@@ -77,7 +76,7 @@ public void testCodeFlow() throws IOException {

             assertEquals("alice, cache size: 0", page.getBody().asNormalizedText());
             assertNotNull(getSessionCookie(webClient, "code-flow"));
-
+            // Logout
             page = webClient.getPage("http://localhost:8081/code-flow/logout");
             assertEquals("Welcome, clientId: quarkus-web-app", page.getBody().asNormalizedText());
             assertNull(getSessionCookie(webClient, "code-flow"));

commit 2a057632d7f5fa3d1c77b9aa037263211c0e0290
Author: rjtmahinay <rjt.mahinay@gmail.com>
AuthorDate:   Mon Jul 10 01:22:32 2023 +0800
Commit: rjtmahinay <rjt.mahinay@gmail.com>
CommitDate:   Mon Jul 10 01:22:32 2023 +0800

    Add QuarkusApplication javadoc
    
    * Fix #34463

diff --git a/core/runtime/src/main/java/io/quarkus/runtime/QuarkusApplication.java b/core/runtime/src/main/java/io/quarkus/runtime/QuarkusApplication.java
index 350685123d5..87d2220eb98 100644
--- a/core/runtime/src/main/java/io/quarkus/runtime/QuarkusApplication.java
+++ b/core/runtime/src/main/java/io/quarkus/runtime/QuarkusApplication.java
@@ -2,0 +3,4 @@
+/**
+ * This is usually used for command mode applications with a startup logic. The logic is executed inside
+ * {@link QuarkusApplication#run} method before the main application exits.
+ */

commit bca2d17491015ea1522f34517223b5a366aea73c (HEAD -> master)
Author: John Smith <john.smith@example.com>
AuthorDate:   Tue Jul 11 18:12:21 2023 -0400
Commit: John Smith <john.smith@example.com>
CommitDate:   Tue Jul 11 18:12:21 2023 -0400

    Delete binary file

diff --git a/trufflehog_3.42.0_linux_arm64.tar.gz b/trufflehog_3.42.0_linux_arm64.tar.gz
deleted file mode 100644
index 7682212..0000000
Binary files a/trufflehog_3.42.0_linux_arm64.tar.gz and /dev/null differ

commit afc6dc5d47f28366638da877ecb6b819c69e659b
Author: John Smith <john.smith@example.com>
AuthorDate:   Mon Jul 10 12:21:33 2023 -0400
Commit: John Smith <john.smith@example.com>
CommitDate:   Mon Jul 10 12:21:33 2023 -0400

    Change binary file

diff --git a/trufflehog_3.42.0_linux_arm64.tar.gz b/trufflehog_3.42.0_linux_arm64.tar.gz
index 0a7a5b4..7682212 100644
Binary files a/trufflehog_3.42.0_linux_arm64.tar.gz and b/trufflehog_3.42.0_linux_arm64.tar.gz differ

commit 638595917417c5c8a956937b28c5127719023363
Author: John Smith <john.smith@example.com>
AuthorDate:   Mon Jul 10 12:20:35 2023 -0400
Commit: John Smith <john.smith@example.com>
CommitDate:   Mon Jul 10 12:20:35 2023 -0400

    Add binary file

diff --git a/trufflehog_3.42.0_linux_arm64.tar.gz b/trufflehog_3.42.0_linux_arm64.tar.gz
new file mode 100644
index 0000000..0a7a5b4
Binary files /dev/null and b/trufflehog_3.42.0_linux_arm64.tar.gz differ

commit ce0f5d1fe0272f180ccb660196f439c0c2f4ec8e (HEAD -> master)
Author: John Smith <john.smith@example.com>
AuthorDate:   Tue Jul 11 18:08:52 2023 -0400
Commit: John Smith <john.smith@example.com>
CommitDate:   Tue Jul 11 18:08:52 2023 -0400

    Delete file

diff --git a/lao b/lao
deleted file mode 100644
index 635ef2c..0000000
--- a/lao
+++ /dev/null
@@ -1,11 +0,0 @@
-The Way that can be told of is not the eternal Way;
-The name that can be named is not the eternal name.
-The Nameless is the origin of Heaven and Earth;
-The Named is the mother of all things.
-Therefore let there always be non-being,
-  so we may see their subtlety,
-And let there always be being,
-  so we may see their outcome.
-The two are the same,
-But after they are produced,
-  they have different names.

commit d606a729383371558473b70a6a7b1ca264b0d205
Author: John Smith <john.smith@example.com>
AuthorDate:   Mon Jul 10 14:17:04 2023 -0400
Commit: John Smith <john.smith@example.com>
CommitDate:   Mon Jul 10 14:17:04 2023 -0400

    Rename file

diff --git a/tzu b/tzu.txt
similarity index 100%
rename from tzu
rename to tzu.txt

commit 7bd16429f1f708746dabf970e54b05d2b4734997 (HEAD -> master)
Author: John Smith <john.smith@example.com>
AuthorDate:   Tue Jul 11 18:10:49 2023 -0400
Commit: John Smith <john.smith@example.com>
CommitDate:   Tue Jul 11 18:10:49 2023 -0400

    Change file

diff --git a/tzu b/tzu
index 5af88a8..c729cdb 100644
--- a/tzu
+++ b/tzu
@@ -11,3 +11,5 @@ But after they are produced,
 They both may be called deep and profound.
 Deeper and more profound,
 The door of all subtleties!
+
+Source: https://www.gnu.org/software/diffutils/manual/diffutils.html#An-Example-of-Unified-Format

commit c7062674c17192caa284615ab2fa9778c6602164 (HEAD -> master)
Author: John Smith <john.smith@example.com>
AuthorDate:   Mon Jul 10 10:15:18 2023 -0400
Commit: John Smith <john.smith@example.com>
CommitDate:   Mon Jul 10 10:15:18 2023 -0400

    Create files

diff --git a/lao b/lao
new file mode 100644
index 0000000..635ef2c
--- /dev/null
+++ b/lao
@@ -0,0 +1,11 @@
+The Way that can be told of is not the eternal Way;
+The name that can be named is not the eternal name.
+The Nameless is the origin of Heaven and Earth;
+The Named is the mother of all things.
+Therefore let there always be non-being,
+  so we may see their subtlety,
+And let there always be being,
+  so we may see their outcome.
+The two are the same,
+But after they are produced,
+  they have different names.
diff --git a/tzu b/tzu
new file mode 100644
index 0000000..5af88a8
--- /dev/null
+++ b/tzu
@@ -0,0 +1,13 @@
+The Nameless is the origin of Heaven and Earth;
+The named is the mother of all things.
+
+Therefore let there always be non-being,
+  so we may see their subtlety,
+And let there always be being,
+  so we may see their outcome.
+The two are the same,
+But after they are produced,
+  they have different names.
+They both may be called deep and profound.
+Deeper and more profound,
+The door of all subtleties!
`

func newTime(timestamp string) time.Time {
	date, _ := time.Parse(defaultDateFormat, timestamp)
	return date
}

func newStringBuilderValue(value string) strings.Builder {
	builder := strings.Builder{}
	builder.Write([]byte(value))
	return builder
}

// This throws a nasty panic if it's a top-level var.
func expectedDiffs() []*Diff {
	return []*Diff{
		{
			PathB:     "C++/1 \320\243\321\200\320\276\320\272/.idea/workspace.xml",
			LineStart: 29,
			Commit: &Commit{
				Hash:      "e50b135fd29e91b2fbb25923797f5ecffe59f359",
				Author:    "lionzxy <nikita@kulikof.ru>",
				Committer: "lionzxy <nikita@kulikof.ru>",
				Date:      newTime("Wed Mar 1 18:20:04 2017 +0300"),
				Message:   newStringBuilderValue("Все работает, но он не принимает :(\n"),
			},
			contentWriter: newBufferWithContent([]byte("\n\n\n            <state relative-caret-position=\"72\">\n              <caret line=\"4\" column=\"0\" lean-forward=\"false\" selection-start-line=\"4\" selection-start-column=\"0\" selection-end-line=\"4\" selection-end-column=\"0\" />\n\n\n\n")),
			IsBinary:      false,
		},
		{
			PathB:     "components/item.lua",
			LineStart: 9,
			Commit: &Commit{
				Hash:      "fd6e99e7a80199b76a694603be57c5ade1de18e7",
				Author:    "Jaliborc <jaliborc@gmail.com>",
				Committer: "Jaliborc <jaliborc@gmail.com>",
				Date:      newTime("Mon Apr 25 16:28:06 2011 +0100"),
				Message:   newStringBuilderValue("Added Unusable coloring\n\nNotes:\nMessage-Id: <1264640755-22447-1-git-send-email-user@example.de>\n"),
			},
			contentWriter: newBufferWithContent([]byte("\n\nlocal Unfit = LibStub('Unfit-1.0')\n\n\n")),
			IsBinary:      false,
		},
		{
			PathB:         "embeds.xml",
			LineStart:     6,
			contentWriter: newBufferWithContent([]byte("\n\n       <Script file=\"libs\\Unfit-1.0\\Unfit-1.0.lua\"/>\n\n\n\n")),
			Commit: &Commit{
				Hash:      "fd6e99e7a80199b76a694603be57c5ade1de18e7",
				Author:    "Jaliborc <jaliborc@gmail.com>",
				Committer: "Jaliborc <jaliborc@gmail.com>",
				Date:      newTime("Mon Apr 25 16:28:06 2011 +0100"),
				Message:   newStringBuilderValue("Added Unusable coloring\n\nNotes:\nMessage-Id: <1264640755-22447-1-git-send-email-user@example.de>\n"),
			},
			IsBinary: false,
		},
		{
			PathB:         "libs/Unfit-1.0",
			LineStart:     1,
			contentWriter: newBufferWithContent([]byte("Subproject commit 0000000000000000000000000000000000000000\n")),
			Commit: &Commit{
				Hash:      "fd6e99e7a80199b76a694603be57c5ade1de18e7",
				Author:    "Jaliborc <jaliborc@gmail.com>",
				Committer: "Jaliborc <jaliborc@gmail.com>",
				Date:      newTime("Mon Apr 25 16:28:06 2011 +0100"),
				Message:   newStringBuilderValue("Added Unusable coloring\n\nNotes:\nMessage-Id: <1264640755-22447-1-git-send-email-user@example.de>\n"),
			},
			IsBinary: false,
		},
		{
			Commit: &Commit{
				Hash:      "4727ffb7ad6dc5130bf4b4dd166e00705abdd018",
				Author:    "John Smith <john.smith@example.com>",
				Committer: "John Smith <john.smith@example.com>",
				Date:      newTime("Tue Jul 11 22:26:11 2023 -0400"),
				Message:   strings.Builder{},
			},
		},
		{
			Commit: &Commit{
				Hash:      "c904e0f5cd9f30ae520c66bd5f70806219fe7ca2",
				Author:    "John Smith <john.smith@example.com>",
				Committer: "John Smith <john.smith@example.com>",
				Date:      newTime("Mon Jul 10 10:17:11 2023 -0400"),
				Message:   newStringBuilderValue("Empty Commit\n"),
			},
		},
		{
			PathB:         "sample.txt",
			LineStart:     1,
			contentWriter: newBufferWithContent([]byte("Hello, world!\n")),
			Commit: &Commit{
				Hash:      "3d76a97faad96e0f326afb61c232b9c2a18dca35",
				Author:    "John Smith <john.smith@example.com>",
				Committer: "John Smith <john.smith@example.com>",
				Date:      newTime("Tue Jul 11 18:03:54 2023 -0400"),
				Message:   strings.Builder{},
			},
			IsBinary: false,
		},
		{
			PathB:         ".gitignore",
			LineStart:     1,
			contentWriter: newBufferWithContent([]byte("\n\n\n**/__pycache__/\n**/*.pyc\n")),
			Commit: &Commit{
				Hash:      "df393b4125c2aa217211b2429b8963d0cefcee27",
				Author:    "Stephen <stephen@egroat.com>",
				Committer: "Stephen <stephen@egroat.com>",
				Date:      newTime("Wed Dec 06 14:44:41 2017 -0800"),
				Message:   newStringBuilderValue("Add travis testing\n"),
			},
			IsBinary: false,
		},
		{
			PathB:     ".travis.yml",
			LineStart: 1,
			Commit: &Commit{
				Hash:      "df393b4125c2aa217211b2429b8963d0cefcee27",
				Author:    "Stephen <stephen@egroat.com>",
				Committer: "Stephen <stephen@egroat.com>",
				Date:      newTime("Wed Dec 06 14:44:41 2017 -0800"),
				Message:   newStringBuilderValue("Add travis testing\n"),
			},
			contentWriter: newBufferWithContent([]byte(`language: python
python:
  - "2.6"
  - "2.7"
  - "3.2"
  - "3.3"
  - "3.4"
  - "3.5"
  - "3.5-dev" # 3.5 development branch
  - "3.6"
  - "3.6-dev" # 3.6 development branch
  - "3.7-dev" # 3.7 development branch
  - "nightly"
`)),
			IsBinary: false,
		},
		{
			PathB:     "Makefile",
			LineStart: 1,
			Commit: &Commit{
				Hash:      "4218c39d99b5f30153f62471c1be1c1596f0a4d4",
				Author:    "Dustin Decker <dustin@trufflesec.com>",
				Committer: "Dustin Decker <dustin@trufflesec.com>",
				Date:      newTime("Thu Jan 13 12:02:24 2022 -0800"),
				Message:   newStringBuilderValue("Initial CLI w/ partially implemented Git source and demo detector (#1)\n"),
			},
			contentWriter: newBufferWithContent([]byte(`PROTOS_IMAGE=us-docker.pkg.dev/thog-artifacts/public/go-ci-1.17-1

.PHONY: check
.PHONY: test
.PHONY: test-race
.PHONY: run
.PHONY: install
.PHONY: protos
.PHONY: protos-windows
.PHONY: vendor

install:
       CGO_ENABLED=0 go install .

check:
       go fmt $(shell go list ./... | grep -v /vendor/)
       go vet $(shell go list ./... | grep -v /vendor/)

test:
       CGO_ENABLED=0 go test $(shell go list ./... | grep -v /vendor/)

test-race:
       CGO_ENABLED=1 go test -race $(shell go list ./... | grep -v /vendor/)

bench:
       CGO_ENABLED=0 go test $(shell go list ./pkg/secrets/... | grep -v /vendor/) -benchmem -run=xxx -bench .

run:
       CGO_ENABLED=0 go run . git file://.

protos:
       docker run -u "$(shell id -u)" -v "$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))":/pwd "${PROTOS_IMAGE}" bash -c "cd /pwd; /pwd/scripts/gen_proto.sh"
`)),
			IsBinary: false,
		},
		{
			PathB:     "plusLine.txt",
			LineStart: 1,
			Commit: &Commit{
				Hash:      "934cf5d255fd8e28b33f5a6ba64276caf0b284bf",
				Author:    "John Smith <john.smith@example.com>",
				Committer: "John Smith <john.smith@example.com>",
				Date:      newTime("Tue Jul 11 18:43:22 2023 -0400"),
				Message:   newStringBuilderValue("Test toFile/plusLine parsing\n"),
			},
			contentWriter: newBufferWithContent([]byte("-- test\n++ test\n\n")),
			IsBinary:      false,
		},
		{
			PathB:     "extensions/oidc/runtime/src/main/java/io/quarkus/oidc/runtime/BackChannelLogoutTokenCache.java",
			LineStart: 45,
			Commit: &Commit{
				Hash:      "2a5d703b02b52d65c65ee9f7928f158b919ab741",
				Author:    "Sergey Beryozkin <sberyozkin@gmail.com>",
				Committer: "Sergey Beryozkin <sberyozkin@gmail.com>",
				Date:      newTime("Fri Jul 7 17:44:26 2023 +0100"),
				Message:   newStringBuilderValue("Do not refresh OIDC session if the user is requesting logout\n"),
			},
			contentWriter: newBufferWithContent([]byte("\n\n    public boolean containsTokenVerification(String token) {\n        return cacheMap.containsKey(token);\n    }\n\n\n\n\n")),
			IsBinary:      false,
		},
		{
			PathB:     "extensions/oidc/runtime/src/main/java/io/quarkus/oidc/runtime/CodeAuthenticationMechanism.java",
			LineStart: 1023,
			Commit: &Commit{
				Hash:      "2a5d703b02b52d65c65ee9f7928f158b919ab741",
				Author:    "Sergey Beryozkin <sberyozkin@gmail.com>",
				Committer: "Sergey Beryozkin <sberyozkin@gmail.com>",
				Date:      newTime("Fri Jul 7 17:44:26 2023 +0100"),
				Message:   newStringBuilderValue("Do not refresh OIDC session if the user is requesting logout\n"),
			},
			contentWriter: newBufferWithContent([]byte("\n\n    private boolean isRpInitiatedLogout(RoutingContext context, TenantConfigContext configContext) {\n\n\n")),
			IsBinary:      false,
		},
		{
			PathB:     "extensions/oidc/runtime/src/main/java/io/quarkus/oidc/runtime/CodeAuthenticationMechanism.java",
			LineStart: 1214,
			Commit: &Commit{
				Hash:      "2a5d703b02b52d65c65ee9f7928f158b919ab741",
				Author:    "Sergey Beryozkin <sberyozkin@gmail.com>",
				Committer: "Sergey Beryozkin <sberyozkin@gmail.com>",
				Date:      newTime("Fri Jul 7 17:44:26 2023 +0100"),
				Message:   newStringBuilderValue("Do not refresh OIDC session if the user is requesting logout\n"),
			},
			contentWriter: newBufferWithContent([]byte("\n\n\n\n    private class LogoutCall implements Function<SecurityIdentity, Uni<?>> {\n        RoutingContext context;\n        TenantConfigContext configContext;\n        String idToken;\n\n        LogoutCall(RoutingContext context, TenantConfigContext configContext, String idToken) {\n            this.context = context;\n            this.configContext = configContext;\n            this.idToken = idToken;\n        }\n\n        @Override\n        public Uni<Void> apply(SecurityIdentity identity) {\n            if (isRpInitiatedLogout(context, configContext)) {\n                LOG.debug(\"Performing an RP initiated logout\");\n                fireEvent(SecurityEvent.Type.OIDC_LOGOUT_RP_INITIATED, identity);\n                return buildLogoutRedirectUriUni(context, configContext, idToken);\n            }\n            if (isBackChannelLogoutPendingAndValid(configContext, identity)\n                    || isFrontChannelLogoutValid(context, configContext,\n                            identity)) {\n                return removeSessionCookie(context, configContext.oidcConfig)\n                        .map(new Function<Void, Void>() {\n                            @Override\n                            public Void apply(Void t) {\n                                throw new LogoutException();\n                            }\n                        });\n\n            }\n            return VOID_UNI;\n        }\n    }\n\n")),
			IsBinary:      false,
		},
		{
			PathB:     "integration-tests/oidc-wiremock/src/main/resources/application.properties",
			LineStart: 20,
			Commit: &Commit{
				Hash:      "2a5d703b02b52d65c65ee9f7928f158b919ab741",
				Author:    "Sergey Beryozkin <sberyozkin@gmail.com>",
				Committer: "Sergey Beryozkin <sberyozkin@gmail.com>",
				Date:      newTime("Fri Jul 7 17:44:26 2023 +0100"),
				Message:   newStringBuilderValue("Do not refresh OIDC session if the user is requesting logout\n"),
			},
			contentWriter: newBufferWithContent([]byte("\n\n\nquarkus.oidc.code-flow.token.refresh-expired=true\nquarkus.oidc.code-flow.token.refresh-token-time-skew=5M\n\n\n")),
			IsBinary:      false,
		},
		// WTF, shouldn't this be filtered out?
		{
			PathB:     "integration-tests/oidc-wiremock/src/test/java/io/quarkus/it/keycloak/CodeFlowAuthorizationTest.java",
			LineStart: 6,
			Commit: &Commit{
				Hash:      "2a5d703b02b52d65c65ee9f7928f158b919ab741",
				Author:    "Sergey Beryozkin <sberyozkin@gmail.com>",
				Committer: "Sergey Beryozkin <sberyozkin@gmail.com>",
				Date:      newTime("Fri Jul 7 17:44:26 2023 +0100"),
				Message:   newStringBuilderValue("Do not refresh OIDC session if the user is requesting logout\n"),
			},
			contentWriter: newBufferWithContent([]byte("\n\n\n\n\n\n")),
			IsBinary:      false,
		},
		{
			PathB:     "integration-tests/oidc-wiremock/src/test/java/io/quarkus/it/keycloak/CodeFlowAuthorizationTest.java",
			LineStart: 76,
			Commit: &Commit{
				Hash:      "2a5d703b02b52d65c65ee9f7928f158b919ab741",
				Author:    "Sergey Beryozkin <sberyozkin@gmail.com>",
				Committer: "Sergey Beryozkin <sberyozkin@gmail.com>",
				Date:      newTime("Fri Jul 7 17:44:26 2023 +0100"),
				Message:   newStringBuilderValue("Do not refresh OIDC session if the user is requesting logout\n"),
			},
			contentWriter: newBufferWithContent([]byte("\n\n            // Logout\n\n\n\n")),
			IsBinary:      false,
		},
		{
			PathB:     "core/runtime/src/main/java/io/quarkus/runtime/QuarkusApplication.java",
			LineStart: 3,
			Commit: &Commit{
				Hash:      "2a057632d7f5fa3d1c77b9aa037263211c0e0290",
				Author:    "rjtmahinay <rjt.mahinay@gmail.com>",
				Committer: "rjtmahinay <rjt.mahinay@gmail.com>",
				Date:      newTime("Mon Jul 10 01:22:32 2023 +0800"),
				Message:   newStringBuilderValue("Add QuarkusApplication javadoc\n\n* Fix #34463\n"),
			},
			contentWriter: newBufferWithContent([]byte("/**\n * This is usually used for command mode applications with a startup logic. The logic is executed inside\n * {@link QuarkusApplication#run} method before the main application exits.\n */\n")),
			IsBinary:      false,
		},
		{
			Commit: &Commit{
				Hash:      "bca2d17491015ea1522f34517223b5a366aea73c",
				Author:    "John Smith <john.smith@example.com>",
				Committer: "John Smith <john.smith@example.com>",
				Date:      newTime("Tue Jul 11 18:12:21 2023 -0400"),
				Message:   newStringBuilderValue("Delete binary file\n"),
			},
		},
		{
			PathB: "trufflehog_3.42.0_linux_arm64.tar.gz",
			Commit: &Commit{
				Hash:      "afc6dc5d47f28366638da877ecb6b819c69e659b",
				Author:    "John Smith <john.smith@example.com>",
				Committer: "John Smith <john.smith@example.com>",
				Date:      newTime("Mon Jul 10 12:21:33 2023 -0400"),
				Message:   newStringBuilderValue("Change binary file\n"),
			},
			contentWriter: newBufferWithContent([]byte("")),
			IsBinary:      true,
		},
		{
			PathB: "trufflehog_3.42.0_linux_arm64.tar.gz",
			Commit: &Commit{
				Hash:      "638595917417c5c8a956937b28c5127719023363",
				Author:    "John Smith <john.smith@example.com>",
				Committer: "John Smith <john.smith@example.com>",
				Date:      newTime("Mon Jul 10 12:20:35 2023 -0400"),
				Message:   newStringBuilderValue("Add binary file\n"),
			},
			contentWriter: newBufferWithContent([]byte("")),
			IsBinary:      true,
		},
		{
			Commit: &Commit{
				Hash:      "ce0f5d1fe0272f180ccb660196f439c0c2f4ec8e",
				Author:    "John Smith <john.smith@example.com>",
				Committer: "John Smith <john.smith@example.com>",
				Date:      newTime("Tue Jul 11 18:08:52 2023 -0400"),
				Message:   newStringBuilderValue("Delete file\n"),
			},
		},
		{
			Commit: &Commit{
				Hash:      "d606a729383371558473b70a6a7b1ca264b0d205",
				Author:    "John Smith <john.smith@example.com>",
				Committer: "John Smith <john.smith@example.com>",
				Date:      newTime("Mon Jul 10 14:17:04 2023 -0400"),
				Message:   newStringBuilderValue("Rename file\n"),
			},
		},
		{
			PathB:     "tzu",
			LineStart: 11,
			Commit: &Commit{
				Hash:      "7bd16429f1f708746dabf970e54b05d2b4734997",
				Author:    "John Smith <john.smith@example.com>",
				Committer: "John Smith <john.smith@example.com>",
				Date:      newTime("Tue Jul 11 18:10:49 2023 -0400"),
				Message:   newStringBuilderValue("Change file\n"),
			},
			contentWriter: newBufferWithContent([]byte("\n\n\n\nSource: https://www.gnu.org/software/diffutils/manual/diffutils.html#An-Example-of-Unified-Format\n")),
			IsBinary:      false,
		},
		{
			PathB:     "lao",
			LineStart: 1,
			Commit: &Commit{
				Hash:      "c7062674c17192caa284615ab2fa9778c6602164",
				Author:    "John Smith <john.smith@example.com>",
				Committer: "John Smith <john.smith@example.com>",
				Date:      newTime("Mon Jul 10 10:15:18 2023 -0400"),
				Message:   newStringBuilderValue("Create files\n"),
			},
			contentWriter: newBufferWithContent([]byte("The Way that can be told of is not the eternal Way;\nThe name that can be named is not the eternal name.\nThe Nameless is the origin of Heaven and Earth;\nThe Named is the mother of all things.\nTherefore let there always be non-being,\n  so we may see their subtlety,\nAnd let there always be being,\n  so we may see their outcome.\nThe two are the same,\nBut after they are produced,\n  they have different names.\n")),
			IsBinary:      false,
		},
		{
			PathB:     "tzu",
			LineStart: 1,
			Commit: &Commit{
				Hash:      "c7062674c17192caa284615ab2fa9778c6602164",
				Author:    "John Smith <john.smith@example.com>",
				Committer: "John Smith <john.smith@example.com>",
				Date:      newTime("Mon Jul 10 10:15:18 2023 -0400"),
				Message:   newStringBuilderValue("Create files\n"),
			},
			contentWriter: newBufferWithContent([]byte("The Nameless is the origin of Heaven and Earth;\nThe named is the mother of all things.\n\nTherefore let there always be non-being,\n  so we may see their subtlety,\nAnd let there always be being,\n  so we may see their outcome.\nThe two are the same,\nBut after they are produced,\n  they have different names.\nThey both may be called deep and profound.\nDeeper and more profound,\nThe door of all subtleties!\n")),
			IsBinary:      false,
		},
	}
}

const stagedDiffs = `diff --git a/aws b/aws
index 2ee133b..12b4843 100644
--- a/aws
+++ b/aws
@@ -1,7 +1,5 @@
-blah blaj
-
-this is the secret: [Default]
-Access key Id: AKIAILE3JG6KMS3HZGCA
-Secret Access Key: 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
-
-okay thank you bye
+[default]
+aws_access_key_id = AKIAXYZDQCEN4B6JSJQI
+aws_secret_access_key = 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
+output = json
+region = us-east-2

diff --git a/aws2 b/aws2
index 239b415..2ee133b 100644
--- a/aws2
+++ b/aws2
@@ -1,5 +1,7 @@
 blah blaj
 
-this is the secret: AKIA2E0A8F3B244C9986
+this is the secret: [Default]
+Access key Id: AKIAILE3JG6KMS3HZGCA
+Secret Access Key: 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
 
-okay thank you bye
\ No newline at end of file
+okay thank you bye

diff --git c/requirements.txt i/requirements.txt
new file mode 100644
index 00000000..e69de29b

diff --git a/core/runtime/src/main/java/io/quarkus/runtime/QuarkusApplication.java b/core/runtime/src/main/java/io/quarkus/runtime/QuarkusApplication.java
index 350685123d5..87d2220eb98 100644
--- a/core/runtime/src/main/java/io/quarkus/runtime/QuarkusApplication.java
+++ b/core/runtime/src/main/java/io/quarkus/runtime/QuarkusApplication.java
@@ -2,0 +3,4 @@
+/**
+ * This is usually used for command mode applications with a startup logic. The logic is executed inside
+ * {@link QuarkusApplication#run} method before the main application exits.
+ */

diff --git a/trufflehog_3.42.0_linux_arm64.tar.gz b/trufflehog_3.42.0_linux_arm64.tar.gz
new file mode 100644
index 0000000..0a7a5b4
Binary files /dev/null and b/trufflehog_3.42.0_linux_arm64.tar.gz differ

diff --git a/lao b/lao
deleted file mode 100644
index 635ef2c..0000000
--- a/lao
+++ /dev/null
@@ -1,11 +0,0 @@
-The Way that can be told of is not the eternal Way;
-The name that can be named is not the eternal name.
-The Nameless is the origin of Heaven and Earth;
-The Named is the mother of all things.
-Therefore let there always be non-being,
-  so we may see their subtlety,
-And let there always be being,
-  so we may see their outcome.
-The two are the same,
-But after they are produced,
-  they have different names.

diff --git a/tzu b/tzu.txt
similarity index 100%
rename from tzu
rename to tzu.txt

diff --git a/tzu b/tzu
index 5af88a8..c729cdb 100644
--- a/tzu
+++ b/tzu
@@ -11,3 +11,5 @@ But after they are produced,
 They both may be called deep and profound.
 Deeper and more profound,
 The door of all subtleties!
+
+Source: https://www.gnu.org/software/diffutils/manual/diffutils.html#An-Example-of-Unified-Format

diff --git a/lao b/lao
new file mode 100644
index 0000000..635ef2c
--- /dev/null
+++ b/lao
@@ -0,0 +1,11 @@
+The Way that can be told of is not the eternal Way;
+The name that can be named is not the eternal name.
+The Nameless is the origin of Heaven and Earth;
+The Named is the mother of all things.
+Therefore let there always be non-being,
+  so we may see their subtlety,
+And let there always be being,
+  so we may see their outcome.
+The two are the same,
+But after they are produced,
+  they have different names.
diff --git a/tzu b/tzu
new file mode 100644
index 0000000..5af88a8
--- /dev/null
+++ b/tzu
@@ -0,0 +1,13 @@
+The Nameless is the origin of Heaven and Earth;
+The named is the mother of all things.
+
+Therefore let there always be non-being,
+  so we may see their subtlety,
+And let there always be being,
+  so we may see their outcome.
+The two are the same,
+But after they are produced,
+  they have different names.
+They both may be called deep and profound.
+Deeper and more profound,
+The door of all subtleties!
`

const singleCommitMultiDiff = `commit 70001020fab32b1fcf2f1f0e5c66424eae649826 (HEAD -> master, origin/master, origin/HEAD)
Author: Dustin Decker <humanatcomputer@gmail.com>
AuthorDate:   Mon Mar 15 23:27:16 2021 -0700
Commit: Dustin Decker <humanatcomputer@gmail.com>
CommitDate:   Mon Mar 15 23:27:16 2021 -0700

    Update aws

diff --git a/aws b/aws
index 2ee133b..12b4843 100644
--- a/aws
+++ b/aws
@@ -1,7 +1,5 @@
-blah blaj
-
-this is the secret: [Default]
-Access key Id: AKIAILE3JG6KMS3HZGCA
-Secret Access Key: 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
-
-okay thank you bye
+[default]
+aws_access_key_id = AKIAXYZDQCEN4B6JSJQI
+aws_secret_access_key = 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
+output = json
+region = us-east-2

diff --git a/aws b/aws
index 239b415..2ee133b 100644
--- a/aws
+++ b/aws
@@ -1,5 +1,7 @@
 blah blaj
 
-this is the secret: AKIA2E0A8F3B244C9986
+this is the secret: [Default]
+Access key Id: AKIAILE3JG6KMS3HZGCA
+Secret Access Key: 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
 
-okay thank you bye
\ No newline at end of file
+okay thank you bye
`

const singleCommitSingleDiff = `commit 70001020fab32b1fcf2f1f0e5c66424eae649826 (HEAD -> master, origin/master, origin/HEAD)
Author: Dustin Decker <humanatcomputer@gmail.com>
AuthorDate:   Mon Mar 15 23:27:16 2021 -0700
Commit: Dustin Decker <humanatcomputer@gmail.com>
CommitDate:   Mon Mar 15 23:27:16 2021 -0700

    Update aws

diff --git a/aws b/aws
index 2ee133b..12b4843 100644
--- a/aws
+++ b/aws
@@ -1,7 +1,5 @@
-blah blaj
-
-this is the secret: [Default]
-Access key Id: AKIAILE3JG6KMS3HZGCA
-Secret Access Key: 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
-
-okay thank you bye
+[default]
+aws_access_key_id = AKIAXYZDQCEN4B6JSJQI
+aws_secret_access_key = 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
+output = json
+region = us-east-2
`
