package gitparse

import (
	"bytes"
	_ "embed"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/log"
)

var (
	//go:embed testdata/panic_diff_1.txt
	panicDiff1 []byte
)

type testCaseLine struct {
	latestState ParseState
	line        []byte
}

type testCase struct {
	passes   []testCaseLine
	fails    []testCaseLine
	function func(bool, ParseState, []byte) bool
}

func TestParsePanicDiff(t *testing.T) {
	// setup logger
	logger, sync := log.New("forager/scanner",
		log.WithConsoleSink(os.Stderr),
	)
	defer func() { _ = sync() }()
	context.SetDefaultLogger(logger)

	ctx := context.Background()
	parser := NewParser()
	commitCh := make(chan Commit, 64)
	parser.FromReader(ctx, io.NopCloser(bytes.NewReader(panicDiff1)), commitCh, false)
}

func TestLineChecks(t *testing.T) {
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
					DateLine,
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
		"dateLine": {
			passes: []testCaseLine{
				{
					AuthorLine,
					[]byte("Date:   Tue Jan 18 16:59:18 2022 -0800"),
				},
			},
			fails: []testCaseLine{
				{
					DateLine,
					[]byte(""),
				},
				{
					AuthorLine,
					[]byte("notcorrect"),
				},
			},
			function: isDateLine,
		},
		"messageStartLine": {
			passes: []testCaseLine{
				{
					DateLine,
					[]byte(""),
				},
			},
			fails: []testCaseLine{
				{
					AuthorLine,
					[]byte("Date:   Tue Jun 20 13:21:19 2023 -0700"),
				},
				{
					DateLine,
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
					DateLine,
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
					BinaryFileLine,
					[]byte("diff --git a/pkg/decoders/utf16_test.go b/pkg/decoders/utf16_test.go"),
				},
				{
					HunkContentLine,
					[]byte("diff --git a/pkg/decoders/utf8.go b/pkg/decoders/utf8.go"),
				},
			},
			fails: []testCaseLine{
				{
					DateLine,
					[]byte("    Make trace error message so newlines aren't escaped (#1396)"),
				},
				{
					MessageLine,
					[]byte("notcorrect"),
				},
			},
			function: isDiffLine,
		},
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

type messageParsingTestCase struct {
	data     string
	expected string
}

func TestMessageParsing(t *testing.T) {
	tests := []messageParsingTestCase{
		{
			data: `commit 70001020fab32b1fcf2f1f0e5c66424eae649826 (HEAD -> master, origin/master, origin/HEAD)
Author: Dustin Decker <humanatcomputer@gmail.com>
Date:   Mon Mar 15 23:27:16 2021 -0700

    Update aws

diff --git a/aws b/aws
index 2ee133b..12b4843 100644
--- a/aws
+++ b/aws
@@ -1,7 +1,5 @@
+[default]
 aws_access_key_id = AKIAXYZDQCEN4B6JSJQI
+aws_secret_access_key = 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
`,
			expected: "Update aws\n",
		},
		{
			data: `commit 74ffbd28787b3bb4e6953ce1c3ee6899af650bce
Author: Zachary Rice <zachary.rice@trufflesec.com>
Date:   Tue Jun 13 14:49:21 2023 -0500

    add a custom detector check for logging duplicate detector (#1394)
    
    * add a custom detector check for logging duplicate detector
    
    * use pb type

diff --git a/pkg/engine/engine.go b/pkg/engine/engine.go
index 090c6ba6..38d67dd2 100644
--- a/pkg/engine/engine.go
+++ b/pkg/engine/engine.go
@@ -165,7 +165,7 @@ func Start(ctx context.Context, options ...EngineOption) *Engine {
                seenDetectors := make(map[config.DetectorID]struct{}, len(dets))
                for _, det := range dets {
                        id := config.GetDetectorID(det)
-                       if _, ok := seenDetectors[id]; ok {
+                       if _, ok := seenDetectors[id]; ok && id.ID != detectorspb.DetectorType_CustomRegex {
                                ctx.Logger().Info("possible duplicate detector configured", "detector", id)
                        }
                        seenDetectors[id] = struct{}{}`,
			expected: `add a custom detector check for logging duplicate detector (#1394)

* add a custom detector check for logging duplicate detector

* use pb type
`,
		},
		{
			data: `commit a8bc99bfe2c7178d1d2de9aa2f8ea6752bcf02c8
Author: Michelle Purcell <92924207+michelle-purcell@users.noreply.github.com>
Date:   Tue Jun 27 13:48:04 2023 +0100

    Update docs/src/main/asciidoc/security-vulnerability-detection.adoc
    
    Co-authored-by: Sergey Beryozkin <sberyozkin@gmail.com>
    (cherry picked from commit 10f04b79e0ab3a331ac1bfae78d7ed399e243bf0)

diff --git a/docs/src/main/asciidoc/security-vulnerability-detection.adoc b/docs/src/main/asciidoc/security-vulnerability-detection.adoc
index 6e90300f9f6..e3cc8d1485f 100644
--- a/docs/src/main/asciidoc/security-vulnerability-detection.adoc
+++ b/docs/src/main/asciidoc/security-vulnerability-detection.adoc
@@ -139 +139 @@ You can adjust the expiry date if you need to.
-* xref:security-authentication-mechanisms.adoc#other-supported-authentication-mechanisms[Other supported authentication mechanisms]
\ No newline at end of file
+* xref:security-authentication-mechanisms.adoc[Authentication mechanisms in Quarkus]
\ No newline at end of file
`,
			expected: `Update docs/src/main/asciidoc/security-vulnerability-detection.adoc

Co-authored-by: Sergey Beryozkin <sberyozkin@gmail.com>
(cherry picked from commit 10f04b79e0ab3a331ac1bfae78d7ed399e243bf0)
`,
		},
	}

	for _, test := range tests {
		r := bytes.NewReader([]byte(test.data))
		commitChan := make(chan Commit)
		parser := NewParser()

		go func() {
			parser.FromReader(context.Background(), r, commitChan, false)
		}()
		for commit := range commitChan {
			if commit.Message.String() != test.expected {
				t.Errorf("Message does not match. Got:\n%s\nexpected:\n%s", commit.Message.String(), test.expected)
			}
		}
	}
}

func TestBinaryPathParse(t *testing.T) {
	cases := map[string]string{
		"Binary files /dev/null and b/plugin.sig differ\n":                    "plugin.sig",
		"Binary files /dev/null and b/ Lunch and Learn - HCDiag.pdf differ\n": " Lunch and Learn - HCDiag.pdf",
	}

	for name, expected := range cases {
		filename := pathFromBinaryLine([]byte(name))
		if filename != expected {
			t.Errorf("Expected: %s, Got: %s", expected, filename)
		}
	}
}

func newTime(timestamp string) time.Time {
	date, _ := time.Parse(defaultDateFormat, timestamp)
	return date
}

func newStringBuilderValue(value string) strings.Builder {
	builder := strings.Builder{}
	builder.Write([]byte(value))
	return builder
}

func TestCommitParsing(t *testing.T) {
	expected := expectedCommits()

	r := bytes.NewReader([]byte(commitLog))
	commitChan := make(chan Commit)
	parser := NewParser()
	go func() {
		parser.FromReader(context.Background(), r, commitChan, false)
	}()
	i := 0
	for commit := range commitChan {
		if len(expected) <= i {
			t.Errorf("Missing expected case for commit: %+v", commit)
			break
		}

		if !commit.Equal(&expected[i]) {
			t.Errorf("Commit does not match.\nexpected: %+v\n%s\nactual  : %+v\n%s", expected[i], expected[i].Message.String(), commit, commit.Message.String())
		}
		i++
	}
}

func TestIndividualCommitParsing(t *testing.T) {
	// Arrange
	expected := expectedCommits()
	commits := strings.Split(commitLog, "\ncommit ")
	for index, commit := range commits {
		if !strings.HasPrefix(commit, "commit") {
			commits[index] = "commit " + commit
		}
	}

	// Act
	for i, commit := range commits {
		r := bytes.NewReader([]byte(commit))
		commitChan := make(chan Commit)
		parser := NewParser()
		go func() {
			parser.FromReader(context.Background(), r, commitChan, false)
		}()
		j := 0
		for commit := range commitChan {
			if len(expected) <= i {
				t.Errorf("Missing expected case for commit: %+v", commit)
				break
			}

			// Assert
			if !commit.Equal(&expected[i]) {
				t.Errorf("Commit does not match.\nexpected: %+v\n%s\nactual  : %+v\n%s", expected[i], expected[j].Message.String(), commit, commit.Message.String())
			}
			j++
		}
	}
}

func TestStagedDiffParsing(t *testing.T) {
	expected := []Commit{
		{
			Hash:    "",
			Author:  "",
			Date:    newTime("0001-01-01 00:00:00 +0000 UTC"),
			Message: strings.Builder{},
			Diffs: []Diff{
				{
					PathB:     "aws",
					LineStart: 1,
					Content:   *bytes.NewBuffer([]byte("[default]\naws_access_key_id = AKIAXYZDQCEN4B6JSJQI\naws_secret_access_key = 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\noutput = json\nregion = us-east-2\n")),
					IsBinary:  false,
				},
				{
					PathB:     "aws2",
					LineStart: 1,
					Content:   *bytes.NewBuffer([]byte("\n\nthis is the secret: [Default]\nAccess key Id: AKIAILE3JG6KMS3HZGCA\nSecret Access Key: 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\n\nokay thank you bye\n")),
					IsBinary:  false,
				},
				{
					PathB:     "core/runtime/src/main/java/io/quarkus/runtime/QuarkusApplication.java",
					LineStart: 3,
					Content:   *bytes.NewBuffer([]byte("/**\n * This is usually used for command mode applications with a startup logic. The logic is executed inside\n * {@link QuarkusApplication#run} method before the main application exits.\n */\n")),
					IsBinary:  false,
				},
				{
					PathB:    "trufflehog_3.42.0_linux_arm64.tar.gz",
					IsBinary: true,
				},
				{
					PathB:     "tzu",
					LineStart: 11,
					Content:   *bytes.NewBuffer([]byte("\n\n\n\nSource: https://www.gnu.org/software/diffutils/manual/diffutils.html#An-Example-of-Unified-Format\n")),
					IsBinary:  false,
				},
				{
					PathB:     "lao",
					LineStart: 1,
					Content:   *bytes.NewBuffer([]byte("The Way that can be told of is not the eternal Way;\nThe name that can be named is not the eternal name.\nThe Nameless is the origin of Heaven and Earth;\nThe Named is the mother of all things.\nTherefore let there always be non-being,\n  so we may see their subtlety,\nAnd let there always be being,\n  so we may see their outcome.\nThe two are the same,\nBut after they are produced,\n  they have different names.\n")),
					IsBinary:  false,
				},
				{
					PathB:     "tzu",
					LineStart: 1,
					Content:   *bytes.NewBuffer([]byte("The Nameless is the origin of Heaven and Earth;\nThe named is the mother of all things.\n\nTherefore let there always be non-being,\n  so we may see their subtlety,\nAnd let there always be being,\n  so we may see their outcome.\nThe two are the same,\nBut after they are produced,\n  they have different names.\nThey both may be called deep and profound.\nDeeper and more profound,\nThe door of all subtleties!\n")),
					IsBinary:  false,
				},
			},
		},
	}

	r := bytes.NewReader([]byte(stagedDiffs))
	commitChan := make(chan Commit)
	parser := NewParser()
	go func() {
		parser.FromReader(context.Background(), r, commitChan, true)
	}()
	i := 0
	for commit := range commitChan {
		if len(expected) <= i {
			t.Errorf("Missing expected case for commit: %+v", commit)
			break
		}

		if !commit.Equal(&expected[i]) {
			t.Errorf("Commit does not match.\nexpected:\n%+v\n\nactual:\n%+v\n", expected[i], commit)
		}
		i++
	}
}

func TestCommitParseFailureRecovery(t *testing.T) {
	expected := []Commit{
		{
			Hash:    "df393b4125c2aa217211b2429b8963d0cefcee27",
			Author:  "Stephen <stephen@egroat.com>",
			Date:    newTime("Wed Dec 06 14:44:41 2017 -0800"),
			Message: newStringBuilderValue("Add travis testing\n"),
			Diffs: []Diff{
				{
					PathB:     ".travis.yml",
					LineStart: 1,
					Content:   *bytes.NewBuffer([]byte("language: python\npython:\n  - \"2.6\"\n  - \"2.7\"\n  - \"3.2\"\n  - \"3.3\"\n  - \"3.4\"\n  - \"3.5\"\n  - \"3.5-dev\" # 3.5 development branch\n  - \"3.6\"\n  - \"3.6-dev\" # 3.6 development branch\n  - \"3.7-dev\" # 3.7 development branch\n  - \"nightly\"\n")),
					IsBinary:  false,
				},
			},
		},
		{
			Hash:    "3d76a97faad96e0f326afb61c232b9c2a18dca35",
			Author:  "John Smith <john.smith@example.com>",
			Date:    newTime("Tue Jul 11 18:03:54 2023 -0400"),
			Message: strings.Builder{},
			Diffs:   []Diff{},
		},
		{
			Hash:    "7bd16429f1f708746dabf970e54b05d2b4734997",
			Author:  "John Smith <john.smith@example.com>",
			Date:    newTime("Tue Jul 11 18:10:49 2023 -0400"),
			Message: newStringBuilderValue("Change file\n"),
			Diffs: []Diff{
				{
					PathB:     "tzu",
					LineStart: 11,
					Content:   *bytes.NewBuffer([]byte("\n\n\n\nSource: https://www.gnu.org/software/diffutils/manual/diffutils.html#An-Example-of-Unified-Format\n")),
					IsBinary:  false,
				},
			},
		},
	}

	r := bytes.NewReader([]byte(recoverableCommits))
	commitChan := make(chan Commit)
	parser := NewParser()
	go func() {
		parser.FromReader(context.Background(), r, commitChan, false)
	}()
	i := 0
	for commit := range commitChan {
		if len(expected) <= i {
			t.Errorf("Missing expected case for commit: %+v", commit)
			break
		}

		if !commit.Equal(&expected[i]) {
			t.Errorf("Commit does not match.\nexpected: %+v\n\nactual  : %+v\n", expected[i], commit)
		}
		i++
	}
}

const recoverableCommits = `commit df393b4125c2aa217211b2429b8963d0cefcee27
Author: Stephen <stephen@egroat.com>
Date:   Wed Dec 06 14:44:41 2017 -0800

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
Date:   Tue Jul 11 18:03:54 2023 -0400

diff --git a/sample.txt b/sample.txt
new file mode 100644
index 0000000..af5626b
--- /dev/null
+++ b/sample.txt
@@ -0,0 +1 @@
!!!ERROR!!!

commit 7bd16429f1f708746dabf970e54b05d2b4734997 (HEAD -> master)
Author: John Smith <john.smith@example.com>
Date:   Tue Jul 11 18:10:49 2023 -0400

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
	expected := []Commit{
		{
			Hash:    "",
			Author:  "",
			Date:    newTime("0001-01-01 00:00:00 +0000 UTC"),
			Message: strings.Builder{},
			Diffs: []Diff{
				{
					PathB:     "aws",
					LineStart: 1,
					Content:   *bytes.NewBuffer([]byte("[default]\naws_access_key_id = AKIAXYZDQCEN4B6JSJQI\naws_secret_access_key = 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\noutput = json\nregion = us-east-2\n")),
					IsBinary:  false,
				},
				{
					PathB:     "tzu",
					LineStart: 11,
					Content:   *bytes.NewBuffer([]byte("\n\n\n\nSource: https://www.gnu.org/software/diffutils/manual/diffutils.html#An-Example-of-Unified-Format\n")),
					IsBinary:  false,
				},
				{
					PathB:     "tzu",
					LineStart: 1,
					Content:   *bytes.NewBuffer([]byte("The Nameless is the origin of Heaven and Earth;\nThe named is the mother of all things.\n\nTherefore let there always be non-being,\n  so we may see their subtlety,\nAnd let there always be being,\n  so we may see their outcome.\nThe two are the same,\nBut after they are produced,\n  they have different names.\nThey both may be called deep and profound.\nDeeper and more profound,\nThe door of all subtleties!\n")),
					IsBinary:  false,
				},
			},
		},
	}

	r := bytes.NewReader([]byte(recoverableDiffs))
	commitChan := make(chan Commit)
	parser := NewParser()
	go func() {
		parser.FromReader(context.Background(), r, commitChan, true)
	}()
	i := 0
	for commit := range commitChan {
		if len(expected) <= i {
			t.Errorf("Missing expected case for commit: %+v", commit)
			break
		}

		if !commit.Equal(&expected[i]) {
			t.Errorf("Commit does not match.\nexpected: %+v\n\nactual  : %+v\n", expected[i], commit)
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
	for i := 0; i <= parser.maxDiffSize/1024+10; i++ {
		builder.WriteString("+" + strings.Repeat("0", 1024) + "\n")
	}
	bigReader := strings.NewReader(builder.String())

	commitChan := make(chan Commit, 1)                                      // Buffer to prevent blocking
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second) // Timeout to prevent long wait
	defer cancel()

	go func() {
		parser.FromReader(ctx, bigReader, commitChan, false)
	}()

	select {
	case commit := <-commitChan:
		if commit.Diffs[0].Content.Len() > parser.maxDiffSize+1024 {
			t.Errorf("diff did not match MaxDiffSize. Got: %d, expected (max): %d", commit.Diffs[0].Content.Len(), parser.maxDiffSize+1024)
		}
	case <-ctx.Done():
		t.Fatal("Test timed out")
	}
}

func TestMaxCommitSize(t *testing.T) {
	parser := NewParser(WithMaxCommitSize(1))
	commitText := bytes.Buffer{}
	commitText.WriteString(singleCommitMultiDiff)
	commitChan := make(chan Commit)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(1)*time.Second)
	defer cancel()
	go func() {
		parser.FromReader(ctx, &commitText, commitChan, false)
	}()
	commitCount := 0
	for range commitChan {
		commitCount++
	}
	if commitCount != 2 {
		t.Errorf("Commit count does not match. Got: %d, expected: %d", commitCount, 2)
	}

}

const commitLog = `commit fd6e99e7a80199b76a694603be57c5ade1de18e7
Author: Jaliborc <jaliborc@gmail.com>
Date:   Mon Apr 25 16:28:06 2011 +0100

    Added Unusable coloring

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
Date:   Tue Jul 11 22:26:11 2023 -0400

commit c904e0f5cd9f30ae520c66bd5f70806219fe7ca2 (HEAD -> master)
Author: John Smith <john.smith@example.com>
Date:   Mon Jul 10 10:17:11 2023 -0400

    Empty Commit

commit 3d76a97faad96e0f326afb61c232b9c2a18dca35 (HEAD -> master)
Author: John Smith <john.smith@example.com>
Date:   Tue Jul 11 18:03:54 2023 -0400

diff --git a/sample.txt b/sample.txt
new file mode 100644
index 0000000..af5626b
--- /dev/null
+++ b/sample.txt
@@ -0,0 +1 @@
+Hello, world!

commit df393b4125c2aa217211b2429b8963d0cefcee27
Author: Stephen <stephen@egroat.com>
Date:   Wed Dec 06 14:44:41 2017 -0800

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
Date:   Thu Jan 13 12:02:24 2022 -0800

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
Date:   Tue Jul 11 18:43:22 2023 -0400

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
Date:   Fri Jul 7 17:44:26 2023 +0100

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
Date:   Mon Jul 10 01:22:32 2023 +0800

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
Date:   Tue Jul 11 18:12:21 2023 -0400

    Delete binary file

diff --git a/trufflehog_3.42.0_linux_arm64.tar.gz b/trufflehog_3.42.0_linux_arm64.tar.gz
deleted file mode 100644
index 7682212..0000000
Binary files a/trufflehog_3.42.0_linux_arm64.tar.gz and /dev/null differ

commit afc6dc5d47f28366638da877ecb6b819c69e659b
Author: John Smith <john.smith@example.com>
Date:   Mon Jul 10 12:21:33 2023 -0400

    Change binary file

diff --git a/trufflehog_3.42.0_linux_arm64.tar.gz b/trufflehog_3.42.0_linux_arm64.tar.gz
index 0a7a5b4..7682212 100644
Binary files a/trufflehog_3.42.0_linux_arm64.tar.gz and b/trufflehog_3.42.0_linux_arm64.tar.gz differ

commit 638595917417c5c8a956937b28c5127719023363
Author: John Smith <john.smith@example.com>
Date:   Mon Jul 10 12:20:35 2023 -0400

    Add binary file

diff --git a/trufflehog_3.42.0_linux_arm64.tar.gz b/trufflehog_3.42.0_linux_arm64.tar.gz
new file mode 100644
index 0000000..0a7a5b4
Binary files /dev/null and b/trufflehog_3.42.0_linux_arm64.tar.gz differ

commit ce0f5d1fe0272f180ccb660196f439c0c2f4ec8e (HEAD -> master)
Author: John Smith <john.smith@example.com>
Date:   Tue Jul 11 18:08:52 2023 -0400

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
Date:   Mon Jul 10 14:17:04 2023 -0400

    Rename file

diff --git a/tzu b/tzu.txt
similarity index 100%
rename from tzu
rename to tzu.txt

commit 7bd16429f1f708746dabf970e54b05d2b4734997 (HEAD -> master)
Author: John Smith <john.smith@example.com>
Date:   Tue Jul 11 18:10:49 2023 -0400

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
Date:   Mon Jul 10 10:15:18 2023 -0400

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

// This throws a nasty panic if it's a top-level var.
func expectedCommits() []Commit {
	return []Commit{
		// a
		{
			Hash:    "fd6e99e7a80199b76a694603be57c5ade1de18e7",
			Author:  "Jaliborc <jaliborc@gmail.com>",
			Date:    newTime("Mon Apr 25 16:28:06 2011 +0100"),
			Message: newStringBuilderValue("Added Unusable coloring\n"),
			Diffs: []Diff{
				{
					PathB:     "components/item.lua",
					LineStart: 9,
					Content:   *bytes.NewBuffer([]byte("\n\nlocal Unfit = LibStub('Unfit-1.0')\n\n\n")),
					IsBinary:  false,
				},
				{
					PathB:     "embeds.xml",
					LineStart: 6,
					Content:   *bytes.NewBuffer([]byte("\n\n       <Script file=\"libs\\Unfit-1.0\\Unfit-1.0.lua\"/>\n\n\n\n")),
					IsBinary:  false,
				},
				{
					PathB:     "libs/Unfit-1.0",
					LineStart: 1,
					Content:   *bytes.NewBuffer([]byte("Subproject commit 0000000000000000000000000000000000000000\n")),
					IsBinary:  false,
				},
			},
		},
		// Empty commit and message. Lord help us.
		{
			Hash:    "4727ffb7ad6dc5130bf4b4dd166e00705abdd018",
			Author:  "John Smith <john.smith@example.com>",
			Date:    newTime("Tue Jul 11 22:26:11 2023 -0400"),
			Message: strings.Builder{},
			Diffs:   []Diff{},
		},
		// Empty commit.
		{
			Hash:    "c904e0f5cd9f30ae520c66bd5f70806219fe7ca2",
			Author:  "John Smith <john.smith@example.com>",
			Date:    newTime("Mon Jul 10 10:17:11 2023 -0400"),
			Message: newStringBuilderValue("Empty Commit\n"),
			Diffs:   []Diff{},
		},
		{
			Hash:    "3d76a97faad96e0f326afb61c232b9c2a18dca35",
			Author:  "John Smith <john.smith@example.com>",
			Date:    newTime("Tue Jul 11 18:03:54 2023 -0400"),
			Message: strings.Builder{},
			Diffs: []Diff{
				{
					PathB:     "sample.txt",
					LineStart: 1,
					Content:   *bytes.NewBuffer([]byte("Hello, world!\n")),
					IsBinary:  false,
				},
			},
		},
		{
			Hash:    "df393b4125c2aa217211b2429b8963d0cefcee27",
			Author:  "Stephen <stephen@egroat.com>",
			Date:    newTime("Wed Dec 06 14:44:41 2017 -0800"),
			Message: newStringBuilderValue("Add travis testing\n"),
			Diffs: []Diff{
				{
					PathB:     ".gitignore",
					LineStart: 1,
					Content:   *bytes.NewBuffer([]byte("\n\n\n**/__pycache__/\n**/*.pyc\n")),
					IsBinary:  false,
				},
				{
					PathB:     ".travis.yml",
					LineStart: 1,
					Content: *bytes.NewBuffer([]byte(`language: python
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
			},
		},
		{
			Hash:    "4218c39d99b5f30153f62471c1be1c1596f0a4d4",
			Author:  "Dustin Decker <dustin@trufflesec.com>",
			Date:    newTime("Thu Jan 13 12:02:24 2022 -0800"),
			Message: newStringBuilderValue("Initial CLI w/ partially implemented Git source and demo detector (#1)\n"),
			Diffs: []Diff{
				{
					PathB:     "Makefile",
					LineStart: 1,
					Content: *bytes.NewBuffer([]byte(`PROTOS_IMAGE=us-docker.pkg.dev/thog-artifacts/public/go-ci-1.17-1

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
			},
		},
		{
			Hash:    "934cf5d255fd8e28b33f5a6ba64276caf0b284bf",
			Author:  "John Smith <john.smith@example.com>",
			Date:    newTime("Tue Jul 11 18:43:22 2023 -0400"),
			Message: newStringBuilderValue("Test toFile/plusLine parsing\n"),
			Diffs: []Diff{
				{
					PathB:     "plusLine.txt",
					LineStart: 1,
					Content:   *bytes.NewBuffer([]byte("-- test\n++ test\n\n")),
					IsBinary:  false,
				},
			},
		},
		{
			Hash:    "2a5d703b02b52d65c65ee9f7928f158b919ab741",
			Author:  "Sergey Beryozkin <sberyozkin@gmail.com>",
			Date:    newTime("Fri Jul 7 17:44:26 2023 +0100"),
			Message: newStringBuilderValue("Do not refresh OIDC session if the user is requesting logout\n"),
			Diffs: []Diff{
				{
					PathB:     "extensions/oidc/runtime/src/main/java/io/quarkus/oidc/runtime/BackChannelLogoutTokenCache.java",
					LineStart: 45,
					Content:   *bytes.NewBuffer([]byte("\n\n    public boolean containsTokenVerification(String token) {\n        return cacheMap.containsKey(token);\n    }\n\n\n\n\n")),
					IsBinary:  false,
				},
				{
					PathB:     "extensions/oidc/runtime/src/main/java/io/quarkus/oidc/runtime/CodeAuthenticationMechanism.java",
					LineStart: 1023,
					Content:   *bytes.NewBuffer([]byte("\n\n    private boolean isRpInitiatedLogout(RoutingContext context, TenantConfigContext configContext) {\n\n\n")),
					IsBinary:  false,
				},
				{
					PathB:     "extensions/oidc/runtime/src/main/java/io/quarkus/oidc/runtime/CodeAuthenticationMechanism.java",
					LineStart: 1214,
					Content:   *bytes.NewBuffer([]byte("\n\n\n\n    private class LogoutCall implements Function<SecurityIdentity, Uni<?>> {\n        RoutingContext context;\n        TenantConfigContext configContext;\n        String idToken;\n\n        LogoutCall(RoutingContext context, TenantConfigContext configContext, String idToken) {\n            this.context = context;\n            this.configContext = configContext;\n            this.idToken = idToken;\n        }\n\n        @Override\n        public Uni<Void> apply(SecurityIdentity identity) {\n            if (isRpInitiatedLogout(context, configContext)) {\n                LOG.debug(\"Performing an RP initiated logout\");\n                fireEvent(SecurityEvent.Type.OIDC_LOGOUT_RP_INITIATED, identity);\n                return buildLogoutRedirectUriUni(context, configContext, idToken);\n            }\n            if (isBackChannelLogoutPendingAndValid(configContext, identity)\n                    || isFrontChannelLogoutValid(context, configContext,\n                            identity)) {\n                return removeSessionCookie(context, configContext.oidcConfig)\n                        .map(new Function<Void, Void>() {\n                            @Override\n                            public Void apply(Void t) {\n                                throw new LogoutException();\n                            }\n                        });\n\n            }\n            return VOID_UNI;\n        }\n    }\n\n")),
					IsBinary:  false,
				},
				{
					PathB:     "integration-tests/oidc-wiremock/src/main/resources/application.properties",
					LineStart: 20,
					Content:   *bytes.NewBuffer([]byte("\n\n\nquarkus.oidc.code-flow.token.refresh-expired=true\nquarkus.oidc.code-flow.token.refresh-token-time-skew=5M\n\n\n")),
					IsBinary:  false,
				},
				// WTF, shouldn't this be filtered out?
				{
					PathB:     "integration-tests/oidc-wiremock/src/test/java/io/quarkus/it/keycloak/CodeFlowAuthorizationTest.java",
					LineStart: 6,
					Content:   *bytes.NewBuffer([]byte("\n\n\n\n\n\n")),
					IsBinary:  false,
				},
				{
					PathB:     "integration-tests/oidc-wiremock/src/test/java/io/quarkus/it/keycloak/CodeFlowAuthorizationTest.java",
					LineStart: 76,
					Content:   *bytes.NewBuffer([]byte("\n\n            // Logout\n\n\n\n")),
					IsBinary:  false,
				},
			},
		},
		{
			Hash:    "2a057632d7f5fa3d1c77b9aa037263211c0e0290",
			Author:  "rjtmahinay <rjt.mahinay@gmail.com>",
			Date:    newTime("Mon Jul 10 01:22:32 2023 +0800"),
			Message: newStringBuilderValue("Add QuarkusApplication javadoc\n\n* Fix #34463\n"),
			Diffs: []Diff{
				{
					PathB:     "core/runtime/src/main/java/io/quarkus/runtime/QuarkusApplication.java",
					LineStart: 3,
					Content:   *bytes.NewBuffer([]byte("/**\n * This is usually used for command mode applications with a startup logic. The logic is executed inside\n * {@link QuarkusApplication#run} method before the main application exits.\n */\n")),
					IsBinary:  false,
				},
			},
		},
		{
			Hash:    "bca2d17491015ea1522f34517223b5a366aea73c",
			Author:  "John Smith <john.smith@example.com>",
			Date:    newTime("Tue Jul 11 18:12:21 2023 -0400"),
			Message: newStringBuilderValue("Delete binary file\n"),
			Diffs:   []Diff{},
		},
		{
			Hash:    "afc6dc5d47f28366638da877ecb6b819c69e659b",
			Author:  "John Smith <john.smith@example.com>",
			Date:    newTime("Mon Jul 10 12:21:33 2023 -0400"),
			Message: newStringBuilderValue("Change binary file\n"),
			Diffs: []Diff{
				{
					PathB:    "trufflehog_3.42.0_linux_arm64.tar.gz",
					IsBinary: true,
				},
			},
		},
		{
			Hash:    "638595917417c5c8a956937b28c5127719023363",
			Author:  "John Smith <john.smith@example.com>",
			Date:    newTime("Mon Jul 10 12:20:35 2023 -0400"),
			Message: newStringBuilderValue("Add binary file\n"),
			Diffs: []Diff{
				{
					PathB:    "trufflehog_3.42.0_linux_arm64.tar.gz",
					IsBinary: true,
				},
			},
		},
		{
			Hash:    "ce0f5d1fe0272f180ccb660196f439c0c2f4ec8e",
			Author:  "John Smith <john.smith@example.com>",
			Date:    newTime("Tue Jul 11 18:08:52 2023 -0400"),
			Message: newStringBuilderValue("Delete file\n"),
			Diffs:   []Diff{},
		},
		{
			Hash:    "d606a729383371558473b70a6a7b1ca264b0d205",
			Author:  "John Smith <john.smith@example.com>",
			Date:    newTime("Mon Jul 10 14:17:04 2023 -0400"),
			Message: newStringBuilderValue("Rename file\n"),
			Diffs:   []Diff{},
		},
		{
			Hash:    "7bd16429f1f708746dabf970e54b05d2b4734997",
			Author:  "John Smith <john.smith@example.com>",
			Date:    newTime("Tue Jul 11 18:10:49 2023 -0400"),
			Message: newStringBuilderValue("Change file\n"),
			Diffs: []Diff{
				{
					PathB:     "tzu",
					LineStart: 11,
					Content:   *bytes.NewBuffer([]byte("\n\n\n\nSource: https://www.gnu.org/software/diffutils/manual/diffutils.html#An-Example-of-Unified-Format\n")),
					IsBinary:  false,
				},
			},
		},
		{
			Hash:    "c7062674c17192caa284615ab2fa9778c6602164",
			Author:  "John Smith <john.smith@example.com>",
			Date:    newTime("Mon Jul 10 10:15:18 2023 -0400"),
			Message: newStringBuilderValue("Create files\n"),
			Diffs: []Diff{
				{
					PathB:     "lao",
					LineStart: 1,
					Content:   *bytes.NewBuffer([]byte("The Way that can be told of is not the eternal Way;\nThe name that can be named is not the eternal name.\nThe Nameless is the origin of Heaven and Earth;\nThe Named is the mother of all things.\nTherefore let there always be non-being,\n  so we may see their subtlety,\nAnd let there always be being,\n  so we may see their outcome.\nThe two are the same,\nBut after they are produced,\n  they have different names.\n")),
					IsBinary:  false,
				},
				{
					PathB:     "tzu",
					LineStart: 1,
					Content:   *bytes.NewBuffer([]byte("The Nameless is the origin of Heaven and Earth;\nThe named is the mother of all things.\n\nTherefore let there always be non-being,\n  so we may see their subtlety,\nAnd let there always be being,\n  so we may see their outcome.\nThe two are the same,\nBut after they are produced,\n  they have different names.\nThey both may be called deep and profound.\nDeeper and more profound,\nThe door of all subtleties!\n")),
					IsBinary:  false,
				},
			},
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
Date:   Mon Mar 15 23:27:16 2021 -0700

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
Date:   Mon Mar 15 23:27:16 2021 -0700

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
