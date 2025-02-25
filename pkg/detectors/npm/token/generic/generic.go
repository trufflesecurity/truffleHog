package generic

import (
	"context"
	"errors"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/npm"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/npm/token"
	newToken "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/npm/token/new"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/npm/token/uuid"
)

type Scanner struct {
	token.BaseScanner
}

// Ensure the Scanner satisfies the interfaces at compile time.
var _ interface {
	detectors.Detector
	detectors.Versioner
} = (*Scanner)(nil)

func (s Scanner) Version() int { return int(npm.TokenGeneric) }

func (s Scanner) Keywords() []string {
	return []string{
		"npm",        // generic
		"_authToken", // npmrc
	}
}

var (
	// genericKeyPat should match all possible values for .npmrc auth tokens.
	genericKeyPat = regexp.MustCompile(`(?:_authToken|(?i:npm(?:[_.-]?config)?[_\-.]?token))['"]?(?:[ \t]*[:=][ \t]*|[ \t]+)(?:'([^']+)'|"([^"]+)"|([a-zA-Z0-9_+-][[:graph:]]{6,}[a-zA-Z0-9_+/=-]))`)
	uuidPat       = regexp.MustCompile("(?i)" + common.UUIDPattern)

	// TODO: Skip package-lock.json and yarn.lock, which are common sources of false positives.
	invalidKeyPat = func() *regexp.Regexp {
		return regexp.MustCompile(`(?i)(data\.token|process\.env\.[a-z_]+|-(assignments|defines|descope|inject-block|properties|providers|stream|string|substitute|whitespace-trim)|-(\d+\.\d+\.\d+|[a-z0-9-]+)\.tgz|registry\.npmjs\.org/[a-z_-]+/\d+\.\d+\.\d+)`)
	}()
)

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)
	logCtx := logContext.AddLogger(ctx)

	// Deduplicate results for more efficient handling.
	tokens := make(map[string]struct{})
	for _, match := range genericKeyPat.FindAllStringSubmatch(dataStr, -1) {
		_, t := firstNonEmptyMatch(match, 1)
		t = strings.TrimSpace(t)
		// Ignore results that can be handled by the v1 or v2 detectors.
		if uuid.TokenPat.MatchString(t) || newToken.TokenPat.MatchString(t) {
			continue
		} else if detectors.StringShannonEntropy(t) < 3 {
			continue
		} else if invalidKeyPat.MatchString(t) {
			continue
		}
		tokens[t] = struct{}{}
	}

	// Handle results.
	for t := range tokens {
		r := detectors.Result{
			DetectorType: s.Type(),
			Raw:          []byte(t),
		}

		if verify {
			verified, extraData, vErr := s.VerifyToken(logCtx, dataStr, t, false)
			r.Verified = verified
			r.ExtraData = extraData
			if vErr != nil {
				if errors.Is(vErr, detectors.ErrNoLocalIP) {
					continue
				}
				r.SetVerificationError(vErr)
			}
		}

		results = append(results, r)
	}

	return
}

// firstNonEmptyMatch returns the index and value of the first non-empty match.
// If no non-empty match is found, it will return: 0, "".
func firstNonEmptyMatch(matches []string, skip int) (int, string) {
	if len(matches) < skip {
		return 0, ""
	}
	// The first index is the entire matched string.
	for i, val := range matches[skip:] {
		if val != "" {
			return i + skip, val
		}
	}
	return 0, ""
}
