package new

import (
	"context"
	"errors"

	regexp "github.com/wasilibs/go-re2"

	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/npm"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/npm/token"
)

type Scanner struct {
	token.BaseScanner
}

// Ensure the Scanner satisfies the interfaces at compile time.
var _ interface {
	detectors.Detector
	detectors.Versioner
} = (*Scanner)(nil)

func (s Scanner) Version() int { return int(npm.TokenNew) }

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"npm_"}
}

var tokenPat = regexp.MustCompile(`\b(npm_[a-zA-Z0-9]{36})\b`)

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)
	logCtx := logContext.AddLogger(ctx)

	// Deduplicate results for more efficient handling.
	tokens := make(map[string]struct{})
	for _, match := range tokenPat.FindAllStringSubmatch(dataStr, -1) {
		m := match[1]
		if detectors.StringShannonEntropy(m) < 4 {
			continue
		}
		tokens[m] = struct{}{}
	}

	// Handle results.
	for t := range tokens {
		r := detectors.Result{
			DetectorType: s.Type(),
			Raw:          []byte(t),
		}

		if verify {
			verified, extraData, vErr := s.VerifyToken(logCtx, dataStr, t)
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
