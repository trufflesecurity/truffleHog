package onepassword

import (
	"context"
	"encoding/base64"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	// Pattern to match "ops_" followed by a base64 encoded string
	keyPat = regexp.MustCompile(`\bops_([A-Za-z0-9+/]{100,}=*)`)
)

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string {
	return []string{"ops_"}
}

// FromData will find and optionally verify OnePassword Service Account tokens in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}

		token := match[0]

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_OnePassword,
			Raw:          []byte(token),
		}

		if verify {
			s1.Verified = verifyToken(token)
		}

		results = append(results, s1)
	}

	return results, nil
}

func verifyToken(token string) bool {
	// Remove the "ops_" prefix
	encodedJWT := token[4:]

	_, err := base64.StdEncoding.DecodeString(encodedJWT)

	return err == nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_OnePassword
}

func (s Scanner) Description() string {
	return "OnePassword Service Account tokens are used to read/write secrets for an entire 1Password account, often in CI/CD environments."
}
