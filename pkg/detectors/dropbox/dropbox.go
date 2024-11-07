package dropbox

import (
	"context"
	"fmt"
	"io"
	"net/http"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{ client *http.Client }

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	// Dropbox API keys typically start with 'sl.u.' followed by a long string of alphanumeric characters.
	// Based on testing, observed key lengths were around 1309 characters.
	// However, to account for potential variations in key length, the regex pattern is set to match
	// keys that are at least 256 characters long after the 'sl.u.' prefix.
	//
	// As per Dropbox API documentation:
	// Access tokens provided by Dropbox should be treated as opaque.
	// Applications must support variable token size with tokens capable of exceeding 1KB.
	// For more information on Dropbox API authentication, see: https://www.dropbox.com/developers/documentation/http/documentation
	keyPat = regexp.MustCompile(`\bsl\.(?:u\.|B)[0-9a-zA-Z_-]{130,}\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string { return []string{"sl.u.", "sl.B"} }

// FromData will find and optionally verify Dropbox secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[0]] = struct{}{}
	}

	for match := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Dropbox,
			Raw:          []byte(match),
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			isVerified, verificationErr := verifyMatch(ctx, client, match)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr, match)
		}

		results = append(results, s1)
	}

	return
}

func verifyMatch(ctx context.Context, client *http.Client, token string) (bool, error) {
	const baseURL = "https://api.dropboxapi.com/2/check/user"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL, nil)
	if err != nil {
		return false, nil
	}
	req.Header.Add("Authorization", "Bearer "+token)

	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized:
		// 401 access token not found
		// The secret is determinately not verified (nothing to do)
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Dropbox
}

func (s Scanner) Description() string {
	return "Dropbox is a file hosting service that offers cloud storage, file synchronization, personal cloud, and client software. Dropbox API keys can be used to access and manage files and folders in a Dropbox account."
}
