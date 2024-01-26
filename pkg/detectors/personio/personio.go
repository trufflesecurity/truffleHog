package personio

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	// Key is always 48 characters long, prefix is always papi-
	keyPat = regexp.MustCompile(`\b(papi-[0-9a-zA-Z]{48})\b`)
	// ID is always a guid, prefixed by papi-
	idPat = regexp.MustCompile(`\b(papi-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"papi"}
}

// FromData will find and optionally verify Personio secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	idMatches := idPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		for _, idMatch := range idMatches {
			if len(idMatch) != 2 {
				continue
			}

			resIdMatch := strings.TrimSpace(idMatch[1])
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Personio,
				Raw:          []byte(resMatch),
			}

			if verify {
				client := s.client
				if client == nil {
					client = defaultClient
				}
				payload := strings.NewReader(fmt.Sprintf(`{"client_id":"%s","client_secret":"%s"}`, resIdMatch, resMatch))
				req, err := http.NewRequestWithContext(ctx, "POST", "https://api.personio.de/v1/auth", payload)
				if err != nil {
					continue
				}
				req.Header.Add("accept", "application/json")
				req.Header.Add("content-type", "application/json")

				res, err := client.Do(req)

				if err == nil {

					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
					} else if res.StatusCode == 401 || res.StatusCode == 403 {
						// The secret is determinately not verified (nothing to do)
						// 403 is returned if invalid key is used for existing key id
					} else {
						err = fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
						s1.SetVerificationError(err, resMatch)
					}
				} else {
					s1.SetVerificationError(err, resMatch)
				}
			}

			// This function will check false positives for common test words, but also it will make sure the key appears 'random' enough to be a real key.
			if !s1.Verified && detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
				continue
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Personio
}
