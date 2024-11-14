package fixerio

import (
	"context"
	"io"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"fixer"}) + `\b([A-Za-z0-9]{32})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"fixer"}
}

// FromData will find and optionally verify FixerIO secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_FixerIO,
			Raw:          []byte(resMatch),
		}

		if verify {
			req, err := http.NewRequestWithContext(ctx, "GET", "https://data.fixer.io/api/latest?access_key="+resMatch, nil)
			if err != nil {
				continue
			}

			res, err := client.Do(req)
			if err == nil {
				defer res.Body.Close()
				bodyBytes, err := io.ReadAll(res.Body)
				if err != nil {
					continue
				}
				body := string(bodyBytes)

				// if client_id and client_secret is valid -> 403 {"error":"invalid_grant","error_description":"Invalid authorization code"}
				// if invalid -> 401 {"error":"access_denied","error_description":"Unauthorized"}
				// ingenious!

				validResponse := strings.Contains(body, `"success": true`) || strings.Contains(body, `"info":"Access Restricted - Your current Subscription Plan does not support HTTPS Encryption."`)
				defer res.Body.Close()

				if res.StatusCode >= 200 && res.StatusCode < 300 && validResponse {
					s1.Verified = true
				}

			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_FixerIO
}

func (s Scanner) Description() string {
	return "Fixer.io is a foreign exchange rates and currency conversion API. Fixer.io API keys can be used to access and retrieve current and historical foreign exchange rates."
}
