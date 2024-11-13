package duply

import (
	"context"
	"net/http"
	"strings"
	"time"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"duply"}) + `\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`)
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"duply"}) + `\b([0-9A-Z]{7}-[0-9A-Z]{7}-[0-9A-Z]{7}-[0-9A-Z]{7})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"duply"}
}

// FromData will find and optionally verify Duply secrets in a given set of bytes.
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
				DetectorType: detectorspb.DetectorType_Duply,
				Raw:          []byte(resMatch),
			}

			if verify {
				timeout := 10 * time.Second
				client.Timeout = timeout
				req, err := http.NewRequestWithContext(ctx, "GET", "https://gen.duply.co/v1/usage", nil)
				if err != nil {
					continue
				}
				req.Header.Add("Content-Type", "application/json")
				req.SetBasicAuth(resIdMatch, resMatch)

				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
					}
				}
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Duply
}

func (s Scanner) Description() string {
	return "An API for generating images. API keys can fetch and create images."
}
