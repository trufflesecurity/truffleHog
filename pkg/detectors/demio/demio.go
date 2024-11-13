package demio

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
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives
	keyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"demio"}) + `\b([a-z0-9A-Z]{32})\b`)
	secretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"demio"}) + `\b([a-z0-9A-Z]{10,20})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"demio"}
}

// FromData will find and optionally verify Demio secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	idMatches := secretPat.FindAllStringSubmatch(dataStr, -1)
	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])
		for _, idmatch := range idMatches {
			if len(idmatch) != 2 {
				continue
			}
			resIdMatch := strings.TrimSpace(idmatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Demio,
				Raw:          []byte(resMatch),
			}

			if verify {
				url := fmt.Sprintf("https://my.demio.com/api/v1/ping/query?api_key=%s&api_secret=%s", resMatch, resIdMatch)
				req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
				if err != nil {
					continue
				}
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
	return detectorspb.DetectorType_Demio
}

func (s Scanner) Description() string {
	return "Demio is a webinar platform that allows users to host, promote, and analyze webinars. Demio API keys can be used to access and manage webinar data."
}
