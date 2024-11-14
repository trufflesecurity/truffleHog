package geocodio

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

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"geocod"}) + `\b([a-z0-9]{39})\b`)
	searchPat = regexp.MustCompile(detectors.PrefixRegex([]string{"geocod"}) + `\b([a-zA-Z0-9\S]{7,30})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"geocod"}
}

// FromData will find and optionally verify Geocodio secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)
	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	searchMatches := searchPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		for _, searchMatch := range searchMatches {
			if len(searchMatch) != 2 {
				continue
			}
			resSearchMatch := strings.TrimSpace(searchMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Geocodio,
				Raw:          []byte(resMatch),
				RawV2:        []byte(resMatch + resSearchMatch),
			}

			if verify {
				req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://api.geocod.io/v1.6/geocode?q=%s&api_key=%s", resSearchMatch, resMatch), nil)
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
	return detectorspb.DetectorType_Geocodio
}

func (s Scanner) Description() string {
	return "Geocodio is a service that provides geocoding and reverse geocoding. Geocodio API keys can be used to convert addresses into geographic coordinates and vice versa."
}
