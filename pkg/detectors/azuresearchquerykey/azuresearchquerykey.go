package azuresearchquerykey

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"azure"}) + `\b([0-9a-zA-Z]{52})\b`)
	urlPat = regexp.MustCompile(detectors.PrefixRegex([]string{"azure"}) + `https:\/\/([0-9a-z]{5,40})\.search\.windows\.net\/indexes\/([0-9a-z]{5,40})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"azure"}
}

// FromData will find and optionally verify AzureSearchQueryKey secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	urlMatches := urlPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		for _, urlMatch := range urlMatches {
			resTrim := strings.Split(strings.TrimSpace(urlMatch[0]), " ")
			resUrlMatch := resTrim[len(resTrim)-1]

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_AzureSearchQueryKey,
				Raw:          []byte(resMatch),
				RawV2:        []byte(resMatch + resUrlMatch),
			}
			if verify {
				if s.client == nil {
					s.client = detectors.GetHttpClientWithNoLocalAddresses()
				}
				req, err := http.NewRequestWithContext(ctx, "GET", resUrlMatch+"/docs/$count?api-version=2023-10-01-Preview", nil)
				if err != nil {
					continue
				}
				req.Header.Add("api-key", resMatch)

				res, err := s.client.Do(req)
				if err == nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
					} else if res.StatusCode == 401 || res.StatusCode == 403 {
						// The secret is determinately not verified (nothing to do)
					} else {
						err = fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
						s1.SetVerificationError(err, resMatch)
					}
				} else {
					s1.SetVerificationError(err, resMatch)
				}
			}

			results = append(results, s1)
		}
	}
	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_AzureSearchQueryKey
}

func (s Scanner) Description() string {
	return "Azure Search Query Keys are used to authenticate search requests to Azure Search service. They should be kept confidential to prevent unauthorized access to search indexes and data."
}
