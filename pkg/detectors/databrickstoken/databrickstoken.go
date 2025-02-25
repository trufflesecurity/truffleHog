package databrickstoken

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
	domain = regexp.MustCompile(`\b([a-z0-9-]+(?:\.[a-z0-9-]+)*\.(cloud\.databricks\.com|gcp\.databricks\.com|azuredatabricks\.net))\b`)
	keyPat = regexp.MustCompile(`\b(dapi[0-9a-f]{32}(-\d)?)\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"databricks", "dapi"}
}

// FromData will find and optionally verify Databrickstoken secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	domainMatches := domain.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		for _, domainmatch := range domainMatches {
			resDomainMatch := strings.TrimSpace(domainmatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_DatabricksToken,
				Raw:          []byte(resMatch),
				RawV2:        []byte(resMatch + resDomainMatch),
			}

			if verify {
				if s.client == nil {
					s.client = detectors.GetHttpClientWithNoLocalAddresses()
				}
				req, err := http.NewRequestWithContext(ctx, "GET", "https://"+resDomainMatch+"/api/2.0/clusters/list", nil)
				if err != nil {
					continue
				}
				req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", resMatch))
				res, err := s.client.Do(req)
				if err == nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
					} else if res.StatusCode == 403 {
						// nothing to do here
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
	return detectorspb.DetectorType_DatabricksToken
}

func (s Scanner) Description() string {
	return "Databricks is a cloud data platform. Databricks tokens can be used to authenticate and interact with Databricks services and APIs."
}
