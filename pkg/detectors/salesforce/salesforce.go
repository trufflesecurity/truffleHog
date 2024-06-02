package salesforce

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

const (
	currentVersion = "58.0" // current Salesforce version
)

type Scanner struct {
	client *http.Client
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	accessTokenPat = regexp.MustCompile(`\b00[a-zA-Z0-9]{13}![a-zA-Z0-9_.]{96}\b`)
	instancePat    = regexp.MustCompile(`\bhttps://[0-9a-zA-Z-\.]{1,100}\.my\.salesforce\.com\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"salesforce"}
}

// FromData will find and optionally verify Salesforce secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	instanceMatches := instancePat.FindAllStringSubmatch(dataStr, -1)
	tokenMatches := accessTokenPat.FindAllStringSubmatch(dataStr, -1)

	for _, instance := range instanceMatches {

		instanceMatch := strings.TrimSpace(instance[0])

		for _, token := range tokenMatches {

			tokenMatch := strings.TrimSpace(token[0])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Salesforce,
				Raw:          []byte(tokenMatch),
			}

			if verify {
				if s.client == nil {
					s.client = detectors.GetHttpClientWithNoLocalAddresses()
				}

				req, err := http.NewRequestWithContext(ctx, "GET", instanceMatch+"/services/data/v"+currentVersion+"/query?q=SELECT+name+from+Account", nil)
				if err != nil {
					continue
				}
				req.Header.Set("Authorization", "Bearer "+tokenMatch)

				res, err := s.client.Do(req)

				if err != nil {
					// End execution, append Detector Result if request fails to prevent panic on response body checks
					s1.SetVerificationError(err, tokenMatch)
					results = append(results, s1)
					continue
				}

				verifiedBodyResponse, err := common.ResponseContainsSubstring(res.Body, "records")

				defer res.Body.Close()
				if res.StatusCode >= 200 && res.StatusCode < 300 && verifiedBodyResponse {
					s1.Verified = true
				} else if res.StatusCode >= 200 && res.StatusCode < 300 && !verifiedBodyResponse {
					s1.Verified = false
				} else if res.StatusCode == 401 {
					s1.Verified = false
				} else {
					err = fmt.Errorf("request to %v returned status %d with error %+v", res.Request.URL, res.StatusCode, err)
					s1.SetVerificationError(err, tokenMatch)
				}

			}

			results = append(results, s1)

		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Salesforce
}

func (s Scanner) Description() string {
	return "Salesforce is a cloud-based software company that provides customer relationship management (CRM) service. Salesforce access tokens can be used to authenticate and interact with Salesforce APIs."
}
