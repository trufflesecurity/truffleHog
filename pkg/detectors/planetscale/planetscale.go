package planetscale

import (
	"context"
	"fmt"
	"net/http"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
	client *http.Client
}

var (
	defaultClient = common.SaneHttpClient()
	usernamePat   = regexp.MustCompile(`\b[a-z0-9]{12}\b`)
	passwordPat   = regexp.MustCompile(`\bpscale_tkn_[A-Za-z0-9_]{43}\b`)
)

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string {
	return []string{"pscale_tkn_"}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	usernameMatches := usernamePat.FindAllString(dataStr, -1)
	passwordMatches := passwordPat.FindAllString(dataStr, -1)

	for _, username := range usernameMatches {

		for _, password := range passwordMatches {
			credentials := fmt.Sprintf("%s:%s", username, password)

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_PlanetScale,
				Raw:          []byte(credentials),
			}

			if verify {
				client := s.client
				if client == nil {
					client = defaultClient
				}

				// Construct HTTP request
				req, err := http.NewRequestWithContext(ctx, "GET", "https://api.planetscale.com/v1/organizations", nil)
				if err != nil {
					continue
				}
				req.Header.Set("Authorization", credentials)
				req.Header.Set("accept", "application/json")

				// Send HTTP request
				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
						s1.AnalysisInfo = map[string]string{
							"id":    username,
							"token": password,
						}
					} else if res.StatusCode == 401 {
						// The secret is determinately not verified
						s1.Verified = false
					} else {
						err = fmt.Errorf("unexpected status code %d", res.StatusCode)
						s1.SetVerificationError(err, password)
					}
				} else {
					s1.SetVerificationError(err, password)
				}
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_PlanetScale
}

func (s Scanner) Description() string {
	return "PlanetScale is a database platform. PlanetScale tokens can be used to access and manage database instances."
}
