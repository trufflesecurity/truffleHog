package okta

import (
	"context"
	"fmt"
	"io"
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
	domainPat = regexp.MustCompile(`\b[a-z0-9-]{1,40}\.okta(?:preview|-emea){0,1}\.com\b`)
	tokenPat  = regexp.MustCompile(`\b00[a-zA-Z0-9_-]{40}\b`)
	// TODO: Oauth client secrets
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{".okta"}
}

// FromData will find and optionally verify Okta secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	for _, tokenMatch := range tokenPat.FindAll(data, -1) {
		token := string(tokenMatch)

		for _, domainMatch := range domainPat.FindAll(data, -1) {
			domain := string(domainMatch)

			result := detectors.Result{
				DetectorType: detectorspb.DetectorType_Okta,
				Raw:          []byte(token),
				RawV2:        []byte(fmt.Sprintf("%s:%s", domain, token)),
			}

			if verify {
				if s.client == nil {
					s.client = detectors.GetHttpClientWithNoLocalAddresses()
				}
				// curl -v -X GET \
				// -H "Accept: application/json" \
				// -H "Content-Type: application/json" \
				// -H "Authorization: Bearer token" \
				// "https://subdomain.okta.com/api/v1/users/me"
				//

				url := fmt.Sprintf("https://%s/api/v1/users/me", domain)
				req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
				if err != nil {
					return results, err
				}
				req.Header.Set("Accept", "application/json")
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Authorization", fmt.Sprintf("SSWS %s", token))

				resp, err := s.client.Do(req)
				if err != nil {
					continue
				}
				defer resp.Body.Close()
				if resp.StatusCode >= 200 && resp.StatusCode < 300 {
					body, _ := io.ReadAll(resp.Body)
					if strings.Contains(string(body), "activated") {
						result.Verified = true
					}
				}
			}

			results = append(results, result)
		}
	}

	return
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Okta
}

func (s Scanner) Description() string {
	return "Okta is an identity and access management service. Okta tokens can be used to authenticate and access various resources and APIs within an organization."
}
