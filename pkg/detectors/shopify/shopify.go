package shopify

import (
	"context"
	"encoding/json"
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

// Ensure the Scanner satisfies the interface at compile time
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.CustomFalsePositiveChecker = (*Scanner)(nil)

var (
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat    = regexp.MustCompile(`\b(shppa_|shpat_)([0-9A-Fa-f]{32})\b`)
	domainPat = regexp.MustCompile(`[a-zA-Z0-9-]+\.myshopify\.com`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"shppa_", "shpat_"}
}

// FromData will find and optionally verify Shopify secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	keyMatches := keyPat.FindAllString(dataStr, -1)
	domainMatches := domainPat.FindAllString(dataStr, -1)

	for _, match := range keyMatches {
		key := strings.TrimSpace(match)

		for _, domainMatch := range domainMatches {
			domainRes := strings.TrimSpace(domainMatch)

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Shopify,
				Redacted:     domainRes,
				Raw:          []byte(key + domainRes),
			}

			if verify {
				if s.client == nil {
					s.client = detectors.GetHttpClientWithNoLocalAddresses()
				}

				req, err := http.NewRequestWithContext(ctx, "GET", "https://"+domainRes+"/admin/oauth/access_scopes.json", nil)
				if err != nil {
					continue
				}
				req.Header.Add("X-Shopify-Access-Token", key)
				res, err := s.client.Do(req)
				if err == nil {
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						shopifyTokenAccessScopes := shopifyTokenAccessScopes{}
						err := json.NewDecoder(res.Body).Decode(&shopifyTokenAccessScopes)
						if err == nil {
							var handleArray []string
							for _, handle := range shopifyTokenAccessScopes.AccessScopes {
								handleArray = append(handleArray, handle.Handle)

							}
							s1.Verified = true
							s1.ExtraData = map[string]string{
								"access_scopes": strings.Join(handleArray, ","),
							}
							s1.AnalysisInfo = map[string]string{
								"key":       key,
								"store_url": domainRes,
							}
						}
						res.Body.Close()
					}
				}
			}

			results = append(results, s1)

		}

	}

	return results, nil

}

func (s Scanner) IsFalsePositive(_ detectors.Result) (bool, string) {
	return false, ""
}

type shopifyTokenAccessScopes struct {
	AccessScopes []struct {
		Handle string `json:"handle"`
	} `json:"access_scopes"`
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Shopify
}

func (s Scanner) Description() string {
	return "An ecommerce platform, API keys can be used to access customer data"
}
