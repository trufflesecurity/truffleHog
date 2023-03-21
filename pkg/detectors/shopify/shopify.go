package shopify

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
	"google.golang.org/protobuf/types/known/structpb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundry characters such as below to reduce false positives.
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
				req, err := http.NewRequestWithContext(ctx, "GET", "https://"+domainRes+"/admin/oauth/access_scopes.json", nil)
				if err != nil {
					continue
				}
				req.Header.Add("X-Shopify-Access-Token", key)
				res, err := client.Do(req)
				if err == nil {
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						shopifyTokenAccessScopes := shopifyTokenAccessScopes{}
						err := json.NewDecoder(res.Body).Decode(&shopifyTokenAccessScopes)
						if err == nil {
							var handleArray []*structpb.Value
							for _, handle := range shopifyTokenAccessScopes.AccessScopes {
								handleArray = append(handleArray, structpb.NewStringValue(handle.Handle))
							}
							s1.Verified = true
							s1.ExtraData = &structpb.Struct{
								Fields: map[string]*structpb.Value{
									"access_scopes": structpb.NewListValue(&structpb.ListValue{Values: handleArray}),
								},
							}
						}
						res.Body.Close()
					}
				} else {
					// This function will check false positives for common test words, but also it will make sure the key appears 'random' enough to be a real key.
					if detectors.IsKnownFalsePositive(key, detectors.DefaultFalsePositives, true) {
						continue
					}
				}
			}

			results = append(results, s1)

		}

	}

	return results, nil

}

type shopifyTokenAccessScopes struct {
	AccessScopes []struct {
		Handle string `json:"handle"`
	} `json:"access_scopes"`
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Shopify
}
