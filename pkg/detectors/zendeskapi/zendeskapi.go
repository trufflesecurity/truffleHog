package zendeskapi

import (
	"context"
	b64 "encoding/base64"
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
	token  = regexp.MustCompile(detectors.PrefixRegex([]string{"zendesk"}) + `([A-Za-z0-9_-]{40})`)
	email  = regexp.MustCompile(`\b([a-zA-Z-0-9-]{5,16}\@[a-zA-Z-0-9]{4,16}\.[a-zA-Z-0-9]{3,6})\b`)
	domain = regexp.MustCompile(`\b([a-zA-Z-0-9]{3,16}\.zendesk\.com)\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"zendesk"}
}

// FromData will find and optionally verify ZendeskApi secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	tokens := token.FindAllStringSubmatch(dataStr, -1)
	domains := domain.FindAllStringSubmatch(dataStr, -1)
	emails := email.FindAllStringSubmatch(dataStr, -1)

	for _, token := range tokens {
		resMatch := strings.TrimSpace(token[1])

		var resDomain string
		for _, domain := range domains {
			resDomain = strings.TrimSpace(domain[1])

			for _, email := range emails {
				resEmail := strings.TrimSpace(email[1])

				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_ZendeskApi,
					Raw:          []byte(resMatch),
				}

				if verify {
					if s.client == nil {
						s.client = detectors.GetHttpClientWithNoLocalAddresses()
					}

					data := fmt.Sprintf("%s/token:%s", resEmail, resMatch)
					sEnc := b64.StdEncoding.EncodeToString([]byte(data))
					req, err := http.NewRequestWithContext(ctx, "GET", "https://"+resDomain+"/api/v2/users.json", nil)
					if err != nil {
						continue
					}
					req.Header.Add("Authorization", fmt.Sprintf("Basic %s", sEnc))
					res, err := s.client.Do(req)
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

	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_ZendeskApi
}

func (s Scanner) Description() string {
	return "Zendesk is a customer service platform. Zendesk API tokens can be used to access and modify customer service data."
}
