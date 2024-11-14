package flowflu

import (
	"context"
	"fmt"
	"io"
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
	keyPat     = regexp.MustCompile(detectors.PrefixRegex([]string{"flowflu"}) + `\b([a-zA-Z0-9]{51})\b`)
	accountPat = regexp.MustCompile(detectors.PrefixRegex([]string{"flowflu", "account"}) + `\b([a-zA-Z0-9]{4,30})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"flowflu"}
}

// FromData will find and optionally verify FlowFlu secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	accountMatches := accountPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		for _, accountMatch := range accountMatches {
			if len(accountMatch) != 2 {
				continue
			}

			resAccount := strings.TrimSpace(accountMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_FlowFlu,
				Raw:          []byte(resMatch),
			}

			if verify {
				req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://%s.flowlu.com/api/v1/module/crm/lead/list?api_key=%s", resAccount, resMatch), nil)
				if err != nil {
					continue
				}
				res, err := client.Do(req)
				if err == nil {
					bodyBytes, err := io.ReadAll(res.Body)
					if err != nil {
						continue
					}

					bodyString := string(bodyBytes)
					validResponse := strings.Contains(bodyString, `total_result`)

					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						if validResponse {
							s1.Verified = true
						} else {
							s1.Verified = false
						}
					}
				}
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_FlowFlu
}

func (s Scanner) Description() string {
	return "FlowFlu is a service used for managing customer relationships and projects. FlowFlu API keys can be used to access and manipulate CRM data."
}
