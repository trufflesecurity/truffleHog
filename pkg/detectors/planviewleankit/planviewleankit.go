package planviewleankit

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
	keyPat       = regexp.MustCompile(detectors.PrefixRegex([]string{"planviewleankit", "planview"}) + `\b([0-9a-f]{128})\b`)
	subDomainPat = regexp.MustCompile(detectors.PrefixRegex([]string{"planviewleankit", "planview"}) + `(?:subdomain).\b([a-zA-Z][a-zA-Z0-9.-]{1,23}[a-zA-Z0-9])\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"planviewleankit", "planview"}
}

// FromData will find and optionally verify PlanviewLeanKit secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	subdomainMatches := subDomainPat.FindAllStringSubmatch(dataStr, -1)

	for _, subdomainMatch := range subdomainMatches {
		resSubdomainMatch := strings.TrimSpace(subdomainMatch[1])

		for _, match := range matches {
			resMatch := strings.TrimSpace(match[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_PlanviewLeanKit,
				Raw:          []byte(resMatch),
			}

			if verify {
				if s.client == nil {
					s.client = detectors.GetHttpClientWithNoLocalAddresses()
				}

				req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://%s.leankit.com/io/account", resSubdomainMatch), nil)
				if err != nil {
					continue
				}
				req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", resMatch))
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

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_PlanviewLeanKit
}

func (s Scanner) Description() string {
	return "Planview LeanKit is a visual project delivery tool that enables teams to apply Lean management principles to their work. The detected credential can be used to access and manage LeanKit accounts."
}
