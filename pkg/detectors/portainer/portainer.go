package portainer

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
	detectors.DefaultMultiPartCredentialProvider
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	endpointPat = regexp.MustCompile(detectors.PrefixRegex([]string{"portainer"}) + `\b(https?:\/\/\S+(:[0-9]{4,5})?)\b`)
	tokenPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"portainer"}) + `\b(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[0-9A-Za-z]{50,310}\.[0-9A-Z-a-z\-_]{43})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"portainer"}
}

// FromData will find and optionally verify Portainer secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := tokenPat.FindAllStringSubmatch(dataStr, -1)
	endpointMatches := endpointPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		for _, endpointMatch := range endpointMatches {
			resEndpointMatch := strings.TrimSpace(endpointMatch[1])

			u, err := detectors.ParseURLAndStripPathAndParams(resEndpointMatch)
			if err != nil {
				// if the URL is invalid just move onto the next one
				continue
			}
			u.Path = "/api/endpoints"

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Portainer,
				Raw:          []byte(resMatch),
				RawV2:        []byte(resMatch + resEndpointMatch),
			}

			if verify {
				if s.client == nil {
					s.client = detectors.GetHttpClientWithLocalAddresses()
				}
				req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
				if err != nil {
					continue
				}
				req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", resMatch))
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

			if len(endpointMatches) > 0 {
				results = append(results, s1)
			}

		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Portainer
}

func (s Scanner) Description() string {
	return "Portainer is a management UI for Docker, Docker Swarm, Kubernetes, and Azure ACI. Portainer API tokens can be used to access and control these environments."
}
