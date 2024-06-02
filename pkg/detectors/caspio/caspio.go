package caspio

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
	keyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"caspio"}) + `\b([a-z0-9]{50})\b`)
	idPat     = regexp.MustCompile(detectors.PrefixRegex([]string{"caspio"}) + `\b([a-z0-9]{50})\b`)
	domainPat = regexp.MustCompile(detectors.PrefixRegex([]string{"caspio"}) + `\b([a-z0-9]{8})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"caspio"}
}

// FromData will find and optionally verify Caspio secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	idMatches := idPat.FindAllStringSubmatch(dataStr, -1)
	domainMatches := domainPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		for _, idMatch := range idMatches {

			resIdMatch := strings.TrimSpace(idMatch[1])

			for _, domainMatch := range domainMatches {

				resDomainMatch := strings.TrimSpace(domainMatch[1])

				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_Caspio,
					Raw:          []byte(resMatch),
					RawV2:        []byte(resMatch + resIdMatch + resDomainMatch),
				}

				if verify {
					if s.client == nil {
						s.client = detectors.GetHttpClientWithNoLocalAddresses()
					}

					payload := strings.NewReader(fmt.Sprintf(`grant_type=client_credentials&client_id=%s&client_secret=%s`, resIdMatch, resMatch))
					req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("https://%s.caspio.com/oauth/token", resDomainMatch), payload)
					if err != nil {
						continue
					}
					req.Header.Add("Content-Type", "text/plain")
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
	return detectorspb.DetectorType_Caspio
}

func (s Scanner) Description() string {
	return "Caspio is a cloud platform for building custom database applications. Caspio credentials can be used to access and manage these applications."
}
