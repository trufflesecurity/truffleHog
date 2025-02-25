package thinkific

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
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"thinkific"}) + `\b([0-9a-f]{32})\b`)
	domainPat = regexp.MustCompile(detectors.PrefixRegex([]string{"thinkific"}) + `\b([0-9A-Za-z]{4,40})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"thinkific"}
}

// FromData will find and optionally verify Thinkific secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	domainMatches := domainPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])
		for _, domainMatch := range domainMatches {
			resDomainMatch := strings.TrimSpace(domainMatch[1])
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Thinkific,
				Raw:          []byte(resMatch),
			}

			if verify {
				if s.client == nil {
					s.client = detectors.GetHttpClientWithNoLocalAddresses()
				}

				domainRes := fmt.Sprintf("%s-s-school", resDomainMatch)
				req, err := http.NewRequestWithContext(ctx, "GET", "https://api.thinkific.com/api/public/v1/collections", nil)
				if err != nil {
					continue
				}
				req.Header.Add("X-Auth-API-Key", resMatch)
				req.Header.Add("X-Auth-Subdomain", domainRes)
				req.Header.Add("Content-Type", "application/json")
				res, err := s.client.Do(req)
				if err == nil {
					defer res.Body.Close()
					bodyBytes, err := io.ReadAll(res.Body)
					if err != nil {
						continue
					}
					body := string(bodyBytes)

					if strings.Contains(body, "API Access is not available") {
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
	return detectorspb.DetectorType_Thinkific
}

func (s Scanner) Description() string {
	return "Thinkific is an online course platform that allows users to create, market, and sell online courses. Thinkific API keys can be used to access and manage course data and user information."
}
