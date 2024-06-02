package freshbooks

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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"freshbooks"}) + `\b([0-9a-z]{64})\b`)
	// TODO: this domain pattern is too restrictive
	uriPat = regexp.MustCompile(detectors.PrefixRegex([]string{"freshbooks"}) + `\b(https://www.[0-9A-Za-z_-]{1,}.com)\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"freshbooks"}
}

// FromData will find and optionally verify Freshbooks secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	uriMatches := uriPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])
		for _, uriMatch := range uriMatches {
			resURI := strings.TrimSpace(uriMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Freshbooks,
				Raw:          []byte(resMatch),
			}

			if verify {
				if s.client == nil {
					s.client = detectors.GetHttpClientWithNoLocalAddresses()
				}

				req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf(`https://auth.freshbooks.com/oauth/authorize?client_id=%s&redirect_uri=%s&response_type=code`, resMatch, resURI), nil)
				if err != nil {
					continue
				}
				res, err := s.client.Do(req)
				if err == nil {
					defer res.Body.Close()
					bodyBytes, err := io.ReadAll(res.Body)
					if err != nil {
						continue
					}
					body := string(bodyBytes)
					if res.StatusCode >= 200 && res.StatusCode < 300 && strings.Contains(body, "Log In to FreshBooks") {
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
	return detectorspb.DetectorType_Freshbooks
}

func (s Scanner) Description() string {
	return "FreshBooks is an accounting software package developed and marketed by 2ndSite Inc. FreshBooks API keys can be used to access and modify accounting data and perform other operations."
}
