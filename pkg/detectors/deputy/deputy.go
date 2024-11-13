package deputy

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
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = detectors.DetectorHttpClientWithNoLocalAddresses

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"deputy"}) + `\b([0-9a-z]{32})\b`)
	urlPat = regexp.MustCompile(`\b([0-9a-z]{1,}\.as\.deputy\.com)\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"deputy"}
}

// FromData will find and optionally verify Deputy secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	urlMatches := urlPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		for _, urlMatch := range urlMatches {
			if len(urlMatch) != 2 {
				continue
			}
			resURL := strings.TrimSpace(urlMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Deputy,
				Raw:          []byte(resMatch),
			}

			if verify {
				req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://%s/api/v1/me", resURL), nil)
				if err != nil {
					continue
				}
				req.Header.Add("Content-Type", "application/json")
				req.Header.Add("Authorization", fmt.Sprintf("OAuth %s", resMatch))
				res, err := client.Do(req)
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
	return detectorspb.DetectorType_Deputy
}

func (s Scanner) Description() string {
	return "Deputy is a workforce management software that provides various tools for scheduling, time tracking, and communication. Deputy API keys can be used to access and modify data within the Deputy platform."
}
