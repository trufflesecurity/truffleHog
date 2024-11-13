package dovico

import (
	"context"
	"fmt"
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
	keyPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"dovico"}) + `\b([0-9a-z]{32}\.[0-9a-z]{1,}\b)`)
	userPat = regexp.MustCompile(detectors.PrefixRegex([]string{"dovico"}) + `\b([0-9a-z]{32}\.[0-9a-z]{1,}\b)`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"dovico"}
}

// FromData will find and optionally verify Dovico secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	userMatches := userPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])
		for _, user := range userMatches {
			if len(user) != 2 {
				continue
			}
			resUser := strings.TrimSpace(user[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Dovico,
				Raw:          []byte(resMatch),
			}

			if verify {
				req, err := http.NewRequestWithContext(ctx, "GET", "https://api.dovico.com/Employees/?version=7", nil)
				if err != nil {
					continue
				}
				req.Header.Add("Content-Type", "application/json")
				req.Header.Add("Authorization", fmt.Sprintf(`WRAP access_token="client=%s&user_token=%s"`, resMatch, resUser))
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
	return detectorspb.DetectorType_Dovico
}

func (s Scanner) Description() string {
	return "Dovico is a time tracking and project management service. Dovico keys can be used to access and manage time tracking and project data."
}
