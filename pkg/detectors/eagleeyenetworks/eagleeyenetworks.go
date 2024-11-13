package eagleeyenetworks

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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"eagleeyenetworks"}) + `\b([a-zA-Z0-9]{15})\b`)
	email  = regexp.MustCompile(detectors.PrefixRegex([]string{"eagleeyenetworks"}) + `\b([a-zA-Z0-9]{3,20}@[a-zA-Z0-9]{2,12}.[a-zA-Z0-9]{2,5})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"eagleeyenetworks"}
}

// FromData will find and optionally verify EagleEyeNetworks secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	emailMatches := email.FindAllStringSubmatch(dataStr, -1)
	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		for _, emailMatch := range emailMatches {
			if len(emailMatch) != 2 {
				continue
			}

			resEmailPatMatch := strings.TrimSpace(emailMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_EagleEyeNetworks,
				Raw:          []byte(resMatch),
			}

			if verify {
				payload := strings.NewReader(fmt.Sprintf(`{"username": "%s", "password": "%s"}`, resEmailPatMatch, resMatch))
				req, err := http.NewRequestWithContext(ctx, "POST", "https://login.eagleeyenetworks.com/g/aaa/authenticate", payload)
				if err != nil {
					continue
				}
				req.Header.Add("Content-Type", "application/json")
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
	return detectorspb.DetectorType_EagleEyeNetworks
}

func (s Scanner) Description() string {
	return "Eagle Eye Networks provides cloud-based video surveillance solutions. The credentials can be used to access and manage surveillance data."
}
