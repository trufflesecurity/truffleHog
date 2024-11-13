package diffbot

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"diffbot"}) + `\b([a-z0-9]{32})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"diffbot"}
}

// FromData will find and optionally verify Diffbot secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Diffbot,
			Raw:          []byte(resMatch),
		}

		if verify {
			timeout := 10 * time.Second
			client.Timeout = timeout
			req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://api.diffbot.com/v4/account?token=%s", resMatch), nil)
			if err != nil {
				continue
			}
			res, err := client.Do(req)
			if err == nil {
				bodyBytes, err := io.ReadAll(res.Body)
				if err == nil {
					bodyString := string(bodyBytes)
					validResponse := strings.Contains(bodyString, `"token":`) && strings.Contains(bodyString, `"planCredits":`)
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
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Diffbot
}

func (s Scanner) Description() string {
	return "Diffbot is a service that provides APIs for extracting data from web pages. Diffbot API tokens can be used to access these services and extract data from web content."
}
