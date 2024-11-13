package envoyapikey

import (
	"context"
	"io"
	"net/http"
	"strings"

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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"envoy"}) + `\b([a-zA-Z0-9]{220})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"envoy"}
}

// FromData will find and optionally verify Envoy secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_EnvoyApiKey,
			Raw:          []byte(resMatch),
		}

		if verify {
			req, err := http.NewRequestWithContext(ctx, "GET", "https://api.envoy.com/v1/locations", nil)
			if err != nil {
				continue
			}
			req.Header.Add("Accept", "application/vnd.envoy+json; version=3")
			req.Header.Add("X-Api-Key", resMatch)
			res, err := client.Do(req)
			if err == nil {
				defer res.Body.Close()
				body, _ := io.ReadAll(res.Body)

				// Invalid API keys can also return status code 200, so check for presence of 'status 401' in response body.
				if res.StatusCode >= 200 && res.StatusCode < 300 || res.StatusCode == 403 {
					if !strings.Contains(string(body), `"status":401`) {
						s1.Verified = true
					}
				}
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_EnvoyApiKey
}

func (s Scanner) Description() string {
	return "Envoy is a cloud-based platform that provides visitor management solutions. Envoy API keys can be used to access and manage visitor data and other resources within the Envoy platform."
}
