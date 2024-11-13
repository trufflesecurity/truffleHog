package digitaloceanv2

import (
	"context"
	"fmt"
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
	keyPat = regexp.MustCompile(`\b((?:dop|doo|dor)_v1_[a-f0-9]{64})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"dop_v1_", "doo_v1_", "dor_v1_"}
}

// FromData will find and optionally verify DigitalOceanV2 secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_DigitalOceanV2,
			Raw:          []byte(resMatch),
		}

		if verify {
			switch {
			case strings.HasPrefix(resMatch, "dor_v1_"):
				req, err := http.NewRequestWithContext(ctx, "GET", "https://cloud.digitalocean.com/v1/oauth/token?grant_type=refresh_token&refresh_token="+resMatch, nil)
				if err != nil {
					continue
				}

				res, err := client.Do(req)
				if err == nil {
					bodyBytes, err := io.ReadAll(res.Body)

					if err != nil {
						continue
					}

					bodyString := string(bodyBytes)
					validResponse := strings.Contains(bodyString, `"access_token"`)
					defer res.Body.Close()

					if res.StatusCode >= 200 && res.StatusCode < 300 && validResponse {
						s1.Verified = true
					}
				}

			case strings.HasPrefix(resMatch, "doo_v1_"), strings.HasPrefix(resMatch, "dop_v1_"):
				req, err := http.NewRequestWithContext(ctx, "GET", "https://api.digitalocean.com/v2/account", nil)
				if err != nil {
					continue
				}
				req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", resMatch))
				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
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
	return detectorspb.DetectorType_DigitalOceanV2
}

func (s Scanner) Description() string {
	return "DigitalOcean is a cloud service provider offering scalable compute and storage solutions. DigitalOcean API keys can be used to access and manage these resources."
}
