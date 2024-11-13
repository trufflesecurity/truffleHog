package ethplorer

import (
	"context"
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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"ethplorer"}) + `\b([a-z0-9A-Z-]{22})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"ethplorer"}
}

// FromData will find and optionally verify Ethplorer secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Ethplorer,
			Raw:          []byte(resMatch),
		}

		if verify {
			payload := strings.NewReader("apiKey=" + resMatch + "&addresses=0xb2930b35844a230f00e51431acae96fe543a0347%2C0xb52d3141ee731fac89927476c6a5207b37cd72ff")
			req, err := http.NewRequestWithContext(ctx, "POST", "https://api-mon.ethplorer.io/createPool", payload)
			if err != nil {
				continue
			}
			req.Header.Add("accept", "application/json")
			req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
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

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Ethplorer
}

func (s Scanner) Description() string {
	return "Ethplorer API keys can be used to interact with the Ethplorer service, which provides access to Ethereum blockchain data and analytics."
}
