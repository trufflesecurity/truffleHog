package elasticemail

import (
	"context"
	"encoding/json"
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

	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"elastic"}) + `\b([A-Za-z0-9_-]{96})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"elasticemail"}
}

// FromData will find and optionally verify ElasticEmail secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_ElasticEmail,
			Raw:          []byte(resMatch),
		}

		if verify {
			req, err := http.NewRequestWithContext(ctx, "GET", "https://api.elasticemail.com/v2/account/profileoverview?apikey="+resMatch, nil)
			if err != nil {
				continue
			}
			res, err := client.Do(req)
			if err == nil {
				data, readErr := io.ReadAll(res.Body)
				res.Body.Close()
				if readErr == nil {
					var ResVar struct {
						Success bool `json:"success"`
					}
					if err := json.Unmarshal(data, &ResVar); err == nil {
						if ResVar.Success {
							s1.Verified = true
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
	return detectorspb.DetectorType_ElasticEmail
}

func (s Scanner) Description() string {
	return "ElasticEmail is an email marketing service. ElasticEmail API keys can be used to send emails, manage contacts, and access other features of the service."
}
