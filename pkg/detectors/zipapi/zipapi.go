package zipapi

import (
	"context"
	b64 "encoding/base64"
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
	keyPat   = regexp.MustCompile(detectors.PrefixRegex([]string{"zipapi"}) + `\b([0-9a-z]{32})\b`)
	emailPat = regexp.MustCompile(common.EmailPattern)
	pwordPat = regexp.MustCompile(detectors.PrefixRegex([]string{"zipapi"}) + `\b([a-zA-Z0-9!=@#$%^]{7,})`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"zipapi"}
}

// FromData will find and optionally verify Zipapi secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueEmailMatches, uniqueKeyMatches, uniquePassMatches := make(map[string]struct{}), make(map[string]struct{}), make(map[string]struct{})
	for _, match := range emailPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueEmailMatches[strings.TrimSpace(match[1])] = struct{}{}
	}

	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueKeyMatches[strings.TrimSpace(match[1])] = struct{}{}
	}

	for _, match := range pwordPat.FindAllStringSubmatch(dataStr, -1) {
		uniquePassMatches[strings.TrimSpace(match[1])] = struct{}{}
	}

	for keyMatch := range uniqueKeyMatches {
		for emailMatch := range uniqueEmailMatches {
			for passMatch := range uniquePassMatches {
				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_ZipAPI,
					Raw:          []byte(keyMatch),
				}

				if verify {
					data := fmt.Sprintf("%s:%s", emailMatch, passMatch)
					sEnc := b64.StdEncoding.EncodeToString([]byte(data))
					req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://service.zipapi.us/zipcode/90210/?X-API-KEY=%s", keyMatch), nil)
					if err != nil {
						continue
					}
					req.Header.Add("Content-Type", "application/json")
					req.Header.Add("Authorization", fmt.Sprintf("Basic %s", sEnc))
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
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_ZipAPI
}

func (s Scanner) Description() string {
	return "ZipAPI is a service used to retrieve ZIP code information. ZipAPI keys can be used to access and retrieve this information from their API."
}
