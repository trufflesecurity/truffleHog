package exportsdk

import (
	"context"
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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"exportsdk"}) + `\b([0-9a-z]{5,15}_[0-9a-z-]{36})\b`)
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"exportsdk"}) + `\b([0-9a-z-]{36})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"exportsdk"}
}

// FromData will find and optionally verify ExportSDK secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	idmatches := idPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])
		for _, idmatch := range idmatches {
			if len(idmatch) != 2 {
				continue
			}
			resIdMatch := strings.TrimSpace(idmatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_ExportSDK,
				Raw:          []byte(resMatch),
			}

			if verify {
				payload := strings.NewReader(`{  "templateId": "` + resIdMatch + `"}`)
				req, err := http.NewRequestWithContext(ctx, "POST", "https://api.exportsdk.com/v1/pdf", payload)
				if err != nil {
					continue
				}
				req.Header.Add("Content-Type", "application/json")
				req.Header.Add("X-API-KEY", resMatch)
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
	return detectorspb.DetectorType_ExportSDK
}

func (s Scanner) Description() string {
	return "ExportSDK is a service used for exporting data and generating PDFs. ExportSDK keys can be used to authenticate API requests and generate documents."
}
