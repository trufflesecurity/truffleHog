package myfreshworks

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"regexp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"freshworks"}) + `\b([a-z0-9A-Z-]{22})\b`)
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"freshworks"}) + `\b([a-zA-Z0-9-_]{2,20})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("freshworks")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {

	matches := keyPat.FindAllSubmatch(data, -1)
	idmatches := idPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])
		for _, idmatch := range idmatches {
			if len(idmatch) != 2 {
				continue
			}
			resIdMatch := bytes.TrimSpace(idmatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Myfreshworks,
				Raw:          resMatch,
			}

			if verify {
				req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://%s.myfreshworks.com/crm/sales/api/sales_accounts/filters", string(resIdMatch)), nil)
				if err != nil {
					continue
				}
				req.Header.Add("Authorization", fmt.Sprintf("Token token=%s", string(resMatch)))
				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
					} else {
						if detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
							continue
						}
					}
				}
			}

			results = append(results, s1)

		}

	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Myfreshworks
}
