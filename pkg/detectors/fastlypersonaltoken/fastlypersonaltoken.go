package fastlypersonaltoken

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
	"google.golang.org/protobuf/types/known/structpb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"fastly"}) + `\b([A-Za-z0-9_-]{32})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"fastly"}
}

type fastlyUserRes struct {
	Login                string `json:"login"`
	Name                 string `json:"name"`
	Role                 string `json:"role"`
	TwoFactorAuthEnabled bool   `json:"two_factor_auth_enabled"`
	Locked               bool   `json:"locked"`
}

// FromData will find and optionally verify FastlyPersonalToken secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_FastlyPersonalToken,
			Raw:          []byte(resMatch),
		}

		if verify {
			req, err := http.NewRequestWithContext(ctx, "GET", "https://api.fastly.com/current_user", nil)
			if err != nil {
				continue
			}
			req.Header.Add("Fastly-Key", resMatch)
			res, err := client.Do(req)
			if err == nil {
				bodyBytes, err := io.ReadAll(res.Body)
				if err != nil {
					continue
				}
				defer res.Body.Close()
				if res.StatusCode >= 200 && res.StatusCode < 300 {
					var userRes fastlyUserRes
					err = json.Unmarshal(bodyBytes, &userRes)
					if err != nil {
						continue
					}
					s1.Verified = true
					s1.ExtraData = &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"username":                structpb.NewStringValue(userRes.Login),
							"name":                    structpb.NewStringValue(userRes.Name),
							"role":                    structpb.NewStringValue(userRes.Role),
							"locked":                  structpb.NewBoolValue(userRes.Locked),
							"two_factor_auth_enabled": structpb.NewBoolValue(userRes.TwoFactorAuthEnabled),
						},
					}
				} else {
					if detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
						continue
					}
				}
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_FastlyPersonalToken
}
