package twilio

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	identifierPat = regexp.MustCompile(`(?i)sid.{0,20}AC[0-9a-f]{32}`) // Should we have this? Seems restrictive.
	sidPat        = regexp.MustCompile(`\bAC[0-9a-f]{32}\b`)
	keyPat        = regexp.MustCompile(`\b[0-9a-f]{32}\b`)
)

type serviceResponse struct {
	Services []service `json:"services"`
}

type service struct {
	FriendlyName string `json:"friendly_name"` // friendly name of a service
	SID          string `json:"sid"`           // object id of service
	AccountSID   string `json:"account_sid"`   // account sid
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"sid"}
}

// FromData will find and optionally verify Twilio secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	identifierMatches := identifierPat.FindAllString(dataStr, -1)

	if len(identifierMatches) == 0 {
		return
	}

	keyMatches := keyPat.FindAllString(dataStr, -1)
	sidMatches := sidPat.FindAllString(dataStr, -1)

	for _, sid := range sidMatches {
		for _, key := range keyMatches {
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Twilio,
				Raw:          []byte(sid),
				RawV2:        []byte(sid + key),
				Redacted:     sid,
			}

			s1.ExtraData = map[string]string{
				"rotation_guide": "https://howtorotate.com/docs/tutorials/twilio/",
			}

			if verify {
				client := s.client
				if client == nil {
					client = defaultClient
				}

				req, err := http.NewRequestWithContext(
					ctx, "GET", "https://verify.twilio.com/v2/Services", nil)
				if err != nil {
					continue
				}
				req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
				req.Header.Add("Accept", "*/*")
				req.SetBasicAuth(sid, key)
				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()

					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
						s1.AnalysisInfo = map[string]string{"key": key, "sid": sid}
						var serviceResponse serviceResponse
						if err := json.NewDecoder(res.Body).Decode(&serviceResponse); err == nil && len(serviceResponse.Services) > 0 { // no error in parsing and have at least one service
							service := serviceResponse.Services[0]
							s1.ExtraData["friendly_name"] = service.FriendlyName
							s1.ExtraData["account_sid"] = service.AccountSID
						}
					} else if res.StatusCode == 401 || res.StatusCode == 403 {
						// The secret is determinately not verified (nothing to do)
					} else {
						err = fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
						s1.SetVerificationError(err, key)
					}
				} else {
					s1.SetVerificationError(err, key)
				}
			}

			if len(keyMatches) > 0 {
				results = append(results, s1)
			}
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Twilio
}

func (s Scanner) Description() string {
	return "Twilio is a cloud communications platform that allows software developers to programmatically make and receive phone calls, send and receive text messages, and perform other communication functions using its web service APIs."
}
