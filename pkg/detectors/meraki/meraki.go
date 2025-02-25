package meraki

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
}

// merakiOrganizations is the partial response from the /organizations api of cisco Meraki.
// api docs: https://developer.cisco.com/meraki/api-v1/get-organizations/
type merakiOrganizations struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	apiKey = regexp.MustCompile(detectors.PrefixRegex([]string{"meraki"}) + `([0-9a-f]{40})`)
)

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}

	return defaultClient
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"meraki"}
}

func (s Scanner) Description() string {
	return "Cisco Meraki is a cloud-managed IT solution that provides networking, security, and device management through an easy-to-use interface." +
		"Meraki APIs make it possible to rapidly deploy and manage networks at scale, build on a platform of intelligent, cloud-connected IT products, and engage with users in powerful new ways."
}

// FromData will find and optionally verify Meraki API Key secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	// uniqueMatches will hold unique match values and ensure we only process unique matches found in the data string
	var uniqueMatches = make(map[string]struct{})

	for _, match := range apiKey.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for match := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Meraki,
			Raw:          []byte(match),
			ExtraData:    make(map[string]string),
		}

		if verify {
			client := s.getClient()
			organizations, isVerified, verificationErr := verifyMerakiApiKey(ctx, client, "https://api.meraki.com/api/v1/organizations", match)
			s1.Verified = isVerified
			if verificationErr != nil {
				s1.SetVerificationError(verificationErr)
			}

			// if organizations are not nil, which means token was verified.
			for _, org := range organizations {
				// format: ExtraData{"organization_1": "Example", organization_2": "Example"}
				s1.ExtraData[fmt.Sprintf("organization_%s", org.ID)] = org.Name
			}

		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Meraki
}

/*
verifyMerakiApiKey verifies if the passed matched api key for meraki is active or not.
docs: https://developer.cisco.com/meraki/api-v1/authorization/#authorization
*/
func verifyMerakiApiKey(ctx context.Context, client *http.Client, apiURL, match string) ([]merakiOrganizations, bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, http.NoBody)
	if err != nil {
		return nil, false, err
	}

	// set the required auth header
	req.Header.Set("X-Cisco-Meraki-API-Key", match)

	resp, err := client.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		// in case token is verified, capture the organization id's and name which are accessible via token.
		var organizations []merakiOrganizations
		if err = json.NewDecoder(resp.Body).Decode(&organizations); err != nil {
			return nil, false, err
		}

		return organizations, true, nil
	case http.StatusUnauthorized:
		return nil, false, nil
	default:
		return nil, false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}
