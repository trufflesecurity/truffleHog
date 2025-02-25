package openvpn

import (
	"context"
	b64 "encoding/base64"
	"fmt"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

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
	clientIDPat     = regexp.MustCompile(detectors.PrefixRegex([]string{"openvpn"}) + `\b([A-Za-z0-9-]{3,40}\.[A-Za-z0-9-]{3,40})\b`)
	clientSecretPat = regexp.MustCompile(`\b([a-zA-Z0-9_-]{64,})\b`)
	domainPat       = regexp.MustCompile(`\b(https?://[A-Za-z0-9-]+\.api\.openvpn\.com)\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"openvpn"}
}

// FromData will find and optionally verify Openvpn secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	domainMatches := domainPat.FindAllStringSubmatch(dataStr, -1)
	clientIdMatches := clientIDPat.FindAllStringSubmatch(dataStr, -1)
	clientSecretMatches := clientSecretPat.FindAllStringSubmatch(dataStr, -1)

	for _, clientIdMatch := range clientIdMatches {
		clientIDRes := strings.TrimSpace(clientIdMatch[1])
		for _, clientSecretMatch := range clientSecretMatches {
			clientSecretRes := strings.TrimSpace(clientSecretMatch[1])
			for _, domainMatch := range domainMatches {
				domainRes := strings.TrimSpace(domainMatch[1])

				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_OpenVpn,
					Raw:          []byte(clientSecretRes),
					RawV2:        []byte(clientIDRes + clientSecretRes),
				}

				if verify {
					if s.client == nil {
						s.client = detectors.GetHttpClientWithNoLocalAddresses()
					}

					payload := strings.NewReader("grant_type=client_credentials")
					// OpenVPN API is in beta, We'll have to update the API endpoint once
					// Docs: https://openvpn.net/cloud-docs/developer/creating-api-credentials.html
					req, err := http.NewRequestWithContext(ctx, "POST", domainRes+"/api/beta/oauth/token", payload)
					if err != nil {
						continue
					}

					data := fmt.Sprintf("%s:%s", clientIDRes, clientSecretRes)
					sEnc := b64.StdEncoding.EncodeToString([]byte(data))

					req.Header.Add("Authorization", fmt.Sprintf("Basic %s", sEnc))
					req.Header.Add("content-type", "application/x-www-form-urlencoded")
					res, err := s.client.Do(req)
					if err == nil {
						defer res.Body.Close()
						if res.StatusCode >= 200 && res.StatusCode < 300 {
							s1.Verified = true
						} else if res.StatusCode == 401 {
							// The secret is determinately not verified (nothing to do)
						} else {
							err = fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
							s1.SetVerificationError(err, clientSecretRes)
						}
					} else {
						s1.SetVerificationError(err, clientSecretRes)
					}
				}

				results = append(results, s1)
			}
		}

	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_OpenVpn
}

func (s Scanner) Description() string {
	return "OpenVPN is a virtual private network (VPN) solution. OpenVPN API credentials can be used to manage and configure VPN connections and settings."
}
