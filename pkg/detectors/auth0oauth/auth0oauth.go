package auth0oauth

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = detectors.DetectorHttpClientWithLocalAddresses

	clientIdPat     = regexp.MustCompile(detectors.PrefixRegex([]string{"auth0"}) + `\b([a-zA-Z0-9_-]{32,60})\b`)
	clientSecretPat = regexp.MustCompile(`\b([a-zA-Z0-9_-]{64,})\b`)
	domainPat       = regexp.MustCompile(`\b([a-zA-Z0-9][a-zA-Z0-9._-]*auth0\.com)\b`) // could be part of url
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"auth0"}
}

// FromData will find and optionally verify Auth0oauth secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)
	uniqueDomainMatches := make(map[string]struct{})
	uniqueClientIDs := make(map[string]struct{})
	uniqueSecrets := make(map[string]struct{})
	for _, m := range domainPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueDomainMatches[strings.TrimSpace(m[1])] = struct{}{}
	}
	for _, m := range clientIdPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueClientIDs[strings.TrimSpace(m[1])] = struct{}{}
	}
	for _, m := range clientSecretPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueSecrets[strings.TrimSpace(m[1])] = struct{}{}
	}

	for clientIdRes := range uniqueClientIDs {
		for clientSecretRes := range uniqueSecrets {
			for domainRes := range uniqueDomainMatches {
				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_Auth0oauth,
					Redacted:     clientIdRes,
					Raw:          []byte(clientSecretRes),
					RawV2:        []byte(clientIdRes + clientSecretRes),
				}

				if verify {
					/*
					   curl --request POST \
					     --url 'https://YOUR_DOMAIN/oauth/token' \
					     --header 'content-type: application/x-www-form-urlencoded' \
					     --data 'grant_type=authorization_code&client_id=W44JmL3qD6LxHeEJyKe9lMuhcwvPOaOq&client_secret=YOUR_CLIENT_SECRET&code=AUTHORIZATION_CODE&redirect_uri=undefined'
					*/

					data := url.Values{}
					data.Set("grant_type", "authorization_code")
					data.Set("client_id", clientIdRes)
					data.Set("client_secret", clientSecretRes)
					data.Set("code", "AUTHORIZATION_CODE")
					data.Set("redirect_uri", "undefined")

					req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+domainRes+"/oauth/token", strings.NewReader(data.Encode())) // URL-encoded payload
					if err != nil {
						continue
					}
					req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
					res, err := client.Do(req)
					if err == nil {
						defer res.Body.Close()
						bodyBytes, err := io.ReadAll(res.Body)
						if err != nil {
							continue
						}
						body := string(bodyBytes)

						// if client_id and client_secret is valid -> 403 {"error":"invalid_grant","error_description":"Invalid authorization code"}
						// if invalid -> 401 {"error":"access_denied","error_description":"Unauthorized"}
						// ingenious!

						if !strings.Contains(body, "access_denied") {
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
	return detectorspb.DetectorType_Auth0oauth
}

func (s Scanner) Description() string {
	return "Auth0 is a service designed to handle authentication and authorization for users. Oauth API keys can be used to impersonate applications and other things related to Auth0's API"
}
