package jiratoken

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
	client *http.Client
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.Versioner = (*Scanner)(nil)

func (Scanner) Version() int { return 2 }

var (
	// https://support.atlassian.com/atlassian-account/docs/manage-api-tokens-for-your-atlassian-account/
	// Tokens created after Jan 18 2023 use a variable length
	tokenPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"jira"}) + `\b([A-Za-z0-9+/=_-]+=[A-Za-z0-9]{8})\b`)
	domainPat = regexp.MustCompile(detectors.PrefixRegex([]string{"jira"}) + `\b([a-zA-Z-0-9]{5,24}\.[a-zA-Z-0-9]{3,16}\.[a-zA-Z-0-9]{3,16})\b`)
	emailPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"jira"}) + `\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,})\b`)
)

const (
	failedAuth           = "AUTHENTICATED_FAILED"
	loginReasonHeaderKey = "X-Seraph-LoginReason"
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"jira"}
}

// FromData will find and optionally verify JiraToken secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	tokens := tokenPat.FindAllStringSubmatch(dataStr, -1)
	domains := domainPat.FindAllStringSubmatch(dataStr, -1)
	emails := emailPat.FindAllStringSubmatch(dataStr, -1)

	for _, email := range emails {
		if len(email) != 2 {
			continue
		}
		resEmail := strings.TrimSpace(email[1])

		for _, token := range tokens {
			resToken := strings.TrimSpace(token[1])
			for _, domain := range domains {
				resDomain := strings.TrimSpace(domain[1])

				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_JiraToken,
					Raw:          []byte(resToken),
					RawV2:        []byte(fmt.Sprintf("%s:%s:%s", resEmail, resToken, resDomain)),
					ExtraData: map[string]string{
						"rotation_guide": "https://howtorotate.com/docs/tutorials/atlassian/",
						"version":        fmt.Sprintf("%d", s.Version()),
					},
				}

				if verify {
					if s.client == nil {
						s.client = detectors.GetHttpClientWithLocalAddresses()
					}
					isVerified, verificationErr := verifyJiratoken(ctx, s.client, resEmail, resDomain, resToken)
					s1.Verified = isVerified
					s1.SetVerificationError(verificationErr, resToken)
				}

				results = append(results, s1)

			}

		}
	}

	return results, nil
}

func verifyJiratoken(ctx context.Context, client *http.Client, email, domain, token string) (bool, error) {
	data := fmt.Sprintf("%s:%s", email, token)
	sEnc := b64.StdEncoding.EncodeToString([]byte(data))
	req, err := http.NewRequestWithContext(ctx, "GET", "https://"+domain+"/rest/api/3/dashboard", nil)
	if err != nil {
		return false, err
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", fmt.Sprintf("Basic %s", sEnc))
	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer res.Body.Close()

	// If the request is successful and the login reason is not failed authentication, then the token is valid.
	// This is because Jira returns a 200 status code even if the token is invalid.
	// Jira returns a default dashboard page.
	if !(res.StatusCode >= 200 && res.StatusCode < 300) {
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}

	if res.Header.Get(loginReasonHeaderKey) != failedAuth {
		return true, nil
	}

	return false, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_JiraToken
}

func (s Scanner) Description() string {
	return "Jira is a proprietary issue tracking product developed by Atlassian that allows bug tracking and agile project management. Jira tokens can be used to authenticate API requests."
}
