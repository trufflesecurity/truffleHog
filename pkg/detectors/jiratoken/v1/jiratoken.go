package jiratoken

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
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.Versioner = (*Scanner)(nil)

func (Scanner) Version() int { return 1 }

var (
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	tokenPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"jira"}) + `\b([a-zA-Z-0-9]{24})\b`)
	domainPat = regexp.MustCompile(detectors.PrefixRegex([]string{"jira"}) + `\b([a-zA-Z-0-9]{5,24}\.[a-zA-Z-0-9]{3,16}\.[a-zA-Z-0-9]{3,16})\b`)
	emailPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"jira"}) + common.EmailPattern)
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

	var uniqueTokens, uniqueDomains, uniqueEmails = make(map[string]struct{}), make(map[string]struct{}), make(map[string]struct{})

	for _, token := range tokenPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueTokens[token[1]] = struct{}{}
	}

	for _, domain := range domainPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueDomains[domain[1]] = struct{}{}
	}

	for _, email := range emailPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueEmails[strings.ToLower(email[1])] = struct{}{}
	}

	for email := range uniqueEmails {
		for token := range uniqueTokens {
			for domain := range uniqueDomains {
				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_JiraToken,
					Raw:          []byte(token),
					RawV2:        []byte(fmt.Sprintf("%s:%s:%s", email, token, domain)),
					ExtraData: map[string]string{
						"rotation_guide": "https://howtorotate.com/docs/tutorials/atlassian/",
						"version":        fmt.Sprintf("%d", s.Version()),
					},
				}

				if verify {
					if s.client == nil {
						s.client = detectors.GetHttpClientWithNoLocalAddresses()
					}
					isVerified, verificationErr := verifyJiratoken(ctx, s.client, email, domain, token)
					s1.Verified = isVerified
					s1.SetVerificationError(verificationErr, token)
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
	return "Jira is a proprietary issue tracking product developed by Atlassian that allows bug tracking and agile project management. Jira tokens can be used to authenticate and interact with Jira's API."
}
