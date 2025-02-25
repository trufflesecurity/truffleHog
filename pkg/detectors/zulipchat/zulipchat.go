package zulipchat

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
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat    = regexp.MustCompile(common.BuildRegex(common.AlphaNumPattern, "", 32))
	idPat     = regexp.MustCompile(`\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b`)
	domainPat = regexp.MustCompile(`(?i)\b([a-z0-9-]+\.zulip(?:chat)?\.com|chat\.zulip\.org)\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"zulip"}
}

// FromData will find and optionally verify ZulipChat secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	keyMatches := make(map[string]struct{})
	for _, m := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		keyMatches[m[1]] = struct{}{}
	}
	idMatches := make(map[string]struct{})
	for _, m := range idPat.FindAllStringSubmatch(dataStr, -1) {
		idMatches[m[1]] = struct{}{}
	}
	domainMatches := make(map[string]struct{})
	for _, m := range domainPat.FindAllStringSubmatch(dataStr, -1) {
		domainMatches[m[1]] = struct{}{}
	}

	for key := range keyMatches {
		for id := range idMatches {
			for domain := range domainMatches {
				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_ZulipChat,
					Raw:          []byte(key),
					RawV2:        []byte(fmt.Sprintf("%s:%s:%s", key, id, domain)),
					ExtraData: map[string]string{
						"Domain": domain,
						"Id":     id,
					},
				}

				if verify {
					if s.client == nil {
						s.client = detectors.GetHttpClientWithNoLocalAddresses()
					}
					verified, verificationErr := verifyResult(ctx, s.client, domain, id, key)
					s1.Verified = verified
					s1.SetVerificationError(verificationErr)
				}

				results = append(results, s1)
			}
		}
	}

	return results, nil
}

func verifyResult(ctx context.Context, client *http.Client, domain, id, key string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://%s/api/v1/users", domain), nil)
	if err != nil {
		return false, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(id, key)

	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusOK:
		var users usersResponse
		if err := json.NewDecoder(res.Body).Decode(&users); err != nil {
			return false, nil
		}
		return true, nil
	case http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

type usersResponse struct {
	Result  string   `json:"result"`
	Members []member `json:"members"`
}

type member struct {
	FullName string `json:"full_name"`
	Email    string `json:"email"`
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_ZulipChat
}

func (s Scanner) Description() string {
	return "ZulipChat is a group chat application used for team communication. ZulipChat API keys can be used to access and manage various functionalities of the chat service."
}
